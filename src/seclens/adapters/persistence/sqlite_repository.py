from __future__ import annotations

import json
from contextlib import asynccontextmanager
from datetime import date
from pathlib import Path

import aiosqlite

from seclens.domain.models import CPE, PatchInfo, Product, Severity, Vulnerability
from seclens.ports.repositories import ProductRepository, VulnRepository


@asynccontextmanager
async def _connection(db_path: Path):
    db = await aiosqlite.connect(db_path)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA foreign_keys=ON")
    try:
        yield db
    finally:
        await db.close()

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS vulnerabilities (
    cve_id TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    cvss_score REAL NOT NULL DEFAULT 0.0,
    severity TEXT NOT NULL DEFAULT 'NONE',
    published TEXT NOT NULL,
    last_modified TEXT NOT NULL,
    affected_cpes TEXT NOT NULL DEFAULT '[]',
    epss_score REAL,
    in_kev INTEGER NOT NULL DEFAULT 0,
    patches TEXT NOT NULL DEFAULT '[]',
    references_ TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_vuln_published ON vulnerabilities(published);
CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vuln_cvss ON vulnerabilities(cvss_score);

CREATE VIRTUAL TABLE IF NOT EXISTS vuln_fts USING fts5(
    cve_id,
    description,
    content='vulnerabilities',
    content_rowid='rowid'
);

CREATE TABLE IF NOT EXISTS cpe_dictionary (
    cpe_uri TEXT PRIMARY KEY,
    part TEXT NOT NULL,
    vendor TEXT NOT NULL,
    product TEXT NOT NULL,
    version TEXT NOT NULL,
    title TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_cpe_vendor ON cpe_dictionary(vendor);
CREATE INDEX IF NOT EXISTS idx_cpe_product ON cpe_dictionary(product);

CREATE VIRTUAL TABLE IF NOT EXISTS cpe_fts USING fts5(
    cpe_uri,
    vendor,
    product,
    title
);

CREATE TABLE IF NOT EXISTS vuln_cpe_map (
    cve_id TEXT NOT NULL,
    cpe_uri TEXT NOT NULL,
    PRIMARY KEY (cve_id, cpe_uri)
);

CREATE INDEX IF NOT EXISTS idx_vcm_cpe ON vuln_cpe_map(cpe_uri);

CREATE TABLE IF NOT EXISTS sync_metadata (
    source TEXT PRIMARY KEY,
    last_sync TEXT NOT NULL,
    record_count INTEGER NOT NULL DEFAULT 0
);
"""


def _vuln_to_row(v: Vulnerability) -> tuple:
    patches_json = json.dumps([
        {
            "fixed_version": p.fixed_version,
            "advisory_id": p.advisory_id,
            "advisory_url": p.advisory_url,
            "patch_date": p.patch_date.isoformat() if p.patch_date else None,
            "source": p.source,
        }
        for p in v.patches
    ])
    return (
        v.cve_id,
        v.description,
        v.cvss_score,
        v.severity.value,
        v.published.isoformat(),
        v.last_modified.isoformat(),
        json.dumps(v.affected_cpes),
        v.epss_score,
        1 if v.in_kev else 0,
        patches_json,
        json.dumps(v.references),
    )


def _row_to_vuln(row: aiosqlite.Row) -> Vulnerability:
    patches_raw = json.loads(row["patches"])
    patches = [
        PatchInfo(
            fixed_version=p.get("fixed_version"),
            advisory_id=p.get("advisory_id"),
            advisory_url=p.get("advisory_url"),
            patch_date=date.fromisoformat(p["patch_date"]) if p.get("patch_date") else None,
            source=p.get("source", "nvd"),
        )
        for p in patches_raw
    ]
    return Vulnerability(
        cve_id=row["cve_id"],
        description=row["description"],
        cvss_score=row["cvss_score"],
        severity=Severity(row["severity"]),
        published=date.fromisoformat(row["published"]),
        last_modified=date.fromisoformat(row["last_modified"]),
        affected_cpes=json.loads(row["affected_cpes"]),
        epss_score=row["epss_score"],
        in_kev=bool(row["in_kev"]),
        patches=patches,
        references=json.loads(row["references_"]),
    )


class SQLiteVulnRepository(VulnRepository):
    def __init__(self, db_path: Path):
        self._db_path = db_path

    def _connect(self):
        """Return an aiosqlite connection context manager (use with `async with`)."""
        return _connection(self._db_path)

    async def initialize(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        async with self._connect() as db:
            await db.executescript(_SCHEMA_SQL)

    async def save_vulnerabilities(self, vulns: list[Vulnerability]) -> int:
        if not vulns:
            return 0
        async with self._connect() as db:
            saved = 0
            for v in vulns:
                row = _vuln_to_row(v)
                await db.execute(
                    """INSERT INTO vulnerabilities
                       (cve_id, description, cvss_score, severity, published,
                        last_modified, affected_cpes, epss_score, in_kev, patches, references_)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(cve_id) DO UPDATE SET
                        description=excluded.description,
                        cvss_score=excluded.cvss_score,
                        severity=excluded.severity,
                        last_modified=excluded.last_modified,
                        affected_cpes=excluded.affected_cpes,
                        epss_score=excluded.epss_score,
                        in_kev=excluded.in_kev,
                        patches=excluded.patches,
                        references_=excluded.references_
                    """,
                    row,
                )
                # Update FTS index
                await db.execute(
                    "INSERT OR REPLACE INTO vuln_fts(rowid, cve_id, description) "
                    "SELECT rowid, cve_id, description FROM vulnerabilities WHERE cve_id=?",
                    (v.cve_id,),
                )
                # Update CPE mapping
                for cpe_uri in v.affected_cpes:
                    await db.execute(
                        "INSERT OR IGNORE INTO vuln_cpe_map(cve_id, cpe_uri) VALUES (?, ?)",
                        (v.cve_id, cpe_uri),
                    )
                saved += 1
            await db.commit()
            return saved

    async def find_by_cpe(self, cpe_uri: str) -> list[Vulnerability]:
        async with self._connect() as db:
            cursor = await db.execute(
                """SELECT v.* FROM vulnerabilities v
                   JOIN vuln_cpe_map m ON v.cve_id = m.cve_id
                   WHERE m.cpe_uri LIKE ?
                   ORDER BY v.cvss_score DESC""",
                (cpe_uri.replace("*", "%"),),
            )
            rows = await cursor.fetchall()
            return [_row_to_vuln(r) for r in rows]

    async def find_by_cve_id(self, cve_id: str) -> Vulnerability | None:
        async with self._connect() as db:
            cursor = await db.execute(
                "SELECT * FROM vulnerabilities WHERE cve_id = ?", (cve_id,)
            )
            row = await cursor.fetchone()
            return _row_to_vuln(row) if row else None

    async def search(self, query: str, limit: int = 50) -> list[Vulnerability]:
        async with self._connect() as db:
            cursor = await db.execute(
                """SELECT v.* FROM vulnerabilities v
                   JOIN vuln_fts f ON v.rowid = f.rowid
                   WHERE vuln_fts MATCH ?
                   ORDER BY rank
                   LIMIT ?""",
                (query, limit),
            )
            rows = await cursor.fetchall()
            return [_row_to_vuln(r) for r in rows]

    async def update_patches(self, cve_id: str, patches: list[PatchInfo]) -> bool:
        """Merge new patches into an existing CVE's patch list."""
        async with self._connect() as db:
            cursor = await db.execute(
                "SELECT patches FROM vulnerabilities WHERE cve_id = ?", (cve_id,)
            )
            row = await cursor.fetchone()
            if not row:
                return False

            existing = json.loads(row["patches"])
            existing_ids = {(p.get("advisory_id"), p.get("source")) for p in existing}

            merged = list(existing)
            for p in patches:
                key = (p.advisory_id, p.source)
                if key not in existing_ids:
                    merged.append({
                        "fixed_version": p.fixed_version,
                        "advisory_id": p.advisory_id,
                        "advisory_url": p.advisory_url,
                        "patch_date": p.patch_date.isoformat() if p.patch_date else None,
                        "source": p.source,
                    })

            await db.execute(
                "UPDATE vulnerabilities SET patches = ? WHERE cve_id = ?",
                (json.dumps(merged), cve_id),
            )
            await db.commit()
            return True

    async def find_redhat_cve_ids(self, limit: int = 5000) -> list[str]:
        """Find CVE IDs that affect Red Hat products and lack Red Hat patch data."""
        async with self._connect() as db:
            cursor = await db.execute(
                """SELECT DISTINCT v.cve_id FROM vulnerabilities v
                   JOIN vuln_cpe_map m ON v.cve_id = m.cve_id
                   WHERE m.cpe_uri LIKE '%redhat%'
                   AND v.patches NOT LIKE '%"source": "redhat"%'
                   LIMIT ?""",
                (limit,),
            )
            rows = await cursor.fetchall()
            return [r["cve_id"] for r in rows]

    async def count(self) -> int:
        async with self._connect() as db:
            cursor = await db.execute("SELECT COUNT(*) FROM vulnerabilities")
            row = await cursor.fetchone()
            return row[0]


class SQLiteProductRepository(ProductRepository):
    def __init__(self, db_path: Path):
        self._db_path = db_path

    def _connect(self):
        return _connection(self._db_path)

    async def save_products(self, products: list[Product]) -> int:
        # Products are derived from CPE dictionary + vulns; not directly persisted
        return 0

    async def search_products(self, query: str, limit: int = 20) -> list[Product]:
        cpe_entries = await self.resolve_cpe(query, limit)
        products = []
        for entry in cpe_entries:
            cpe = CPE(
                uri=entry["cpe_uri"],
                part=entry["part"],
                vendor=entry["vendor"],
                product=entry["product"],
                version=entry["version"],
            )
            products.append(Product(
                name=entry.get("title") or cpe.display_name,
                cpe=cpe,
                vendor=entry["vendor"],
                version=entry["version"],
            ))
        return products

    async def find_by_cpe(self, cpe_uri: str) -> Product | None:
        async with self._connect() as db:
            cursor = await db.execute(
                "SELECT * FROM cpe_dictionary WHERE cpe_uri = ?", (cpe_uri,)
            )
            row = await cursor.fetchone()
            if not row:
                return None
            cpe = CPE(
                uri=row["cpe_uri"],
                part=row["part"],
                vendor=row["vendor"],
                product=row["product"],
                version=row["version"],
            )
            return Product(
                name=row["title"] or cpe.display_name,
                cpe=cpe,
                vendor=row["vendor"],
                version=row["version"],
            )

    async def save_cpe_dictionary(self, cpes: list[dict]) -> int:
        if not cpes:
            return 0
        async with self._connect() as db:
            saved = 0
            for c in cpes:
                await db.execute(
                    """INSERT INTO cpe_dictionary (cpe_uri, part, vendor, product, version, title)
                       VALUES (?, ?, ?, ?, ?, ?)
                       ON CONFLICT(cpe_uri) DO UPDATE SET title=excluded.title""",
                    (c["cpe_uri"], c["part"], c["vendor"], c["product"], c["version"], c.get("title", "")),
                )
                await db.execute(
                    "INSERT OR REPLACE INTO cpe_fts(rowid, cpe_uri, vendor, product, title) "
                    "SELECT rowid, cpe_uri, vendor, product, title FROM cpe_dictionary WHERE cpe_uri=?",
                    (c["cpe_uri"],),
                )
                saved += 1
            await db.commit()
            return saved

    async def resolve_cpe(self, query: str, limit: int = 10) -> list[dict]:
        query_clean = query.strip().replace("_", " ")
        async with self._connect() as db:
            # Try FTS first
            fts_query = " ".join(f'"{w}"' for w in query_clean.split() if w)
            cursor = await db.execute(
                """SELECT * FROM cpe_dictionary
                   WHERE rowid IN (
                       SELECT rowid FROM cpe_fts WHERE cpe_fts MATCH ?
                   )
                   LIMIT ?""",
                (fts_query, limit),
            )
            rows = await cursor.fetchall()

            if not rows:
                # Fallback to LIKE search
                like_pattern = f"%{query_clean}%"
                cursor = await db.execute(
                    """SELECT * FROM cpe_dictionary
                       WHERE product LIKE ? OR vendor LIKE ? OR title LIKE ?
                       LIMIT ?""",
                    (like_pattern, like_pattern, like_pattern, limit),
                )
                rows = await cursor.fetchall()

            return [dict(r) for r in rows]
