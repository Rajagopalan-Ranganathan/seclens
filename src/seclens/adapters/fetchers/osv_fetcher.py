"""OSV.dev API adapter for open-source vulnerability queries."""

from __future__ import annotations

import logging

import httpx

from seclens.domain.models import Dependency
from seclens.domain.models.dependency import DependencyVuln
from seclens.ports.osv_fetcher import OSVFetcher as OSVFetcherPort

logger = logging.getLogger(__name__)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_SINGLE_URL = "https://api.osv.dev/v1/query"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"

_ECOSYSTEM_MAP: dict[str, str] = {
    "PyPI": "PyPI",
    "npm": "npm",
    "Go": "Go",
    "crates.io": "crates.io",
    "Maven": "Maven",
    "RubyGems": "RubyGems",
    "NuGet": "NuGet",
    "Packagist": "Packagist",
    "Pub": "Pub",
    "Hex": "Hex",
}

BATCH_SIZE = 100


class OSVApiFetcher(OSVFetcherPort):
    """Queries the OSV.dev batch API for dependency vulnerabilities."""

    async def query_batch(self, deps: list[Dependency]) -> list[Dependency]:
        if not deps:
            return deps

        queryable = [
            (i, d) for i, d in enumerate(deps) if d.version and d.ecosystem in _ECOSYSTEM_MAP
        ]

        for batch_start in range(0, len(queryable), BATCH_SIZE):
            batch = queryable[batch_start : batch_start + BATCH_SIZE]
            queries = [
                {
                    "package": {"name": d.name, "ecosystem": _ECOSYSTEM_MAP[d.ecosystem]},
                    "version": d.version,
                }
                for _, d in batch
            ]

            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    resp = await client.post(OSV_BATCH_URL, json={"queries": queries})
                    resp.raise_for_status()
                    data = resp.json()
            except (httpx.HTTPError, OSError, ValueError):
                logger.warning("OSV batch query failed for batch starting at %d", batch_start)
                continue

            results = data.get("results", [])
            for (idx, dep), result in zip(batch, results):
                vulns_data = result.get("vulns", [])
                if not vulns_data:
                    continue
                dep_vulns = [self._parse_vuln(v) for v in vulns_data]
                deps[idx].vulnerabilities = dep_vulns

        return deps

    @staticmethod
    def _parse_vuln(v: dict) -> DependencyVuln:
        vuln_id = v.get("id", "")
        aliases = v.get("aliases", [])
        summary = v.get("summary", "")
        url = f"https://osv.dev/vulnerability/{vuln_id}" if vuln_id else ""

        severity = "UNKNOWN"
        cvss_score = None
        for sev in v.get("severity", []):
            score_str = sev.get("score")
            if score_str:
                try:
                    cvss_score = float(score_str)
                except (ValueError, TypeError):
                    pass

        if cvss_score is not None:
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"
        elif v.get("database_specific", {}).get("severity"):
            severity = v["database_specific"]["severity"].upper()

        fixed_version = None
        for affected in v.get("affected", []):
            for r in affected.get("ranges", []):
                for event in r.get("events", []):
                    if "fixed" in event:
                        fixed_version = event["fixed"]
                        break

        return DependencyVuln(
            vuln_id=vuln_id,
            aliases=aliases,
            summary=summary,
            severity=severity,
            cvss_score=cvss_score,
            fixed_version=fixed_version,
            url=url,
        )
