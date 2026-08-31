from __future__ import annotations

import logging
import time

from seclens.domain.events import SearchPerformed
from seclens.domain.models import CPE, Product
from seclens.domain.models.product import PRODUCT_ALIASES
from seclens.domain.scoring import compute_score
from seclens.ports.data_fetchers import VulnDataFetcher
from seclens.ports.event_bus import EventBus
from seclens.ports.repositories import ProductRepository, VulnRepository

logger = logging.getLogger(__name__)


class SearchService:
    """Orchestrates free-text search: resolve query -> find products -> attach vulns -> score.

    If the local DB has no results, falls back to live NVD API queries.
    """

    def __init__(
        self,
        product_repo: ProductRepository,
        vuln_repo: VulnRepository,
        event_bus: EventBus,
        vuln_fetcher: VulnDataFetcher | None = None,
    ) -> None:
        self._products = product_repo
        self._vulns = vuln_repo
        self._events = event_bus
        self._fetcher = vuln_fetcher

    async def search(self, query: str, limit: int = 20) -> list[Product]:
        start = time.monotonic()

        _part, vendor, product_name, version = self._resolve_query(query)

        # Try local DB first
        products = await self._products.search_products(query, limit=limit)

        # If no local results, try alias-resolved search
        if not products:
            products = await self._products.search_products(f"{vendor} {product_name}", limit=limit)

        # Filter by version if the user specified one
        if products and version != "*":
            version_filtered = [
                p
                for p in products
                if p.version == version
                or p.version.startswith(version + ".")
                or p.version.startswith(version)
            ]
            if version_filtered:
                products = version_filtered
            else:
                # User asked for a specific version we don't have locally -- try live
                products = []

        if products:
            for product in products:
                vulns = await self._vulns.find_by_cpe(product.cpe.uri)
                product.vulnerabilities = vulns
                product.name = product.cpe.display_name
                if vulns:
                    product.score = compute_score(vulns)
        elif self._fetcher:
            # No local results matching -- try live NVD query as fallback
            products = await self._live_search(query, limit)

        elapsed_ms = (time.monotonic() - start) * 1000
        self._events.publish(
            SearchPerformed(
                query=query,
                results_count=len(products),
                duration_ms=elapsed_ms,
            )
        )

        return products

    @staticmethod
    def _resolve_query(query: str) -> tuple[str, str, str, str]:
        """Resolve a free-text query to (part, vendor, product, version) using aliases.

        Returns:
            (part, vendor, product, version) where part is a/o/h or * for unknown.

        Examples:
            "RHEL 9"     -> ("o", "redhat", "enterprise_linux", "9")
            "openssl"    -> ("a", "openssl", "openssl", "*")
            "apache httpd 2.4" -> ("a", "apache", "http_server", "2.4")
        """
        q = query.lower().strip()

        # Check aliases (longest match first)
        version = "*"
        for alias in sorted(PRODUCT_ALIASES.keys(), key=len, reverse=True):
            if q == alias or q.startswith(alias + " "):
                remainder = q[len(alias) :].strip()
                if remainder:
                    version = remainder.split()[0]
                part, vendor, product = PRODUCT_ALIASES[alias]
                return part, vendor, product, version

        # No alias match -- split into terms
        terms = q.split()
        if len(terms) >= 2 and terms[-1][0].isdigit():
            version = terms[-1]
            terms = terms[:-1]

        if len(terms) >= 2:
            vendor = terms[0]
            product = "_".join(terms[1:])
        else:
            vendor = terms[0]
            product = terms[0]

        return "*", vendor, product, version

    async def _live_search(self, query: str, limit: int) -> list[Product]:
        """Fall back to live NVD API when local DB has no data for this query."""
        logger.info("No local results for %r, trying live NVD query...", query)

        part, vendor, product, version = self._resolve_query(query)
        logger.info(
            "Resolved query %r -> part=%s vendor=%s product=%s version=%s",
            query,
            part,
            vendor,
            product,
            version,
        )
        vulns: list = []

        # Strategy 1: Exact CPE match (most precise)
        # If user gave version "9", try "9.0" first (NVD uses minor versions)
        versions_to_try = [version]
        if version != "*" and "." not in version:
            versions_to_try.insert(0, f"{version}.0")

        for v in versions_to_try:
            if vulns:
                break
            cpe_uri = f"cpe:2.3:{part}:{vendor}:{product}:{v}:*:*:*:*:*:*:*"
            try:
                logger.info("Trying exact CPE: %s", cpe_uri)
                vulns = await self._fetcher.fetch_by_cpe(cpe_uri)
            except Exception:  # noqa: BLE001 — best-effort live fallback
                logger.warning("Exact CPE match failed for %s", cpe_uri)

        # Strategy 2: Broader CPE match without version
        if not vulns and version != "*":
            cpe_uri = f"cpe:2.3:{part}:{vendor}:{product}:*:*:*:*:*:*:*:*"
            try:
                logger.info("Trying broad CPE: %s", cpe_uri)
                vulns = await self._fetcher.fetch_by_cpe(cpe_uri)
            except Exception:  # noqa: BLE001 — best-effort live fallback
                logger.warning("Broad CPE match failed for %r", query)

        # Strategy 3: Keyword search as fallback
        if not vulns and hasattr(self._fetcher, "fetch_by_keyword"):
            product_readable = product.replace("_", " ")
            keyword = f"{vendor.replace('_', ' ')} {product_readable}"
            if version != "*":
                keyword += f" {version}"
            try:
                logger.info("Trying keyword search: %s", keyword)
                vulns = await self._fetcher.fetch_by_keyword(keyword, limit=500)
            except Exception:  # noqa: BLE001 — best-effort live fallback
                logger.warning("Keyword search failed for %r", keyword)

        if not vulns:
            return []

        # Cache the results locally for future searches
        await self._vulns.save_vulnerabilities(vulns)

        # Also save CPE entries so future searches hit the local DB
        cpe_entries = []
        seen_cpes: set[str] = set()
        for v in vulns:
            for cpe_str in v.affected_cpes:
                if cpe_str in seen_cpes or not cpe_str.startswith("cpe:2.3:"):
                    continue
                seen_cpes.add(cpe_str)
                parts = cpe_str.split(":")
                if len(parts) >= 6:
                    cpe_entries.append(
                        {
                            "cpe_uri": cpe_str,
                            "part": parts[2],
                            "vendor": parts[3],
                            "product": parts[4],
                            "version": parts[5],
                            "title": "",
                        }
                    )
        if cpe_entries:
            await self._products.save_cpe_dictionary(cpe_entries)

        # Group vulns by (vendor, product, version) for cleaner results
        product_groups: dict[str, dict] = {}
        for v in vulns:
            for cpe_str in v.affected_cpes:
                try:
                    cpe = CPE.from_uri(cpe_str)
                except ValueError:
                    continue
                key = f"{cpe.vendor}:{cpe.product}:{cpe.version}"
                product_groups.setdefault(key, {"cpe": cpe, "vulns": []})
                product_groups[key]["vulns"].append(v)

        products = []
        for group in product_groups.values():
            cpe = group["cpe"]
            cpe_vulns = group["vulns"]
            seen_ids: set[str] = set()
            unique_vulns = []
            for v in cpe_vulns:
                if v.cve_id not in seen_ids:
                    seen_ids.add(v.cve_id)
                    unique_vulns.append(v)

            p = Product(
                name=cpe.display_name,
                cpe=cpe,
                vendor=cpe.vendor,
                version=cpe.version,
                vulnerabilities=unique_vulns,
            )
            p.score = compute_score(unique_vulns)
            products.append(p)

        # Filter to products matching the resolved vendor/product
        relevant = [p for p in products if p.cpe.vendor == vendor or p.cpe.product == product]
        if relevant:
            products = relevant

        # Strictly filter by version when the user specified one
        if version != "*":
            products = [p for p in products if p.version.startswith(version)]

        # Sort: specific versions first (not wildcard), then by vuln count
        products.sort(key=lambda p: (p.version == "*", -len(p.vulnerabilities)))
        return products[:limit]

    async def lookup_cve(self, cve_id: str):
        vuln = await self._vulns.find_by_cve_id(cve_id)
        if vuln:
            return vuln
        # Live fallback for CVE lookup
        if self._fetcher:
            logger.info("CVE %s not in local DB, trying live NVD...", cve_id)
            try:
                vulns = await self._fetcher.fetch_by_cpe(cve_id)
                if vulns:
                    await self._vulns.save_vulnerabilities(vulns)
                    return vulns[0]
            except Exception:  # noqa: BLE001 — best-effort live fallback
                logger.warning("Live CVE lookup failed for %s", cve_id)
        return None
