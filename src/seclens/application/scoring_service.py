from __future__ import annotations

import logging
import time

from seclens.domain.events import ScoreComputed
from seclens.domain.models import Product, SecurityScore, Vulnerability
from seclens.domain.scoring import compute_score
from seclens.ports.event_bus import EventBus
from seclens.ports.repositories import ProductRepository, VulnRepository

logger = logging.getLogger(__name__)


class ScoringService:
    """Computes security scorecards for products."""

    def __init__(
        self,
        product_repo: ProductRepository,
        vuln_repo: VulnRepository,
        event_bus: EventBus,
        advisory_fetcher=None,
    ) -> None:
        self._products = product_repo
        self._vulns = vuln_repo
        self._events = event_bus
        self._advisory = advisory_fetcher

    async def score_product(self, cpe_uri: str) -> tuple[Product, SecurityScore] | None:
        start = time.monotonic()

        product = await self._products.find_by_cpe(cpe_uri)
        if not product:
            return None

        vulns = await self._vulns.find_by_cpe(cpe_uri)

        if self._advisory and "redhat" in cpe_uri:
            vulns = await self._enrich_with_advisories(vulns)

        product.vulnerabilities = vulns
        score = compute_score(vulns)
        product.score = score

        elapsed_ms = (time.monotonic() - start) * 1000
        self._events.publish(ScoreComputed(
            product_name=product.name,
            cpe_uri=cpe_uri,
            score=score.overall,
            grade=score.grade,
            computation_ms=elapsed_ms,
        ))

        return product, score

    async def get_vulnerabilities(self, cpe_uri: str):
        return await self._vulns.find_by_cpe(cpe_uri)

    async def get_patches(self, cpe_uri: str):
        vulns = await self._vulns.find_by_cpe(cpe_uri)

        # Enrich with Red Hat advisory data if available
        if self._advisory and "redhat" in cpe_uri:
            vulns = await self._enrich_with_advisories(vulns)

        patched = [v for v in vulns if v.is_patched]
        return patched

    async def _enrich_with_advisories(self, vulns: list[Vulnerability]) -> list[Vulnerability]:
        """Enrich vulnerabilities with Red Hat RHSA advisory data."""
        if not self._advisory:
            return vulns

        cve_ids = [v.cve_id for v in vulns if not v.is_patched][:100]
        if not cve_ids:
            return vulns

        try:
            advisory_map = await self._advisory.fetch_patches_batch(cve_ids)
        except Exception:
            logger.warning("Failed to fetch Red Hat advisories")
            return vulns

        enriched = []
        for v in vulns:
            if v.cve_id in advisory_map:
                new_patches = list(v.patches) + advisory_map[v.cve_id]
                v = Vulnerability(
                    cve_id=v.cve_id,
                    description=v.description,
                    cvss_score=v.cvss_score,
                    severity=v.severity,
                    published=v.published,
                    last_modified=v.last_modified,
                    affected_cpes=v.affected_cpes,
                    epss_score=v.epss_score,
                    in_kev=v.in_kev,
                    patches=new_patches,
                    references=v.references,
                )
            enriched.append(v)
        return enriched
