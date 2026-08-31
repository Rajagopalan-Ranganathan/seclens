"""Red Hat Security Data API adapter for advisory/errata enrichment."""

from __future__ import annotations

import logging
from datetime import date, datetime

import httpx

from seclens.domain.models import PatchInfo

logger = logging.getLogger(__name__)

REDHAT_CVE_API = "https://access.redhat.com/hydra/rest/securitydata/cve"


class RedHatAdvisoryFetcher:
    """Fetches advisory/patch data from Red Hat's public Security Data API.

    Enriches vulnerability records with RHSA errata IDs and fix versions.
    This is a supplementary fetcher -- not a primary VulnDataFetcher port.
    """

    async def fetch_patches_for_cve(self, cve_id: str) -> list[PatchInfo]:
        """Fetch Red Hat advisories (RHSA) that fix a specific CVE."""
        url = f"{REDHAT_CVE_API}/{cve_id}.json"
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(url)
                if resp.status_code == 404:
                    return []
                resp.raise_for_status()
                data = resp.json()
        except Exception:
            logger.debug("Red Hat API unavailable for %s", cve_id)
            return []

        patches: list[PatchInfo] = []
        for fix in data.get("affected_release", []):
            advisory = fix.get("advisory", "")
            package = fix.get("package", "")

            fixed_version = package.split("-")[-2] if "-" in package else None

            patch_date = None
            raw_date = fix.get("release_date")
            if raw_date:
                try:
                    patch_date = datetime.strptime(raw_date, "%Y-%m-%dT%H:%M:%SZ").date()
                except (ValueError, TypeError):
                    try:
                        patch_date = date.fromisoformat(raw_date[:10])
                    except (ValueError, TypeError):
                        pass

            patches.append(PatchInfo(
                fixed_version=fixed_version,
                advisory_id=advisory,
                advisory_url=f"https://access.redhat.com/errata/{advisory}" if advisory else None,
                patch_date=patch_date,
                source="redhat",
            ))

        return patches

    async def fetch_patches_batch(self, cve_ids: list[str]) -> dict[str, list[PatchInfo]]:
        """Fetch Red Hat advisories for multiple CVEs with concurrency."""
        import asyncio

        results: dict[str, list[PatchInfo]] = {}
        semaphore = asyncio.Semaphore(5)

        async def _fetch_one(cve_id: str) -> None:
            async with semaphore:
                patches = await self.fetch_patches_for_cve(cve_id)
                if patches:
                    results[cve_id] = patches

        tasks = [_fetch_one(cve_id) for cve_id in cve_ids]
        await asyncio.gather(*tasks, return_exceptions=True)
        return results
