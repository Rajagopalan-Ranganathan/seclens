from __future__ import annotations

import logging
import time

from seclens.domain.events import DataSyncCompleted
from seclens.ports.data_fetchers import EPSSFetcher, KEVFetcher, VulnDataFetcher
from seclens.ports.event_bus import EventBus
from seclens.ports.repositories import ProductRepository, VulnRepository

logger = logging.getLogger(__name__)


class SyncService:
    """Orchestrates data synchronization from NVD, EPSS, and CISA KEV."""

    def __init__(
        self,
        vuln_repo: VulnRepository,
        product_repo: ProductRepository,
        vuln_fetcher: VulnDataFetcher,
        epss_fetcher: EPSSFetcher,
        kev_fetcher: KEVFetcher,
        event_bus: EventBus,
        advisory_fetcher=None,
    ) -> None:
        self._vuln_repo = vuln_repo
        self._product_repo = product_repo
        self._vuln_fetcher = vuln_fetcher
        self._epss_fetcher = epss_fetcher
        self._kev_fetcher = kev_fetcher
        self._events = event_bus
        self._advisory = advisory_fetcher

    async def sync_all(self, max_vulns: int = 10000) -> dict[str, int]:
        """Run a full sync of all data sources. Returns counts per source."""
        results = {}
        results["nvd"] = await self.sync_nvd(max_vulns=max_vulns)
        results["epss"] = await self.sync_epss()
        results["kev"] = await self.sync_kev()
        if self._advisory:
            results["redhat"] = await self.sync_redhat_advisories()
        return results

    async def sync_nvd(self, max_vulns: int = 10000) -> int:
        """Sync vulnerability data from NVD."""
        start = time.monotonic()
        errors: list[str] = []
        total_saved = 0

        try:
            start_index = 0
            while start_index < max_vulns:
                batch_size = min(2000, max_vulns - start_index)
                logger.info("Syncing NVD batch: start=%d size=%d", start_index, batch_size)

                vulns, total_available = await self._vuln_fetcher.fetch_all(
                    start_index=start_index, batch_size=batch_size
                )
                if not vulns:
                    break

                saved = await self._vuln_repo.save_vulnerabilities(vulns)
                total_saved += saved
                start_index += len(vulns)

                # Also collect CPE data from vulnerabilities
                cpe_entries = self._extract_cpe_entries(vulns)
                if cpe_entries:
                    await self._product_repo.save_cpe_dictionary(cpe_entries)

                logger.info(
                    "NVD batch saved: %d vulns, %d CPEs (total available: %d)",
                    saved,
                    len(cpe_entries),
                    total_available,
                )

                if start_index >= total_available:
                    break

        except Exception as e:
            errors.append(str(e))
            logger.exception("NVD sync error")

        elapsed_ms = (time.monotonic() - start) * 1000
        self._events.publish(
            DataSyncCompleted(
                source="nvd",
                records_synced=total_saved,
                duration_ms=elapsed_ms,
                errors=errors,
            )
        )
        return total_saved

    async def sync_epss(self) -> int:
        """Sync EPSS scores and update stored vulnerabilities."""
        start = time.monotonic()
        errors: list[str] = []
        updated = 0

        try:
            scores = await self._epss_fetcher.fetch_all_scores()
            # We'll update EPSS scores on vulnerabilities as they're queried
            # For now, store the count
            updated = len(scores)
            logger.info("Fetched %d EPSS scores", updated)
        except Exception as e:
            errors.append(str(e))
            logger.exception("EPSS sync error")

        elapsed_ms = (time.monotonic() - start) * 1000
        self._events.publish(
            DataSyncCompleted(
                source="epss",
                records_synced=updated,
                duration_ms=elapsed_ms,
                errors=errors,
            )
        )
        return updated

    async def sync_kev(self) -> int:
        """Sync CISA KEV catalog."""
        start = time.monotonic()
        errors: list[str] = []
        count = 0

        try:
            kev_ids = await self._kev_fetcher.fetch_kev_ids()
            count = len(kev_ids)
            logger.info("Fetched %d KEV entries", count)
        except Exception as e:
            errors.append(str(e))
            logger.exception("KEV sync error")

        elapsed_ms = (time.monotonic() - start) * 1000
        self._events.publish(
            DataSyncCompleted(
                source="kev",
                records_synced=count,
                duration_ms=elapsed_ms,
                errors=errors,
            )
        )
        return count

    async def sync_redhat_advisories(self, batch_size: int = 50) -> int:
        """Enrich stored Red Hat CVEs with RHSA advisory/patch data."""
        start = time.monotonic()
        errors: list[str] = []
        enriched = 0

        try:
            cve_ids = await self._vuln_repo.find_redhat_cve_ids(limit=2000)
            logger.info("Found %d Red Hat CVEs needing advisory enrichment", len(cve_ids))

            for i in range(0, len(cve_ids), batch_size):
                batch = cve_ids[i : i + batch_size]
                advisory_map = await self._advisory.fetch_patches_batch(batch)

                for cve_id, patches in advisory_map.items():
                    if patches:
                        updated = await self._vuln_repo.update_patches(cve_id, patches)
                        if updated:
                            enriched += 1

                logger.info(
                    "Red Hat advisory batch %d-%d: enriched %d CVEs",
                    i,
                    i + len(batch),
                    enriched,
                )

        except Exception as e:
            errors.append(str(e))
            logger.exception("Red Hat advisory sync error")

        elapsed_ms = (time.monotonic() - start) * 1000
        self._events.publish(
            DataSyncCompleted(
                source="redhat",
                records_synced=enriched,
                duration_ms=elapsed_ms,
                errors=errors,
            )
        )
        return enriched

    @staticmethod
    def _extract_cpe_entries(vulns) -> list[dict]:
        """Extract unique CPE entries from vulnerability data for the CPE dictionary."""
        seen: set[str] = set()
        entries: list[dict] = []
        for v in vulns:
            for cpe_uri in v.affected_cpes:
                if cpe_uri in seen or not cpe_uri.startswith("cpe:2.3:"):
                    continue
                seen.add(cpe_uri)
                parts = cpe_uri.split(":")
                if len(parts) >= 6:
                    entries.append(
                        {
                            "cpe_uri": cpe_uri,
                            "part": parts[2],
                            "vendor": parts[3],
                            "product": parts[4],
                            "version": parts[5],
                            "title": f"{parts[3].replace('_', ' ').title()} {parts[4].replace('_', ' ').title()}",
                        }
                    )
        return entries
