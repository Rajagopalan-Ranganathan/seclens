"""CISA Known Exploited Vulnerabilities (KEV) catalog fetcher."""

from __future__ import annotations

import logging

import httpx

from seclens.ports.data_fetchers import KEVFetcher

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CISAKEVFetcher(KEVFetcher):
    async def fetch_kev_ids(self) -> set[str]:
        logger.info("Fetching CISA KEV catalog...")
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(KEV_URL)
            resp.raise_for_status()
            data = resp.json()

        kev_ids = {
            entry.get("cveID", "")
            for entry in data.get("vulnerabilities", [])
            if entry.get("cveID")
        }
        logger.info("Loaded %d KEV entries", len(kev_ids))
        return kev_ids
