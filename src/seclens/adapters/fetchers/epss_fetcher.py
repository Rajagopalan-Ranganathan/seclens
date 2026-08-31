"""EPSS (Exploit Prediction Scoring System) data fetcher."""

from __future__ import annotations

import csv
import io
import logging

import httpx

from seclens.ports.data_fetchers import EPSSFetcher

logger = logging.getLogger(__name__)

EPSS_API_BASE = "https://api.first.org/data/v1/epss"
EPSS_CSV_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


class EPSSDataFetcher(EPSSFetcher):
    async def fetch_scores(self, cve_ids: list[str]) -> dict[str, float]:
        if not cve_ids:
            return {}

        scores: dict[str, float] = {}
        # EPSS API accepts up to 100 CVEs per request
        for i in range(0, len(cve_ids), 100):
            batch = cve_ids[i : i + 100]
            cve_param = ",".join(batch)
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(EPSS_API_BASE, params={"cve": cve_param})
                resp.raise_for_status()
                data = resp.json()

            for entry in data.get("data", []):
                cve_id = entry.get("cve", "")
                epss = float(entry.get("epss", 0.0))
                scores[cve_id] = epss

        return scores

    async def fetch_all_scores(self) -> dict[str, float]:
        """Download the full EPSS CSV dataset (gzipped).

        The CSV has a comment header line, then: cve,epss,percentile
        """
        logger.info("Downloading full EPSS dataset...")
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.get(EPSS_CSV_URL)
            resp.raise_for_status()

        # Decompress gzip
        import gzip

        raw = gzip.decompress(resp.content).decode("utf-8")

        scores: dict[str, float] = {}
        reader = csv.reader(io.StringIO(raw))
        for row in reader:
            if not row or row[0].startswith("#") or row[0] == "cve":
                continue
            if len(row) >= 2:
                scores[row[0]] = float(row[1])

        logger.info("Loaded %d EPSS scores", len(scores))
        return scores
