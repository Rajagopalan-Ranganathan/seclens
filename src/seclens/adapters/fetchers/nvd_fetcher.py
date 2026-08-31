"""NVD (National Vulnerability Database) API 2.0 adapter."""

from __future__ import annotations

import asyncio
import datetime as _dt
import logging
from datetime import date, timedelta

import httpx

from seclens.domain.models import PatchInfo, Severity, Vulnerability
from seclens.ports.data_fetchers import VulnDataFetcher

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Without an API key: 5 requests per 30 seconds
RATE_LIMIT_DELAY = 6.5


class NVDFetcher(VulnDataFetcher):
    def __init__(self, api_key: str | None = None):
        self._api_key = api_key
        self._rate_delay = 0.6 if api_key else RATE_LIMIT_DELAY

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self._api_key:
            headers["apiKey"] = self._api_key
        return headers

    async def fetch_by_cpe(self, cpe_uri: str) -> list[Vulnerability]:
        params = {"cpeName": cpe_uri, "resultsPerPage": 2000}
        return await self._fetch_vulns(params)

    async def fetch_by_keyword(self, keyword: str, limit: int = 2000) -> list[Vulnerability]:
        """Search NVD by keyword (free-text search across CVE descriptions)."""
        params = {"keywordSearch": keyword, "resultsPerPage": min(limit, 2000)}
        return await self._fetch_vulns(params)

    async def fetch_by_cpe_match(self, cpe_prefix: str) -> list[Vulnerability]:
        """Search NVD using virtualMatchString for CPE prefix matching.

        e.g., "cpe:2.3:o:redhat:enterprise_linux:9" matches 9.0, 9.1, 9.2, etc.
        """
        params = {"virtualMatchString": cpe_prefix, "resultsPerPage": 2000}
        return await self._fetch_vulns(params)

    async def fetch_recent(self, days: int = 7) -> list[Vulnerability]:
        end = _dt.datetime.now(tz=_dt.UTC).date()
        start = end - timedelta(days=days)
        params = {
            "pubStartDate": f"{start.isoformat()}T00:00:00.000",
            "pubEndDate": f"{end.isoformat()}T23:59:59.999",
            "resultsPerPage": 2000,
        }
        return await self._fetch_vulns(params)

    async def fetch_all(
        self, start_index: int = 0, batch_size: int = 2000
    ) -> tuple[list[Vulnerability], int]:
        params = {"startIndex": start_index, "resultsPerPage": batch_size}
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.get(NVD_API_BASE, params=params, headers=self._headers())
            resp.raise_for_status()
            data = resp.json()

        total = data.get("totalResults", 0)
        vulns = [self._parse_cve(item) for item in data.get("vulnerabilities", [])]
        return vulns, total

    async def _fetch_vulns(self, params: dict) -> list[Vulnerability]:
        all_vulns: list[Vulnerability] = []
        start_index = 0

        async with httpx.AsyncClient(timeout=60.0) as client:
            while True:
                params["startIndex"] = start_index
                logger.info("NVD fetch: startIndex=%d", start_index)

                resp = await client.get(NVD_API_BASE, params=params, headers=self._headers())
                resp.raise_for_status()
                data = resp.json()

                items = data.get("vulnerabilities", [])
                for item in items:
                    all_vulns.append(self._parse_cve(item))

                total = data.get("totalResults", 0)
                start_index += len(items)

                if start_index >= total or not items:
                    break

                await asyncio.sleep(self._rate_delay)

        return all_vulns

    def _parse_cve(self, item: dict) -> Vulnerability:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        cvss_score = self._extract_cvss(cve)
        published = self._parse_date(cve.get("published", ""))
        last_modified = self._parse_date(cve.get("lastModified", ""))

        affected_cpes = self._extract_cpes(cve)
        patches = self._extract_patches(cve)
        refs = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]

        return Vulnerability(
            cve_id=cve_id,
            description=desc,
            cvss_score=cvss_score,
            severity=Severity.from_cvss(cvss_score),
            published=published,
            last_modified=last_modified,
            affected_cpes=affected_cpes,
            patches=patches,
            references=refs,
        )

    @staticmethod
    def _extract_cvss(cve: dict) -> float:
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                return entries[0].get("cvssData", {}).get("baseScore", 0.0)
        return 0.0

    @staticmethod
    def _extract_cpes(cve: dict) -> list[str]:
        cpes: list[str] = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        cpes.append(match.get("criteria", ""))
        return cpes

    @staticmethod
    def _extract_patches(cve: dict) -> list[PatchInfo]:
        patches: list[PatchInfo] = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    fixed = match.get("versionEndExcluding")
                    if fixed and match.get("vulnerable"):
                        patches.append(PatchInfo(fixed_version=fixed, source="nvd"))
        return patches

    @staticmethod
    def _parse_date(dt_str: str) -> date:
        if not dt_str:
            return _dt.datetime.now(tz=_dt.UTC).date()
        return date.fromisoformat(dt_str[:10])
