"""Have I Been Pwned API adapter for data breach history."""

from __future__ import annotations

import logging
import os
from datetime import date

import httpx

from seclens.domain.models.privacy import BreachRecord
from seclens.ports.privacy_fetchers import BreachFetcher as BreachFetcherPort

logger = logging.getLogger(__name__)

HIBP_API = "https://haveibeenpwned.com/api/v3/breaches"


class HIBPFetcher(BreachFetcherPort):
    """Queries the Have I Been Pwned API for breach records."""

    def __init__(self) -> None:
        self._api_key = os.environ.get("HIBP_API_KEY", "")

    async def fetch_breaches(self, domain: str) -> list[BreachRecord]:
        headers: dict[str, str] = {"User-Agent": "seclens-privacy-scanner"}
        if self._api_key:
            headers["hibp-api-key"] = self._api_key

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    HIBP_API,
                    params={"domain": domain},
                    headers=headers,
                )
                if resp.status_code == 404:
                    return []
                resp.raise_for_status()
                data = resp.json()
        except (httpx.HTTPError, OSError, ValueError) as exc:
            logger.warning("HIBP breach lookup failed for %s: %s", domain, exc)
            return []

        breaches: list[BreachRecord] = []
        for item in data:
            breach_date = None
            raw_date = item.get("BreachDate")
            if raw_date:
                try:
                    breach_date = date.fromisoformat(raw_date)
                except ValueError:
                    pass

            breaches.append(
                BreachRecord(
                    name=item.get("Name", ""),
                    domain=item.get("Domain", domain),
                    breach_date=breach_date,
                    record_count=item.get("PwnCount", 0),
                    data_types=tuple(item.get("DataClasses", [])),
                    is_verified=item.get("IsVerified", True),
                )
            )

        return breaches
