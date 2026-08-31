"""ToS;DR (Terms of Service; Didn't Read) API adapter."""

from __future__ import annotations

import logging

import httpx

from seclens.domain.models.privacy import PrivacySignal
from seclens.ports.privacy_fetchers import ToSDRFetcher as ToSDRFetcherPort

logger = logging.getLogger(__name__)

TOSDR_SEARCH_URL = "https://api.tosdr.org/search/v4/"
TOSDR_SERVICE_URL = "https://api.tosdr.org/service/v2/"

_CASE_STATUS_MAP = {
    "approved": True,
    "declined": False,
}

_POINT_CATEGORY_MAP = {
    "data": "data_collection",
    "security": "policy",
    "social": "sharing",
    "law": "policy",
    "misc": "policy",
}


class ToSDRApiFetcher(ToSDRFetcherPort):
    """Fetches privacy ratings from the ToS;DR API."""

    async def fetch_service(
        self, service_name: str, tosdr_id: int | None = None
    ) -> tuple[str | None, list[PrivacySignal]]:
        service_id = tosdr_id
        if not service_id:
            service_id = await self._search_id(service_name)
        if not service_id:
            return None, []
        return await self._fetch_by_id(service_id)

    async def _search_id(self, service_name: str) -> int | None:
        """Search ToS;DR for a service and return its ID."""
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(TOSDR_SEARCH_URL, params={"query": service_name})
                resp.raise_for_status()
                data = resp.json()
        except (httpx.HTTPError, OSError, ValueError) as exc:
            logger.warning("ToS;DR search failed for %r: %s", service_name, exc)
            return None

        services = data.get("parameters", {}).get("services", [])
        if not services:
            return None
        raw_id = services[0].get("id")
        if raw_id is None:
            return None
        try:
            return int(raw_id)
        except (ValueError, TypeError):
            return None

    async def _fetch_by_id(self, service_id: int) -> tuple[str | None, list[PrivacySignal]]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(TOSDR_SERVICE_URL, params={"id": service_id})
                resp.raise_for_status()
                data = resp.json()
        except (httpx.HTTPError, OSError, ValueError) as exc:
            logger.warning("ToS;DR service fetch failed for id=%d: %s", service_id, exc)
            return None, []

        return self._parse_service(data)

    @staticmethod
    def _parse_service(data: dict) -> tuple[str | None, list[PrivacySignal]]:
        parameters = data.get("parameters", {})
        rating = parameters.get("rating")
        if isinstance(rating, dict):
            grade = rating.get("letter")
        elif isinstance(rating, str) and len(rating) == 1:
            grade = rating.upper()
        else:
            grade = None

        signals: list[PrivacySignal] = []
        for point in parameters.get("points", []):
            title = point.get("title", "")
            if not title:
                continue
            case_data = point.get("case", {}) or {}
            classification = case_data.get("classification", "neutral")
            tosdr_category = case_data.get("topic", "misc")
            category = _POINT_CATEGORY_MAP.get(tosdr_category, "policy")

            sentiment_map = {
                "good": "good",
                "neutral": "neutral",
                "bad": "bad",
                "blocker": "blocker",
            }
            sentiment = sentiment_map.get(classification, "neutral")

            signals.append(
                PrivacySignal(
                    source="tosdr",
                    category=category,
                    description=title,
                    sentiment=sentiment,
                    raw_score=None,
                )
            )

        return grade, signals
