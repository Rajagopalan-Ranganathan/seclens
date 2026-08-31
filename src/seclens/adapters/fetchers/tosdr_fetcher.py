"""ToS;DR (Terms of Service; Didn't Read) API adapter."""

from __future__ import annotations

import logging

import httpx

from seclens.domain.models.privacy import PrivacySignal
from seclens.ports.privacy_fetchers import ToSDRFetcher as ToSDRFetcherPort

logger = logging.getLogger(__name__)

TOSDR_API_V4 = "https://api.tosdr.org/search/v4/"
TOSDR_SERVICE_V1 = "https://api.tosdr.org/service/v1/"

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
        if tosdr_id:
            return await self._fetch_by_id(tosdr_id)
        return await self._search(service_name)

    async def _fetch_by_id(self, service_id: int) -> tuple[str | None, list[PrivacySignal]]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    TOSDR_SERVICE_V1,
                    params={"id": service_id},
                )
                resp.raise_for_status()
                data = resp.json()
        except (httpx.HTTPError, OSError, ValueError) as exc:
            logger.warning("ToS;DR service fetch failed for id=%d: %s", service_id, exc)
            return None, []

        return self._parse_service(data)

    async def _search(self, service_name: str) -> tuple[str | None, list[PrivacySignal]]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    TOSDR_API_V4,
                    params={"query": service_name},
                )
                resp.raise_for_status()
                data = resp.json()
        except (httpx.HTTPError, OSError, ValueError) as exc:
            logger.warning("ToS;DR search failed for %r: %s", service_name, exc)
            return None, []

        parameters = data.get("parameters", {})
        services = parameters.get("services", [])
        if not services:
            return None, []

        best = services[0]
        service_id = best.get("id")
        if not service_id:
            return None, []

        return await self._fetch_by_id(service_id)

    @staticmethod
    def _parse_service(data: dict) -> tuple[str | None, list[PrivacySignal]]:
        parameters = data.get("parameters", {})
        grade = (
            parameters.get("rating", {}).get("letter")
            if isinstance(parameters.get("rating"), dict)
            else None
        )

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
