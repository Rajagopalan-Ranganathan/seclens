"""PrivacySpy dataset adapter — loads privacy scores from the PrivacySpy hosted API."""

from __future__ import annotations

import logging

import httpx

from seclens.domain.models.privacy import PrivacySignal
from seclens.ports.privacy_fetchers import PrivacySpyFetcher as PrivacySpyFetcherPort

logger = logging.getLogger(__name__)

PRIVACYSPY_API_URL = "https://privacyspy.org/api/v2/products.json"

_CATEGORY_MAP = {
    "collection": "data_collection",
    "handling": "sharing",
    "transparency": "policy",
}


class PrivacySpyApiFetcher(PrivacySpyFetcherPort):
    """Loads the PrivacySpy product dataset and provides score lookups."""

    def __init__(self) -> None:
        self._products: dict[str, dict] = {}
        self._domain_index: dict[str, str] = {}
        self._loaded = False

    async def load(self) -> None:
        if self._loaded:
            return
        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                resp = await client.get(PRIVACYSPY_API_URL)
                resp.raise_for_status()
                data = resp.json()
        except (httpx.HTTPError, OSError, ValueError) as exc:
            logger.warning("Failed to load PrivacySpy dataset: %s", exc)
            return

        products = data if isinstance(data, list) else data.get("products", [])
        for product in products:
            if not isinstance(product, dict):
                continue
            slug = product.get("slug", "").lower()
            name = product.get("name", "").lower()
            hostnames = product.get("hostnames", [])

            if slug:
                self._products[slug] = product
            if name:
                self._products[name] = product
            for hostname in hostnames:
                if hostname:
                    self._domain_index[hostname.lower()] = slug or name

        self._loaded = True
        logger.info("Loaded PrivacySpy dataset: %d products", len(self._products))

    async def fetch_score(
        self, service_name: str, domain: str
    ) -> tuple[float | None, list[PrivacySignal]]:
        if not self._loaded:
            await self.load()

        product = self._find_product(service_name, domain)
        if product is None:
            return None, []

        score = product.get("score")
        if score is None:
            return None, []

        try:
            score_val = float(score)
        except (ValueError, TypeError):
            return None, []

        signals = self._extract_signals(product)
        return score_val, signals

    def _find_product(self, service_name: str, domain: str) -> dict | None:
        name_lower = service_name.lower()
        if name_lower in self._products:
            return self._products[name_lower]

        for key in self._products:
            if name_lower in key or key in name_lower:
                return self._products[key]

        domain_lower = domain.lower().replace("www.", "")
        if domain_lower in self._domain_index:
            slug = self._domain_index[domain_lower]
            return self._products.get(slug)

        return None

    @staticmethod
    def _extract_signals(product: dict) -> list[PrivacySignal]:
        signals: list[PrivacySignal] = []

        rubric = product.get("rubric", [])
        if not isinstance(rubric, list):
            return signals

        for entry in rubric:
            if not isinstance(entry, dict):
                continue
            question = entry.get("question", {})
            option = entry.get("option", {})
            if not question or not option:
                continue

            q_text = question.get("text", "")
            q_category = question.get("category", "")
            opt_text = option.get("text", "")
            opt_percent = option.get("percent", 0)

            category = _CATEGORY_MAP.get(q_category, "policy")

            try:
                percent = float(opt_percent)
                raw_score = percent / 10.0
            except (ValueError, TypeError):
                raw_score = None
                percent = 0.0

            if percent >= 70:
                sentiment = "good"
            elif percent >= 30:
                sentiment = "neutral"
            else:
                sentiment = "bad"

            description = f"{q_text} → {opt_text}" if opt_text else q_text

            signals.append(
                PrivacySignal(
                    source="privacyspy",
                    category=category,
                    description=description,
                    sentiment=sentiment,
                    raw_score=raw_score,
                )
            )

        return signals
