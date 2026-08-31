"""PrivacySpy dataset adapter — loads privacy scores from the PrivacySpy GitHub repo."""

from __future__ import annotations

import logging

import httpx

from seclens.domain.models.privacy import PrivacySignal
from seclens.ports.privacy_fetchers import PrivacySpyFetcher as PrivacySpyFetcherPort

logger = logging.getLogger(__name__)

PRIVACYSPY_INDEX_URL = (
    "https://raw.githubusercontent.com/Politiwatch/privacyspy/master/src/data/products.json"
)


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
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(PRIVACYSPY_INDEX_URL)
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
            hostname = product.get("hostnames", [""])[0] if product.get("hostnames") else ""

            if slug:
                self._products[slug] = product
            if name:
                self._products[name] = product
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

        rubric = product.get("rubric", {})
        if not isinstance(rubric, dict):
            return signals

        rubric_items = {
            "behavioralMarketing": ("data_collection", "Uses data for behavioral marketing"),
            "security": ("policy", "Has adequate security practices"),
            "thirdPartyCollection": ("sharing", "Collects data from third parties"),
            "thirdPartySharing": ("sharing", "Shares data with third parties"),
            "trackingByService": ("data_collection", "Tracks you on their service"),
            "trackingByThirdParties": ("data_collection", "Allows third-party tracking"),
            "dataBreaches": ("policy", "History of data breaches"),
            "dataCollection": ("data_collection", "Amount of personal data collected"),
            "dataDeletion": ("policy", "Provides data deletion mechanism"),
            "lawEnforcement": ("policy", "Law enforcement data sharing policy"),
        }

        for key, (category, description) in rubric_items.items():
            val = rubric.get(key)
            if val is None:
                continue

            sentiment = "neutral"
            raw_score = None
            try:
                raw_score = float(val)
                if raw_score >= 7:
                    sentiment = "good"
                elif raw_score >= 4:
                    sentiment = "neutral"
                else:
                    sentiment = "bad"
            except (ValueError, TypeError):
                if isinstance(val, str):
                    val_lower = val.lower()
                    if val_lower in ("yes", "true"):
                        sentiment = "bad"
                    elif val_lower in ("no", "false"):
                        sentiment = "good"

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
