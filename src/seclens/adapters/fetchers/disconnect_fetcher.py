"""Disconnect tracker list adapter — loads a static JSON tracker database."""

from __future__ import annotations

import logging

import httpx

from seclens.ports.privacy_fetchers import TrackerRegistry as TrackerRegistryPort

logger = logging.getLogger(__name__)

DISCONNECT_URL = (
    "https://raw.githubusercontent.com/disconnectme/"
    "disconnect-tracking-protection/master/services.json"
)


class DisconnectTrackerRegistry(TrackerRegistryPort):
    """Loads the Disconnect tracker list and provides domain lookups."""

    def __init__(self) -> None:
        self._domain_to_categories: dict[str, list[str]] = {}
        self._loaded = False

    async def load(self) -> None:
        if self._loaded:
            return
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(DISCONNECT_URL)
                resp.raise_for_status()
                data = resp.json()
        except (httpx.HTTPError, OSError, ValueError) as exc:
            logger.warning("Failed to load Disconnect tracker list: %s", exc)
            return

        categories = data.get("categories", data)
        for category_name, entries in categories.items():
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                for domains_data in entry.values():
                    if not isinstance(domains_data, dict):
                        continue
                    for domain_or_key, val in domains_data.items():
                        if domain_or_key in ("dnt", "performance"):
                            continue
                        if isinstance(val, list):
                            for d in val:
                                if isinstance(d, str) and "." in d:
                                    self._add_mapping(d, category_name)
                        elif isinstance(val, str) and "." in val:
                            self._add_mapping(val, category_name)
                        if isinstance(domain_or_key, str) and "." in domain_or_key:
                            self._add_mapping(domain_or_key, category_name)

        self._loaded = True
        logger.info("Loaded Disconnect tracker list: %d domains", len(self._domain_to_categories))

    def _add_mapping(self, domain: str, category: str) -> None:
        domain = domain.lower().strip()
        if domain not in self._domain_to_categories:
            self._domain_to_categories[domain] = []
        if category not in self._domain_to_categories[domain]:
            self._domain_to_categories[domain].append(category)

    async def lookup(self, domain: str) -> list[str]:
        if not self._loaded:
            await self.load()

        domain = domain.lower().strip()
        categories: list[str] = []

        if domain in self._domain_to_categories:
            categories.extend(self._domain_to_categories[domain])

        parts = domain.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self._domain_to_categories:
                for cat in self._domain_to_categories[parent]:
                    if cat not in categories:
                        categories.append(cat)

        return categories
