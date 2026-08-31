"""Ports for privacy data sources."""

from __future__ import annotations

from abc import ABC, abstractmethod

from seclens.domain.models.privacy import BreachRecord, PrivacySignal


class ToSDRFetcher(ABC):
    """Port for fetching Terms of Service; Didn't Read ratings."""

    @abstractmethod
    async def fetch_service(
        self, service_name: str, tosdr_id: int | None = None
    ) -> tuple[str | None, list[PrivacySignal]]:
        """Fetch ToS;DR grade and policy points for a service.

        Returns (grade_letter_or_None, list_of_signals).
        """


class BreachFetcher(ABC):
    """Port for fetching data breach history."""

    @abstractmethod
    async def fetch_breaches(self, domain: str) -> list[BreachRecord]:
        """Fetch known data breaches for a domain."""


class TrackerRegistry(ABC):
    """Port for looking up tracking associations."""

    @abstractmethod
    async def lookup(self, domain: str) -> list[str]:
        """Return tracker categories associated with a domain.

        Categories: Advertising, Analytics, Social, Fingerprinting, Content.
        """

    @abstractmethod
    async def load(self) -> None:
        """Load/refresh the tracker registry data."""


class PrivacySpyFetcher(ABC):
    """Port for fetching PrivacySpy privacy scores."""

    @abstractmethod
    async def fetch_score(
        self, service_name: str, domain: str
    ) -> tuple[float | None, list[PrivacySignal]]:
        """Fetch PrivacySpy score (0-10) and rubric signals.

        Returns (score_or_None, list_of_signals).
        """

    @abstractmethod
    async def load(self) -> None:
        """Load/refresh the PrivacySpy dataset."""
