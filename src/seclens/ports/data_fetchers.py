from __future__ import annotations

from abc import ABC, abstractmethod

from seclens.domain.models import Vulnerability


class VulnDataFetcher(ABC):
    """Port for fetching vulnerability data from an external source (e.g. NVD)."""

    @abstractmethod
    async def fetch_by_cpe(self, cpe_uri: str) -> list[Vulnerability]:
        """Fetch vulnerabilities affecting a specific CPE."""

    @abstractmethod
    async def fetch_recent(self, days: int = 7) -> list[Vulnerability]:
        """Fetch recently published/modified vulnerabilities."""

    @abstractmethod
    async def fetch_all(self, start_index: int = 0, batch_size: int = 2000) -> tuple[list[Vulnerability], int]:
        """Fetch a batch of all vulnerabilities. Returns (vulns, total_count)."""


class EPSSFetcher(ABC):
    """Port for fetching EPSS (Exploit Prediction Scoring System) data."""

    @abstractmethod
    async def fetch_scores(self, cve_ids: list[str]) -> dict[str, float]:
        """Fetch EPSS scores for a list of CVE IDs. Returns {cve_id: score}."""

    @abstractmethod
    async def fetch_all_scores(self) -> dict[str, float]:
        """Fetch the complete EPSS dataset. Returns {cve_id: score}."""


class KEVFetcher(ABC):
    """Port for fetching CISA Known Exploited Vulnerabilities catalog."""

    @abstractmethod
    async def fetch_kev_ids(self) -> set[str]:
        """Fetch all CVE IDs currently on the KEV list."""
