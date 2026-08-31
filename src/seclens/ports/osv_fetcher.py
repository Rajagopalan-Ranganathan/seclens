from __future__ import annotations

from abc import ABC, abstractmethod

from seclens.domain.models import Dependency


class OSVFetcher(ABC):
    """Port for querying the OSV vulnerability database."""

    @abstractmethod
    async def query_batch(self, deps: list[Dependency]) -> list[Dependency]:
        """Query OSV for vulnerabilities affecting the given dependencies.

        Returns the same dependency list with vulnerabilities populated.
        """
