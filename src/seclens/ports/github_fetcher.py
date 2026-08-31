from __future__ import annotations

from abc import ABC, abstractmethod

from seclens.domain.models import Dependency, RepoSecuritySignals


class GitHubFetcher(ABC):
    """Port for fetching data from GitHub repositories."""

    @abstractmethod
    async def fetch_sbom(self, owner: str, repo: str) -> list[Dependency]:
        """Fetch the SPDX SBOM via GitHub's dependency graph API."""

    @abstractmethod
    async def fetch_manifests(self, owner: str, repo: str) -> list[Dependency]:
        """Fetch and parse dependency manifest files from the repo."""

    @abstractmethod
    async def fetch_repo_signals(self, owner: str, repo: str) -> RepoSecuritySignals:
        """Fetch security-relevant repository metadata."""

    @abstractmethod
    async def fetch_repo_description(self, owner: str, repo: str) -> str:
        """Fetch the repository description."""
