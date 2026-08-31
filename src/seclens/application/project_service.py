"""Orchestrates GitHub project security analysis."""

from __future__ import annotations

import logging

from seclens.domain.models import GitHubProject, parse_github_url
from seclens.domain.project_scoring import compute_project_score
from seclens.ports.github_fetcher import GitHubFetcher
from seclens.ports.osv_fetcher import OSVFetcher

logger = logging.getLogger(__name__)


class ProjectService:
    """Analyzes a GitHub project's security posture."""

    def __init__(self, github: GitHubFetcher, osv: OSVFetcher) -> None:
        self._github = github
        self._osv = osv

    async def analyze(self, url: str) -> GitHubProject:
        owner, repo = parse_github_url(url)

        description = await self._github.fetch_repo_description(owner, repo)

        project = GitHubProject(
            owner=owner,
            repo=repo,
            url=f"https://github.com/{owner}/{repo}",
            description=description,
        )

        deps = await self._github.fetch_sbom(owner, repo)
        if not deps:
            logger.info("SBOM unavailable, falling back to manifest parsing for %s/%s", owner, repo)
            deps = await self._github.fetch_manifests(owner, repo)

        logger.info("Found %d dependencies for %s/%s", len(deps), owner, repo)

        if deps:
            deps = await self._osv.query_batch(deps)
            vuln_count = sum(1 for d in deps if d.is_vulnerable)
            logger.info(
                "OSV query complete: %d/%d deps have vulnerabilities", vuln_count, len(deps)
            )

        project.dependencies = deps

        signals = await self._github.fetch_repo_signals(owner, repo)
        project.repo_signals = signals

        project.score = compute_project_score(deps, signals)

        return project
