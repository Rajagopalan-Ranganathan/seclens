from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from .dependency import Dependency
from .repo_signals import RepoSecuritySignals

_GITHUB_RE = re.compile(
    r"(?:https?://)?(?:www\.)?github\.com/([a-zA-Z0-9\-_.]+)/([a-zA-Z0-9\-_.]+)/?",
)


def parse_github_url(url: str) -> tuple[str, str]:
    """Extract (owner, repo) from a GitHub URL. Raises ValueError if invalid."""
    m = _GITHUB_RE.match(url.strip())
    if not m:
        raise ValueError(f"Not a valid GitHub URL: {url}")
    owner, repo = m.group(1), m.group(2)
    repo = repo.removesuffix(".git")
    return owner, repo


@dataclass(frozen=True)
class ProjectScoreBreakdown:
    """Individual factors composing the project security score."""

    dependency_risk: float
    repo_posture: float
    supply_chain: float


@dataclass(frozen=True)
class ProjectScore:
    """Composite security scorecard for a GitHub project."""

    overall: float
    grade: str
    computed_at: datetime
    breakdown: ProjectScoreBreakdown
    total_deps: int
    vulnerable_deps: int
    critical_vulns: int
    high_vulns: int

    @classmethod
    def create(
        cls,
        breakdown: ProjectScoreBreakdown,
        total_deps: int,
        vulnerable_deps: int,
        critical_vulns: int,
        high_vulns: int,
    ) -> ProjectScore:
        from ..models.score import _score_to_grade

        overall = (
            breakdown.dependency_risk * 0.50
            + breakdown.repo_posture * 0.30
            + breakdown.supply_chain * 0.20
        )
        overall = round(max(0.0, min(100.0, overall)), 1)
        return cls(
            overall=overall,
            grade=_score_to_grade(overall),
            computed_at=datetime.now(UTC),
            breakdown=breakdown,
            total_deps=total_deps,
            vulnerable_deps=vulnerable_deps,
            critical_vulns=critical_vulns,
            high_vulns=high_vulns,
        )


@dataclass
class GitHubProject:
    """A GitHub project with its dependencies and security assessment."""

    owner: str
    repo: str
    url: str
    description: str = ""
    dependencies: list[Dependency] = field(default_factory=list)
    repo_signals: RepoSecuritySignals | None = None
    score: ProjectScore | None = None

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.repo}"
