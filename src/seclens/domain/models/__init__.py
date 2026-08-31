from .dependency import Dependency, DependencyVuln
from .privacy import (
    BreachRecord,
    PrivacyBreakdown,
    PrivacyResult,
    PrivacyScore,
    PrivacySignal,
    ServiceInfo,
)
from .product import CPE, Product
from .project import GitHubProject, ProjectScore, ProjectScoreBreakdown, parse_github_url
from .repo_signals import RepoSecuritySignals
from .score import ScoreBreakdown, SecurityScore
from .vulnerability import PatchInfo, Severity, Vulnerability

__all__ = [
    "CPE",
    "BreachRecord",
    "Dependency",
    "DependencyVuln",
    "GitHubProject",
    "PatchInfo",
    "PrivacyBreakdown",
    "PrivacyResult",
    "PrivacyScore",
    "PrivacySignal",
    "Product",
    "ProjectScore",
    "ProjectScoreBreakdown",
    "RepoSecuritySignals",
    "ScoreBreakdown",
    "SecurityScore",
    "ServiceInfo",
    "Severity",
    "Vulnerability",
    "parse_github_url",
]
