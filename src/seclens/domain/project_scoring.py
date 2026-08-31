"""Pure scoring algorithm for GitHub projects -- no I/O, no side effects."""

from __future__ import annotations

from datetime import date

from .models.dependency import Dependency
from .models.project import ProjectScore, ProjectScoreBreakdown
from .models.repo_signals import RepoSecuritySignals


def compute_project_score(
    deps: list[Dependency],
    signals: RepoSecuritySignals | None,
) -> ProjectScore:
    """Compute a composite project security score."""
    dep_score = _score_dependency_risk(deps)
    repo_score = _score_repo_posture(signals)
    supply_score = _score_supply_chain(deps)

    total_deps = len(deps)
    vuln_deps = sum(1 for d in deps if d.is_vulnerable)
    crit = sum(d.critical_count for d in deps)
    high = sum(d.high_count for d in deps)

    breakdown = ProjectScoreBreakdown(
        dependency_risk=dep_score,
        repo_posture=repo_score,
        supply_chain=supply_score,
    )

    return ProjectScore.create(
        breakdown=breakdown,
        total_deps=total_deps,
        vulnerable_deps=vuln_deps,
        critical_vulns=crit,
        high_vulns=high,
    )


def _score_dependency_risk(deps: list[Dependency]) -> float:
    """Score based on vulnerability count, severity, and fix availability.

    100 = no vulnerable deps, 0 = many critical unpatched deps.
    """
    if not deps:
        return 100.0

    total = len(deps)
    vuln_count = sum(1 for d in deps if d.is_vulnerable)
    if vuln_count == 0:
        return 100.0

    vuln_ratio = vuln_count / total

    total_vulns = sum(len(d.vulnerabilities) for d in deps)
    crit_count = sum(d.critical_count for d in deps)
    high_count = sum(d.high_count for d in deps)
    fixable = sum(1 for d in deps if d.is_vulnerable and d.has_fix)
    fix_ratio = fixable / vuln_count if vuln_count else 1.0

    score = 100.0
    score -= vuln_ratio * 30
    score -= min(crit_count * 8, 30)
    score -= min(high_count * 3, 20)
    score -= min((total_vulns - crit_count - high_count) * 0.5, 10)
    score += fix_ratio * 15

    return round(max(0.0, min(100.0, score)), 1)


def _score_repo_posture(signals: RepoSecuritySignals | None) -> float:
    """Score based on repository security configuration.

    Each signal contributes points. Unknown signals get partial credit.
    """
    if signals is None:
        return 50.0

    score = 0.0
    max_points = 0.0

    checks = [
        (signals.default_branch_protected, 25.0),
        (signals.secret_scanning_enabled, 20.0),
        (signals.code_scanning_enabled, 15.0),
        (signals.dependency_updates_enabled, 15.0),
    ]

    for value, points in checks:
        max_points += points
        if value is True:
            score += points
        elif value is None:
            score += points * 0.5

    if signals.license_name and signals.license_name not in ("NOASSERTION",):
        score += 10.0
    max_points += 10.0

    if signals.is_actively_maintained:
        score += 15.0
    elif signals.archived:
        score += 0.0
    else:
        score += 5.0
    max_points += 15.0

    if max_points == 0:
        return 50.0
    return round((score / max_points) * 100.0, 1)


def _score_supply_chain(deps: list[Dependency]) -> float:
    """Score based on supply chain hygiene signals.

    Factors: direct vs transitive vulnerability ratio,
    pinned versions, ecosystem diversity.
    """
    if not deps:
        return 100.0

    score = 70.0

    pinned = sum(1 for d in deps if d.version and d.version != "*")
    pin_ratio = pinned / len(deps) if deps else 1.0
    score += pin_ratio * 15

    direct_deps = [d for d in deps if d.is_direct]
    direct_vuln = sum(1 for d in direct_deps if d.is_vulnerable)
    if direct_deps and direct_vuln == 0:
        score += 10
    elif direct_deps:
        direct_vuln_ratio = direct_vuln / len(direct_deps)
        score -= direct_vuln_ratio * 15

    transitive = [d for d in deps if not d.is_direct]
    if transitive:
        trans_vuln = sum(1 for d in transitive if d.is_vulnerable)
        if trans_vuln > 0:
            score -= min(trans_vuln * 2, 10)

    return round(max(0.0, min(100.0, score)), 1)
