from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True)
class ScoreBreakdown:
    """Individual factors that compose the overall security score."""

    vuln_density: float        # 0-100, lower CVE count per year = higher
    avg_severity: float        # 0-100, lower mean CVSS = higher
    exploit_likelihood: float  # 0-100, lower EPSS mean = higher
    kev_exposure: float        # 0-100, fewer KEV entries = higher
    patch_velocity: float      # 0-100, faster median patch time = higher
    unpatched_ratio: float     # 0-100, fewer unpatched CVEs = higher


GRADE_THRESHOLDS = [
    (97, "A+"), (93, "A"), (90, "A-"),
    (87, "B+"), (83, "B"), (80, "B-"),
    (77, "C+"), (73, "C"), (70, "C-"),
    (67, "D+"), (63, "D"), (60, "D-"),
]


def _score_to_grade(score: float) -> str:
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


@dataclass(frozen=True)
class SecurityScore:
    """Composite security scorecard for a product."""

    overall: float
    breakdown: ScoreBreakdown
    grade: str
    computed_at: datetime
    total_cves: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    none_count: int

    @classmethod
    def create(
        cls,
        breakdown: ScoreBreakdown,
        total_cves: int,
        critical_count: int,
        high_count: int,
        medium_count: int,
        low_count: int,
        none_count: int,
    ) -> SecurityScore:
        overall = (
            breakdown.vuln_density * 0.10
            + breakdown.avg_severity * 0.15
            + breakdown.exploit_likelihood * 0.15
            + breakdown.kev_exposure * 0.20
            + breakdown.patch_velocity * 0.20
            + breakdown.unpatched_ratio * 0.20
        )
        overall = round(max(0.0, min(100.0, overall)), 1)
        return cls(
            overall=overall,
            breakdown=breakdown,
            grade=_score_to_grade(overall),
            computed_at=datetime.now(UTC),
            total_cves=total_cves,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            none_count=none_count,
        )
