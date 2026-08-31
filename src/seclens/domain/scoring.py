"""Pure scoring algorithm — no I/O, no side effects."""

from __future__ import annotations

import datetime as _dt
import math
import statistics
from datetime import date

from .models import ScoreBreakdown, SecurityScore, Severity, Vulnerability


def compute_score(
    vulnerabilities: list[Vulnerability], product_first_seen: date | None = None
) -> SecurityScore:
    """Compute a composite security score from a list of vulnerabilities.

    All sub-scores are 0-100 where higher = more secure.
    """
    if not vulnerabilities:
        breakdown = ScoreBreakdown(
            vuln_density=100.0,
            avg_severity=100.0,
            exploit_likelihood=100.0,
            kev_exposure=100.0,
            patch_velocity=100.0,
            unpatched_ratio=100.0,
        )
        return SecurityScore.create(
            breakdown=breakdown,
            total_cves=0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            none_count=0,
        )

    severity_counts = _count_severities(vulnerabilities)

    breakdown = ScoreBreakdown(
        vuln_density=_score_vuln_density(vulnerabilities, product_first_seen),
        avg_severity=_score_avg_severity(vulnerabilities),
        exploit_likelihood=_score_exploit_likelihood(vulnerabilities),
        kev_exposure=_score_kev_exposure(vulnerabilities),
        patch_velocity=_score_patch_velocity(vulnerabilities),
        unpatched_ratio=_score_unpatched_ratio(vulnerabilities),
    )

    return SecurityScore.create(
        breakdown=breakdown,
        total_cves=len(vulnerabilities),
        **severity_counts,
    )


def _count_severities(vulns: list[Vulnerability]) -> dict[str, int]:
    counts = {
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "none_count": 0,
    }
    for v in vulns:
        match v.severity:
            case Severity.CRITICAL:
                counts["critical_count"] += 1
            case Severity.HIGH:
                counts["high_count"] += 1
            case Severity.MEDIUM:
                counts["medium_count"] += 1
            case Severity.LOW:
                counts["low_count"] += 1
            case Severity.NONE:
                counts["none_count"] += 1
    return counts


def _score_vuln_density(vulns: list[Vulnerability], first_seen: date | None) -> float:
    """Fewer CVEs per year of product existence = higher score.

    Uses a logarithmic scale so that heavily-audited products (RHEL, Linux
    Kernel, Chrome) aren't unfairly penalized. Having more CVEs reported
    and fixed can indicate a healthy security process.

    Scale: 0 CVEs/yr = 100, ~10/yr = 80, ~50/yr = 60, ~200/yr = 40, ~500/yr = 20
    """
    if first_seen is None:
        earliest = min(v.published for v in vulns)
    else:
        earliest = first_seen

    years = max((_dt.datetime.now(tz=_dt.UTC).date() - earliest).days / 365.25, 1.0)
    density = len(vulns) / years

    if density <= 0:
        return 100.0

    score = 100.0 - 15.0 * math.log(density)
    return round(max(0.0, min(100.0, score)), 1)


def _score_avg_severity(vulns: list[Vulnerability]) -> float:
    """Lower effective CVSS = higher score.

    Patched CVEs have their CVSS halved for scoring purposes since
    the active risk is substantially reduced once a fix is available.
    """
    effective_scores = []
    for v in vulns:
        if v.is_patched:
            effective_scores.append(v.cvss_score * 0.5)
        else:
            effective_scores.append(v.cvss_score)
    mean_cvss = statistics.mean(effective_scores)
    return round(max(0.0, (10.0 - mean_cvss) * 10.0), 1)


def _score_exploit_likelihood(vulns: list[Vulnerability]) -> float:
    """Lower mean EPSS = higher score."""
    epss_scores = [v.epss_score for v in vulns if v.epss_score is not None]
    if not epss_scores:
        return 70.0  # lean positive when no exploit evidence
    mean_epss = statistics.mean(epss_scores)
    # EPSS is 0-1; invert and scale to 0-100
    return round(max(0.0, (1.0 - mean_epss) * 100.0), 1)


def _score_kev_exposure(vulns: list[Vulnerability]) -> float:
    """Fewer CVEs on CISA KEV list = higher score."""
    if not vulns:
        return 100.0
    kev_count = sum(1 for v in vulns if v.in_kev)
    kev_ratio = kev_count / len(vulns)
    # 0% on KEV = 100, 100% on KEV = 0
    return round((1.0 - kev_ratio) * 100.0, 1)


def _score_patch_velocity(vulns: list[Vulnerability]) -> float:
    """Faster median time-to-patch = higher score.

    Uses a logistic decay curve centered at 90 days:
    0 days = 100, 7d = 97, 30d = 82, 45d = 73, 90d = 50, 180d = 26.
    A 30-45 day patch cycle (typical for enterprise) scores well.
    """
    patch_times = [v.days_to_patch for v in vulns if v.days_to_patch is not None]
    if not patch_times:
        return 40.0
    median_days = statistics.median(patch_times)
    if median_days <= 0:
        return 100.0

    score = 100.0 / (1.0 + (median_days / 90.0) ** 1.5)
    return round(max(0.0, min(100.0, score)), 1)


def _score_unpatched_ratio(vulns: list[Vulnerability]) -> float:
    """Fewer unpatched CVEs = higher score.

    Note: NVD often doesn't record fix versions even when patches exist
    (especially for vendor-specific advisories like RHSA). We use a
    softer curve to avoid over-penalizing products with incomplete
    NVD patch data.
    """
    if not vulns:
        return 100.0
    unpatched = sum(1 for v in vulns if not v.is_patched)
    ratio = unpatched / len(vulns)
    # Softer curve: 0% unpatched = 100, 50% = 65, 100% = 30
    return round(max(30.0, 100.0 - (ratio * 70.0)), 1)
