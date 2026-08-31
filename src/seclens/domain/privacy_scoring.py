"""Pure privacy scoring algorithm — no I/O, no side effects."""

from __future__ import annotations

import math

from .models.privacy import (
    BreachRecord,
    PrivacyBreakdown,
    PrivacyResult,
    PrivacyScore,
    PrivacySignal,
)

_TOSDR_GRADE_SCORES: dict[str, float] = {
    "A": 95.0,
    "B": 78.0,
    "C": 55.0,
    "D": 30.0,
    "E": 10.0,
}

_MINIMUM_SOURCES = 2


def compute_privacy_score(result: PrivacyResult) -> PrivacyScore | None:
    """Compute a composite privacy score from collected privacy data.

    Returns None if fewer than _MINIMUM_SOURCES have data.
    """
    if len(result.sources_used) < _MINIMUM_SOURCES:
        return None

    all_signals: list[PrivacySignal] = []
    all_signals.extend(result.tosdr_points)
    all_signals.extend(result.privacyspy_signals)

    factors: dict[str, float] = {}
    weights: dict[str, float] = {
        "data_collection": 0.25,
        "tracker_exposure": 0.20,
        "policy_practices": 0.25,
        "breach_history": 0.20,
        "data_sharing": 0.10,
    }

    if result.tosdr_grade or result.privacyspy_score is not None:
        factors["data_collection"] = _score_data_collection(result)
        factors["policy_practices"] = _score_policy_practices(result)
        factors["data_sharing"] = _score_data_sharing(result)
    if result.tracker_categories is not None:
        factors["tracker_exposure"] = _score_tracker_exposure(result)
    factors["breach_history"] = _score_breach_history(result.breaches)

    if not factors:
        return None

    active_weight = sum(weights[k] for k in factors)
    if active_weight == 0:
        return None

    breakdown = PrivacyBreakdown(
        data_collection=round(factors.get("data_collection", 0.0), 1),
        tracker_exposure=round(factors.get("tracker_exposure", 0.0), 1),
        policy_practices=round(factors.get("policy_practices", 0.0), 1),
        breach_history=round(factors.get("breach_history", 0.0), 1),
        data_sharing=round(factors.get("data_sharing", 0.0), 1),
    )

    return PrivacyScore.create(
        breakdown=breakdown,
        signals=all_signals,
        breaches=result.breaches,
        sources_used=result.sources_used,
        active_factors=set(factors.keys()),
    )


def _score_data_collection(result: PrivacyResult) -> float:
    """Score based on how much data the service collects (higher = less collection)."""
    scores: list[float] = []

    if result.tosdr_grade:
        scores.append(_TOSDR_GRADE_SCORES.get(result.tosdr_grade.upper(), 50.0))

    if result.privacyspy_score is not None:
        scores.append(result.privacyspy_score * 10.0)

    collection_signals = [s for s in result.tosdr_points if s.category == "data_collection"]
    if collection_signals:
        bad = sum(1 for s in collection_signals if s.sentiment in ("bad", "blocker"))
        good = sum(1 for s in collection_signals if s.sentiment == "good")
        total = len(collection_signals)
        signal_score = max(0.0, 100.0 - (bad / max(total, 1)) * 80 + (good / max(total, 1)) * 20)
        scores.append(signal_score)

    return sum(scores) / len(scores) if scores else 50.0


def _score_tracker_exposure(result: PrivacyResult) -> float:
    """Score based on tracker presence (higher = fewer/no trackers)."""
    cats = result.tracker_categories
    if not cats:
        return 90.0

    penalty_map = {
        "Advertising": 25.0,
        "Analytics": 15.0,
        "Social": 10.0,
        "Fingerprinting": 30.0,
        "Content": 5.0,
    }
    total_penalty = sum(penalty_map.get(c, 10.0) for c in cats)
    return round(max(0.0, 100.0 - total_penalty), 1)


def _score_policy_practices(result: PrivacyResult) -> float:
    """Score based on privacy policy quality."""
    scores: list[float] = []

    if result.tosdr_grade:
        scores.append(_TOSDR_GRADE_SCORES.get(result.tosdr_grade.upper(), 50.0))

    policy_signals = [s for s in result.tosdr_points if s.category == "policy"]
    if policy_signals:
        bad = sum(1 for s in policy_signals if s.sentiment in ("bad", "blocker"))
        good = sum(1 for s in policy_signals if s.sentiment == "good")
        blocker = sum(1 for s in policy_signals if s.sentiment == "blocker")
        total = len(policy_signals)
        signal_score = 100.0
        signal_score -= (bad / max(total, 1)) * 60
        signal_score -= blocker * 10
        signal_score += (good / max(total, 1)) * 20
        scores.append(max(0.0, min(100.0, signal_score)))

    if result.privacyspy_score is not None:
        scores.append(result.privacyspy_score * 10.0)

    return sum(scores) / len(scores) if scores else 50.0


def _score_breach_history(breaches: list[BreachRecord]) -> float:
    """Score based on data breach history (higher = fewer/no breaches)."""
    if not breaches:
        return 100.0

    verified = [b for b in breaches if b.is_verified]
    if not verified:
        return 85.0

    count = len(verified)
    total_records = sum(b.record_count for b in verified)
    sensitive_types = {"Passwords", "Credit cards", "Social security numbers", "Bank accounts"}
    has_sensitive = any(dt in sensitive_types for b in verified for dt in b.data_types)

    score = 100.0
    score -= min(count * 12, 40)
    score -= min(math.log10(max(total_records, 1)) * 5, 30)
    if has_sensitive:
        score -= 15
    return round(max(0.0, score), 1)


def _score_data_sharing(result: PrivacyResult) -> float:
    """Score based on data sharing practices (higher = less sharing)."""
    sharing_signals = [s for s in result.tosdr_points if s.category == "sharing"]
    if not sharing_signals:
        return 70.0

    bad = sum(1 for s in sharing_signals if s.sentiment in ("bad", "blocker"))
    good = sum(1 for s in sharing_signals if s.sentiment == "good")
    total = len(sharing_signals)

    score = 80.0
    score -= (bad / max(total, 1)) * 60
    score += (good / max(total, 1)) * 20
    return round(max(0.0, min(100.0, score)), 1)
