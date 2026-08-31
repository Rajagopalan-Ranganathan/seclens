"""Privacy scorecard domain models — pure data, no I/O."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, date, datetime


@dataclass(frozen=True)
class ServiceInfo:
    """Maps a CPE product to its web-service identity for privacy lookups."""

    name: str
    domain: str
    tosdr_id: int | None = None


@dataclass(frozen=True)
class PrivacySignal:
    """A single finding from a privacy data source."""

    source: str  # "tosdr", "hibp", "disconnect", "privacyspy"
    category: str  # "data_collection", "tracking", "breach", "policy", "sharing"
    description: str
    sentiment: str  # "good", "neutral", "bad", "blocker"
    raw_score: float | None = None


@dataclass(frozen=True)
class BreachRecord:
    """A data breach incident for a service."""

    name: str
    domain: str
    breach_date: date | None = None
    record_count: int = 0
    data_types: tuple[str, ...] = ()
    is_verified: bool = True


@dataclass(frozen=True)
class PrivacyBreakdown:
    """Individual factors composing the privacy score."""

    data_collection: float  # 0-100
    tracker_exposure: float  # 0-100
    policy_practices: float  # 0-100
    breach_history: float  # 0-100
    data_sharing: float  # 0-100


@dataclass(frozen=True)
class PrivacyScore:
    """Composite privacy scorecard for a product or service."""

    overall: float
    grade: str
    computed_at: datetime
    breakdown: PrivacyBreakdown
    signals: tuple[PrivacySignal, ...]
    breaches: tuple[BreachRecord, ...]
    sources_used: tuple[str, ...]

    @classmethod
    def create(
        cls,
        breakdown: PrivacyBreakdown,
        signals: list[PrivacySignal],
        breaches: list[BreachRecord],
        sources_used: list[str],
    ) -> PrivacyScore:
        from .score import _score_to_grade

        overall = (
            breakdown.data_collection * 0.25
            + breakdown.tracker_exposure * 0.20
            + breakdown.policy_practices * 0.25
            + breakdown.breach_history * 0.20
            + breakdown.data_sharing * 0.10
        )
        overall = round(max(0.0, min(100.0, overall)), 1)
        return cls(
            overall=overall,
            grade=_score_to_grade(overall),
            computed_at=datetime.now(UTC),
            breakdown=breakdown,
            signals=tuple(signals),
            breaches=tuple(breaches),
            sources_used=tuple(sources_used),
        )


@dataclass
class PrivacyResult:
    """Bundles raw data collected from privacy sources before scoring."""

    service_name: str
    domain: str
    tosdr_grade: str | None = None
    tosdr_points: list[PrivacySignal] = field(default_factory=list)
    breaches: list[BreachRecord] = field(default_factory=list)
    tracker_categories: list[str] = field(default_factory=list)
    privacyspy_score: float | None = None
    privacyspy_signals: list[PrivacySignal] = field(default_factory=list)
    sources_used: list[str] = field(default_factory=list)
