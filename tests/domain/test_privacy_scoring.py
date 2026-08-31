"""Tests for the privacy scoring algorithm."""

from datetime import date

from seclens.domain.models.privacy import BreachRecord, PrivacyResult, PrivacySignal
from seclens.domain.privacy_scoring import compute_privacy_score


def _make_signal(
    source: str = "tosdr",
    category: str = "policy",
    description: str = "Test signal",
    sentiment: str = "bad",
) -> PrivacySignal:
    return PrivacySignal(
        source=source,
        category=category,
        description=description,
        sentiment=sentiment,
    )


def _make_breach(
    name: str = "TestBreach",
    record_count: int = 1_000_000,
    has_passwords: bool = False,
) -> BreachRecord:
    data_types = ("Email addresses",)
    if has_passwords:
        data_types = ("Email addresses", "Passwords")
    return BreachRecord(
        name=name,
        domain="example.com",
        breach_date=date(2023, 6, 1),
        record_count=record_count,
        data_types=data_types,
        is_verified=True,
    )


class TestPrivacyScoringMinimumSources:
    def test_returns_none_with_zero_sources(self):
        result = PrivacyResult(service_name="test", domain="test.com")
        assert compute_privacy_score(result) is None

    def test_returns_none_with_one_source(self):
        result = PrivacyResult(
            service_name="test",
            domain="test.com",
            sources_used=["tosdr"],
            tosdr_grade="B",
        )
        assert compute_privacy_score(result) is None

    def test_returns_score_with_two_sources(self):
        result = PrivacyResult(
            service_name="test",
            domain="test.com",
            sources_used=["tosdr", "hibp"],
            tosdr_grade="B",
        )
        score = compute_privacy_score(result)
        assert score is not None
        assert 0 <= score.overall <= 100


class TestPrivacyScoringGrades:
    def test_good_privacy_high_score(self):
        result = PrivacyResult(
            service_name="good-service",
            domain="good.org",
            tosdr_grade="A",
            privacyspy_score=9.0,
            sources_used=["tosdr", "hibp", "disconnect", "privacyspy"],
        )
        score = compute_privacy_score(result)
        assert score is not None
        assert score.overall >= 80
        assert score.grade in ("A+", "A", "A-", "B+", "B")

    def test_bad_privacy_low_score(self):
        bad_signals = [
            _make_signal(category="data_collection", sentiment="blocker"),
            _make_signal(category="sharing", sentiment="bad"),
            _make_signal(category="policy", sentiment="bad"),
            _make_signal(category="policy", sentiment="blocker"),
        ]
        result = PrivacyResult(
            service_name="bad-service",
            domain="bad.com",
            tosdr_grade="E",
            tosdr_points=bad_signals,
            tracker_categories=["Advertising", "Analytics", "Fingerprinting"],
            breaches=[_make_breach(record_count=50_000_000, has_passwords=True)],
            privacyspy_score=1.5,
            sources_used=["tosdr", "hibp", "disconnect", "privacyspy"],
        )
        score = compute_privacy_score(result)
        assert score is not None
        assert score.overall < 40
        assert score.grade in ("F", "D-", "D", "D+")


class TestBreachHistoryScoring:
    def test_no_breaches_perfect_score(self):
        result = PrivacyResult(
            service_name="safe",
            domain="safe.org",
            tosdr_grade="B",
            sources_used=["tosdr", "hibp"],
        )
        score = compute_privacy_score(result)
        assert score is not None
        assert score.breakdown.breach_history == 100.0

    def test_major_breach_lowers_score(self):
        result = PrivacyResult(
            service_name="breached",
            domain="breached.com",
            tosdr_grade="B",
            breaches=[
                _make_breach(record_count=100_000_000, has_passwords=True),
                _make_breach(name="Second", record_count=5_000_000),
            ],
            sources_used=["tosdr", "hibp"],
        )
        score = compute_privacy_score(result)
        assert score is not None
        assert score.breakdown.breach_history < 50


class TestTrackerExposure:
    def test_no_trackers_high_score(self):
        result = PrivacyResult(
            service_name="clean",
            domain="clean.org",
            tosdr_grade="B",
            tracker_categories=[],
            sources_used=["tosdr", "disconnect"],
        )
        score = compute_privacy_score(result)
        assert score is not None
        assert score.breakdown.tracker_exposure >= 85

    def test_advertising_trackers_lower_score(self):
        result = PrivacyResult(
            service_name="adtech",
            domain="adtech.com",
            tosdr_grade="C",
            tracker_categories=["Advertising", "Analytics", "Fingerprinting"],
            sources_used=["tosdr", "disconnect"],
        )
        score = compute_privacy_score(result)
        assert score is not None
        assert score.breakdown.tracker_exposure < 40


class TestScoreMetadata:
    def test_sources_used_tracked(self):
        result = PrivacyResult(
            service_name="test",
            domain="test.com",
            tosdr_grade="C",
            sources_used=["tosdr", "hibp", "disconnect"],
        )
        score = compute_privacy_score(result)
        assert score is not None
        assert "tosdr" in score.sources_used
        assert "hibp" in score.sources_used

    def test_signals_preserved(self):
        signals = [
            _make_signal(sentiment="good", description="User can delete account"),
            _make_signal(sentiment="bad", description="Tracks across sites"),
        ]
        result = PrivacyResult(
            service_name="test",
            domain="test.com",
            tosdr_grade="C",
            tosdr_points=signals,
            sources_used=["tosdr", "hibp"],
        )
        score = compute_privacy_score(result)
        assert score is not None
        assert len(score.signals) == 2

    def test_breaches_preserved(self):
        breaches = [_make_breach(), _make_breach(name="Second")]
        result = PrivacyResult(
            service_name="test",
            domain="test.com",
            tosdr_grade="C",
            breaches=breaches,
            sources_used=["tosdr", "hibp"],
        )
        score = compute_privacy_score(result)
        assert score is not None
        assert len(score.breaches) == 2
