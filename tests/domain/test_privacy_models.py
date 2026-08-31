"""Tests for privacy domain models."""

from datetime import date

from seclens.domain.models.privacy import (
    BreachRecord,
    PrivacyBreakdown,
    PrivacyResult,
    PrivacyScore,
    PrivacySignal,
    ServiceInfo,
)
from seclens.domain.models.product import SERVICE_MAPPINGS


class TestServiceInfo:
    def test_basic_fields(self):
        svc = ServiceInfo(name="Test", domain="test.com", tosdr_id=42)
        assert svc.name == "Test"
        assert svc.domain == "test.com"
        assert svc.tosdr_id == 42

    def test_no_tosdr_id(self):
        svc = ServiceInfo(name="Test", domain="test.com")
        assert svc.tosdr_id is None


class TestServiceMappings:
    def test_google_chrome_mapped(self):
        svc = SERVICE_MAPPINGS.get(("google", "chrome"))
        assert svc is not None
        assert svc.domain == "google.com"

    def test_apple_mapped(self):
        svc = SERVICE_MAPPINGS.get(("apple", "macos"))
        assert svc is not None
        assert svc.domain == "apple.com"

    def test_firefox_mapped(self):
        svc = SERVICE_MAPPINGS.get(("mozilla", "firefox"))
        assert svc is not None
        assert svc.tosdr_id == 175

    def test_all_mappings_have_domain(self):
        for key, svc in SERVICE_MAPPINGS.items():
            assert svc.domain, f"Missing domain for {key}"
            assert svc.name, f"Missing name for {key}"


class TestPrivacySignal:
    def test_frozen(self):
        s = PrivacySignal(
            source="tosdr",
            category="policy",
            description="Test",
            sentiment="good",
        )
        assert s.source == "tosdr"
        assert s.sentiment == "good"


class TestBreachRecord:
    def test_frozen_with_defaults(self):
        b = BreachRecord(name="TestBreach", domain="test.com")
        assert b.record_count == 0
        assert b.is_verified is True
        assert b.data_types == ()

    def test_with_data(self):
        b = BreachRecord(
            name="BigBreach",
            domain="big.com",
            breach_date=date(2023, 1, 15),
            record_count=10_000_000,
            data_types=("Email addresses", "Passwords"),
        )
        assert b.record_count == 10_000_000
        assert "Passwords" in b.data_types


class TestPrivacyScore:
    def test_create_computes_weighted_score(self):
        breakdown = PrivacyBreakdown(
            data_collection=80.0,
            tracker_exposure=90.0,
            policy_practices=70.0,
            breach_history=100.0,
            data_sharing=60.0,
        )
        score = PrivacyScore.create(
            breakdown=breakdown,
            signals=[],
            breaches=[],
            sources_used=["tosdr", "hibp"],
        )
        expected = (80 * 0.25) + (90 * 0.20) + (70 * 0.25) + (100 * 0.20) + (60 * 0.10)
        assert abs(score.overall - round(expected, 1)) < 0.2
        assert score.grade  # has a grade

    def test_perfect_score_is_a_plus(self):
        breakdown = PrivacyBreakdown(
            data_collection=100.0,
            tracker_exposure=100.0,
            policy_practices=100.0,
            breach_history=100.0,
            data_sharing=100.0,
        )
        score = PrivacyScore.create(
            breakdown=breakdown,
            signals=[],
            breaches=[],
            sources_used=["tosdr"],
        )
        assert score.overall == 100.0
        assert score.grade == "A+"


class TestPrivacyResult:
    def test_default_empty(self):
        r = PrivacyResult(service_name="test", domain="test.com")
        assert r.tosdr_grade is None
        assert r.breaches == []
        assert r.tracker_categories == []
        assert r.sources_used == []
