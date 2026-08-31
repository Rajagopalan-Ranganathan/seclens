"""Tests for the project scoring algorithm."""

from seclens.domain.models import Dependency, RepoSecuritySignals
from seclens.domain.models.dependency import DependencyVuln
from seclens.domain.project_scoring import (
    _score_dependency_risk,
    _score_repo_posture,
    _score_supply_chain,
    compute_project_score,
)


def _make_dep(name: str, vulns: int = 0, critical: int = 0, has_fix: bool = False, is_direct: bool = True, version: str = "1.0") -> Dependency:
    vuln_list = []
    for i in range(vulns):
        sev = "CRITICAL" if i < critical else "HIGH"
        vuln_list.append(DependencyVuln(
            vuln_id=f"GHSA-{name}-{i}",
            severity=sev,
            fixed_version="2.0" if has_fix else None,
        ))
    return Dependency(name=name, version=version, ecosystem="PyPI", is_direct=is_direct, vulnerabilities=vuln_list)


class TestDependencyRisk:
    def test_no_deps(self):
        assert _score_dependency_risk([]) == 100.0

    def test_all_clean(self):
        deps = [_make_dep("a"), _make_dep("b"), _make_dep("c")]
        assert _score_dependency_risk(deps) == 100.0

    def test_one_critical(self):
        deps = [_make_dep("a"), _make_dep("b", vulns=1, critical=1)]
        score = _score_dependency_risk(deps)
        assert 40 < score < 80

    def test_many_criticals_low_score(self):
        deps = [_make_dep(f"d{i}", vulns=2, critical=2) for i in range(5)]
        score = _score_dependency_risk(deps)
        assert score < 45

    def test_fix_available_improves_score(self):
        no_fix = [_make_dep("a", vulns=2, critical=1)]
        with_fix = [_make_dep("a", vulns=2, critical=1, has_fix=True)]
        assert _score_dependency_risk(with_fix) > _score_dependency_risk(no_fix)


class TestRepoPosture:
    def test_none_signals(self):
        assert _score_repo_posture(None) == 50.0

    def test_all_enabled(self):
        signals = RepoSecuritySignals(
            default_branch_protected=True,
            secret_scanning_enabled=True,
            code_scanning_enabled=True,
            dependency_updates_enabled=True,
            license_name="MIT",
            last_push_date=__import__("datetime").date.today(),
        )
        score = _score_repo_posture(signals)
        assert score == 100.0

    def test_all_disabled(self):
        signals = RepoSecuritySignals(
            default_branch_protected=False,
            secret_scanning_enabled=False,
            code_scanning_enabled=False,
            dependency_updates_enabled=False,
            archived=True,
        )
        score = _score_repo_posture(signals)
        assert score < 20


class TestSupplyChain:
    def test_no_deps(self):
        assert _score_supply_chain([]) == 100.0

    def test_all_pinned_clean(self):
        deps = [_make_dep("a"), _make_dep("b")]
        score = _score_supply_chain(deps)
        assert score > 85

    def test_transitive_vulns_reduce_score(self):
        clean = [_make_dep("a", is_direct=False)]
        vuln = [_make_dep("a", vulns=2, is_direct=False)]
        assert _score_supply_chain(clean) > _score_supply_chain(vuln)


class TestComputeProjectScore:
    def test_clean_project(self):
        deps = [_make_dep("a"), _make_dep("b"), _make_dep("c")]
        signals = RepoSecuritySignals(
            default_branch_protected=True,
            secret_scanning_enabled=True,
            code_scanning_enabled=True,
            dependency_updates_enabled=True,
            license_name="MIT",
            last_push_date=__import__("datetime").date.today(),
        )
        score = compute_project_score(deps, signals)
        assert score.overall > 90
        assert score.grade in ("A+", "A", "A-")
        assert score.vulnerable_deps == 0
        assert score.total_deps == 3

    def test_vulnerable_project(self):
        deps = [
            _make_dep("safe"),
            _make_dep("vuln1", vulns=3, critical=2),
            _make_dep("vuln2", vulns=1, critical=0),
        ]
        score = compute_project_score(deps, None)
        assert score.overall < 70
        assert score.vulnerable_deps == 2
        assert score.critical_vulns == 2
