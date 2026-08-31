from datetime import date

from seclens.domain.models import PatchInfo, Severity, Vulnerability
from seclens.domain.scoring import compute_score


def _make_vuln(
    cve_id: str = "CVE-2024-0001",
    cvss: float = 5.0,
    epss: float | None = 0.1,
    in_kev: bool = False,
    patched: bool = False,
    published: date = date(2024, 1, 1),
) -> Vulnerability:
    patches = []
    if patched:
        patches = [PatchInfo(fixed_version="1.0.1", patch_date=date(2024, 1, 15))]
    return Vulnerability(
        cve_id=cve_id,
        description=f"Test vulnerability {cve_id}",
        cvss_score=cvss,
        severity=Severity.from_cvss(cvss),
        published=published,
        last_modified=published,
        epss_score=epss,
        in_kev=in_kev,
        patches=patches,
    )


class TestScoring:
    def test_empty_vulns_perfect_score(self):
        score = compute_score([])
        assert score.overall == 100.0
        assert score.grade == "A+"
        assert score.total_cves == 0

    def test_single_low_vuln(self):
        vulns = [_make_vuln(cvss=2.0, epss=0.01, patched=True)]
        score = compute_score(vulns)
        assert score.overall > 80.0
        assert score.grade in ("A+", "A", "A-", "B+", "B")

    def test_many_critical_vulns(self):
        vulns = [
            _make_vuln(cve_id=f"CVE-2024-{i:04d}", cvss=9.8, epss=0.9, in_kev=True)
            for i in range(50)
        ]
        score = compute_score(vulns)
        assert score.overall < 30.0
        assert score.grade == "F"
        assert score.critical_count == 50

    def test_mixed_vulns(self):
        vulns = [
            _make_vuln(cve_id="CVE-2024-0001", cvss=9.0, epss=0.5, in_kev=True),
            _make_vuln(cve_id="CVE-2024-0002", cvss=5.0, epss=0.1, patched=True),
            _make_vuln(cve_id="CVE-2024-0003", cvss=3.0, epss=0.02, patched=True),
        ]
        score = compute_score(vulns)
        assert 20.0 < score.overall < 80.0
        assert score.total_cves == 3
        assert score.critical_count == 1  # 9.0 is CRITICAL (>= 9.0)
        assert score.high_count == 0

    def test_severity_counts(self):
        vulns = [
            _make_vuln(cve_id="CVE-1", cvss=9.8),  # CRITICAL
            _make_vuln(cve_id="CVE-2", cvss=8.0),   # HIGH
            _make_vuln(cve_id="CVE-3", cvss=5.0),   # MEDIUM
            _make_vuln(cve_id="CVE-4", cvss=2.0),   # LOW
            _make_vuln(cve_id="CVE-5", cvss=0.0),   # NONE
        ]
        score = compute_score(vulns)
        assert score.critical_count == 1
        assert score.high_count == 1
        assert score.medium_count == 1
        assert score.low_count == 1
        assert score.none_count == 1

    def test_patched_vulns_improve_score(self):
        unpatched = [_make_vuln(cve_id=f"CVE-{i}", cvss=7.0) for i in range(10)]
        patched = [_make_vuln(cve_id=f"CVE-{i}", cvss=7.0, patched=True) for i in range(10)]

        score_unpatched = compute_score(unpatched)
        score_patched = compute_score(patched)

        assert score_patched.overall > score_unpatched.overall

    def test_kev_vulns_reduce_score(self):
        no_kev = [_make_vuln(cve_id=f"CVE-{i}", cvss=7.0, in_kev=False) for i in range(10)]
        with_kev = [_make_vuln(cve_id=f"CVE-{i}", cvss=7.0, in_kev=True) for i in range(10)]

        score_no_kev = compute_score(no_kev)
        score_with_kev = compute_score(with_kev)

        assert score_no_kev.overall > score_with_kev.overall

    def test_score_is_bounded(self):
        vulns = [_make_vuln(cvss=10.0, epss=1.0, in_kev=True)]
        score = compute_score(vulns)
        assert 0.0 <= score.overall <= 100.0

        score_empty = compute_score([])
        assert 0.0 <= score_empty.overall <= 100.0
