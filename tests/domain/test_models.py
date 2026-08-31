from datetime import date

from seclens.domain.models import CPE, PatchInfo, Severity, Vulnerability


class TestCPE:
    def test_from_uri(self):
        cpe = CPE.from_uri("cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*")
        assert cpe.part == "a"
        assert cpe.vendor == "apache"
        assert cpe.product == "http_server"
        assert cpe.version == "2.4.51"

    def test_build(self):
        cpe = CPE.build("o", "redhat", "enterprise_linux", "9.0")
        assert cpe.uri == "cpe:2.3:o:redhat:enterprise_linux:9.0:*:*:*:*:*:*:*"
        assert cpe.part_label == "operating_system"

    def test_display_name(self):
        cpe = CPE.build("a", "apache", "http_server", "2.4.51")
        assert cpe.display_name == "Apache HTTP Server 2.4.51"

    def test_display_name_wildcard(self):
        cpe = CPE.build("a", "apache", "http_server")
        assert cpe.display_name == "Apache HTTP Server"

    def test_display_name_no_redundancy(self):
        cpe = CPE.build("a", "openssl", "openssl", "3.0.1")
        assert cpe.display_name == "OpenSSL 3.0.1"

    def test_display_name_linux_kernel(self):
        cpe = CPE.build("o", "linux", "linux_kernel", "5.15")
        assert cpe.display_name == "Linux Kernel 5.15"

    def test_invalid_uri_raises(self):
        try:
            CPE.from_uri("not-a-cpe")
            assert False, "Should have raised ValueError"
        except ValueError:
            pass


class TestSeverity:
    def test_from_cvss(self):
        assert Severity.from_cvss(0.0) == Severity.NONE
        assert Severity.from_cvss(3.5) == Severity.LOW
        assert Severity.from_cvss(5.5) == Severity.MEDIUM
        assert Severity.from_cvss(8.0) == Severity.HIGH
        assert Severity.from_cvss(9.8) == Severity.CRITICAL


class TestVulnerability:
    def test_is_patched(self):
        v = Vulnerability(
            cve_id="CVE-2021-44228",
            description="Log4Shell",
            cvss_score=10.0,
            severity=Severity.CRITICAL,
            published=date(2021, 12, 10),
            last_modified=date(2021, 12, 15),
            patches=[PatchInfo(fixed_version="2.16.0")],
        )
        assert v.is_patched is True

    def test_not_patched(self):
        v = Vulnerability(
            cve_id="CVE-2024-0001",
            description="Test vuln",
            cvss_score=7.5,
            severity=Severity.HIGH,
            published=date(2024, 1, 1),
            last_modified=date(2024, 1, 1),
        )
        assert v.is_patched is False

    def test_days_to_patch(self):
        v = Vulnerability(
            cve_id="CVE-2021-44228",
            description="Log4Shell",
            cvss_score=10.0,
            severity=Severity.CRITICAL,
            published=date(2021, 12, 10),
            last_modified=date(2021, 12, 15),
            patches=[PatchInfo(fixed_version="2.16.0", patch_date=date(2021, 12, 13))],
        )
        assert v.days_to_patch == 3

    def test_days_to_patch_none(self):
        v = Vulnerability(
            cve_id="CVE-2024-0001",
            description="No patch",
            cvss_score=5.0,
            severity=Severity.MEDIUM,
            published=date(2024, 1, 1),
            last_modified=date(2024, 1, 1),
        )
        assert v.days_to_patch is None
