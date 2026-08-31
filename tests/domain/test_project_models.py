"""Tests for project domain models."""

import pytest

from seclens.domain.models import parse_github_url
from seclens.domain.models.dependency import Dependency, DependencyVuln


class TestParseGitHubUrl:
    def test_https(self):
        owner, repo = parse_github_url("https://github.com/pallets/flask")
        assert owner == "pallets"
        assert repo == "flask"

    def test_with_git_suffix(self):
        owner, repo = parse_github_url("https://github.com/owner/repo.git")
        assert repo == "repo"

    def test_no_scheme(self):
        owner, repo = parse_github_url("github.com/foo/bar")
        assert owner == "foo"
        assert repo == "bar"

    def test_www(self):
        owner, repo = parse_github_url("https://www.github.com/x/y")
        assert owner == "x"
        assert repo == "y"

    def test_trailing_slash(self):
        owner, repo = parse_github_url("https://github.com/a/b/")
        assert owner == "a"
        assert repo == "b"

    def test_invalid(self):
        with pytest.raises(ValueError):
            parse_github_url("https://gitlab.com/a/b")

    def test_not_url(self):
        with pytest.raises(ValueError):
            parse_github_url("just some text")


class TestDependency:
    def test_display_name(self):
        d = Dependency(name="requests", version="2.31.0", ecosystem="PyPI")
        assert d.display_name == "requests@2.31.0"

    def test_display_name_no_version(self):
        d = Dependency(name="requests", version="", ecosystem="PyPI")
        assert d.display_name == "requests"

    def test_is_vulnerable(self):
        d = Dependency(
            name="a", version="1.0", ecosystem="PyPI",
            vulnerabilities=[DependencyVuln(vuln_id="GHSA-1")],
        )
        assert d.is_vulnerable is True

    def test_not_vulnerable(self):
        d = Dependency(name="a", version="1.0", ecosystem="PyPI")
        assert d.is_vulnerable is False

    def test_critical_count(self):
        d = Dependency(
            name="a", version="1.0", ecosystem="PyPI",
            vulnerabilities=[
                DependencyVuln(vuln_id="1", severity="CRITICAL"),
                DependencyVuln(vuln_id="2", severity="HIGH"),
                DependencyVuln(vuln_id="3", severity="CRITICAL"),
            ],
        )
        assert d.critical_count == 2
        assert d.high_count == 1

    def test_has_fix(self):
        d = Dependency(
            name="a", version="1.0", ecosystem="PyPI",
            vulnerabilities=[
                DependencyVuln(vuln_id="1", fixed_version="2.0"),
            ],
        )
        assert d.has_fix is True
