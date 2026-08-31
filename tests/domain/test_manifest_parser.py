"""Tests for manifest file parsers."""

from seclens.adapters.fetchers.manifest_parser import (
    parse_cargo_toml,
    parse_gemfile,
    parse_go_mod,
    parse_package_json,
    parse_pom_xml,
    parse_pyproject_toml,
    parse_requirements_txt,
)


class TestRequirementsTxt:
    def test_basic(self):
        content = "requests==2.31.0\nflask>=2.0\nnumpy"
        deps = parse_requirements_txt(content)
        assert len(deps) == 3
        assert deps[0].name == "requests"
        assert deps[0].version == "2.31.0"
        assert deps[0].ecosystem == "PyPI"
        assert deps[1].name == "flask"
        assert deps[1].version == "2.0"
        assert deps[2].name == "numpy"
        assert deps[2].version == ""

    def test_skips_comments_and_flags(self):
        content = "# comment\n-r base.txt\nrequests==1.0\n  \n"
        deps = parse_requirements_txt(content)
        assert len(deps) == 1
        assert deps[0].name == "requests"


class TestGoMod:
    def test_basic(self):
        content = """module github.com/example/app

go 1.21

require (
\tgithub.com/gin-gonic/gin v1.9.1
\tgolang.org/x/text v0.14.0 // indirect
)

require github.com/stretchr/testify v1.8.4
"""
        deps = parse_go_mod(content)
        assert len(deps) == 3
        assert deps[0].name == "github.com/gin-gonic/gin"
        assert deps[0].version == "1.9.1"
        assert deps[0].ecosystem == "Go"
        assert deps[0].is_direct is True
        assert deps[1].name == "golang.org/x/text"
        assert deps[1].is_direct is False
        assert deps[2].name == "github.com/stretchr/testify"


class TestPackageJson:
    def test_basic(self):
        content = '{"dependencies": {"express": "^4.18.2"}, "devDependencies": {"jest": "~29.7.0"}}'
        deps = parse_package_json(content)
        assert len(deps) == 2
        assert deps[0].name == "express"
        assert deps[0].version == "4.18.2"
        assert deps[0].ecosystem == "npm"
        assert deps[0].is_direct is True
        assert deps[1].name == "jest"
        assert deps[1].is_direct is False

    def test_empty(self):
        deps = parse_package_json("{}")
        assert len(deps) == 0

    def test_invalid_json(self):
        deps = parse_package_json("not json")
        assert len(deps) == 0


class TestCargoToml:
    def test_basic(self):
        content = """[dependencies]
serde = "1.0"
tokio = { version = "1.35", features = ["full"] }

[dev-dependencies]
criterion = "0.5"
"""
        deps = parse_cargo_toml(content)
        assert len(deps) == 3
        assert deps[0].name == "serde"
        assert deps[0].version == "1.0"
        assert deps[0].ecosystem == "crates.io"
        assert deps[0].is_direct is True
        assert deps[1].name == "tokio"
        assert deps[1].version == "1.35"
        assert deps[2].name == "criterion"
        assert deps[2].is_direct is False


class TestPomXml:
    def test_basic(self):
        content = """<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>6.1.2</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
    </dependency>
  </dependencies>
</project>"""
        deps = parse_pom_xml(content)
        assert len(deps) == 2
        assert deps[0].name == "org.springframework:spring-core"
        assert deps[0].version == "6.1.2"
        assert deps[0].ecosystem == "Maven"
        assert deps[1].version == ""


class TestGemfile:
    def test_basic(self):
        content = """source 'https://rubygems.org'
gem 'rails', '~> 7.1'
gem 'puma'
# gem 'debug'
"""
        deps = parse_gemfile(content)
        assert len(deps) == 2
        assert deps[0].name == "rails"
        assert deps[0].version == "7.1"
        assert deps[0].ecosystem == "RubyGems"
        assert deps[1].name == "puma"


class TestPyprojectToml:
    def test_inline_deps(self):
        content = """[project]
dependencies = ["requests>=2.31", "click"]
"""
        deps = parse_pyproject_toml(content)
        assert len(deps) == 2
        assert deps[0].name == "requests"
        assert deps[0].version == "2.31"

    def test_multiline_deps(self):
        content = """[project]
dependencies = [
    "httpx>=0.25",
    "pydantic",
]
"""
        deps = parse_pyproject_toml(content)
        assert len(deps) == 2
        assert deps[0].name == "httpx"
