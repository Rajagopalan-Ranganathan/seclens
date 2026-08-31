"""Parsers for dependency manifest files across ecosystems."""

from __future__ import annotations

import json
import re

from seclens.domain.models import Dependency

MANIFEST_FILES: dict[str, str] = {
    "requirements.txt": "PyPI",
    "setup.py": "PyPI",
    "Pipfile.lock": "PyPI",
    "pyproject.toml": "PyPI",
    "go.mod": "Go",
    "go.sum": "Go",
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "Cargo.toml": "crates.io",
    "Cargo.lock": "crates.io",
    "pom.xml": "Maven",
    "build.gradle": "Maven",
    "Gemfile": "RubyGems",
    "Gemfile.lock": "RubyGems",
}

PREFERRED_MANIFESTS = [
    "go.mod",
    "requirements.txt",
    "package.json",
    "Cargo.toml",
    "pom.xml",
    "Gemfile",
    "pyproject.toml",
    "Pipfile.lock",
    "package-lock.json",
    "Cargo.lock",
    "Gemfile.lock",
]


def detect_ecosystem(filename: str) -> str | None:
    return MANIFEST_FILES.get(filename)


def parse_manifest(filename: str, content: str) -> list[Dependency]:
    """Parse a manifest file and return dependencies."""
    parser = _PARSERS.get(filename)
    if not parser:
        for suffix, func in _SUFFIX_PARSERS.items():
            if filename.endswith(suffix):
                parser = func
                break
    if not parser:
        return []
    return parser(content)


def parse_requirements_txt(content: str) -> list[Dependency]:
    deps: list[Dependency] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        m = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([=<>!~]+\s*[\d\w\.\*\-]+)?", line)
        if m:
            name = m.group(1)
            version_spec = m.group(2) or ""
            version = re.sub(r"[=<>!~\s]+", "", version_spec).strip() or ""
            deps.append(Dependency(name=name, version=version, ecosystem="PyPI"))
    return deps


def parse_go_mod(content: str) -> list[Dependency]:
    deps: list[Dependency] = []
    in_require = False
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if in_require or line.startswith("require "):
            parts = line.removeprefix("require ").strip().split()
            if len(parts) >= 2:
                module = parts[0]
                version = parts[1].lstrip("v")
                if "// indirect" in line:
                    deps.append(
                        Dependency(name=module, version=version, ecosystem="Go", is_direct=False)
                    )
                else:
                    deps.append(Dependency(name=module, version=version, ecosystem="Go"))
    return deps


def parse_package_json(content: str) -> list[Dependency]:
    deps: list[Dependency] = []
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return deps

    for section, is_direct in [("dependencies", True), ("devDependencies", False)]:
        for name, version_spec in data.get(section, {}).items():
            version = re.sub(r"[\^~>=<\s]", "", version_spec).strip()
            deps.append(
                Dependency(name=name, version=version, ecosystem="npm", is_direct=is_direct)
            )
    return deps


def parse_cargo_toml(content: str) -> list[Dependency]:
    deps: list[Dependency] = []
    in_deps = False
    in_dev_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped == "[dependencies]":
            in_deps, in_dev_deps = True, False
            continue
        if stripped == "[dev-dependencies]":
            in_deps, in_dev_deps = False, True
            continue
        if stripped.startswith("["):
            in_deps = in_dev_deps = False
            continue
        if in_deps or in_dev_deps:
            m = re.match(r'^([a-zA-Z0-9_\-]+)\s*=\s*"([^"]*)"', stripped)
            if m:
                deps.append(
                    Dependency(
                        name=m.group(1),
                        version=m.group(2),
                        ecosystem="crates.io",
                        is_direct=in_deps,
                    )
                )
            m2 = re.match(r'^([a-zA-Z0-9_\-]+)\s*=\s*\{.*version\s*=\s*"([^"]*)"', stripped)
            if m2:
                deps.append(
                    Dependency(
                        name=m2.group(1),
                        version=m2.group(2),
                        ecosystem="crates.io",
                        is_direct=in_deps,
                    )
                )
    return deps


def parse_pom_xml(content: str) -> list[Dependency]:
    deps: list[Dependency] = []
    dep_pattern = re.compile(
        r"<dependency>\s*"
        r"<groupId>([^<]+)</groupId>\s*"
        r"<artifactId>([^<]+)</artifactId>\s*"
        r"(?:<version>([^<]*)</version>)?",
        re.DOTALL,
    )
    for m in dep_pattern.finditer(content):
        group_id, artifact_id = m.group(1), m.group(2)
        version = m.group(3) or ""
        name = f"{group_id}:{artifact_id}"
        deps.append(Dependency(name=name, version=version, ecosystem="Maven"))
    return deps


def parse_gemfile(content: str) -> list[Dependency]:
    deps: list[Dependency] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"""^gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]*?)['"])?""", line)
        if m:
            name = m.group(1)
            version = re.sub(r"[~>=<\s]", "", m.group(2) or "")
            deps.append(Dependency(name=name, version=version, ecosystem="RubyGems"))
    return deps


def parse_pyproject_toml(content: str) -> list[Dependency]:
    deps: list[Dependency] = []
    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped == "dependencies = [" or stripped.startswith("dependencies = ["):
            in_deps = True
            inline = stripped.removeprefix("dependencies = [").rstrip("]").strip()
            if inline:
                for item in _split_toml_list(inline):
                    d = _parse_pep508(item)
                    if d:
                        deps.append(d)
            if stripped.endswith("]"):
                in_deps = False
            continue
        if in_deps:
            if stripped.startswith("]"):
                in_deps = False
                continue
            d = _parse_pep508(stripped.strip('", '))
            if d:
                deps.append(d)
    return deps


def _split_toml_list(s: str) -> list[str]:
    return [item.strip().strip('"').strip("'") for item in s.split(",") if item.strip()]


def _parse_pep508(spec: str) -> Dependency | None:
    spec = spec.strip().strip('"').strip("'").strip(",")
    if not spec:
        return None
    m = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([=<>!~]+\s*[\d\w\.\*\-]+)?", spec)
    if m:
        name = m.group(1)
        version = re.sub(r"[=<>!~\s]+", "", m.group(2) or "").strip() if m.group(2) else ""
        return Dependency(name=name, version=version, ecosystem="PyPI")
    return None


_PARSERS: dict[str, callable] = {
    "requirements.txt": parse_requirements_txt,
    "go.mod": parse_go_mod,
    "package.json": parse_package_json,
    "Cargo.toml": parse_cargo_toml,
    "pom.xml": parse_pom_xml,
    "Gemfile": parse_gemfile,
    "pyproject.toml": parse_pyproject_toml,
}

_SUFFIX_PARSERS: dict[str, callable] = {
    "requirements.txt": parse_requirements_txt,
    "go.mod": parse_go_mod,
    "package.json": parse_package_json,
    "Cargo.toml": parse_cargo_toml,
    "pom.xml": parse_pom_xml,
    "Gemfile": parse_gemfile,
    "pyproject.toml": parse_pyproject_toml,
}
