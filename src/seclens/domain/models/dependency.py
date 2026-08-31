from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class DependencyVuln:
    """A vulnerability affecting a specific dependency."""

    vuln_id: str
    aliases: list[str] = field(default_factory=list)
    summary: str = ""
    severity: str = "UNKNOWN"
    cvss_score: float | None = None
    fixed_version: str | None = None
    url: str = ""


@dataclass
class Dependency:
    """A software dependency of a project."""

    name: str
    version: str
    ecosystem: str
    is_direct: bool = True
    license: str | None = None
    vulnerabilities: list[DependencyVuln] = field(default_factory=list)

    @property
    def is_vulnerable(self) -> bool:
        return len(self.vulnerabilities) > 0

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == "HIGH")

    @property
    def has_fix(self) -> bool:
        return any(v.fixed_version for v in self.vulnerabilities)

    @property
    def display_name(self) -> str:
        if self.version:
            return f"{self.name}@{self.version}"
        return self.name
