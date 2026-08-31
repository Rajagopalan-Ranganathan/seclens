from __future__ import annotations

from dataclasses import dataclass
from datetime import date


@dataclass(frozen=True)
class RepoSecuritySignals:
    """Security-relevant metadata about a GitHub repository."""

    default_branch_protected: bool | None = None
    secret_scanning_enabled: bool | None = None
    code_scanning_enabled: bool | None = None
    dependency_updates_enabled: bool | None = None
    license_name: str | None = None
    last_push_date: date | None = None
    archived: bool = False
    fork: bool = False
    stargazers_count: int = 0
    open_issues_count: int = 0

    @property
    def is_actively_maintained(self) -> bool:
        if self.archived:
            return False
        if self.last_push_date is None:
            return False
        days_since = (date.today() - self.last_push_date).days
        return days_since < 365
