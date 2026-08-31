"""Pydantic models for API request/response DTOs."""

from __future__ import annotations

from datetime import date, datetime

from pydantic import BaseModel


class PatchInfoResponse(BaseModel):
    fixed_version: str | None = None
    advisory_id: str | None = None
    advisory_url: str | None = None
    patch_date: date | None = None
    source: str = "nvd"


class VulnerabilityResponse(BaseModel):
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    published: date
    last_modified: date
    epss_score: float | None = None
    in_kev: bool = False
    is_patched: bool = False
    patches: list[PatchInfoResponse] = []
    references: list[str] = []


class ScoreBreakdownResponse(BaseModel):
    vuln_density: float
    avg_severity: float
    exploit_likelihood: float
    kev_exposure: float
    patch_velocity: float
    unpatched_ratio: float


class SecurityScoreResponse(BaseModel):
    overall: float
    grade: str
    computed_at: datetime
    total_cves: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    none_count: int
    breakdown: ScoreBreakdownResponse


class ProductResponse(BaseModel):
    name: str
    cpe_uri: str
    vendor: str
    version: str
    vuln_count: int = 0
    score: SecurityScoreResponse | None = None


class SearchResponse(BaseModel):
    query: str
    results: list[ProductResponse]
    total: int


class SyncResponse(BaseModel):
    status: str
    counts: dict[str, int]


class HealthResponse(BaseModel):
    status: str
    vuln_count: int
    version: str = "0.1.0"


# --- GitHub Project Scoring ---


class DependencyVulnResponse(BaseModel):
    vuln_id: str
    aliases: list[str] = []
    summary: str = ""
    severity: str = "UNKNOWN"
    cvss_score: float | None = None
    fixed_version: str | None = None
    url: str = ""


class DependencyResponse(BaseModel):
    name: str
    version: str
    ecosystem: str
    is_direct: bool = True
    license: str | None = None
    is_vulnerable: bool = False
    vuln_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    vulnerabilities: list[DependencyVulnResponse] = []


class RepoSignalsResponse(BaseModel):
    default_branch_protected: bool | None = None
    secret_scanning_enabled: bool | None = None
    code_scanning_enabled: bool | None = None
    dependency_updates_enabled: bool | None = None
    license_name: str | None = None
    last_push_date: date | None = None
    archived: bool = False
    fork: bool = False
    stargazers_count: int = 0
    is_actively_maintained: bool = False


class ProjectScoreBreakdownResponse(BaseModel):
    dependency_risk: float
    repo_posture: float
    supply_chain: float


class ProjectScoreResponse(BaseModel):
    overall: float
    grade: str
    computed_at: datetime
    total_deps: int
    vulnerable_deps: int
    critical_vulns: int
    high_vulns: int
    breakdown: ProjectScoreBreakdownResponse


class ProjectResponse(BaseModel):
    owner: str
    repo: str
    full_name: str
    url: str
    description: str = ""
    score: ProjectScoreResponse | None = None
    repo_signals: RepoSignalsResponse | None = None
    dependencies: list[DependencyResponse] = []
    total_deps: int = 0
    vulnerable_deps: int = 0
