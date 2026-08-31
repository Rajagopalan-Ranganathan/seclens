from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from .dependencies import (
    get_metrics,
    get_project_service,
    get_scoring_service,
    get_search_service,
    get_sync_service,
    get_vuln_repo,
)
from .schemas import (
    DependencyResponse,
    DependencyVulnResponse,
    HealthResponse,
    PatchInfoResponse,
    ProductResponse,
    ProjectResponse,
    ProjectScoreBreakdownResponse,
    ProjectScoreResponse,
    RepoSignalsResponse,
    ScoreBreakdownResponse,
    SearchResponse,
    SecurityScoreResponse,
    SyncResponse,
    VulnerabilityResponse,
)

router = APIRouter(prefix="/api/v1")


@router.get("/search", response_model=SearchResponse)
async def search(q: str = Query(..., min_length=1, description="Search query")):
    svc = get_search_service()
    products = await svc.search(q)
    return SearchResponse(
        query=q,
        results=[_product_to_response(p) for p in products],
        total=len(products),
    )


@router.get("/products/{cpe:path}/score", response_model=SecurityScoreResponse)
async def product_score(cpe: str):
    svc = get_scoring_service()
    result = await svc.score_product(cpe)
    if not result:
        raise HTTPException(404, f"Product not found: {cpe}")
    _, score = result
    return _score_to_response(score)


@router.get("/products/{cpe:path}/vulns", response_model=list[VulnerabilityResponse])
async def product_vulns(cpe: str):
    svc = get_scoring_service()
    vulns = await svc.get_vulnerabilities(cpe)
    return [_vuln_to_response(v) for v in vulns]


@router.get("/products/{cpe:path}/patches", response_model=list[VulnerabilityResponse])
async def product_patches(cpe: str):
    svc = get_scoring_service()
    patched = await svc.get_patches(cpe)
    return [_vuln_to_response(v) for v in patched]


@router.get("/vulns/{cve_id}", response_model=VulnerabilityResponse)
async def vulnerability_detail(cve_id: str):
    svc = get_search_service()
    vuln = await svc.lookup_cve(cve_id)
    if not vuln:
        raise HTTPException(404, f"CVE not found: {cve_id}")
    return _vuln_to_response(vuln)


@router.post("/sync", response_model=SyncResponse)
async def trigger_sync():
    svc = get_sync_service()
    counts = await svc.sync_all(max_vulns=5000)
    return SyncResponse(status="completed", counts=counts)


@router.post("/sync/redhat", response_model=SyncResponse)
async def trigger_redhat_sync():
    """Enrich stored Red Hat CVEs with RHSA advisory data."""
    svc = get_sync_service()
    count = await svc.sync_redhat_advisories()
    return SyncResponse(status="completed", counts={"redhat": count})


@router.get("/project", response_model=ProjectResponse)
async def analyze_project(url: str = Query(..., description="GitHub repository URL")):
    svc = get_project_service()
    try:
        project = await svc.analyze(url)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:  # noqa: BLE001 — surface upstream errors as 502
        raise HTTPException(502, f"Failed to analyze project: {e}")
    return _project_to_response(project)


@router.get("/health", response_model=HealthResponse)
async def health():
    repo = get_vuln_repo()
    count = await repo.count()
    return HealthResponse(status="ok", vuln_count=count)


@router.get("/metrics")
async def metrics():
    return get_metrics().summary()


def _product_to_response(p) -> ProductResponse:
    score_resp = _score_to_response(p.score) if p.score else None
    return ProductResponse(
        name=p.cpe.display_name,
        cpe_uri=p.cpe.uri,
        vendor=p.cpe.vendor_display,
        version=p.version if p.version != "*" else "",
        vuln_count=len(p.vulnerabilities),
        score=score_resp,
    )


def _score_to_response(s) -> SecurityScoreResponse:
    return SecurityScoreResponse(
        overall=s.overall,
        grade=s.grade,
        computed_at=s.computed_at,
        total_cves=s.total_cves,
        critical_count=s.critical_count,
        high_count=s.high_count,
        medium_count=s.medium_count,
        low_count=s.low_count,
        none_count=s.none_count,
        breakdown=ScoreBreakdownResponse(
            vuln_density=s.breakdown.vuln_density,
            avg_severity=s.breakdown.avg_severity,
            exploit_likelihood=s.breakdown.exploit_likelihood,
            kev_exposure=s.breakdown.kev_exposure,
            patch_velocity=s.breakdown.patch_velocity,
            unpatched_ratio=s.breakdown.unpatched_ratio,
        ),
    )


def _vuln_to_response(v) -> VulnerabilityResponse:
    return VulnerabilityResponse(
        cve_id=v.cve_id,
        description=v.description,
        cvss_score=v.cvss_score,
        severity=v.severity.value,
        published=v.published,
        last_modified=v.last_modified,
        epss_score=v.epss_score,
        in_kev=v.in_kev,
        is_patched=v.is_patched,
        patches=[
            PatchInfoResponse(
                fixed_version=p.fixed_version,
                advisory_id=p.advisory_id,
                advisory_url=p.advisory_url,
                patch_date=p.patch_date,
                source=p.source,
            )
            for p in v.patches
        ],
        references=v.references,
    )


def _project_to_response(p) -> ProjectResponse:
    score_resp = None
    if p.score:
        score_resp = ProjectScoreResponse(
            overall=p.score.overall,
            grade=p.score.grade,
            computed_at=p.score.computed_at,
            total_deps=p.score.total_deps,
            vulnerable_deps=p.score.vulnerable_deps,
            critical_vulns=p.score.critical_vulns,
            high_vulns=p.score.high_vulns,
            breakdown=ProjectScoreBreakdownResponse(
                dependency_risk=p.score.breakdown.dependency_risk,
                repo_posture=p.score.breakdown.repo_posture,
                supply_chain=p.score.breakdown.supply_chain,
            ),
        )

    signals_resp = None
    if p.repo_signals:
        s = p.repo_signals
        signals_resp = RepoSignalsResponse(
            default_branch_protected=s.default_branch_protected,
            secret_scanning_enabled=s.secret_scanning_enabled,
            code_scanning_enabled=s.code_scanning_enabled,
            dependency_updates_enabled=s.dependency_updates_enabled,
            license_name=s.license_name,
            last_push_date=s.last_push_date,
            archived=s.archived,
            fork=s.fork,
            stargazers_count=s.stargazers_count,
            is_actively_maintained=s.is_actively_maintained,
        )

    dep_responses = []
    for d in p.dependencies:
        dep_responses.append(
            DependencyResponse(
                name=d.name,
                version=d.version,
                ecosystem=d.ecosystem,
                is_direct=d.is_direct,
                license=d.license,
                is_vulnerable=d.is_vulnerable,
                vuln_count=len(d.vulnerabilities),
                critical_count=d.critical_count,
                high_count=d.high_count,
                vulnerabilities=[
                    DependencyVulnResponse(
                        vuln_id=v.vuln_id,
                        aliases=v.aliases,
                        summary=v.summary,
                        severity=v.severity,
                        cvss_score=v.cvss_score,
                        fixed_version=v.fixed_version,
                        url=v.url,
                    )
                    for v in d.vulnerabilities
                ],
            )
        )

    return ProjectResponse(
        owner=p.owner,
        repo=p.repo,
        full_name=p.full_name,
        url=p.url,
        description=p.description,
        score=score_resp,
        repo_signals=signals_resp,
        dependencies=dep_responses,
        total_deps=len(p.dependencies),
        vulnerable_deps=sum(1 for d in p.dependencies if d.is_vulnerable),
    )
