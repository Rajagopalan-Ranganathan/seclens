# Seclens Agent Instructions

This file provides context for AI agents (Claude, Cursor, Copilot, etc.) working on the seclens codebase. Read this before making any changes.

## What is Seclens?

A security-focused search engine that scores the security posture of:
1. **Software products** (via CPE) using NVD, EPSS, CISA KEV, and vendor advisory data
2. **GitHub projects** (via repository URL) using SBOM/manifests, OSV.dev, and repo security signals

## Quick Start

```bash
cd /Users/rarangan/go/src/github.com/seclens
source .venv/bin/activate
python -c "from seclens.main import cli; cli()" serve    # Start server on :8000
python -c "from seclens.main import cli; cli()" sync     # Sync NVD/EPSS/KEV data
pytest -v tests/                                          # Run all tests (70+)
```

## Architecture (Read First)

Detailed docs are in `docs/`. The key files:
- [docs/architecture.md](docs/architecture.md) -- system overview, data flows, diagrams
- [docs/design-principles.md](docs/design-principles.md) -- patterns and conventions
- [docs/scoring.md](docs/scoring.md) -- how scores are calculated
- [docs/domain-models.md](docs/domain-models.md) -- all data models
- [docs/adapters.md](docs/adapters.md) -- data sources and how to add new ones
- [docs/api-reference.md](docs/api-reference.md) -- all API endpoints
- [docs/frontend.md](docs/frontend.md) -- frontend architecture

### Layer Rules (Critical)

```
domain/     → Pure logic. NO I/O. NO imports from ports/adapters/api.
ports/      → Abstract interfaces (ABCs). Import domain models only.
application/→ Orchestration. Import domain + ports. NO business rules.
adapters/   → Concrete implementations. Import ports.
api/        → HTTP layer + DI wiring. Imports everything.
```

**Test**: If `domain/` imports `httpx`, `aiosqlite`, or any I/O library, you broke the architecture.

## Common Tasks

### Adding a new data source

1. Define abstract port in `src/seclens/ports/{name}_fetcher.py`
2. Implement adapter in `src/seclens/adapters/fetchers/{name}_fetcher.py`
3. Wire as singleton in `src/seclens/api/dependencies.py`
4. Inject into the appropriate application service
5. Add tests in `tests/`

### Adding a vendor enricher (e.g., Ubuntu USN, Microsoft MSRC)

Follow the Red Hat pattern in `adapters/fetchers/redhat_fetcher.py`:
1. Create `{vendor}_fetcher.py` with `fetch_patches_for_cve()` and `fetch_patches_batch()`
2. Parse the vendor's API response into `PatchInfo` objects (include `patch_date`!)
3. Inject into `ScoringService` and `SyncService`
4. Add vendor detection (e.g., `"canonical" in cpe_uri`)

### Adding a scoring factor

1. Write `_score_new_factor(vulns)` in `domain/scoring.py` (returns 0-100)
2. Add field to `ScoreBreakdown` in `domain/models/score.py`
3. Add weight in `SecurityScore.create()`
4. Update frontend `breakdownItem()` calls in `frontend/static/js/app.js`
5. Update `docs/scoring.md`

### Adding an API endpoint

1. Add Pydantic schema(s) in `api/schemas.py`
2. Add route in `api/router.py`
3. Add mapping function `_xxx_to_response()` in `api/router.py`
4. Wire any new services in `api/dependencies.py`

### Adding a manifest parser

1. Add parser function in `adapters/fetchers/manifest_parser.py`
2. Register in `_PARSERS` dict and `MANIFEST_FILES` dict
3. Add to `PREFERRED_MANIFESTS` list (order = priority)
4. Add tests in `tests/domain/test_manifest_parser.py`

### Modifying the frontend

- Edit `frontend/static/js/app.js` (all logic) and `frontend/static/css/style.css` (all styles)
- No build step -- changes are live on refresh
- Pattern: add render function, wire into search router or navigation, add CSS
- The frontend can be fully replaced; backend API contracts are stable

## Code Conventions

### Python
- Python 3.11+, use `from __future__ import annotations`
- Dataclasses for domain models, Pydantic for API schemas
- All I/O is async (`async/await`)
- Domain functions are synchronous (pure)
- Use `asyncio.Semaphore()` for concurrent external API calls
- Use `asyncio.gather()` for parallel independent operations

### Naming
- Domain models: singular nouns (`product.py`, `vulnerability.py`)
- Adapters: `{vendor}_{role}.py` (`nvd_fetcher.py`, `sqlite_repository.py`)
- Services: `{noun}_service.py` (`search_service.py`)
- Tests: `test_{module}.py`

### Error handling
- Domain: custom exceptions from `domain/exceptions.py`
- Adapters: catch external errors, log warnings, return safe defaults (never crash)
- API: translate to HTTP status codes

### Testing
- Domain: pure unit tests, no mocks
- Adapters: integration tests with real ephemeral resources
- API: `httpx.AsyncClient` with `pytest-asyncio`
- Run: `pytest -v tests/`

## Key Files Quick Reference

| What | Where |
|------|-------|
| Composition root / CLI | `src/seclens/main.py` |
| DI wiring (all singletons) | `src/seclens/api/dependencies.py` |
| Product scoring algorithm | `src/seclens/domain/scoring.py` |
| Project scoring algorithm | `src/seclens/domain/project_scoring.py` |
| Product aliases (RHEL→redhat) | `src/seclens/domain/models/product.py` |
| Score weights | `src/seclens/domain/models/score.py` (line ~60) |
| Grade thresholds | `src/seclens/domain/models/score.py` (line ~20) |
| Database schema | `src/seclens/adapters/persistence/sqlite_repository.py` (`_SCHEMA_SQL`) |
| All API routes | `src/seclens/api/router.py` |
| Frontend app logic | `frontend/static/js/app.js` |
| Frontend styles | `frontend/static/css/style.css` |

## Gotchas

1. **Red Hat API uses `release_date`, not `date`** in `affected_release` entries.
2. **NVD doesn't always record fix versions** -- vendor enrichment is critical for accurate patch data.
3. **EPSS defaults to 70 (not 50)** when no data exists -- no exploitation evidence = lean positive.
4. **Scoring uses logistic/logarithmic curves**, not linear. This prevents popular products from being unfairly penalized.
5. **Patched CVEs count at half CVSS** in severity scoring.
6. **GitHub SBOM API** requires the dependency graph to be enabled on the repo. Falls back to manifest parsing.
7. **OSV batch API** accepts max 1000 queries but we batch at 100 for reliability.
8. **SQLite connections** use `asynccontextmanager` -- don't reuse `aiosqlite` connection objects across tasks.
9. **The `data/` directory is gitignored** -- the SQLite DB is created on first run/sync.

## Docker & Containers

The production image uses Red Hat Hummingbird distroless base images for minimal attack surface.

```bash
make docker-build              # Build container image (Containerfile, multi-stage)
make docker-run                # Run via docker compose (compose.yml)
make docker-stop               # Stop containers
make docker-logs               # Tail container logs
```

### Container Architecture
- **Build stage**: `registry.access.redhat.com/hi/python:3.12-builder` (includes shell, dnf, pip)
- **Runtime stage**: `registry.access.redhat.com/hi/python:3.12` (distroless, no shell, zero CVEs)
- Non-root user via `CONTAINER_DEFAULT_USER`
- `requirements.lock` for pinned, reproducible builds
- SBOM generated at release time (CycloneDX)

### Modifying Dependencies
1. Update `pyproject.toml` with new/changed dependencies
2. Run `make lock` to regenerate `requirements.lock`
3. Verify Docker build: `make docker-build`

## CI/CD Pipeline

### GitHub Actions Workflows

| Workflow | Trigger | Jobs |
|----------|---------|------|
| `ci.yml` | Push to `main`, PRs | lint, test, codeql, docker-build, pip-audit |
| `release.yml` | Tag push (`v*`) | Build + push Docker image, generate SBOM |

### Pre-commit Hooks
Installed via `make dev`. Hooks run automatically on `git commit`:
- `ruff` lint + format
- `check-yaml`, `check-toml`, `check-json`
- `detect-secrets` (blocks leaked credentials)
- `no-commit-to-branch` (prevents direct commits to `main`)
- `check-github-workflows` (validates workflow syntax)

### Security Tooling

```bash
make audit                     # pip-audit: check deps for known vulns
make sbom                      # Generate CycloneDX SBOM (sbom.cdx.json)
make pre-commit                # Run all pre-commit hooks manually
```

## Key Security Files

| File | Purpose |
|------|---------|
| `.github/dependabot.yml` | Daily pip + weekly Actions dependency updates |
| `.github/workflows/ci.yml` | Lint, test, CodeQL, Docker build, pip-audit on every PR |
| `.github/workflows/release.yml` | Docker build + push + SBOM on version tags |
| `.github/secret_scanning.yml` | Push protection for leaked secrets |
| `.github/CODEOWNERS` | Require review from maintainers |
| `.pre-commit-config.yaml` | Local pre-commit hooks |
| `SECURITY.md` | Vulnerability disclosure policy |
| `CONTRIBUTING.md` | Development guidelines, branch rules, commit conventions |
| `Containerfile` | Multi-stage Hummingbird build |
| `compose.yml` | Docker Compose for local dev |
| `requirements.lock` | Pinned production dependencies |

## Before Submitting Changes

```bash
pytest -v tests/              # All tests must pass
make lint                     # Lint must pass
make docker-build             # Container must build
# If you changed scoring:
#   Update docs/scoring.md with new formulas/weights
# If you added a data source:
#   Update docs/adapters.md
# If you added an API endpoint:
#   Update docs/api-reference.md
# If you changed dependencies:
#   Run `make lock` to update requirements.lock
```
