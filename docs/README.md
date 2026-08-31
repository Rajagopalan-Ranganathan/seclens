# Seclens Documentation

Security-focused search engine for scoring software products and GitHub projects.

## Documentation Index

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | System overview, high-level design, data flow diagrams, directory structure |
| [Design Principles](design-principles.md) | Hexagonal architecture, DDD, observer-probe pattern, conventions |
| [Domain Models](domain-models.md) | CPE, Product, Vulnerability, Dependency, Project -- all data structures |
| [Scoring Algorithm](scoring.md) | How product and project scores are calculated, with formulas and examples |
| [Data Sources & Adapters](adapters.md) | NVD, EPSS, KEV, Red Hat, GitHub, OSV -- APIs, auth, rate limits |
| [API Reference](api-reference.md) | All REST endpoints with request/response examples |
| [Frontend](frontend.md) | UI architecture, component overview, how to extend or replace |
| [Roadmap](roadmap.md) | Future features: hardware device scoring, privacy scorecard, vendor expansion |

## Security & Operations

| Document | Description |
|----------|-------------|
| [SECURITY.md](../SECURITY.md) | Vulnerability disclosure policy |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | Development setup, workflow, branch rules, commit conventions |
| [Containerfile](../Containerfile) | Multi-stage Docker build with Red Hat Hummingbird images |
| [openapi.yaml](../openapi.yaml) | Auto-generated OpenAPI 3.1 spec (do not edit by hand) |

### Quick Reference

| Task | Command |
|------|---------|
| Build container | `make docker-build` |
| Run container | `make docker-run` |
| Audit dependencies | `make audit` |
| Generate SBOM | `make sbom` |
| Run pre-commit hooks | `make pre-commit` |
| Pin dependencies | `make lock` |
| Regenerate OpenAPI spec | `make openapi` |
| Verify spec is current | `make openapi-check` |
| Run all gates | `make all` |

## For AI Agents

See [AGENTS.md](../AGENTS.md) in the project root for agent-specific instructions, Docker/CI/security details, common tasks, and gotchas.

## Quick Start

```bash
source .venv/bin/activate
make dev                     # Install deps + pre-commit hooks
make serve                   # http://localhost:8000
make sync                    # Populate local DB
make all                     # Lint + test + openapi-check
```

## Architecture at a Glance

```
User → Frontend → FastAPI Router → Application Services → Domain (pure logic)
                                         ↕                      ↕
                                    Ports (ABCs)          Scoring Algorithms
                                         ↕
                                    Adapters (NVD, GitHub, OSV, SQLite, ...)
```

Two main flows:
1. **Product search**: Query → CPE resolution → NVD/local vulns → scoring → scorecard
2. **Project analysis**: GitHub URL → SBOM/manifests → OSV vulns → repo signals → scoring → scorecard
