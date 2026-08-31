# seclens

Security search engine — given any software or hardware, get a security scorecard, privacy scorecard, and active vulnerability listing.

## Quick Start

```bash
# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install (with pre-commit hooks)
make dev

# Sync vulnerability data (NVD, EPSS, CISA KEV)
make sync

# (Optional) Set a GitHub token for GitHub project scoring (5,000 req/hr)
export GITHUB_TOKEN=ghp_your_token_here

# Start the server
make serve

# Open http://localhost:8000 in your browser
```

### Docker

```bash
make docker-build   # Build using Red Hat Hummingbird distroless base
make docker-run     # Start via docker compose
make docker-stop    # Stop containers
```

## Architecture

- **Domain-Driven Design** with hexagonal architecture (ports & adapters)
- **Observer-probe pattern** for domain-oriented observability
- **Replaceable frontend** — backend serves a clean REST API

## API

```
GET  /api/v1/search?q={query}        Search by keyword, product name, or CPE
GET  /api/v1/products/{cpe}/score     Security scorecard
GET  /api/v1/products/{cpe}/vulns     Vulnerability list
GET  /api/v1/products/{cpe}/patches   Known patches/advisories
GET  /api/v1/vulns/{cve_id}           Direct CVE lookup
POST /api/v1/sync                     Trigger data sync
```

## Data Sources

- [NVD](https://nvd.nist.gov/) — CVE and CPE data
- [EPSS](https://www.first.org/epss/) — Exploit prediction scores
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — Known exploited vulnerabilities
- [Red Hat Security Data API](https://access.redhat.com/documentation/en-us/red_hat_security_data_api/) — RHSA advisories and patches
- [GitHub SBOM API](https://docs.github.com/en/rest/dependency-graph/sboms) — Dependency graph for GitHub projects
- [OSV.dev](https://osv.dev/) — Open Source Vulnerabilities database

## Security

- **Container**: Multi-stage build on Red Hat Hummingbird `hi/python:3.12` (distroless, zero CVEs)
- **CI**: CodeQL, pip-audit, Docker build verification on every PR
- **Pre-commit**: ruff, detect-secrets, yaml/toml validation
- **Dependencies**: Dependabot daily updates, pinned in `requirements.lock`
- **Secrets**: GitHub push protection + detect-secrets pre-commit hook

See [SECURITY.md](SECURITY.md) for vulnerability disclosure and [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.
