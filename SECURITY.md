# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.x     | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in seclens, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please:

1. Email **security@seclens.dev** with a description of the vulnerability
2. Include steps to reproduce, if possible
3. Allow up to 72 hours for an initial response

We will:

- Acknowledge receipt within 72 hours
- Provide an estimated timeline for a fix
- Credit you in the advisory (unless you prefer anonymity)

## Security Practices

This project follows these security practices:

- **Dependency scanning**: Dependabot monitors all dependencies daily
- **Static analysis**: CodeQL runs on every PR and push to `main`
- **Secret scanning**: GitHub push protection prevents accidental credential leaks
- **Container security**: Production images use Red Hat Hummingbird distroless base (zero CVEs)
- **Pre-commit hooks**: `detect-secrets`, `ruff`, and `check-yaml` run before every commit
- **Dependency auditing**: `pip-audit` runs in CI to catch known vulnerabilities

## Scope

The following are in scope for security reports:

- Vulnerabilities in seclens application code
- Dependency vulnerabilities that affect seclens
- Container image security issues
- API authentication or authorization bypasses

The following are out of scope:

- Vulnerabilities in upstream data sources (NVD, EPSS, CISA KEV)
- Social engineering attacks
- Denial of service via rate limiting external APIs
