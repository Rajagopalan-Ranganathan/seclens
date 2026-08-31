# Contributing to seclens

Thank you for your interest in contributing to seclens! This guide will help you get started.

## Development Setup

```bash
git clone https://github.com/your-org/seclens.git
cd seclens
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

## Development Workflow

1. Create a feature branch from `main`
2. Make your changes
3. Run the test suite: `make test`
4. Run the linter: `make lint`
5. Commit your changes (pre-commit hooks will run automatically)
6. Open a pull request

## Code Style

- Python code follows [ruff](https://docs.astral.sh/ruff/) defaults with a 100-character line length
- Target Python 3.12+
- Use type hints for all function signatures
- Follow Domain-Driven Design patterns established in the codebase

## Testing

```bash
make test          # run full test suite
pytest tests/ -v   # verbose output
pytest tests/domain/test_scoring.py  # run specific test file
```

All new features should include tests. Aim for coverage of:
- Domain model invariants
- Scoring algorithm edge cases
- API endpoint behavior
- Adapter integration (use mocks for external services)

## Docker

```bash
make docker-build  # build the container image
make docker-run    # run the container
make docker-stop   # stop the container
```

## Branch Protection

The `main` branch has the following protections (configured via GitHub UI):

- **Required PR reviews**: At least 1 approval before merge
- **Required status checks**: `lint`, `test`, `codeql`, and `docker-build` must pass
- **No force pushes**: History is immutable on `main`
- **No direct commits**: All changes go through pull requests

## Commit Messages

Use clear, descriptive commit messages:

```
feat: add OSV.dev integration for dependency scanning
fix: correct CVSS score normalization for patched CVEs
docs: update API reference with project endpoint
ci: add pip-audit to CI pipeline
```

Prefixes: `feat`, `fix`, `docs`, `ci`, `refactor`, `test`, `deps`

## Security

- Never commit secrets, API keys, or credentials
- The `detect-secrets` pre-commit hook will block accidental leaks
- See [SECURITY.md](SECURITY.md) for vulnerability reporting

## Pull Request Guidelines

- Keep PRs focused — one feature or fix per PR
- Include a description of what changed and why
- Link related issues
- Ensure all CI checks pass before requesting review

## Architecture

seclens follows a Domain-Driven Design (DDD) architecture:

```
src/seclens/
├── domain/       # Core business logic (models, scoring, events)
├── ports/        # Abstract interfaces (repositories, fetchers)
├── adapters/     # Concrete implementations (SQLite, NVD, GitHub)
├── application/  # Service orchestration
├── api/          # FastAPI routes and schemas
└── observability/  # Metrics and probes
```

When adding new data sources:
1. Define the port interface in `ports/`
2. Implement the adapter in `adapters/`
3. Wire it up in `api/dependencies.py`

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
