.PHONY: all install dev sync serve test lint format clean \
       openapi openapi-check \
       docker-build docker-run docker-stop docker-logs \
       audit sbom lock pre-commit

# ── All ──────────────────────────────────────────────────────
all: lint test openapi-check
	@echo "All checks passed. Run 'make audit' separately to check for dependency vulnerabilities."

# ── Development ──────────────────────────────────────────────
install:
	pip install -e .

dev:
	pip install -e ".[dev]"
	pre-commit install

sync:
	python -m seclens.main sync

serve:
	python -m seclens.main serve

test:
	pytest -v

lint:
	ruff check src/ tests/
	ruff format --check src/ tests/

format:
	ruff format src/ tests/

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .coverage htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} +

# ── OpenAPI ───────────────────────────────────────────────────
openapi:
	python scripts/generate_openapi.py

openapi-check:
	python scripts/generate_openapi.py --check

# ── Docker ───────────────────────────────────────────────────
IMAGE_NAME ?= seclens
IMAGE_TAG  ?= latest

docker-build:
	docker build -f Containerfile -t $(IMAGE_NAME):$(IMAGE_TAG) .

docker-run:
	docker compose up -d

docker-stop:
	docker compose down

docker-logs:
	docker compose logs -f

# ── Security ─────────────────────────────────────────────────
audit:
	pip-audit --desc --skip-editable

sbom:
	cyclonedx-py environment -o sbom.cdx.json --of json
	@echo "SBOM written to sbom.cdx.json"

lock:
	pip freeze --exclude-editable | sort > requirements.lock
	@echo "requirements.lock updated"

pre-commit:
	pre-commit run --all-files
