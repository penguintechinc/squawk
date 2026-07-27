# Makefile for Squawk DNS System
.PHONY: help setup test test-unit test-integration test-security test-performance clean build run stop logs shell fix-lint install-hooks smoke-test test-e2e test-functional

# NOTE: no root-level venv/ is created by this Makefile (setup-venv only
# creates dns-server/venv and squawk-client/venv) -- these resolve via PATH so
# targets work with whatever interpreter/tools are active (system, pyenv, or
# a manually activated venv), instead of pointing at a venv/ that never exists.
PYTHON := python3
PIP := pip3
PYTEST := pytest
FLAKE8 := flake8
BLACK := black
MYPY := mypy
BANDIT := bandit
SAFETY := safety

# Default target
help:
	@echo "Squawk DNS System - Available targets:"
	@echo ""
	@echo "Setup and Development:"
	@echo "  setup                 - Set up development environment"
	@echo "  setup-dev             - Set up development environment with all tools"
	@echo "  install               - Install dependencies"
	@echo "  install-dev           - Install development dependencies"
	@echo "  install-hooks         - Install git pre-commit hooks"
	@echo ""
	@echo "Testing:"
	@echo "  smoke-test            - Run fast smoke tests (pre-commit)"
	@echo "  test-unit             - Run unit tests"
	@echo "  test-integration      - Run integration tests"
	@echo "  test-e2e              - Run end-to-end tests"
	@echo "  test                  - Run all tests (unit + integration)"
	@echo "  test-security         - Run security scans"
	@echo "  test-performance      - Run performance tests"
	@echo "  test-coverage         - Run tests with coverage report"
	@echo ""
	@echo "Code Quality:"
	@echo "  lint                  - Run linting (flake8, black, isort)"
	@echo "  fix-lint              - Fix linting errors (black, isort)"
	@echo "  format                - Format code (black)"
	@echo "  type-check            - Run type checking (mypy)"
	@echo "  security-check        - Run security checks"
	@echo "  quality-check         - Run all quality checks"
	@echo ""
	@echo "Docker:"
	@echo "  build                 - Build Docker images"
	@echo "  run                   - Start services with Docker Compose"
	@echo "  stop                  - Stop all services"
	@echo "  logs                  - View service logs"
	@echo ""

# Setup targets
setup: setup-venv install
	@echo "Development environment setup complete!"

setup-dev: setup-venv install-dev setup-pre-commit
	@echo "Full development environment setup complete!"

setup-venv:
	@echo "Setting up virtual environments..."
	cd dns-server && python3 -m venv venv
	cd squawk-client && python3 -m venv venv

install:
	@echo "Installing production dependencies..."
	cd dns-server && $(PIP) install -r requirements.txt
	cd squawk-client && $(PIP) install -r requirements.txt

install-dev:
	@echo "Installing development dependencies..."
	cd dns-server && $(PIP) install -r requirements.txt -r requirements-dev.txt
	cd squawk-client && $(PIP) install -r requirements.txt -r requirements-dev.txt

setup-pre-commit: install-hooks

install-hooks:
	@echo "Installing pre-commit hooks..."
	@if command -v pre-commit >/dev/null 2>&1; then \
		pre-commit install && pre-commit install --hook-type pre-push; \
	else \
		echo "pre-commit not found. Install with: pip install pre-commit"; \
		exit 1; \
	fi

# Testing targets
test: test-unit test-integration

# Each service's tests/ package is literally named "tests" with its own
# __init__.py, so combining any two of them in a single pytest invocation
# trips the same conftest/module-name collision as mypy's "Duplicate module
# named app" (see type-check below) -- pytest registers both as the plugin
# "tests.conftest" and errors. Run each service as its own invocation.
test-unit:
	@echo "Running unit tests..."
	python3 -m pytest tests/unit/ -v --tb=short
	python3 -m pytest dns-server/tests/ -v --tb=short
	python3 -m pytest squawk-client/tests/ -v --tb=short
	python3 -m pytest manager/backend/tests/ -v --tb=short
	python3 -m pytest dhcp-server/tests/ -v --tb=short
	python3 -m pytest ntp-server/tests/ -v --tb=short

test-integration:
	@echo "Running integration tests..."
	python3 -m pytest tests/integration/ -v --tb=short

test-performance:
	@echo "Running performance tests..."
	cd dns-server && $(PYTHON) -m pytest tests/ -m "performance" -v

# Run + accumulate coverage per service (see test-unit note on why these
# can't be combined into one pytest invocation), then report against the
# combined data file so the 90% threshold applies across all services.
test-coverage:
	@echo "Running tests with coverage (90% house threshold)..."
	rm -f .coverage
	$(PYTHON) -m pytest dns-server/tests --cov=dns-server/app --cov-append -q
	$(PYTHON) -m pytest squawk-client/tests --cov=squawk-client/bins --cov-append -q
	$(PYTHON) -m pytest manager/backend/tests --cov=manager/backend/app --cov-append -q
	$(PYTHON) -m pytest dhcp-server/tests --cov=dhcp-server/app --cov-append -q
	$(PYTHON) -m pytest ntp-server/tests --cov=ntp-server/bins --cov-append -q
	$(PYTHON) -m coverage html -d htmlcov
	$(PYTHON) -m coverage xml -o coverage.xml
	$(PYTHON) -m coverage report -m --fail-under=90

# Code quality targets
lint:
	@echo "=== Linting ==="
	@exit_code=0; \
	if command -v flake8 >/dev/null 2>&1; then \
		echo "-- flake8 --"; \
		python3 -m flake8 dns-server/app manager/backend/app squawk-client/bins dhcp-server/app ntp-server/bins --config=.flake8 || exit_code=1; \
	else \
		echo "flake8 not installed, skipping"; \
	fi; \
	if command -v black >/dev/null 2>&1; then \
		echo "-- black (check) --"; \
		black --check dns-server/app manager/backend/app squawk-client/bins dhcp-server/app ntp-server/bins --line-length=120 || true; \
	else \
		echo "black not installed, skipping"; \
	fi; \
	if command -v isort >/dev/null 2>&1; then \
		echo "-- isort (check, advisory) --"; \
		isort --check-only dns-server/app manager/backend/app squawk-client/bins dhcp-server/app ntp-server/bins --profile=black --line-length=120 2>&1 || true; \
	else \
		echo "isort not installed, skipping"; \
	fi; \
	if command -v golangci-lint >/dev/null 2>&1; then \
		echo "-- golangci-lint (advisory) --"; \
		cd squawk-client-go && golangci-lint run --config=../.golangci.yml 2>&1 || true; cd ..; \
	else \
		echo "golangci-lint not installed, skipping"; \
	fi; \
	if command -v hadolint >/dev/null 2>&1; then \
		echo "-- hadolint --"; \
		find . -name "Dockerfile*" -not -path "*/.git/*" -not -path "*/venv/*" | xargs hadolint || exit_code=1; \
	else \
		echo "hadolint not installed, skipping"; \
	fi; \
	if command -v shellcheck >/dev/null 2>&1; then \
		echo "-- shellcheck (advisory) --"; \
		find . -name "*.sh" -not -path "*/.git/*" -not -path "*/venv/*" | xargs shellcheck || true; \
	else \
		echo "shellcheck not installed, skipping"; \
	fi; \
	exit $$exit_code

fix-lint: format

format:
	@echo "Formatting code..."
	cd dns-server && $(BLACK) app/ tests/
	cd squawk-client && $(BLACK) bins/ tests/
	cd manager/backend && $(BLACK) app/ tests/ --line-length=120
	cd dhcp-server && $(BLACK) app/ tests/ --line-length=120
	cd ntp-server && $(BLACK) bins/ tests/ --line-length=120

# Run per-service (`cd <service> && mypy <dir>/`), never all at once --
# dns-server/app, manager/backend/app, and dhcp-server/app are each their own
# top-level "app" package, so a single combined invocation trips mypy's
# "Duplicate module named app" check. See [tool.mypy] in pyproject.toml.
type-check:
	@echo "Running type checks..."
	cd dns-server && $(MYPY) app/
	cd manager/backend && $(MYPY) app/
	cd dhcp-server && $(MYPY) app/
	cd ntp-server && $(MYPY) bins/
	cd squawk-client && $(MYPY) bins/

test-security:
	@echo "=== Security Scans ==="
	@exit_code=0; \
	if command -v bandit >/dev/null 2>&1; then \
		echo "-- bandit --"; \
		bandit -r dns-server/app manager/backend/app squawk-client/bins dhcp-server/app ntp-server/bins -ll -q || exit_code=1; \
	else \
		echo "bandit not installed, skipping"; \
	fi; \
	if command -v pip-audit >/dev/null 2>&1; then \
		echo "-- pip-audit --"; \
		find . -name "requirements.txt" -not -path "*/.git/*" -not -path "*/venv/*" | xargs -I{} pip-audit -r {} || exit_code=1; \
	else \
		echo "pip-audit not installed, skipping"; \
	fi; \
	if command -v gosec >/dev/null 2>&1; then \
		echo "-- gosec --"; \
		cd squawk-client-go && gosec ./... || exit_code=1; cd ..; \
	else \
		echo "gosec not installed, skipping"; \
	fi; \
	if command -v govulncheck >/dev/null 2>&1; then \
		echo "-- govulncheck --"; \
		cd squawk-client-go && govulncheck ./... || exit_code=1; cd ..; \
	else \
		echo "govulncheck not installed, skipping"; \
	fi; \
	if command -v gitleaks >/dev/null 2>&1; then \
		echo "-- gitleaks --"; \
		gitleaks detect --source . --no-git -v || exit_code=1; \
	else \
		echo "gitleaks not installed, skipping"; \
	fi; \
	exit $$exit_code

security-check: test-security
	@echo "All security checks completed!"

quality-check: lint format type-check security-check
	@echo "All quality checks completed!"

# Docker targets
build:
	@echo "Building Docker images..."
	docker-compose build

run:
	@echo "Starting Squawk DNS services..."
	docker-compose up -d

stop:
	@echo "Stopping all services..."
	docker-compose down

logs:
	@echo "Following service logs..."
	docker-compose logs -f

clean:
	@echo "Cleaning up generated files..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type f -name ".coverage" -delete
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "coverage.xml" -delete

dev:
	@echo "Starting development environment..."
	@$(MAKE) docker-build && docker-compose up

smoke-test:
	@echo "Running smoke tests..."
	python3 -m pytest tests/smoke/ -v --tb=short -m "not slow"

test-e2e:
	@echo "Running end-to-end tests (Playwright, tests/e2e)..."
	npm run test:e2e; \
	status=$$?; \
	npm run test:e2e:cleanup >/dev/null 2>&1 || true; \
	exit $$status

test-functional:
	@echo "Running functional tests..."
	python3 -m pytest tests/ -v --tb=short -k "functional"

docker-build:
	@echo "Building Docker images..."
	docker-compose build

docker-push:
	@echo "Pushing Docker images..."
	docker-compose push

deploy-dev:
	@echo "Set up dev deployment"

deploy-prod:
	@echo "Set up prod deployment"

seed-mock-data:
	@echo "No mock data seeding defined"

pre-commit: lint test-security test
	@echo "=== Pre-commit complete ==="
