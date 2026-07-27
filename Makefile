# Makefile for Squawk DNS System
.PHONY: help setup test test-unit test-integration test-security test-performance clean build run stop logs shell fix-lint install-hooks smoke-test test-e2e test-functional

PYTHON := venv/bin/python3
PIP := venv/bin/pip3
PYTEST := venv/bin/pytest
FLAKE8 := venv/bin/flake8
BLACK := venv/bin/black
MYPY := venv/bin/mypy
BANDIT := venv/bin/bandit
SAFETY := venv/bin/safety

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

test-unit:
	@echo "Running unit tests..."
	python3 -m pytest tests/unit/ dns-server/tests/ squawk-client/tests/ manager/backend/tests/ \
		-v --tb=short

test-integration:
	@echo "Running integration tests..."
	python3 -m pytest tests/integration/ -v --tb=short

test-performance:
	@echo "Running performance tests..."
	cd dns-server && $(PYTHON) -m pytest tests/ -m "performance" -v

test-coverage:
	@echo "Running tests with coverage..."
	$(PYTHON) -m pytest dns-server/tests squawk-client/tests \
		--cov=dns-server/app --cov=squawk-client/bins \
		--cov-report=html:htmlcov --cov-report=term-missing --cov-report=xml:coverage.xml \
		--cov-fail-under=98

# Code quality targets
lint:
	@echo "=== Linting ==="
	@exit_code=0; \
	if command -v flake8 >/dev/null 2>&1; then \
		echo "-- flake8 --"; \
		python3 -m flake8 dns-server/app manager/backend/app squawk-client/bins --config=.flake8 || exit_code=1; \
	else \
		echo "flake8 not installed, skipping"; \
	fi; \
	if command -v black >/dev/null 2>&1; then \
		echo "-- black (check) --"; \
		black --check dns-server/app manager/backend/app squawk-client/bins --line-length=120 || true; \
	else \
		echo "black not installed, skipping"; \
	fi; \
	if command -v isort >/dev/null 2>&1; then \
		echo "-- isort (check, advisory) --"; \
		isort --check-only dns-server/app manager/backend/app squawk-client/bins --profile=black --line-length=120 2>&1 || true; \
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
	if command -v npx >/dev/null 2>&1; then \
		echo "-- spectral (OpenAPI) --"; \
		npx --yes @stoplight/spectral-cli@6.16.0 lint openapi/v1.yaml || exit_code=1; \
	else \
		echo "npx not installed, skipping OpenAPI linting"; \
	fi; \
	exit $$exit_code

fix-lint: format

format:
	@echo "Formatting code..."
	cd dns-server && $(BLACK) app/ tests/
	cd squawk-client && $(BLACK) bins/ tests/

type-check:
	@echo "Running type checks..."
	cd dns-server && $(MYPY) app/
	cd squawk-client && $(MYPY) bins/

test-security:
	@echo "=== Security Scans ==="
	@exit_code=0; \
	if command -v bandit >/dev/null 2>&1; then \
		echo "-- bandit --"; \
		bandit -r dns-server/app manager/backend/app squawk-client/bins -ll -q || exit_code=1; \
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
	@echo "Running end-to-end tests..."
	python3 -m pytest tests/integration/ tests/load/ -v --tb=short

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