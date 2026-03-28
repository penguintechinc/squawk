# Makefile for Squawk DNS System
.PHONY: help setup test test-unit test-integration test-security test-performance clean build run stop logs shell fix-lint

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
	@echo ""
	@echo "Testing:"
	@echo "  test                  - Run all tests"
	@echo "  test-unit             - Run unit tests only"
	@echo "  test-integration      - Run integration tests"
	@echo "  test-security         - Run security tests"
	@echo "  test-performance      - Run performance tests"
	@echo "  test-coverage         - Run tests with coverage report"
	@echo ""
	@echo "Code Quality:"
	@echo "  lint                  - Run linting (flake8)"
	@echo "  fix-lint              - Fix linting errors (black)"
	@echo "  format                - Format code (black)"
	@echo "  type-check            - Run type checking (mypy)"
	@echo "  security-check        - Run security checks (bandit, safety)"
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
	cd dns-client && python3 -m venv venv

install:
	@echo "Installing production dependencies..."
	cd dns-server && $(PIP) install -r requirements.txt
	cd dns-client && $(PIP) install -r requirements.txt

install-dev:
	@echo "Installing development dependencies..."
	cd dns-server && $(PIP) install -r requirements.txt -r requirements-dev.txt
	cd dns-client && $(PIP) install -r requirements.txt -r requirements-dev.txt

setup-pre-commit:
	@echo "Setting up pre-commit hooks..."
	cd dns-server && venv/bin/pre-commit install

# Testing targets
test: test-unit test-integration

test-unit:
	@echo "Running unit tests..."
	cd dns-server && $(PYTHON) -m pytest tests/ --ignore=tests/integration/ -v

test-integration:
	@echo "Running integration tests..."
	cd dns-server && $(PYTHON) -m pytest tests/integration/ -v

test-security:
	@echo "Running security tests..."
	cd dns-server && $(PYTHON) -m pytest tests/ -m "security" -v

test-performance:
	@echo "Running performance tests..."
	cd dns-server && $(PYTHON) -m pytest tests/ -m "performance" -v

test-coverage:
	@echo "Running tests with coverage..."
	$(PYTHON) -m pytest dns-server/tests dns-client/tests dns-server/flask_app/tests \
		--cov=dns-server/bins --cov=dns-client/bins --cov=dns-server/flask_app \
		--cov-report=html:htmlcov --cov-report=term-missing --cov-report=xml:coverage.xml \
		--cov-fail-under=98

# Code quality targets
lint:
	@echo "=== Linting ==="
	@if command -v flake8 >/dev/null 2>&1; then echo "-- flake8 --"; python3 -m flake8 . --max-line-length=120 --exclude=.git,__pycache__,venv,node_modules || true; fi
	@if command -v black >/dev/null 2>&1; then echo "-- black --"; black --check . --exclude '/(\.git|venv|__pycache__|node_modules)/' || true; fi
	@if command -v isort >/dev/null 2>&1; then echo "-- isort --"; isort --check-only . || true; fi
	@if command -v mypy >/dev/null 2>&1; then echo "-- mypy --"; python3 -m mypy . --ignore-missing-imports || true; fi
	@if command -v golangci-lint >/dev/null 2>&1; then echo "-- golangci-lint --"; find . -name "go.mod" -not -path "*/.git/*" -not -path "*/vendor/*" | xargs -I{} dirname {} | xargs -I{} sh -c 'cd {} && golangci-lint run || true'; fi
	@if command -v hadolint >/dev/null 2>&1; then echo "-- hadolint --"; find . -name "Dockerfile*" -not -path "*/.git/*" | xargs hadolint || true; fi
	@if command -v shellcheck >/dev/null 2>&1; then echo "-- shellcheck --"; find . -name "*.sh" -not -path "*/.git/*" | xargs shellcheck || true; fi

fix-lint: format

format:
	@echo "Formatting code..."
	cd dns-server && $(BLACK) bins/ tests/
	cd dns-client && $(BLACK) bins/ tests/

type-check:
	@echo "Running type checks..."
	cd dns-server && $(MYPY) bins/
	cd dns-client && $(MYPY) bins/

test-security:
	@echo "=== Security Scans ==="
	@if command -v bandit >/dev/null 2>&1; then echo "-- bandit --"; bandit -r . -x ./tests,./venv,./.git --quiet || true; fi
	@if command -v pip-audit >/dev/null 2>&1; then echo "-- pip-audit --"; find . -name "requirements.txt" -not -path "*/.git/*" -not -path "*/venv/*" | xargs -I{} pip-audit -r {} 2>/dev/null || true; fi
	@if command -v gosec >/dev/null 2>&1; then echo "-- gosec --"; find . -name "go.mod" -not -path "*/.git/*" -not -path "*/vendor/*" | xargs -I{} dirname {} | xargs -I{} sh -c 'cd {} && gosec ./... || true'; fi
	@if command -v govulncheck >/dev/null 2>&1; then echo "-- govulncheck --"; find . -name "go.mod" -not -path "*/.git/*" -not -path "*/vendor/*" | xargs -I{} dirname {} | xargs -I{} sh -c 'cd {} && govulncheck ./... || true'; fi
	@find . -name "package.json" -not -path "*/.git/*" -not -path "*/node_modules/*" -maxdepth 3 | xargs -I{} dirname {} | xargs -I{} sh -c 'cd {} && npm audit 2>/dev/null || true'
	@if command -v gitleaks >/dev/null 2>&1; then echo "-- gitleaks --"; gitleaks detect --source . --no-git 2>/dev/null || true; fi

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

test-functional:
	@echo "No functional tests defined"

test-e2e:
	@echo "No e2e tests defined"

smoke-test:
	@echo "No smoke tests defined"

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