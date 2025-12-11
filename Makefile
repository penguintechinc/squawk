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
	cd dns-server && $(PYTHON) -m pytest tests/ --cov=bins --cov-report=html --cov-report=term-missing

# Code quality targets
lint:
	@echo "Running linting..."
	cd dns-server && $(FLAKE8) bins/ tests/
	cd dns-client && $(FLAKE8) bins/ tests/

fix-lint: format

format:
	@echo "Formatting code..."
	cd dns-server && $(BLACK) bins/ tests/
	cd dns-client && $(BLACK) bins/ tests/

type-check:
	@echo "Running type checks..."
	cd dns-server && $(MYPY) bins/
	cd dns-client && $(MYPY) bins/

security-check:
	@echo "Running security checks..."
	cd dns-server && \
		$(BANDIT) -r bins/ -f json -o bandit-report.json || true && \
		$(SAFETY) check --output json > safety-report.json || true

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