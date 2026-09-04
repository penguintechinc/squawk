# Squawk DNS Test Suite Makefile
# Usage: make <target>

.PHONY: all install smoke smoke-alpha smoke-beta unit integration load clean help

# Default target
all: smoke-alpha

# Install test dependencies
install:
	@echo "Installing test dependencies..."
	pip install -r requirements.txt

# Run all smoke tests
smoke:
	@echo "Running smoke tests..."
	pytest smoke/ -v --tb=short

# Run smoke tests - quick mode (health checks only)
smoke-quick:
	@echo "Running quick smoke tests (health checks only)..."
	pytest smoke/test_container_health.py -v --tb=short

# Run smoke tests - pages only
smoke-pages:
	@echo "Running page load smoke tests..."
	pytest smoke/test_web_console_pages.py -v --tb=short

# Run smoke tests - APIs only
smoke-api:
	@echo "Running API smoke tests..."
	pytest smoke/test_web_console_api.py smoke/test_dns_server_api.py smoke/test_manager_api.py -v --tb=short

# Run smoke tests - auth only
smoke-auth:
	@echo "Running authentication smoke tests..."
	pytest smoke/test_authentication.py -v --tb=short

# ============================================================================
# Alpha (Local Development) Tests - Full Gambit
# ============================================================================
smoke-alpha:
	@echo "Running Alpha (Local) smoke tests - full gambit..."
	./smoke/alpha/run_alpha.sh

alpha: smoke-alpha

# Alpha without script - direct pytest
smoke-alpha-direct:
	@echo "Running Alpha tests directly..."
	ALPHA_DNS_SERVER_URL=http://localhost:8080 \
	ALPHA_WEB_CONSOLE_URL=http://localhost:8005 \
	pytest smoke/alpha/ smoke/test_container_health.py smoke/test_web_console_pages.py \
		smoke/test_web_console_api.py smoke/test_dns_server_api.py smoke/test_authentication.py \
		-v --tb=short

# ============================================================================
# Beta (dal2.penguintech.io K8s) Tests - Post-Deployment Verification
# ============================================================================
smoke-beta:
	@echo "Running Beta (K8s) smoke tests - deployment verification..."
	./smoke/beta/run_beta.sh

beta: smoke-beta

# Beta without script - direct pytest
smoke-beta-direct:
	@echo "Running Beta tests directly..."
	pytest smoke/beta/ -v --tb=short

# ============================================================================
# Combined Environment Tests
# ============================================================================
smoke-all-envs: smoke-alpha smoke-beta
	@echo "All environment tests completed."

# Run all unit tests
unit:
	@echo "Running unit tests..."
	pytest unit/ -v --tb=short

# Run unit tests with coverage
unit-cov:
	@echo "Running unit tests with coverage..."
	pytest unit/ -v --tb=short --cov=../dns-server --cov-report=html

# Run all integration tests
integration:
	@echo "Running integration tests..."
	pytest integration/ -v --tb=short

# Run integration tests - DNS only
integration-dns:
	@echo "Running DNS integration tests..."
	pytest integration/test_dns_resolution.py -v --tb=short

# Run integration tests - Web console only
integration-web:
	@echo "Running web console integration tests..."
	pytest integration/test_web_console_integration.py -v --tb=short

# Run all load tests
load:
	@echo "Running load tests..."
	pytest load/ -v --tb=short -s

# Run load tests - quick mode
load-quick:
	@echo "Running quick load tests..."
	LOAD_CONCURRENT_USERS=5 LOAD_REQUESTS_PER_USER=20 pytest load/ -v --tb=short -s

# Run load tests - stress mode
load-stress:
	@echo "Running stress tests..."
	pytest load/ -v --tb=short -s -m stress

# Run all tests
test-all: smoke unit integration
	@echo "All tests completed."

# Run tests by marker
test-health:
	pytest -v --tb=short -m health

test-api:
	pytest -v --tb=short -m api

test-auth:
	pytest -v --tb=short -m auth

test-slow:
	pytest -v --tb=short -m slow

# Generate HTML report
report:
	@echo "Generating test report..."
	pytest smoke/ unit/ integration/ --html=reports/test_report.html --self-contained-html -v

# Clean up
clean:
	@echo "Cleaning up..."
	rm -rf __pycache__ .pytest_cache .coverage htmlcov reports/
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

# Show help
help:
	@echo "Squawk DNS Test Suite"
	@echo ""
	@echo "=========================================="
	@echo "Environment-Specific Tests:"
	@echo "=========================================="
	@echo "  make smoke-alpha   - Alpha (Local) - Full comprehensive tests"
	@echo "  make smoke-beta    - Beta (K8s) - Post-deployment verification"
	@echo "  make smoke-all-envs - Run both alpha and beta tests"
	@echo ""
	@echo "=========================================="
	@echo "General Smoke Tests:"
	@echo "=========================================="
	@echo "  make smoke         - Run all smoke tests"
	@echo "  make smoke-quick   - Quick smoke tests (health only)"
	@echo "  make smoke-pages   - Page load tests"
	@echo "  make smoke-api     - API tests"
	@echo "  make smoke-auth    - Authentication tests"
	@echo ""
	@echo "=========================================="
	@echo "Other Test Types:"
	@echo "=========================================="
	@echo "  make unit          - Unit tests"
	@echo "  make integration   - Integration tests"
	@echo "  make load          - Load tests"
	@echo "  make test-all      - All tests"
	@echo ""
	@echo "=========================================="
	@echo "Utilities:"
	@echo "=========================================="
	@echo "  make install       - Install test dependencies"
	@echo "  make report        - Generate HTML test report"
	@echo "  make clean         - Clean up test artifacts"
	@echo ""
	@echo "=========================================="
	@echo "Alpha Environment Variables (Local):"
	@echo "=========================================="
	@echo "  ALPHA_DNS_SERVER_URL   (default: http://localhost:8080)"
	@echo "  ALPHA_WEB_CONSOLE_URL  (default: http://localhost:8005)"
	@echo "  ALPHA_ADMIN_EMAIL      (default: admin@localhost)"
	@echo "  ALPHA_ADMIN_PASSWORD   (default: admin123)"
	@echo ""
	@echo "=========================================="
	@echo "Beta Environment Variables (K8s):"
	@echo "=========================================="
	@echo "  BETA_DNS_SERVER_URL    (default: https://dns.squawk.dal2.penguintech.io)"
	@echo "  BETA_WEB_CONSOLE_URL   (default: https://console.squawk.dal2.penguintech.io)"
	@echo "  BETA_ADMIN_EMAIL       (default: admin@penguintech.io)"
	@echo "  BETA_ADMIN_PASSWORD    (required - from K8s secret)"
	@echo "  BETA_VERIFY_SSL        (default: true)"
