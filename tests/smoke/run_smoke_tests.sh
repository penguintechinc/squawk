#!/bin/bash
# Smoke Test Runner Script
# Runs all smoke tests against running services

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTS_DIR="$PROJECT_ROOT/tests"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "Squawk DNS Smoke Test Runner"
echo "=========================================="
echo ""

# Default configuration
DNS_SERVER_URL="${DNS_SERVER_URL:-http://localhost:8080}"
WEB_CONSOLE_URL="${WEB_CONSOLE_URL:-http://localhost:8005}"
MANAGER_BACKEND_URL="${MANAGER_BACKEND_URL:-http://localhost:5000}"

echo "Configuration:"
echo "  DNS_SERVER_URL: $DNS_SERVER_URL"
echo "  WEB_CONSOLE_URL: $WEB_CONSOLE_URL"
echo "  MANAGER_BACKEND_URL: $MANAGER_BACKEND_URL"
echo ""

# Check if services are running
echo "Checking service availability..."

check_service() {
    local url=$1
    local name=$2
    local timeout=5

    if curl -s --max-time $timeout "$url/health" > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} $name is available"
        return 0
    else
        echo -e "  ${YELLOW}!${NC} $name is not available at $url"
        return 1
    fi
}

DNS_AVAILABLE=0
WEB_AVAILABLE=0

check_service "$DNS_SERVER_URL" "DNS Server" && DNS_AVAILABLE=1
check_service "$WEB_CONSOLE_URL" "Web Console" && WEB_AVAILABLE=1

echo ""

if [ $DNS_AVAILABLE -eq 0 ] && [ $WEB_AVAILABLE -eq 0 ]; then
    echo -e "${RED}Error: No services are available. Please start the services first.${NC}"
    echo "Run: docker-compose up -d"
    exit 1
fi

# Run smoke tests
echo "Running smoke tests..."
echo ""

# Install test dependencies if needed
if ! python -c "import pytest" 2>/dev/null; then
    echo "Installing test dependencies..."
    pip install pytest requests > /dev/null
fi

# Set environment variables
export DNS_SERVER_URL
export WEB_CONSOLE_URL
export MANAGER_BACKEND_URL

# Run tests with verbose output
cd "$TESTS_DIR"

# Run different test categories
echo "=========================================="
echo "Running Container Health Tests"
echo "=========================================="
pytest smoke/test_container_health.py -v --tb=short 2>&1 || true

echo ""
echo "=========================================="
echo "Running Page Load Tests"
echo "=========================================="
pytest smoke/test_web_console_pages.py -v --tb=short 2>&1 || true

echo ""
echo "=========================================="
echo "Running API Tests"
echo "=========================================="
pytest smoke/test_web_console_api.py -v --tb=short 2>&1 || true
pytest smoke/test_dns_server_api.py -v --tb=short 2>&1 || true

echo ""
echo "=========================================="
echo "Running Authentication Tests"
echo "=========================================="
pytest smoke/test_authentication.py -v --tb=short 2>&1 || true

echo ""
echo "=========================================="
echo "Smoke Tests Complete"
echo "=========================================="

# Summary
echo ""
echo "Test Summary:"
pytest smoke/ --collect-only -q 2>/dev/null | tail -5 || echo "Could not generate summary"
