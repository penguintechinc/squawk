#!/bin/bash
# Alpha (Local Development) Smoke Test Runner
# Runs full comprehensive tests against local Docker Compose environment

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
PROJECT_ROOT="$(cd "$TESTS_DIR/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=========================================="
echo "Squawk DNS - Alpha Smoke Tests"
echo "Environment: Local Development"
echo -e "==========================================${NC}"
echo ""

# Default configuration for local environment
export ALPHA_DNS_SERVER_URL="${ALPHA_DNS_SERVER_URL:-http://localhost:8080}"
export ALPHA_WEB_CONSOLE_URL="${ALPHA_WEB_CONSOLE_URL:-http://localhost:8005}"
export ALPHA_MANAGER_URL="${ALPHA_MANAGER_URL:-http://localhost:5000}"
export ALPHA_ADMIN_EMAIL="${ALPHA_ADMIN_EMAIL:-admin@localhost}"
export ALPHA_ADMIN_PASSWORD="${ALPHA_ADMIN_PASSWORD:-admin123}"
export ALPHA_MANAGER_USER="${ALPHA_MANAGER_USER:-admin}"
export ALPHA_MANAGER_PASS="${ALPHA_MANAGER_PASS:-admin123}"

echo "Configuration:"
echo "  DNS Server:    $ALPHA_DNS_SERVER_URL"
echo "  Web Console:   $ALPHA_WEB_CONSOLE_URL"
echo "  Manager:       $ALPHA_MANAGER_URL"
echo "  Admin Email:   $ALPHA_ADMIN_EMAIL"
echo ""

# Check if services are running locally
echo -e "${YELLOW}Checking local services...${NC}"

check_service() {
    local url=$1
    local name=$2
    if curl -s --max-time 5 "$url/health" > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} $name is running"
        return 0
    else
        echo -e "  ${RED}✗${NC} $name is not running at $url"
        return 1
    fi
}

SERVICES_OK=1
check_service "$ALPHA_DNS_SERVER_URL" "DNS Server" || SERVICES_OK=0
check_service "$ALPHA_WEB_CONSOLE_URL" "Web Console" || SERVICES_OK=0

if [ $SERVICES_OK -eq 0 ]; then
    echo ""
    echo -e "${YELLOW}Some services are not running. Start them with:${NC}"
    echo "  cd $PROJECT_ROOT && docker-compose up -d"
    echo ""
    echo "Continuing with available services..."
fi

echo ""
echo -e "${BLUE}Running Alpha Tests (Full Gambit)...${NC}"
echo ""

cd "$TESTS_DIR"

# Run all alpha tests
pytest smoke/alpha/ \
    smoke/test_container_health.py \
    smoke/test_web_console_pages.py \
    smoke/test_web_console_api.py \
    smoke/test_dns_server_api.py \
    smoke/test_authentication.py \
    -v \
    --tb=short \
    -m "not slow" \
    2>&1

# Also run unit tests
echo ""
echo -e "${BLUE}Running Unit Tests...${NC}"
pytest unit/ -v --tb=short 2>&1 || true

# Summary
echo ""
echo -e "${BLUE}=========================================="
echo "Alpha Smoke Tests Complete"
echo -e "==========================================${NC}"
