#!/bin/bash
# Beta (penguintech.cloud K8s) Smoke Test Runner
# Runs post-deployment verification against K8s cluster
# Catches issues like: hardcoded localhost URLs, missing env vars, K8s networking issues

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}=========================================="
echo "Squawk DNS - Beta Smoke Tests"
echo "Environment: penguintech.cloud K8s Cluster"
echo -e "==========================================${NC}"
echo ""

# Default configuration for K8s cluster
export BETA_BASE_DOMAIN="${BETA_BASE_DOMAIN:-squawk.penguintech.cloud}"
export BETA_DNS_SERVER_URL="${BETA_DNS_SERVER_URL:-https://dns.squawk.penguintech.cloud}"
export BETA_WEB_CONSOLE_URL="${BETA_WEB_CONSOLE_URL:-https://console.squawk.penguintech.cloud}"
export BETA_MANAGER_URL="${BETA_MANAGER_URL:-https://api.squawk.penguintech.cloud}"
export BETA_ADMIN_EMAIL="${BETA_ADMIN_EMAIL:-admin@penguintech.io}"
export BETA_VERIFY_SSL="${BETA_VERIFY_SSL:-true}"

# Check for required credentials
if [ -z "$BETA_ADMIN_PASSWORD" ]; then
    echo -e "${YELLOW}WARNING: BETA_ADMIN_PASSWORD not set${NC}"
    echo "Set with: export BETA_ADMIN_PASSWORD=<password>"
    echo "Or from kubectl secret:"
    echo "  export BETA_ADMIN_PASSWORD=\$(kubectl get secret squawk-admin -n squawk -o jsonpath='{.data.password}' | base64 -d)"
    echo ""
fi

if [ -z "$BETA_MANAGER_PASS" ]; then
    echo -e "${YELLOW}WARNING: BETA_MANAGER_PASS not set${NC}"
fi

echo "Configuration:"
echo "  Base Domain:   $BETA_BASE_DOMAIN"
echo "  DNS Server:    $BETA_DNS_SERVER_URL"
echo "  Web Console:   $BETA_WEB_CONSOLE_URL"
echo "  Manager:       $BETA_MANAGER_URL"
echo "  Admin Email:   $BETA_ADMIN_EMAIL"
echo "  Verify SSL:    $BETA_VERIFY_SSL"
echo ""

# Test connectivity to K8s cluster
echo -e "${YELLOW}Checking K8s cluster connectivity...${NC}"

check_k8s_service() {
    local url=$1
    local name=$2
    local timeout=10

    # Use --insecure if SSL verification is disabled
    local curl_opts="--max-time $timeout"
    if [ "$BETA_VERIFY_SSL" != "true" ]; then
        curl_opts="$curl_opts --insecure"
    fi

    if curl -s $curl_opts "$url/health" > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} $name is accessible"
        return 0
    else
        echo -e "  ${RED}✗${NC} $name is not accessible at $url"
        return 1
    fi
}

SERVICES_OK=1
check_k8s_service "$BETA_DNS_SERVER_URL" "DNS Server" || SERVICES_OK=0
check_k8s_service "$BETA_WEB_CONSOLE_URL" "Web Console" || SERVICES_OK=0

if [ $SERVICES_OK -eq 0 ]; then
    echo ""
    echo -e "${RED}Some K8s services are not accessible!${NC}"
    echo ""
    echo "Common issues:"
    echo "  1. Services not deployed - check: kubectl get pods -n squawk"
    echo "  2. Ingress not configured - check: kubectl get ingress -n squawk"
    echo "  3. DNS not resolving - check: nslookup $BETA_BASE_DOMAIN"
    echo "  4. SSL certificate issues - try: export BETA_VERIFY_SSL=false"
    echo ""
    echo "Continuing with available services..."
fi

echo ""
echo -e "${CYAN}Running Beta Tests (Post-Deployment Verification)...${NC}"
echo ""
echo -e "${YELLOW}These tests catch deployment issues like:${NC}"
echo "  - Hardcoded localhost URLs"
echo "  - Missing environment variables"
echo "  - K8s networking/ingress issues"
echo "  - SSL certificate problems"
echo "  - Service discovery failures"
echo ""

cd "$TESTS_DIR"

# Run beta-specific tests
pytest smoke/beta/ \
    -v \
    --tb=short \
    2>&1

# Also run core smoke tests against beta environment
# (These use the BETA_ environment variables via the beta conftest.py)
echo ""
echo -e "${CYAN}Running Core Smoke Tests Against K8s...${NC}"

# Export beta URLs as default URLs for shared tests
export DNS_SERVER_URL="$BETA_DNS_SERVER_URL"
export WEB_CONSOLE_URL="$BETA_WEB_CONSOLE_URL"
export MANAGER_BACKEND_URL="$BETA_MANAGER_URL"
export TEST_ADMIN_EMAIL="$BETA_ADMIN_EMAIL"
export TEST_ADMIN_PASSWORD="$BETA_ADMIN_PASSWORD"

pytest smoke/test_container_health.py \
    smoke/test_web_console_pages.py::TestPublicPages \
    -v \
    --tb=short \
    2>&1 || true

# Summary
echo ""
echo -e "${CYAN}=========================================="
echo "Beta Smoke Tests Complete"
echo -e "==========================================${NC}"
echo ""
echo "If tests failed, common K8s deployment issues to check:"
echo "  1. Pod logs: kubectl logs -n squawk deployment/squawk-dns-server"
echo "  2. Pod status: kubectl get pods -n squawk"
echo "  3. Service endpoints: kubectl get endpoints -n squawk"
echo "  4. Ingress status: kubectl describe ingress -n squawk"
echo "  5. Config maps: kubectl get configmap -n squawk"
