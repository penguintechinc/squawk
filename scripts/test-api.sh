#!/bin/bash
#
# Comprehensive API Test Script for Squawk DNS
# Tests all API endpoints across all containers
#

# Don't exit on errors - we want to run all tests
set +e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DNS_SERVER_URL="${DNS_SERVER_URL:-http://localhost:8080}"
WEB_CONSOLE_URL="${WEB_CONSOLE_URL:-http://localhost:8005}"
DNS_CLIENT_PORT="${DNS_CLIENT_PORT:-5353}"
VALKEY_PORT="${VALKEY_PORT:-6380}"

# Test counters
PASSED=0
FAILED=0
SKIPPED=0

# Cookie file for authenticated requests
COOKIE_FILE="/tmp/squawk-test-cookies.txt"

# Logging
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    PASSED=$((PASSED + 1))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    FAILED=$((FAILED + 1))
}

log_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1"
    SKIPPED=$((SKIPPED + 1))
}

log_header() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

# Test a HTTP endpoint
test_endpoint() {
    local name="$1"
    local method="$2"
    local url="$3"
    local expected_code="$4"
    local data="$5"
    local use_cookies="$6"

    local curl_opts="-s -o /tmp/response.txt -w %{http_code} --max-time 10"

    if [ "$use_cookies" = "true" ]; then
        curl_opts="$curl_opts -c $COOKIE_FILE -b $COOKIE_FILE"
    fi

    if [ "$method" = "POST" ] && [ -n "$data" ]; then
        curl_opts="$curl_opts -X POST -d '$data'"
        response_code=$(eval curl $curl_opts "'$url'" 2>/dev/null || echo "000")
    elif [ "$method" = "POST" ]; then
        curl_opts="$curl_opts -X POST"
        response_code=$(eval curl $curl_opts "'$url'" 2>/dev/null || echo "000")
    else
        response_code=$(eval curl $curl_opts "'$url'" 2>/dev/null || echo "000")
    fi

    if [ "$response_code" = "$expected_code" ]; then
        log_success "$name (HTTP $response_code)"
        return 0
    else
        log_fail "$name (Expected: $expected_code, Got: $response_code)"
        return 1
    fi
}

# ============================================================================
# DNS Server API Tests
# ============================================================================
test_dns_server() {
    log_header "DNS Server API Tests ($DNS_SERVER_URL)"

    # Health check
    test_endpoint "Health Check" "GET" "$DNS_SERVER_URL/health" "200"

    # DNS query - GET method
    test_endpoint "DNS Query (GET)" "GET" "$DNS_SERVER_URL/dns-query?name=google.com&type=A" "200"

    # DNS query - POST method with JSON
    response=$(curl -s -X POST "$DNS_SERVER_URL/resolve" \
        -H "Content-Type: application/json" \
        -d '{"name":"google.com","type":"A"}' \
        -w "\n%{http_code}")
    code=$(echo "$response" | tail -1)
    if [ "$code" = "200" ]; then
        log_success "DNS Query (POST JSON) (HTTP $code)"
    else
        log_fail "DNS Query (POST JSON) (Expected: 200, Got: $code)"
    fi

    # DNS over HTTPS standard format
    test_endpoint "DNS-over-HTTPS Standard" "GET" "$DNS_SERVER_URL/dns-query?dns=AAABAAABAAAAAAAAB2dvb2dsZQNjb20AAAEAAQ" "200"

    # Metrics endpoint (if available)
    response_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$DNS_SERVER_URL/metrics" 2>/dev/null || echo "000")
    if [ "$response_code" = "200" ]; then
        log_success "Prometheus Metrics (HTTP $response_code)"
    else
        log_skip "Prometheus Metrics (not enabled)"
    fi

    # SAML SSO endpoint (enterprise feature)
    response_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$DNS_SERVER_URL/api/saml/sso" 2>/dev/null || echo "000")
    if [ "$response_code" = "403" ] || [ "$response_code" = "400" ]; then
        log_success "SAML SSO Endpoint (HTTP $response_code - enterprise feature protected)"
    elif [ "$response_code" = "404" ] || [ "$response_code" = "000" ]; then
        log_skip "SAML SSO Endpoint (not available)"
    else
        log_fail "SAML SSO Endpoint (Unexpected: $response_code)"
    fi

    # SCIM endpoint (enterprise feature)
    response_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$DNS_SERVER_URL/api/scim/v2/Users" 2>/dev/null || echo "000")
    if [ "$response_code" = "403" ]; then
        log_success "SCIM Users Endpoint (HTTP $response_code - enterprise feature protected)"
    elif [ "$response_code" = "404" ] || [ "$response_code" = "000" ]; then
        log_skip "SCIM Users Endpoint (not available)"
    else
        log_fail "SCIM Users Endpoint (Unexpected: $response_code)"
    fi
}

# ============================================================================
# Web Console API Tests
# ============================================================================
test_web_console() {
    log_header "Web Console API Tests ($WEB_CONSOLE_URL)"

    # Clear cookies
    rm -f "$COOKIE_FILE"

    # Health check
    test_endpoint "Health Check" "GET" "$WEB_CONSOLE_URL/health" "200"

    # Login page
    test_endpoint "Login Page" "GET" "$WEB_CONSOLE_URL/auth/login" "200"

    # Perform login (expecting 302 redirect on success)
    log_info "Authenticating as admin@localhost..."
    response_code=$(curl -s -c "$COOKIE_FILE" -b "$COOKIE_FILE" --max-time 10 \
        -X POST "$WEB_CONSOLE_URL/auth/login" \
        -d "email=admin@localhost&password=admin123" \
        -o /dev/null -w "%{http_code}")
    if [ "$response_code" = "302" ]; then
        log_success "Login (HTTP $response_code - redirect to dashboard)"
    elif [ "$response_code" = "200" ]; then
        # 200 means login page re-rendered (failed login)
        log_fail "Login failed - invalid credentials"
        log_info "Skipping authenticated tests due to login failure"
        return
    else
        log_fail "Login (Expected: 302, Got: $response_code)"
        log_info "Skipping authenticated tests due to login failure"
        return
    fi

    # Dashboard pages (authenticated)
    test_endpoint "Dashboard Index" "GET" "$WEB_CONSOLE_URL/dashboard/" "200" "" "true"
    test_endpoint "Users Page" "GET" "$WEB_CONSOLE_URL/dashboard/users" "200" "" "true"
    test_endpoint "Groups Page" "GET" "$WEB_CONSOLE_URL/dashboard/groups" "200" "" "true"
    test_endpoint "Zones Page" "GET" "$WEB_CONSOLE_URL/dashboard/zones" "200" "" "true"
    test_endpoint "Records Page" "GET" "$WEB_CONSOLE_URL/dashboard/records" "200" "" "true"
    test_endpoint "Permissions Page" "GET" "$WEB_CONSOLE_URL/dashboard/permissions" "200" "" "true"
    test_endpoint "Queries Page" "GET" "$WEB_CONSOLE_URL/dashboard/queries" "200" "" "true"
    test_endpoint "IOC Page" "GET" "$WEB_CONSOLE_URL/dashboard/ioc" "200" "" "true"
    test_endpoint "Threats Page" "GET" "$WEB_CONSOLE_URL/dashboard/threats" "200" "" "true"
    test_endpoint "Blocked Page" "GET" "$WEB_CONSOLE_URL/dashboard/blocked" "200" "" "true"
    test_endpoint "Logs Page" "GET" "$WEB_CONSOLE_URL/dashboard/logs" "200" "" "true"
    test_endpoint "Cache Page" "GET" "$WEB_CONSOLE_URL/dashboard/cache" "200" "" "true"
    test_endpoint "Config Page" "GET" "$WEB_CONSOLE_URL/dashboard/config" "200" "" "true"
    test_endpoint "Analytics Page" "GET" "$WEB_CONSOLE_URL/dashboard/analytics" "200" "" "true"

    # API endpoints
    response_code=$(curl -s -c "$COOKIE_FILE" -b "$COOKIE_FILE" --max-time 5 \
        -o /dev/null -w "%{http_code}" "$WEB_CONSOLE_URL/api/queries" 2>/dev/null || echo "000")
    if [ "$response_code" = "200" ]; then
        log_success "API: Queries (HTTP $response_code)"
    elif [ "$response_code" = "302" ]; then
        log_skip "API: Queries (requires additional auth)"
    else
        log_fail "API: Queries (Unexpected: $response_code)"
    fi

    # Test form submissions (zone add)
    response=$(curl -s -c "$COOKIE_FILE" -b "$COOKIE_FILE" --max-time 5 \
        -X POST "$WEB_CONSOLE_URL/dashboard/zones/add" \
        -d "zone_name=apitest$RANDOM.example.com&visibility=PUBLIC&primary_ns=ns1.test.com&admin_email=admin@test.com&ttl=3600" \
        -w "\n%{http_code}")
    code=$(echo "$response" | tail -1)
    if [ "$code" = "302" ] || [ "$code" = "200" ]; then
        log_success "Form: Add Zone (HTTP $code)"
    else
        log_fail "Form: Add Zone (Expected: 302, Got: $code)"
    fi

    # Logout
    test_endpoint "Logout" "GET" "$WEB_CONSOLE_URL/auth/logout" "302" "" "true"
}

# ============================================================================
# DNS Client Tests
# ============================================================================
test_dns_client() {
    log_header "DNS Client Tests (Port $DNS_CLIENT_PORT)"

    # Check if DNS client is responding
    if command -v dig &> /dev/null; then
        result=$(dig @127.0.0.1 -p $DNS_CLIENT_PORT google.com +short +timeout=5 2>/dev/null)
        if [ -n "$result" ]; then
            log_success "DNS Client Query (google.com -> $result)"
            ((PASSED++))
        else
            log_fail "DNS Client Query (no response)"
            ((FAILED++))
        fi

        # Test different record types
        result=$(dig @127.0.0.1 -p $DNS_CLIENT_PORT google.com MX +short +timeout=5 2>/dev/null)
        if [ -n "$result" ]; then
            log_success "DNS Client MX Query"
            ((PASSED++))
        else
            log_skip "DNS Client MX Query (no response)"
        fi

        result=$(dig @127.0.0.1 -p $DNS_CLIENT_PORT google.com TXT +short +timeout=5 2>/dev/null)
        if [ -n "$result" ]; then
            log_success "DNS Client TXT Query"
            ((PASSED++))
        else
            log_skip "DNS Client TXT Query (no response)"
        fi
    else
        log_skip "DNS Client Tests (dig command not available)"
    fi
}

# ============================================================================
# Valkey/Redis Cache Tests
# ============================================================================
test_valkey() {
    log_header "Valkey/Redis Cache Tests (Port $VALKEY_PORT)"

    if command -v redis-cli &> /dev/null; then
        # Ping test
        result=$(redis-cli -p $VALKEY_PORT PING 2>/dev/null)
        if [ "$result" = "PONG" ]; then
            log_success "Valkey PING"
            ((PASSED++))
        else
            log_fail "Valkey PING (no response)"
            ((FAILED++))
        fi

        # Info test
        result=$(redis-cli -p $VALKEY_PORT INFO server 2>/dev/null | head -1)
        if [ -n "$result" ]; then
            log_success "Valkey INFO"
            ((PASSED++))
        else
            log_fail "Valkey INFO (no response)"
            ((FAILED++))
        fi
    else
        log_skip "Valkey Tests (redis-cli not available)"
    fi
}

# ============================================================================
# Container Health Tests
# ============================================================================
test_container_health() {
    log_header "Container Health Tests"

    if command -v docker &> /dev/null; then
        containers=("squawk-dns-server" "squawk-web-console" "squawk-dns-client" "squawk-valkey")

        for container in "${containers[@]}"; do
            running=$(docker inspect --format='{{.State.Running}}' "$container" 2>/dev/null || echo "false")
            if [ "$running" = "true" ]; then
                status=$(docker inspect --format='{{.State.Health.Status}}' "$container" 2>/dev/null || echo "none")
                if [ "$status" = "healthy" ]; then
                    log_success "Container: $container (healthy)"
                elif [ "$status" = "unhealthy" ]; then
                    log_fail "Container: $container (unhealthy)"
                else
                    log_success "Container: $container (running)"
                fi
            else
                log_fail "Container: $container (not running)"
            fi
        done
    else
        log_skip "Container Health Tests (docker not available)"
    fi
}

# ============================================================================
# Main
# ============================================================================
main() {
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║       Squawk DNS - Comprehensive API Test Suite            ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Check if containers are running
    log_info "Checking container status..."

    # Run all tests
    test_container_health
    test_dns_server
    test_web_console
    test_dns_client
    test_valkey

    # Summary
    log_header "Test Summary"
    echo -e "${GREEN}Passed:${NC}  $PASSED"
    echo -e "${RED}Failed:${NC}  $FAILED"
    echo -e "${YELLOW}Skipped:${NC} $SKIPPED"
    echo ""

    TOTAL=$((PASSED + FAILED))
    if [ $TOTAL -gt 0 ]; then
        PERCENTAGE=$((PASSED * 100 / TOTAL))
        echo -e "Success Rate: ${GREEN}$PERCENTAGE%${NC}"
    fi

    # Cleanup
    rm -f "$COOKIE_FILE" /tmp/response.txt

    # Exit with failure if any tests failed
    if [ $FAILED -gt 0 ]; then
        exit 1
    fi
    exit 0
}

# Run main
main "$@"
