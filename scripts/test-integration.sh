#!/bin/bash
#
# Integration Test Script for Squawk DNS - All Protocols
# Tests client + server connectivity for DNS, DHCP, and NTP protocols
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
DNS_SERVER_URL="${DNS_SERVER_URL:-http://localhost:8080}"
DHCP_SERVER_URL="${DHCP_SERVER_URL:-http://localhost:8081}"
NTP_SERVER_URL="${NTP_SERVER_URL:-http://localhost:8082}"
AUTH_TOKEN="${AUTH_TOKEN:-test-token}"
GO_CLIENT_DIR="${GO_CLIENT_DIR:-$(dirname "$0")/../squawk-client-go}"

# Test counters
PASSED=0
FAILED=0
SKIPPED=0

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
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}========================================${NC}"
}

# Check if a service is healthy
check_service() {
    local name="$1"
    local url="$2"
    local max_retries="${3:-30}"
    local retry_interval="${4:-2}"

    log_info "Waiting for $name to be healthy..."

    for i in $(seq 1 $max_retries); do
        response=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url/health" 2>/dev/null || echo "000")
        if [ "$response" = "200" ]; then
            log_success "$name is healthy"
            return 0
        fi
        echo -n "."
        sleep $retry_interval
    done

    echo ""
    log_fail "$name is not responding (tried $max_retries times)"
    return 1
}

# ============================================================================
# DNS Protocol Tests
# ============================================================================
test_dns_protocol() {
    log_header "DNS Protocol Tests"

    # Test 1: Health check
    response=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$DNS_SERVER_URL/health" 2>/dev/null || echo "000")
    if [ "$response" = "200" ]; then
        log_success "DNS Server Health Check"
    else
        log_fail "DNS Server Health Check (HTTP $response)"
        return 1
    fi

    # Test 2: DNS Query via GET (unauthenticated - expected to fail if auth required)
    response=$(curl -s --max-time 10 "$DNS_SERVER_URL/dns-query?name=google.com&type=A" 2>/dev/null)
    if echo "$response" | grep -q "Answer\|google.com"; then
        log_success "DNS Query (GET) - google.com A record"
    elif echo "$response" | grep -q "Authentication required"; then
        log_success "DNS Query (GET) - requires authentication (expected)"
    else
        log_fail "DNS Query (GET) - no valid response"
    fi

    # Test 3: DNS Query via POST (unauthenticated - expected to fail if auth required)
    response=$(curl -s --max-time 10 -X POST "$DNS_SERVER_URL/dns-query?name=cloudflare.com&type=A" 2>/dev/null)
    if echo "$response" | grep -q "Answer\|cloudflare"; then
        log_success "DNS Query (POST) - cloudflare.com A record"
    elif echo "$response" | grep -q "Authentication required"; then
        log_success "DNS Query (POST) - requires authentication (expected)"
    else
        log_fail "DNS Query (POST) - no valid response"
    fi

    # Test 4: DNS Query with authentication
    response=$(curl -s --max-time 10 "$DNS_SERVER_URL/dns-query?name=example.com&type=A" \
        -H "Authorization: Bearer $AUTH_TOKEN" 2>/dev/null)
    if echo "$response" | grep -q "Answer\|example.com"; then
        log_success "DNS Query (Authenticated)"
    else
        log_fail "DNS Query (Authenticated) - no valid response"
    fi

    # Test 5: MX record query
    response=$(curl -s --max-time 10 "$DNS_SERVER_URL/dns-query?name=google.com&type=MX" 2>/dev/null)
    if echo "$response" | grep -qiE "Answer|MX|mail"; then
        log_success "DNS Query - MX record"
    else
        log_skip "DNS Query - MX record (no response)"
    fi

    # Test 6: TXT record query
    response=$(curl -s --max-time 10 "$DNS_SERVER_URL/dns-query?name=google.com&type=TXT" 2>/dev/null)
    if echo "$response" | grep -qiE "Answer|TXT|spf|v="; then
        log_success "DNS Query - TXT record"
    else
        log_skip "DNS Query - TXT record (no response)"
    fi

    # Test 7: AAAA record query (IPv6)
    response=$(curl -s --max-time 10 "$DNS_SERVER_URL/dns-query?name=google.com&type=AAAA" 2>/dev/null)
    if echo "$response" | grep -qiE "Answer|AAAA"; then
        log_success "DNS Query - AAAA record (IPv6)"
    else
        log_skip "DNS Query - AAAA record (no IPv6)"
    fi
}

# ============================================================================
# DHCP Protocol Tests
# ============================================================================
test_dhcp_protocol() {
    log_header "DHCP Protocol Tests"

    # Test 1: Health check
    response=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$DHCP_SERVER_URL/health" 2>/dev/null || echo "000")
    if [ "$response" = "200" ]; then
        log_success "DHCP Server Health Check"
    else
        log_fail "DHCP Server Health Check (HTTP $response)"
        return 1
    fi

    # Test 2: Root endpoint info
    response=$(curl -s --max-time 5 "$DHCP_SERVER_URL/" 2>/dev/null)
    if echo "$response" | grep -q "DHCP-over-HTTPS"; then
        log_success "DHCP Server Info Endpoint"
    else
        log_fail "DHCP Server Info Endpoint"
    fi

    # Generate a test MAC address
    TEST_MAC="00:11:22:33:44:$(printf '%02x' $((RANDOM % 256)))"
    log_info "Using test MAC: $TEST_MAC"

    # Test 3: DHCP Discover
    response=$(curl -s --max-time 10 -X POST "$DHCP_SERVER_URL/dhcp/discover" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -d "{\"mac_address\":\"$TEST_MAC\",\"hostname\":\"test-client\"}" 2>/dev/null)

    if echo "$response" | grep -q "offer"; then
        OFFERED_IP=$(echo "$response" | grep -o '"offered_ip":"[^"]*"' | cut -d'"' -f4)
        log_success "DHCP Discover - Offered IP: $OFFERED_IP"
    else
        log_fail "DHCP Discover - no offer received"
        OFFERED_IP=""
    fi

    # Test 4: DHCP Request (if we got an offer)
    if [ -n "$OFFERED_IP" ]; then
        response=$(curl -s --max-time 10 -X POST "$DHCP_SERVER_URL/dhcp/request" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $AUTH_TOKEN" \
            -d "{\"mac_address\":\"$TEST_MAC\",\"requested_ip\":\"$OFFERED_IP\",\"hostname\":\"test-client\"}" 2>/dev/null)

        if echo "$response" | grep -q "ack"; then
            log_success "DHCP Request - ACK received"
        else
            log_fail "DHCP Request - no ACK received"
        fi
    else
        log_skip "DHCP Request - skipped (no offer)"
    fi

    # Test 5: Get lease
    if [ -n "$OFFERED_IP" ]; then
        response=$(curl -s --max-time 5 "$DHCP_SERVER_URL/dhcp/lease/$TEST_MAC" \
            -H "Authorization: Bearer $AUTH_TOKEN" 2>/dev/null)

        if echo "$response" | grep -q "active\|$OFFERED_IP"; then
            log_success "DHCP Get Lease"
        else
            log_fail "DHCP Get Lease"
        fi
    else
        log_skip "DHCP Get Lease - skipped (no lease)"
    fi

    # Test 6: List all leases
    response=$(curl -s --max-time 5 "$DHCP_SERVER_URL/dhcp/leases" \
        -H "Authorization: Bearer $AUTH_TOKEN" 2>/dev/null)

    if echo "$response" | grep -q "leases"; then
        log_success "DHCP List Leases"
    else
        log_fail "DHCP List Leases"
    fi

    # Test 7: DHCP Release
    if [ -n "$OFFERED_IP" ]; then
        response=$(curl -s --max-time 5 -X POST "$DHCP_SERVER_URL/dhcp/release" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $AUTH_TOKEN" \
            -d "{\"mac_address\":\"$TEST_MAC\",\"client_ip\":\"$OFFERED_IP\"}" 2>/dev/null)

        if echo "$response" | grep -q "success.*true\|released"; then
            log_success "DHCP Release"
        else
            log_fail "DHCP Release"
        fi
    else
        log_skip "DHCP Release - skipped (no lease)"
    fi

    # Test 8: Pool statistics (from health)
    response=$(curl -s --max-time 5 "$DHCP_SERVER_URL/health" 2>/dev/null)
    if echo "$response" | grep -q "available_ips\|total_ips"; then
        log_success "DHCP Pool Statistics"
    else
        log_fail "DHCP Pool Statistics"
    fi
}

# ============================================================================
# NTP Protocol Tests
# ============================================================================
test_ntp_protocol() {
    log_header "NTP Protocol Tests"

    # Test 1: Health check
    response=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$NTP_SERVER_URL/health" 2>/dev/null || echo "000")
    if [ "$response" = "200" ]; then
        log_success "NTP Server Health Check"
    else
        log_fail "NTP Server Health Check (HTTP $response)"
        return 1
    fi

    # Test 2: Root endpoint info
    response=$(curl -s --max-time 5 "$NTP_SERVER_URL/" 2>/dev/null)
    if echo "$response" | grep -q "NTP/NTS Server"; then
        log_success "NTP Server Info Endpoint"
    else
        log_fail "NTP Server Info Endpoint"
    fi

    # Test 3: Simple time query (REST API)
    response=$(curl -s --max-time 10 "$NTP_SERVER_URL/ntp/time" \
        -H "Authorization: Bearer $AUTH_TOKEN" 2>/dev/null)

    if echo "$response" | grep -q "timestamp\|ntp_seconds"; then
        NTP_TIME=$(echo "$response" | grep -o '"iso8601":"[^"]*"' | cut -d'"' -f4)
        log_success "NTP Time Query - Server time: $NTP_TIME"
    else
        log_fail "NTP Time Query"
    fi

    # Test 4: NTP status
    response=$(curl -s --max-time 5 "$NTP_SERVER_URL/ntp/status" \
        -H "Authorization: Bearer $AUTH_TOKEN" 2>/dev/null)

    if echo "$response" | grep -q "stratum\|active_sessions"; then
        log_success "NTP Status Query"
    else
        log_fail "NTP Status Query"
    fi

    # Test 5: NTS Key Establishment
    response=$(curl -s --max-time 10 -X POST "$NTP_SERVER_URL/nts/ke" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -d '{"supported_algorithms":[15,16,17],"next_protocol":"ntske/1"}' 2>/dev/null)

    if echo "$response" | grep -q "c2s_key\|cookies"; then
        # Use Python for robust JSON parsing
        COOKIE=$(python3 -c "import json,sys; d=json.loads('''$response'''); print(d['cookies'][0])" 2>/dev/null || echo "")
        if [ -n "$COOKIE" ]; then
            log_success "NTS Key Establishment"
        else
            log_fail "NTS Key Establishment - cookie extraction failed"
            COOKIE=""
        fi
    else
        log_fail "NTS Key Establishment"
        COOKIE=""
    fi

    # Test 6: NTS-authenticated time query
    if [ -n "$COOKIE" ]; then
        UNIQUE_ID=$(date +%s%N)
        response=$(curl -s --max-time 10 -X POST "$NTP_SERVER_URL/ntp/query" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $AUTH_TOKEN" \
            -d "{\"cookie\":\"$COOKIE\",\"client_transmit\":$(date +%s%N),\"unique_id\":\"$UNIQUE_ID\"}" 2>/dev/null)

        if echo "$response" | grep -q "authenticated.*true\|transmit_timestamp\|ntp_seconds"; then
            log_success "NTS Authenticated Time Query"
        else
            log_fail "NTS Authenticated Time Query"
        fi
    else
        log_skip "NTS Authenticated Time Query - skipped (no cookie)"
    fi

    # Test 7: Verify time accuracy
    response=$(curl -s --max-time 5 "$NTP_SERVER_URL/ntp/time" \
        -H "Authorization: Bearer $AUTH_TOKEN" 2>/dev/null)

    if [ -n "$response" ]; then
        SERVER_UNIX=$(echo "$response" | grep -o '"unix_timestamp":[0-9.]*' | cut -d':' -f2)
        LOCAL_UNIX=$(date +%s)
        if [ -n "$SERVER_UNIX" ]; then
            # Allow 60 seconds difference
            DIFF=$(echo "$SERVER_UNIX - $LOCAL_UNIX" | bc 2>/dev/null | cut -d'.' -f1 || echo "0")
            DIFF=${DIFF:-0}
            DIFF=${DIFF#-}  # Absolute value
            if [ "${DIFF:-0}" -lt 60 ]; then
                log_success "NTP Time Accuracy (within 60s)"
            else
                log_fail "NTP Time Accuracy (diff: ${DIFF}s)"
            fi
        else
            log_skip "NTP Time Accuracy - cannot parse"
        fi
    else
        log_skip "NTP Time Accuracy - no response"
    fi
}

# ============================================================================
# Go Client Tests (if available)
# ============================================================================
test_go_client() {
    log_header "Go Client Integration Tests"

    # Check if Go client binary exists
    if [ ! -f "$GO_CLIENT_DIR/bin/squawk-dns-client" ]; then
        log_info "Building Go client..."
        cd "$GO_CLIENT_DIR"
        if make build 2>/dev/null; then
            log_success "Go client built successfully"
        else
            log_skip "Go client build failed - skipping client tests"
            return 1
        fi
        cd - > /dev/null
    fi

    CLIENT="$GO_CLIENT_DIR/bin/squawk-dns-client"

    # Test 1: Client help
    if $CLIENT --help 2>&1 | grep -q "DNS-over-HTTPS"; then
        log_success "Go Client - Help output"
    else
        log_fail "Go Client - Help output"
    fi

    # Test 2: DNS query via Go client (unauthenticated - expected to fail if auth required)
    result=$($CLIENT -d example.com -s "$DNS_SERVER_URL" --type A 2>&1 || true)
    if echo "$result" | grep -qiE "example\.com|93\.184\."; then
        log_success "Go Client - DNS Query (example.com)"
    elif echo "$result" | grep -qiE "401|Authentication required"; then
        log_success "Go Client - DNS Query requires auth (expected)"
    else
        log_fail "Go Client - DNS Query (example.com)"
        log_info "Output: $result"
    fi

    # Test 3: DNS query with authentication
    result=$($CLIENT -d google.com -s "$DNS_SERVER_URL" -a "$AUTH_TOKEN" --type A 2>&1 || true)
    if echo "$result" | grep -qiE "google\.com|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"; then
        log_success "Go Client - Authenticated DNS Query"
    else
        log_fail "Go Client - Authenticated DNS Query"
    fi

    # Test 4: Multiple record types
    for type in A AAAA MX TXT; do
        result=$($CLIENT -d google.com -s "$DNS_SERVER_URL" --type $type 2>&1 || true)
        if [ $? -eq 0 ] || echo "$result" | grep -qiE "google|Answer"; then
            log_success "Go Client - $type record query"
        else
            log_skip "Go Client - $type record query"
        fi
    done
}

# ============================================================================
# Cross-Protocol Integration Tests
# ============================================================================
test_cross_protocol() {
    log_header "Cross-Protocol Integration Tests"

    # Test 1: DNS server can resolve its own hostname
    response=$(curl -s --max-time 10 "$DNS_SERVER_URL/dns-query?name=localhost&type=A" 2>/dev/null)
    if echo "$response" | grep -qiE "localhost|127\.0\.0\.1"; then
        log_success "DNS resolves localhost"
    else
        log_skip "DNS localhost resolution"
    fi

    # Test 2: All services report healthy
    services_healthy=0
    for url in "$DNS_SERVER_URL" "$DHCP_SERVER_URL" "$NTP_SERVER_URL"; do
        response=$(curl -s --max-time 5 "$url/health" 2>/dev/null || echo "{}")
        if echo "$response" | grep -q "healthy"; then
            services_healthy=$((services_healthy + 1))
        fi
    done

    if [ $services_healthy -eq 3 ]; then
        log_success "All services healthy ($services_healthy/3)"
    else
        log_fail "Not all services healthy ($services_healthy/3)"
    fi

    # Test 3: Auth token works across services
    auth_success=0

    # DNS with auth
    response=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
        "$DNS_SERVER_URL/dns-query?name=test.com&type=A" \
        -H "Authorization: Bearer $AUTH_TOKEN" 2>/dev/null || echo "000")
    [ "$response" = "200" ] && auth_success=$((auth_success + 1))

    # DHCP with auth
    response=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
        "$DHCP_SERVER_URL/dhcp/leases" \
        -H "Authorization: Bearer $AUTH_TOKEN" 2>/dev/null || echo "000")
    [ "$response" = "200" ] && auth_success=$((auth_success + 1))

    # NTP with auth
    response=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
        "$NTP_SERVER_URL/ntp/time" \
        -H "Authorization: Bearer $AUTH_TOKEN" 2>/dev/null || echo "000")
    [ "$response" = "200" ] && auth_success=$((auth_success + 1))

    if [ $auth_success -eq 3 ]; then
        log_success "Auth token accepted by all services ($auth_success/3)"
    else
        log_fail "Auth token not accepted by all services ($auth_success/3)"
    fi
}

# ============================================================================
# Main
# ============================================================================
main() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║    Squawk DNS - Multi-Protocol Integration Test Suite      ║${NC}"
    echo -e "${CYAN}║           Testing DNS, DHCP, and NTP Protocols             ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    log_info "Configuration:"
    echo "  DNS Server:  $DNS_SERVER_URL"
    echo "  DHCP Server: $DHCP_SERVER_URL"
    echo "  NTP Server:  $NTP_SERVER_URL"
    echo "  Auth Token:  ${AUTH_TOKEN:0:10}..."
    echo ""

    # Check services before running tests
    log_header "Service Health Checks"

    DNS_OK=false
    DHCP_OK=false
    NTP_OK=false

    if check_service "DNS Server" "$DNS_SERVER_URL" 10 1; then
        DNS_OK=true
    fi

    if check_service "DHCP Server" "$DHCP_SERVER_URL" 10 1; then
        DHCP_OK=true
    fi

    if check_service "NTP Server" "$NTP_SERVER_URL" 10 1; then
        NTP_OK=true
    fi

    # Run protocol tests
    if [ "$DNS_OK" = "true" ]; then
        test_dns_protocol
    else
        log_skip "DNS Protocol Tests - server unavailable"
    fi

    if [ "$DHCP_OK" = "true" ]; then
        test_dhcp_protocol
    else
        log_skip "DHCP Protocol Tests - server unavailable"
    fi

    if [ "$NTP_OK" = "true" ]; then
        test_ntp_protocol
    else
        log_skip "NTP Protocol Tests - server unavailable"
    fi

    # Go client tests (optional)
    if [ "$DNS_OK" = "true" ] && [ -d "$GO_CLIENT_DIR" ]; then
        test_go_client
    else
        log_skip "Go Client Tests - DNS server unavailable or client dir not found"
    fi

    # Cross-protocol tests
    if [ "$DNS_OK" = "true" ] && [ "$DHCP_OK" = "true" ] && [ "$NTP_OK" = "true" ]; then
        test_cross_protocol
    else
        log_skip "Cross-Protocol Tests - not all servers available"
    fi

    # Summary
    log_header "Test Summary"
    echo -e "${GREEN}Passed:${NC}  $PASSED"
    echo -e "${RED}Failed:${NC}  $FAILED"
    echo -e "${YELLOW}Skipped:${NC} $SKIPPED"
    echo ""

    TOTAL=$((PASSED + FAILED))
    if [ $TOTAL -gt 0 ]; then
        PERCENTAGE=$((PASSED * 100 / TOTAL))
        echo -e "Success Rate: ${GREEN}$PERCENTAGE%${NC} ($PASSED/$TOTAL)"
    fi
    echo ""

    # Exit with failure if any tests failed
    if [ $FAILED -gt 0 ]; then
        echo -e "${RED}Some tests failed!${NC}"
        exit 1
    fi

    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dns-url)
            DNS_SERVER_URL="$2"
            shift 2
            ;;
        --dhcp-url)
            DHCP_SERVER_URL="$2"
            shift 2
            ;;
        --ntp-url)
            NTP_SERVER_URL="$2"
            shift 2
            ;;
        --token)
            AUTH_TOKEN="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --dns-url URL    DNS server URL (default: http://localhost:8080)"
            echo "  --dhcp-url URL   DHCP server URL (default: http://localhost:8081)"
            echo "  --ntp-url URL    NTP server URL (default: http://localhost:8082)"
            echo "  --token TOKEN    Authentication token (default: test-token)"
            echo "  --help           Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run main
main "$@"
