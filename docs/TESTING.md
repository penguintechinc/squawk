# Testing Guide

Comprehensive testing documentation for Squawk's DNS/DHCP/Time Synchronization services, including unit tests, integration tests, smoke tests, mock data, and cross-architecture validation.

## Overview

Testing is organized into multiple levels to ensure comprehensive coverage, fast feedback, and production-ready code for Squawk's network services:

| Test Level | Purpose | Speed | Coverage |
|-----------|---------|-------|----------|
| **Smoke Tests** | Fast verification of DNS/DHCP/NTP services | <2 min | Build, run, API health, health endpoints |
| **Unit Tests** | Isolated function/method testing for services | <2 min | DNS resolution, token validation, DHCP pool logic, time sync |
| **Integration Tests** | Service interaction verification (DNS+DB, DHCP+DNS, NTP+Client) | 2-5 min | Data flow, API contracts, token permissions |
| **E2E Tests** | Critical workflows end-to-end | 5-10 min | DNS queries, DHCP leases, Time sync, selective routing |
| **Performance Tests** | Throughput and latency validation | 5-15 min | Concurrent DNS queries, lease allocation rate, time drift |
| **Security Tests** | Token validation, injection prevention, LDAP auth | 2-5 min | Auth bypass attempts, SQL injection, XSS prevention |

## Mock Data Scripts

### Purpose

Mock data scripts populate the development database with realistic test data for Squawk services:
- Rapid local development without manual data entry
- Consistent test data across the development team
- Documentation of expected data structure and relationships
- Quick feature iteration with pre-populated databases

### Location & Structure

```
scripts/mock-data/
├── seed-all.py                  # Orchestrator: runs all seeders in order
├── seed-tokens.py               # 3-4 tokens with different permission sets
├── seed-domains.py              # 3-4 domains (internal, public, wildcards)
├── seed-dhcp-pools.py           # 3-4 DHCP pools with different CIDR ranges
├── seed-dhcp-leases.py          # 3-4 active leases per pool
├── seed-time-servers.py         # 2-3 PTP/NTP time servers
├── seed-query-logs.py           # Sample DNS query logs for testing
├── seed-threat-intel.py         # IOC feeds and blacklist entries
└── README.md                    # Instructions for running mock data
```

### Naming Convention

- **Python**: `seed-{feature-name}.py`
- **Organization**: One seeder per logical entity/feature
- **Scope**: 3-4 representative items per feature

### Scope: 3-4 Items Per Feature

Each seeder should create **exactly 3-4 representative items** to test all service variations:

**Example (Tokens)**:
```python
# seed-tokens.py
items = [
    {"name": "admin-token", "description": "Admin token", "permissions": ["*.internal"]},
    {"name": "public-token", "description": "Public DNS only", "permissions": ["example.com"]},
    {"name": "wildcard-token", "description": "All domains", "permissions": ["*"]},
    {"name": "selective-token", "description": "Group-based routing", "permissions": ["internal.corp"]},
]
```

**Example (DHCP Pools)**:
```python
# seed-dhcp-pools.py
items = [
    {"name": "office", "network": "192.168.1.0/24", "gateway": "192.168.1.1", "lease_duration": 86400},
    {"name": "lab", "network": "10.0.0.0/24", "gateway": "10.0.0.1", "lease_duration": 3600},
    {"name": "guests", "network": "172.16.0.0/24", "gateway": "172.16.0.1", "lease_duration": 7200},
    {"name": "iot", "network": "10.20.0.0/24", "gateway": "10.20.0.1", "lease_duration": 604800},
]
```

**Example (Time Servers)**:
```python
# seed-time-servers.py
items = [
    {"name": "Primary PTP", "server": "ptp.internal", "protocol": "ptp", "stratum": 1},
    {"name": "Backup NTP", "server": "ntp.internal", "protocol": "ntp", "stratum": 2},
    {"name": "Public NTP", "server": "pool.ntp.org", "protocol": "ntp", "stratum": 3},
]
```

### Execution

**Seed all test data**:
```bash
make seed-mock-data          # Via Makefile
python scripts/mock-data/seed-all.py  # Direct execution
```

**Seed specific service**:
```bash
python scripts/mock-data/seed-tokens.py
python scripts/mock-data/seed-dhcp-pools.py
python scripts/mock-data/seed-time-servers.py
```

### Implementation Pattern

**Python (PyDAL)**:
```python
#!/usr/bin/env python3
"""Seed mock data for tokens."""

import os
import sys
from pydal import DAL

def seed_tokens():
    db = DAL(os.getenv('DB_URL', 'sqlite:memory'))

    tokens = [
        {"token": "admin-token-abc123", "name": "Admin Token", "active": True},
        {"token": "public-token-def456", "name": "Public DNS", "active": True},
        {"token": "test-token-ghi789", "name": "Test Token", "active": True},
        {"token": "inactive-token-jkl012", "name": "Inactive", "active": False},
    ]

    for token_data in tokens:
        db.tokens.insert(**token_data)

    print(f"✓ Seeded {len(tokens)} tokens")

if __name__ == "__main__":
    seed_tokens()
```

### Makefile Integration

Add to your `Makefile`:

```makefile
.PHONY: seed-mock-data
seed-mock-data:
	@echo "Seeding mock data for DNS/DHCP/Time services..."
	@python scripts/mock-data/seed-all.py
	@echo "✓ Mock data seeding complete"

.PHONY: clean-data
clean-data:
	@echo "Clearing mock data..."
	@rm -f data/dev.db
	@echo "✓ Mock data cleared"
```

---

## Smoke Tests

### Purpose

Smoke tests provide fast verification that Squawk's core network services work correctly after code changes.

### Requirements (Mandatory)

All projects **MUST** implement smoke tests before committing:

- ✅ **Build Tests**: All containers build successfully without errors
- ✅ **Run Tests**: All containers start and remain healthy (DNS, DHCP, manager, frontend)
- ✅ **API Health Checks**: DNS server, DHCP manager, and manager API respond with 200 status
- ✅ **Service Functionality Tests**: DNS queries resolve, DHCP assigns IPs, time servers sync
- ✅ **Network Connectivity**: Services communicate correctly (DNS+DB, DHCP+DNS, NTP+Client)

### Location & Structure

```
tests/smoke/
├── build/                  # Container build verification
│   ├── test-dns-build.sh
│   ├── test-dhcp-build.sh
│   ├── test-manager-build.sh
│   └── test-frontend-build.sh
├── run/                    # Container runtime and health
│   ├── test-dns-run.sh
│   ├── test-dhcp-run.sh
│   ├── test-manager-run.sh
│   └── test-frontend-run.sh
├── api/                    # API health endpoint validation
│   ├── test-dns-health.sh
│   ├── test-dhcp-health.sh
│   ├── test-manager-health.sh
│   └── README.md
├── services/               # Service functionality tests
│   ├── test-dns-query.sh
│   ├── test-dhcp-lease.sh
│   ├── test-time-sync.sh
│   └── README.md
├── run-all.sh              # Execute all smoke tests
└── README.md               # Documentation
```

### Execution

**Run all smoke tests**:
```bash
make smoke-test              # Via Makefile
./tests/smoke/run-all.sh     # Direct execution
```

**Run specific test category**:
```bash
./tests/smoke/build/test-dns-build.sh
./tests/smoke/api/test-dns-health.sh
./tests/smoke/services/test-dns-query.sh
```

### Speed Requirement

Complete smoke test suite **MUST run in under 2 minutes** to provide fast feedback during development.

### Implementation Examples

**Build Test (Shell)**:
```bash
#!/bin/bash
# tests/smoke/build/test-dns-build.sh

set -e

echo "Testing DNS Server build..."
cd dns-server

if docker build -t squawk-dns:test .; then
    echo "✓ DNS Server builds successfully"
    exit 0
else
    echo "✗ DNS Server build failed"
    exit 1
fi
```

**Health Check Test**:
```bash
#!/bin/bash
# tests/smoke/api/test-dns-health.sh

set -e

echo "Checking DNS Server health..."
HEALTH_URL="http://localhost:8080/health"

RESPONSE=$(curl -s -w "\n%{http_code}" "$HEALTH_URL")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ DNS Server is healthy (HTTP $HTTP_CODE)"
    exit 0
else
    echo "✗ DNS Server is unhealthy (HTTP $HTTP_CODE)"
    exit 1
fi
```

**DNS Query Test**:
```bash
#!/bin/bash
# tests/smoke/services/test-dns-query.sh

set -e

echo "Testing DNS query functionality..."
TOKEN="test-token-abc123"
DOMAIN="example.com"

RESPONSE=$(curl -s "http://localhost:8080/dns/query?domain=$DOMAIN&type=A" \
  -H "Authorization: Bearer $TOKEN")

if echo "$RESPONSE" | grep -q '"Status":0'; then
    echo "✓ DNS query successful for $DOMAIN"
    exit 0
else
    echo "✗ DNS query failed for $DOMAIN"
    exit 1
fi
```

**DHCP Lease Test**:
```bash
#!/bin/bash
# tests/smoke/services/test-dhcp-lease.sh

set -e

echo "Testing DHCP lease assignment..."
POOL_ID="office"
MAC="aa:bb:cc:dd:ee:ff"

RESPONSE=$(curl -s -X POST "http://localhost:8000/api/v1/dhcp/lease" \
  -H "Content-Type: application/json" \
  -d "{\"pool_id\": \"$POOL_ID\", \"mac\": \"$MAC\"}")

if echo "$RESPONSE" | grep -q '"success":true'; then
    echo "✓ DHCP lease assignment successful"
    exit 0
else
    echo "✗ DHCP lease assignment failed"
    exit 1
fi
```

### Pre-Commit Integration

Smoke tests run as part of the pre-commit checklist and **must pass before proceeding** to full test suite:

```bash
./scripts/pre-commit/pre-commit.sh
# Step 1: Linters
# Step 2: Security scans
# Step 3: No secrets
# Step 4: Build & Run
# Step 5: Smoke tests ← Must pass
# Step 6: Full tests
```

---

## Unit Tests

### Purpose

Unit tests verify individual functions and methods in DNS resolution, token validation, DHCP logic, and time synchronization in isolation with mocked dependencies.

### Location

```
tests/unit/
├── dns-server/
│   ├── test_token_validation.py
│   ├── test_dns_resolution.py
│   ├── test_ioc_blocking.py
│   └── test_selective_routing.py
├── dns-client/
│   ├── test_doh_client.py
│   ├── test_dns_forwarder.py
│   └── test_config.py
├── manager/
│   ├── test_token_management.py
│   ├── test_dhcp_pools.py
│   └── test_time_servers.py
└── frontend/
    ├── test_components.tsx
    └── test_utils.ts
```

### Execution

```bash
make test-unit              # All unit tests
pytest tests/unit/          # Python
npm test                    # JavaScript/TypeScript
```

### Requirements

- All dependencies must be mocked
- Network calls must be stubbed
- Database access must be isolated
- Tests must run in parallel when possible

---

## Integration Tests

### Purpose

Integration tests verify that Squawk components work together correctly, including real database interactions and service communication (DNS+DB, DHCP+DNS, NTP+Client).

### Location

```
tests/integration/
├── dns/
│   ├── test_token_dns_flow.py
│   ├── test_selective_routing.py
│   └── test_threat_intel.py
├── dhcp/
│   ├── test_pool_management.py
│   ├── test_lease_allocation.py
│   └── test_ddns_integration.py
├── time/
│   ├── test_ptp_ntp_failover.py
│   └── test_time_sync_flow.py
├── multi-service/
│   ├── test_dns_dhcp_coordination.py
│   └── test_manager_service_sync.py
└── database/
    ├── test_migrations.py
    └── test_queries.py
```

### Execution

```bash
make test-integration       # All integration tests
pytest tests/integration/   # Python
npm run test:integration    # JavaScript
```

### Requirements

- Use real databases (test instances)
- Test complete workflows (DNS queries with token auth, DHCP lease assignment, time sync)
- Verify API contracts between services
- Test error scenarios and failover paths

---

## End-to-End Tests

### Purpose

E2E tests verify critical user workflows from start to finish, testing Squawk's entire application stack.

### Location

```
tests/e2e/
├── dns-queries.spec.ts
├── dhcp-management.spec.ts
├── time-synchronization.spec.ts
├── selective-routing.spec.ts
├── token-lifecycle.spec.ts
└── multi-tenant.spec.ts
```

### Execution

```bash
make test-e2e               # All E2E tests
npx playwright test tests/e2e/  # Playwright
```

---

## Performance Tests

### Purpose

Performance tests validate throughput, latency, and resource usage under load for DNS queries, DHCP lease allocation, and time synchronization.

### Location

```
tests/performance/
├── dns-load-test.js        # DNS query throughput
├── dhcp-load-test.js       # DHCP lease assignment rate
├── time-sync-test.js       # Time offset convergence
└── profile-report.md
```

### Execution

```bash
make test-performance
npm run test:performance
```

### Key Metrics

- DNS queries per second
- DHCP lease assignment time
- Time synchronization drift
- Memory usage under load
- CPU utilization
- Database query time

---

## Security Tests

### Purpose

Security tests validate token validation, selective routing permissions, SQL injection prevention, LDAP authentication, and threat intelligence blocking.

### Location

```
tests/security/
├── test_token_validation.py
├── test_sql_injection.py
├── test_xss_prevention.py
├── test_ldap_auth.py
├── test_permission_boundaries.py
└── test_ioc_blocking.py
```

### Execution

```bash
pytest tests/security/
npm run test:security
```

### Requirements

- Test token validation and expiry
- Verify permission boundaries (no privilege escalation)
- Test SQL injection attempts
- Verify XSS prevention in web console
- Test LDAP bind failures and DN validation
- Verify IOC blocking for malicious domains

---

## Cross-Architecture Testing

### Purpose

Cross-architecture testing ensures Squawk builds and runs correctly on both amd64 and arm64 architectures, preventing platform-specific bugs in DNS resolution, DHCP, and time synchronization services.

### When to Test

**Before every final commit**, test on the alternate architecture:
- Developing on amd64 → Build and test arm64 with QEMU
- Developing on arm64 → Build and test amd64 with QEMU

### Setup (First Time)

Enable Docker buildx for multi-architecture builds:

```bash
docker buildx create --name multiarch --driver docker-container
docker buildx use multiarch
```

### Single Architecture Build

```bash
# Test current architecture (native, fast)
docker build -t squawk-dns:test dns-server/

# Or explicitly specify architecture
docker build --platform linux/amd64 -t squawk-dns:test dns-server/
```

### Cross-Architecture Build (QEMU)

```bash
# Test alternate architecture (uses QEMU emulation)
docker buildx build --platform linux/arm64 -t squawk-dns:test dns-server/

# Or test both simultaneously
docker buildx build --platform linux/amd64,linux/arm64 -t squawk-dns:test dns-server/
```

### Multi-Architecture Build Script

Create `scripts/build/test-multiarch.sh`:

```bash
#!/bin/bash
# Test both architectures before commit

set -e

SERVICES=("dns-server" "dns-client" "manager" "frontend")
ARCHITECTURES=("linux/amd64" "linux/arm64")

for service in "${SERVICES[@]}"; do
    echo "Testing $service on multiple architectures..."

    for arch in "${ARCHITECTURES[@]}"; do
        echo "  → Building for $arch..."
        docker buildx build \
            --platform "$arch" \
            -t "squawk-$service:multiarch-test" \
            "$service/" || {
            echo "✗ Build failed for $service on $arch"
            exit 1
        }
    done

    echo "✓ $service builds successfully on amd64 and arm64"
done

echo "✓ All services passed multi-architecture testing"
```

### Makefile Integration

```makefile
.PHONY: test-multiarch
test-multiarch:
	@echo "Testing multi-architecture builds..."
	@bash scripts/build/test-multiarch.sh

.PHONY: build-multiarch
build-multiarch:
	@docker buildx build \
		--platform linux/amd64,linux/arm64 \
		-t $(IMAGE_NAME):$(VERSION) \
		--push .
```

---

## Test Execution Order (Pre-Commit)

Follow this order for efficient testing before commits:

1. **Linters** (fast, <1 min)
2. **Security scans** (fast, <1 min)
3. **Secrets check** (fast, <1 min)
4. **Build & Run** (5-10 min)
5. **Smoke tests** (fast, <2 min) ← Gates further testing
6. **Unit tests** (1-2 min)
7. **Integration tests** (2-5 min)
8. **E2E tests** (5-10 min)
9. **Cross-architecture build** (optional, slow)

## CI/CD Integration

All tests run automatically in GitHub Actions:

- **On PR**: Smoke + Unit + Integration tests
- **On main merge**: All tests + Performance tests
- **Nightly**: Performance + Cross-architecture tests
- **Release**: Full suite + Manual sign-off

### Security & Coverage Gates (Enforced)

- **CodeQL** static analysis runs across `python`, `go`, and `javascript-typescript` on push/PR (plus a weekly schedule)
- **bandit** (Python) and **gosec** (Go) run as build-gating security scans — findings fail the build
- **Coverage gate**: dns-server tests are gated at **90%** (`--cov-fail-under=90` against `dns-server/app`); the build fails below the threshold

See [Workflows](WORKFLOWS.md) for detailed CI/CD configuration.

---

**Last Updated**: 2026-01-06
**Maintained by**: Squawk Team
