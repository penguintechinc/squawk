# Pre-Commit Checklist

**CRITICAL: This checklist MUST be followed before every commit to Squawk.**

## Automated Pre-Commit Script

**Run the automated pre-commit script to execute all checks:**

```bash
./scripts/pre-commit/pre-commit.sh
```

This script will:
1. Run all checks in the correct order
2. Log output to `/tmp/pre-commit-squawk-<epoch>.log`
3. Provide a summary of pass/fail status
4. Echo the log file location for review

**Individual check scripts** (run separately if needed):
- `./scripts/pre-commit/check-python.sh` - Python linting & security (DNS server, manager)
- `./scripts/pre-commit/check-go.sh` - Go linting & security (DNS client)
- `./scripts/pre-commit/check-node.sh` - Node.js/React linting, audit & build (frontend)
- `./scripts/pre-commit/check-security.sh` - All security scans
- `./scripts/pre-commit/check-secrets.sh` - Secret detection
- `./scripts/pre-commit/check-docker.sh` - Docker build & validation
- `./scripts/pre-commit/check-tests.sh` - Unit tests

## Required Steps (In Order)

Before committing, run in this order (or use `./scripts/pre-commit/pre-commit.sh`):

### Foundation Checks
- [ ] **Linters**: `npm run lint` (React), `ruff check --select=F,E9,B . && mypy .` (Python), `golangci-lint run` (Go)
- [ ] **Security scans**: `npm audit`, `gosec ./...`, `bandit -r .` (per language)
- [ ] **No secrets**: Verify no credentials, API keys, tokens, or LDAP passwords in code

### Build & Integration Verification
- [ ] **Build & Run**: Verify code compiles and containers start successfully
  ```bash
  docker-compose -f docker-compose.yml build
  docker-compose -f docker-compose.yml up -d
  # Wait 10-15 seconds for services to start
  docker-compose logs --tail=20
  ```
- [ ] **Smoke tests** (mandatory, <2 min): `make smoke-test`
  - All containers build without errors
  - All containers start and remain healthy (DNS, DHCP, manager, frontend)
  - All API health endpoints respond with 200 status
  - DNS queries resolve correctly
  - DHCP lease assignment works
  - Time synchronization responds
  - See: [Testing Documentation - Smoke Tests](TESTING.md#smoke-tests)

### Feature Testing & Documentation
- [ ] **Mock data** (for testing features): Ensure 3-4 test items per feature via `make seed-mock-data`
  - Populate development database with realistic test data
  - Needed before UI testing and verification
  - Examples: 3-4 tokens, 3-4 DHCP pools, 2-3 time servers
  - See: [Testing Documentation - Mock Data Scripts](TESTING.md#mock-data-scripts)
- [ ] **Screenshots** (for UI changes): `node scripts/capture-screenshots.cjs`
  - Requires running `make dev` and `make seed-mock-data` first
  - Screenshots should showcase features with realistic mock data
  - Automatically removes old screenshots, captures fresh ones
  - Commit updated screenshots with feature/UI changes

### Comprehensive Testing
- [ ] **Unit tests**: `npm test`, `go test ./...`, `pytest`
  - Network isolated, mocked dependencies
  - Python: minimum 80% coverage with `pytest --cov`
  - Go: tests with `-race` flag enabled
  - Must pass before committing
  - See: [Testing Documentation - Unit Tests](TESTING.md#unit-tests)
- [ ] **Integration tests**: Component interaction verification
  - Tests with real database and service communication
  - Verify DNS+DB, DHCP+DNS, manager+services integration
  - See: [Testing Documentation - Integration Tests](TESTING.md#integration-tests)

### Finalization
- [ ] **Version updates**: Update `.version` if releasing new version
- [ ] **Documentation**: Update docs if adding/changing workflows
- [ ] **Docker builds**: Verify services use debian-slim base where appropriate
  - DNS server and manager: ubuntu:24.04 (for LDAP support with lber.h header)
  - DNS client and frontend: debian-slim or ubuntu:24.04 base
- [ ] **Cross-architecture**: (Optional) Test alternate architecture with QEMU
  - `docker buildx build --platform linux/arm64 .` (if on amd64)
  - `docker buildx build --platform linux/amd64 .` (if on arm64)
  - See: [Testing Documentation - Cross-Architecture Testing](TESTING.md#cross-architecture-testing)

## Language-Specific Commands

### Python (DNS Server & Manager)

**Linting**:
```bash
ruff format .                     # Format code + sort imports
ruff check --select=F,E9,B .      # Check style (blocking subset)
mypy .                            # Type checking
```

**Security**:
```bash
bandit -r .                      # Security scan
safety check                     # Dependency vulnerabilities
```

**Build & Run**:
```bash
python -m py_compile *.py        # Syntax check
pip install -r requirements.txt  # Dependencies
python app.py &                  # Verify it starts (then kill)
```

**Tests**:
```bash
pytest                           # All tests
pytest --cov                     # With coverage
pytest -v                        # Verbose output
```

### Go (DNS Client)

**Linting**:
```bash
golangci-lint run               # All linting checks
go vet ./...                    # Vet checks
```

**Security**:
```bash
gosec ./...                     # Security scan
```

**Build & Run**:
```bash
go build ./...                  # Compile all packages
go run main.go &                # Verify it starts (then kill)
```

**Tests**:
```bash
go test ./...                   # All tests
go test -race ./...             # With race detector
go test -cover ./...            # With coverage
```

### Node.js / JavaScript / TypeScript / ReactJS (Frontend)

**Linting**:
```bash
npm run lint                    # ESLint
# or
npx eslint .
```

**Security (REQUIRED)**:
```bash
npm audit                       # Check for vulnerabilities
npm audit fix                   # Auto-fix if possible
```

**Build & Run**:
```bash
npm run build                   # Compile/bundle
npm start &                     # Verify it starts (then kill)
# For React: npm run dev or npm run preview
```

**Tests**:
```bash
npm test                        # All tests
npm test -- --coverage         # With coverage
```

### Docker / Containers

**Lint Dockerfiles**:
```bash
hadolint Dockerfile
```

**Verify base image**:
```bash
# DNS server and manager: ubuntu:24.04 with LDAP support
grep -E "^FROM ubuntu:24.04" Dockerfile

# Other services: debian-slim or ubuntu:24.04
grep -E "^FROM (debian-slim|ubuntu:24.04)" Dockerfile
```

**Build & Run**:
```bash
docker build -t squawk-service:test .                    # Build image
docker run -d --name test-container squawk-service:test  # Start container
docker logs test-container                               # Check for errors
docker stop test-container && docker rm test-container   # Cleanup
```

**Docker Compose (if applicable)**:
```bash
docker-compose -f docker-compose.dev.yml build  # Build all services
docker-compose -f docker-compose.dev.yml up -d  # Start all services
docker-compose -f docker-compose.dev.yml logs   # Check for errors
docker-compose -f docker-compose.dev.yml down   # Cleanup
```

## Commit Rules

- **NEVER commit automatically** unless explicitly requested by the user
- **NEVER push to remote repositories** under any circumstances
- **ONLY commit when explicitly asked** - never assume commit permission
- **Wait for approval** before running `git commit`

## Security Scanning Requirements

### Before Every Commit
- **Run security audits on all modified packages**:
  - **Go packages**: Run `gosec ./...` on modified Go services (DNS client)
  - **Node.js packages**: Run `npm audit` on modified Node.js services (frontend)
  - **Python packages**: Run `bandit -r .` and `safety check` on modified Python services (DNS server, manager)
- **Do NOT commit if security vulnerabilities are found** - fix all issues first
- **Document vulnerability fixes** in commit message if applicable

### Vulnerability Response
1. Identify affected packages and severity
2. Update to patched versions immediately
3. Test updated dependencies thoroughly
4. Document security fixes in commit messages
5. Verify no new vulnerabilities introduced

## API Testing Requirements

Before committing changes to DNS server, DHCP service, or manager:

- **Create and run API testing scripts** for each modified service
- **Testing scope**: All new endpoints and modified functionality
- **Test files location**: `tests/api/` directory with service-specific subdirectories
  - `tests/api/dns-server/` - DNS server API tests
  - `tests/api/dhcp-manager/` - DHCP manager API tests
  - `tests/api/time-server/` - Time server API tests
  - `tests/api/manager/` - Manager service API tests
- **Run before commit**: Each test script should be executable and pass completely
- **Test coverage**: Health checks, authentication with tokens, CRUD operations, selective routing, error cases

**Example Test Commands**:
```bash
# DNS Server API tests
curl -H "Authorization: Bearer TOKEN" http://localhost:8080/dns/query?domain=example.com

# DHCP Manager API tests
curl http://localhost:8000/api/v1/dhcp/pools

# Time Server API tests
curl http://localhost:8080/health/time

# Manager service tests
curl http://localhost:8000/api/v1/tokens
```

## Token Validation Testing

Before committing changes to token or selective routing logic:

- [ ] **Test token validation**:
  - Valid token should allow DNS queries
  - Invalid token should be rejected
  - Expired token should be rejected
  - Inactive token should be rejected
  - Test wildcard permissions (`*`)
  - Test specific domain permissions
  - Test parent domain inheritance

- [ ] **Test selective routing**:
  - Token with permission should see correct DNS response
  - Token without permission should be denied or see different records
  - LDAP group membership should affect visible domains
  - Group-based routing should work correctly

- [ ] **Test permission boundaries**:
  - No privilege escalation (user token can't access admin functions)
  - Token can't access domains it doesn't have permission for
  - Permission revocation takes effect immediately

## Screenshot & Mock Data Requirements

### Prerequisites
Before capturing screenshots, ensure development environment is running with mock data:

```bash
make dev                   # Start all services
make seed-mock-data        # Populate with 3-4 test items per feature
```

### Capture Screenshots
For all UI changes, update screenshots to show current application state with realistic data:

```bash
node scripts/capture-screenshots.cjs
# Or via npm script if configured: npm run screenshots
```

### What to Screenshot
- **Dashboard** (main page with stats)
- **Token Management** page (list with 3-4 sample tokens)
- **DHCP Pools** page (4 pools showing different CIDR ranges)
- **Time Servers** page (2-3 servers showing PTP/NTP mix)
- **Selective Routing** page (group-based domain access)
- **Login page** (unauthenticated state)

### Commit Guidelines
- Automatically removes old screenshots and captures fresh ones
- Commit updated screenshots with relevant feature/UI/documentation changes
- Screenshots demonstrate feature purpose and functionality
- Helpful error message if login fails: "Ensure mock data is seeded"

## DNS/DHCP/Time Sync Specific Checks

Before committing changes to network services:

### DNS Server Changes
- [ ] Token validation logic works correctly
- [ ] Selective routing respects permissions
- [ ] DNS queries return correct record types (A, AAAA, MX, etc.)
- [ ] Threat intelligence blocks malicious domains
- [ ] Caching doesn't cause stale records
- [ ] Upstream DNS failover works
- [ ] LDAP authentication integrates properly

### DHCP Service Changes
- [ ] IP pools don't overlap
- [ ] Leases are properly allocated and tracked
- [ ] Reservations take precedence over pool allocation
- [ ] DHCP options (gateway, DNS, NTP) are correctly distributed
- [ ] Dynamic DNS (DDNS) updates coordinate with DNS service
- [ ] Lease renewal works correctly
- [ ] Lease expiry cleanup functions properly

### Time Synchronization Changes
- [ ] PTP (IEEE 1588) primary protocol responds correctly
- [ ] NTP (v4) fallback works when PTP unavailable
- [ ] Client time forwarding (port 123) works on all platforms
- [ ] OS time service interception (Windows W32Time, macOS timed, Linux chrony) works
- [ ] Fallback to public NTP servers functions properly
- [ ] Time offset caching reduces load
- [ ] Cross-architecture support for ARM64 and AMD64

## Common Issues Checklist

- [ ] No Python dependencies with `--break-system-packages` flag
- [ ] Python virtual environment created and activated in Dockerfile
- [ ] SQLAlchemy used only for schema initialization
- [ ] PyDAL used for all CRUD operations
- [ ] All database connections use connection pooling
- [ ] No hardcoded database credentials
- [ ] No mixed SQLAlchemy/PyDAL transactions
- [ ] All error handlers properly implemented
- [ ] LDAP integration tests pass (requires ubuntu:24.04)
- [ ] Token permissions checked on every DNS query
- [ ] DHCP lease conflicts detected and prevented
- [ ] Time sync drift monitoring active
- [ ] Cross-architecture Docker builds tested

## Example Pre-Commit Workflow

```bash
# 1. Make code changes
# 2. Test locally
npm run lint && npm test               # Frontend
pytest --cov && ruff check --select=F,E9,B . && bandit -r . # Python services
golangci-lint run && go test -race ./... # Go client

# 3. Run smoke tests
make smoke-test

# 4. Seed mock data and test manually
make seed-mock-data
# Test DNS queries, DHCP allocation, time sync

# 5. Run full pre-commit checklist
./scripts/pre-commit/pre-commit.sh

# 6. Fix any issues found
# 7. Verify all checks pass
# 8. Commit when ready
git add .
git commit -m "feat: describe your changes"
```

---

**Last Updated**: 2026-01-06
**Maintained by**: Squawk Team
