# Squawk - Claude Code Context

This document provides essential context for Claude Code operations on the Squawk project, an enterprise network infrastructure platform providing DNS, DHCP, and Time Synchronization services.

**Quick Summary**: Squawk is a multi-service network infrastructure solution (Python 3.13 server, Go 1.23 client, Python 3.13 manager, Node.js 18+ React UI) providing DNS-over-HTTPS, DHCP management, and Time Synchronization (PTP/NTP) with advanced threat intelligence, selective routing, and enterprise licensing. All development standards detailed in companion documentation; this file provides quick reference and project-specific context.

## Project Overview

**Squawk** is an enterprise network infrastructure platform featuring:

### Core Network Services
- **DNS**: Python 3.13 DNS-over-HTTPS server with RFC 1035 compliance, caching, and threat intelligence
- **DHCP**: IP address pool management, leases, reservations, and dynamic DNS updates
- **Time Sync**: PTP (IEEE 1588) primary with NTPv4 fallback for server-side; NTPv4/Chrony client-side forwarding

### Platform Components
- Go 1.23 cross-platform CLI client (Linux, macOS, Windows; AMD64, ARM64)
- Python 3.13 manager service (py4web backend with REST API)
- Node.js 18+ React frontend (web management console)
- Advanced threat intelligence with IOC blocking
- Selective DNS routing (per-user/group access control via token-based identity)
- Enterprise licensing system with three-tier feature gating
- mTLS authentication and multi-factor support
- Multi-tenant architecture for organizations

**Project Repository**: https://github.com/PenguinCloud/squawk-dns

## Core Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| DNS Server | Python 3.13 | Core DoH service with caching, threat intelligence, and selective routing |
| CLI Client | Go 1.23 | Cross-platform binary with token validation and offline caching |
| Manager | Python 3.13 + py4web | Administrative backend, API, configuration management |
| Frontend | Node.js 18+ + React | Web UI for management, monitoring, and analytics |
| Database | PostgreSQL (MySQL/SQLite) | User tokens, DNS zones, groups, audit logs |
| Cache | Valkey/Redis | Query caching and performance optimization |

**Key Libraries**:
- **python-ldap**: LDAP authentication (requires ubuntu:24.04 - has lber.h header)
- **Flask-Security-Too**: Authentication and authorization framework
- **PyDAL**: Database abstraction layer (mandatory for all operations)
- **SQLAlchemy**: Database initialization and schema migration only
- **cryptography**: TLS/mTLS certificate management with ECC support
- **prometheus_client**: Metrics and observability (Grafana compatible)
- **py4web**: Web framework with native REST API and authentication

## Project Structure

```
squawk-dns/
├── dns-server/              # Python DNS server (core service)
│   ├── bins/                # Implementation files
│   │   ├── server_optimized.py              # Community edition
│   │   ├── server_premium_integrated.py     # Enterprise edition
│   │   ├── selective_dns_routing.py         # Per-user DNS filtering
│   │   ├── ioc_manager.py                   # Threat intelligence
│   │   ├── cert_manager.py                  # mTLS certificates
│   │   ├── whois_manager.py                 # WHOIS lookup caching
│   │   ├── prometheus_metrics.py            # Metrics collection
│   │   └── systray.py                       # Desktop client
│   ├── requirements.txt
│   └── Dockerfile
├── dns-client/              # Go CLI client (cross-platform)
│   ├── main.go
│   ├── go.mod
│   └── Dockerfile
├── manager/                 # Manager service (Python 3.13 + React)
│   ├── app.py
│   ├── requirements.txt
│   ├── frontend/            # React UI (Node.js 18+)
│   └── Dockerfile
├── docs/                    # Documentation
│   ├── STANDARDS.md         # Development standards
│   ├── WORKFLOWS.md         # CI/CD workflow details
│   ├── RELEASE_NOTES.md     # Version history
│   └── OVERVIEW.md          # Architecture documentation
├── .github/workflows/       # GitHub Actions automation
├── docker-compose.yml       # Production configuration
├── docker-compose.dev.yml   # Development configuration
├── .version                 # Version tracking (vMajor.Minor.Patch)
├── Makefile                 # Build automation
├── CHANGELOG.md             # Detailed changelog
└── CLAUDE.md               # This file
```

## Version Management System

**Format**: Semantic versioning `vMajor.Minor.Patch` (e.g., `v2.1.0`)
- **Major**: Breaking changes, API incompatibilities
- **Minor**: New features, enhancements
- **Patch**: Bug fixes, security patches

**Key Characteristics**:
- All four services share same version number
- No epoch64 timestamps in version (unlike project-template standard)
- Stored in `.version` file (single line, plain text)

**CI/CD Tag Generation**:
1. **Version Release** (when `.version` changes):
   - Main: `service-name:vX.X.X-beta` (pre-release tag)
   - Feature branches: `service-name:vX.X.X-alpha`
   - Release tag: `service-name:vX.X.X` + `latest`
   - Auto-creates GitHub pre-release with extracted release notes

2. **Regular Build** (when service code changes, no version change):
   - Main: `service-name:beta-<epoch64>`
   - Feature branches: `service-name:alpha-<epoch64>`

**Update Process**:
1. Update `.version` file with new semantic version
2. Update `CHANGELOG.md` with changes
3. Create pull request to main
4. Merge to main (automatically triggers all release workflows)
5. GitHub Actions automatically builds all containers and publishes artifacts

## Enterprise Licensing System

**License Server**: `https://license.squawkdns.com` (sales-team access only)

**License Format**: `SQWK-XXXX-XXXX-XXXX-XXXX-YYYY` with checksum validation

**Three-Tier Model**:
1. **Community (Free)**: Basic DNS, 1 threat feed, mTLS, basic console
2. **Enterprise Self-Hosted ($5/user/month)**: All community + unlimited threat feeds, selective DNS routing, SAML/LDAP/SSO, multi-tenant, self-managed
3. **Enterprise Cloud-Hosted ($7/user/month)**: All self-hosted + managed infrastructure, 99.9% SLA, 24/7 support, global CDN, compliance reporting

**Feature Gating Implementation**:
- Check license status before enabling premium features
- Graceful degradation with upgrade prompts for unlicensed features
- Real-time validation via license server API
- Cached validation (24 hours for client, per-request for server) for offline resilience
- Environment variables: `USE_LICENSE_SERVER=true`, `LICENSE_SERVER_URL=https://license.squawkdns.com`

**Key Enterprise Benefit - Selective DNS Routing**:
Single endpoint serves different DNS responses based on user identity and group membership:
- Internal users: Private + public DNS access
- External users: Public DNS only
- Custom groups: Per-group DNS zone visibility
- Built on token-based identity + group membership model

## Critical Technical Requirements

### Docker Base Image (MANDATORY for Python Services)
**MUST use**: `ubuntu:24.04` LTS with Python 3.13 from deadsnakes PPA

**Reason**: python-ldap requires `lber.h` header (missing in Debian-slim)
- Ubuntu provides proper LDAP dev packages (libldap-dev, libsasl2-dev)
- Python 3.13 via deadsnakes PPA is reliable and secure
- **NEVER use** `python:3.13-slim` or Debian-based images

**Example Dockerfile Header**:
```dockerfile
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y \
    python3.13 python3.13-dev python3.13-venv \
    libldap-dev libsasl2-dev libldap2-dev \
    && rm -rf /var/lib/apt/lists/*
```

### Python Virtual Environment (MANDATORY)
ALL Python Dockerfile MUST include:
```dockerfile
RUN python3.13 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"
RUN /app/venv/bin/pip install --upgrade pip
RUN /app/venv/bin/pip install -r requirements.txt
```
- Prevents system package conflicts (e.g., blinker)
- Ensures clean dependency isolation
- Never use `--break-system-packages` flag

### Database Strategy (Hybrid Approach - MANDATORY)
- **SQLAlchemy**: Schema initialization and migrations only (not day-to-day ops)
- **PyDAL**: All CRUD operations and query management (primary interface)
- **DB_TYPE**: Environment variable (`postgres`, `mysql`, or `sqlite` only)
- **Connection Pooling**: Required for production (pool_size via env)

**MariaDB Galera Support** (when using MySQL with Galera):
- wsrep_sync_wait=1 for read-your-writes consistency
- innodb_autoinc_lock_mode=2 (interleaved) for Galera compatibility
- READ-COMMITTED transaction isolation level
- ALL tables MUST have explicit primary keys
- No large transactions (>1GB); chunk batch operations

### Four-Service CI/CD Architecture
- **DNS Server**: Python 3.13, pytest tests, bandit security scanning
- **DNS Client**: Go 1.23, -race enabled tests, gosec security scanning
- **Manager**: Python 3.13, pytest tests, bandit security scanning
- **Frontend**: Node.js 18+, Jest tests, npm audit security scanning
- **Unified Version**: All services version together
- **Independent Releases**: DNS Server and Client can release separately

## Development Standards (Abbreviated)

**Complete Reference**: See [docs/STANDARDS.md](docs/STANDARDS.md)

### Code Quality Requirements
- ✅ Passes linting (black, flake8, mypy for Python; golangci-lint, gosec for Go; ESLint for Node.js)
- ✅ 80%+ test coverage minimum
- ✅ Type hints mandatory (Python/Go/TypeScript)
- ✅ Security scanning passes (bandit/gosec/Trivy/npm audit)
- ✅ No hardcoded secrets or credentials
- ✅ Complete error handling
- ✅ Appropriate logging in place
- ✅ Documentation updated

### Pre-Commit Checklist
Before every commit:
1. **Linting**: `black . && isort . && flake8 . && mypy .` (Python)
2. **Security**: `bandit -r .` (Python), `gosec ./...` (Go), `npm audit` (Node.js)
3. **Tests**: `pytest` (Python), `go test -race ./...` (Go), `npm test` (Node.js) - all pass
4. **Coverage**: Verify ≥80%
5. **Docker**: Verify container builds successfully
6. **Secrets**: Scan for hardcoded credentials/tokens

### Critical Red Flags (NEVER commit if any present)
- Hardcoded database credentials
- Mixed SQLAlchemy/PyDAL transactions
- Unclosed database connections
- Missing error handling
- Unsupported DB_TYPE values
- No connection pooling in production code
- Tests skipped or commented out
- Hardcoded API keys, tokens, or secrets

## Service-Specific Standards

### DNS Server (Python 3.13)
- RFC 1035 compliance mandatory
- LDAP integration with proper DN handling
- Redis/Valkey caching with TTL management
- py4web web console with REST API
- Selective DNS routing with token validation
- Threat intelligence IOC blocking
- Prometheus metrics endpoint
- Async request handling
- mTLS certificate validation

### DNS Client (Go 1.23)
- Cross-platform support (Linux, macOS, Windows; AMD64, ARM64)
- TLS certificate validation
- Connection pooling and timeout handling
- CLI argument parsing with defaults
- License validation with 24-hour cache
- Graceful error handling and fallback logic
- Configuration file support

### Manager Service (Python 3.13)
- User and token lifecycle management
- Role-based access control (RBAC)
- Configuration distribution API
- Audit logging for compliance
- Database schema management
- py4web native REST API
- Permission-based visibility filtering

### DHCP Server (Python 3.13)
- IP pool management with CIDR notation
- Lease allocation and renewal
- Static reservations by MAC address
- DHCP options distribution (gateway, DNS, NTP, domain)
- Dynamic DNS (DDNS) integration
- Team-based pool access control
- Lease history and audit logging

### Time Server (Python 3.13)
- PTP (IEEE 1588) primary protocol for microsecond accuracy
- NTPv4 fallback for millisecond accuracy
- Stratum configuration and management
- Time source priority ordering
- Team-based time server access control
- Sync logging and drift monitoring

### Time Client (Go 1.23)
- NTPv4/Chrony local forwarder (port 123)
- OS time service interception (Windows W32Time, macOS timed, Linux chrony)
- Fallback to public NTP servers
- Time offset caching
- Cross-platform support

### Frontend (React 18+ with TypeScript)
- Responsive web interface
- Real-time status updates
- User authentication integration
- Token and group management UI
- Zone and record management
- Analytics dashboard
- WCAG 2.1 accessibility compliance

## Important Environment Variables

```bash
# Server Configuration
PORT=8080
MAX_WORKERS=100
MAX_CONCURRENT_REQUESTS=1000
ENABLE_MTLS=true
MTLS_ENFORCE=false
CACHE_ENABLED=true
CACHE_TTL=300

# Database (Hybrid: SQLAlchemy + PyDAL)
DB_TYPE=postgres           # postgres, mysql, sqlite only
DB_URL=postgresql://user:pass@host/squawk
DB_POOL_SIZE=10

# LDAP Authentication (Enterprise)
ENABLE_LDAP=true
LDAP_SERVER=ldap://ldap.company.com
LDAP_BASE_DN=dc=company,dc=com

# License Management
USE_LICENSE_SERVER=true
LICENSE_SERVER_URL=https://license.squawkdns.com
SQUAWK_LICENSE_KEY=SQWK-XXXX-XXXX-XXXX-XXXX-YYYY
SQUAWK_USER_TOKEN=<user-token>
SQUAWK_VALIDATE_ONLINE=true
SQUAWK_LICENSE_CACHE_TIME=1440

# Logging
LOG_LEVEL=INFO             # DEBUG, INFO, WARNING, ERROR
LOG_FORMAT=json            # json or text
ENABLE_SYSLOG=false
SYSLOG_HOST=localhost
SYSLOG_PORT=514

# TLS/Certificates
USE_ECC_KEYS=true
ECC_CURVE=SECP384R1
CA_VALIDITY_DAYS=3650
CERT_VALIDITY_DAYS=365

# Cache
VALKEY_URL=redis://localhost:6379
CACHE_PREFIX=squawk:dns:

# Threat Intelligence
ENABLE_BLACKLIST=false
BLACKLIST_UPDATE_HOURS=24

# DHCP Configuration
ENABLE_DHCP=true
DHCP_LISTEN_ADDRESS=0.0.0.0
DHCP_PORT=67
DHCP_LEASE_DEFAULT=86400       # Default lease duration (seconds)
DHCP_ENABLE_DDNS=true          # Dynamic DNS updates
DHCP_DNS_ZONE=internal.local   # Zone for DDNS updates

# Time Synchronization (Server)
ENABLE_TIME_SERVER=true
TIME_PTP_ENABLED=true          # IEEE 1588 PTP (primary)
TIME_PTP_DOMAIN=0
TIME_PTP_INTERFACE=eth0
TIME_NTP_ENABLED=true          # NTPv4 (fallback)
TIME_NTP_PORT=123
TIME_STRATUM=2
TIME_UPSTREAM_SERVERS=time.google.com,time.cloudflare.com

# Time Synchronization (Client)
TIME_FORWARD_ENABLED=true      # Forward local OS time requests
TIME_FORWARD_PORT=123
TIME_FALLBACK_SERVERS=pool.ntp.org,time.google.com
TIME_CACHE_OFFSET=true
```

## Git Workflow (MANDATORY RULES)

- **NEVER commit automatically** unless explicitly requested by user
- **NEVER push to remote repositories** under any circumstances
- **ONLY commit when explicitly asked** - never assume commit permission
- Use feature branches for development
- Require PR reviews before merge to main
- All CI checks must pass before merge

## Common Development Commands

```bash
# Development Setup
make setup                 # Install all dependencies
make dev                   # Start docker-compose development environment
make test                  # Run all tests (unit + integration)
make lint                  # Run all linting checks

# Build & Deploy
make docker-build          # Build all service containers
make docker-push           # Push containers to registry

# Version Management
cat .version               # View current version
# To release: edit .version, commit, merge to main
# GitHub Actions automatically creates release

# Debugging
docker-compose logs -f service-name
docker exec container-name bash
docker exec container-name python -c "import ldap; print('LDAP OK')"
```

## Troubleshooting Guide

| Issue | Solution |
|-------|----------|
| LDAP import errors | Use ubuntu:24.04 base image (python-ldap needs lber.h) |
| Virtual env conflicts | Ensure Dockerfile creates and activates `/app/venv` |
| Database connection fails | Check DB_TYPE, DB_URL, connection pooling config, PostgreSQL running |
| License validation fails | Verify LICENSE_SERVER_URL, network connectivity, license format (SQWK-...) |
| Port conflicts | Check docker-compose port mappings, existing containers |
| Container build fails | Review Dockerfile Ubuntu base image, Python 3.13 version, apt-get packages |
| LDAP bind errors | Verify LDAP_SERVER, LDAP_BASE_DN, LDAP credentials in env |
| Token validation fails | Check token format, license server connectivity, token expiration |
| DHCP not assigning IPs | Check DHCP_PORT 67/68 not blocked, pool has available addresses, MAC not blacklisted |
| DHCP lease conflicts | Verify no overlapping pools, check reservation conflicts, review lease logs |
| PTP sync failures | Verify TIME_PTP_INTERFACE correct, network supports multicast, grandmaster reachable |
| NTP port 123 blocked | Check firewall rules, verify TIME_NTP_PORT, try alternate upstream servers |
| Time drift on clients | Enable TIME_CACHE_OFFSET, check TIME_FALLBACK_SERVERS connectivity |

## Important Notes

- **License Portal**: https://license.squawkdns.com/sales/dashboard (sales team only)
- **Documentation Domain**: All docs reference squawkdns.com
- **Web Console**: Default at http://localhost:8000/dns_console
- **API Health**: GET http://localhost:8080/health (DNS server availability)
- **Metrics**: GET http://localhost:8080/metrics (Prometheus format)
- **Multi-server Support**: Clients support failover to multiple DNS servers
- **WHOIS Caching**: Domain and IP lookups cached in PostgreSQL (monthly cleanup)
- **IOC Overrides**: Per-token allow/block rules for threat intelligence
- **System Tray**: Desktop client with health monitoring and DNS fallback
- **DHCP-DNS Integration**: DHCP leases can auto-register in DNS zones (DDNS)
- **Time Sync Ports**: PTP uses 319/320 UDP, NTP uses 123 UDP
- **Time Client Forwarding**: Similar to DNS forwarding, intercepts OS time requests on port 123

## Complete Documentation References

- **[Development Standards](docs/STANDARDS.md)** - Code quality, testing, security, all languages
- **[CI/CD Workflows](docs/WORKFLOWS.md)** - Build automation, release process, version management
- **[Release Notes](docs/RELEASE_NOTES.md)** - Version history and feature changelog
- **DNS Server README**: dns-server/README.md
- **DNS Client README**: dns-client/README.md
- **Manager README**: manager/README.md
- **Architecture Overview**: docs/OVERVIEW.md

---

**Template Version**: Gold Standard (matches project-template design patterns)
**Last Updated**: 2026-01-05
**Maintained by**: Squawk Team
**License**: Limited AGPL3
