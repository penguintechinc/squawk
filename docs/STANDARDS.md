# Development Standards

This document consolidates all development standards, patterns, and requirements for Squawk DNS, covering all four integrated services (DNS Server, DNS Client, Manager Service, Frontend).

## Table of Contents

1. [Language Selection & Versioning](#language-selection--versioning)
2. [Code Quality Standards](#code-quality-standards)
3. [Service-Specific Standards](#service-specific-standards)
4. [Security Standards](#security-standards)
5. [Testing Requirements](#testing-requirements)
6. [Database Standards](#database-standards)
7. [API Standards](#api-standards)
8. [Docker Standards](#docker-standards)
9. [Git Workflow](#git-workflow)
10. [CI/CD Compliance](#cicd-compliance)

---

## Language Selection & Versioning

### Language Stack

**Python 3.13** - DNS Server, Manager Service
- RFC 1035 DNS protocol implementation
- LDAP directory integration
- Threat intelligence and IOC management
- Web console (py4web framework)
- Default choice for all services unless performance-critical

**Go 1.23** - DNS Client (CLI)
- Cross-platform binary (Linux, macOS, Windows; AMD64, ARM64)
- High-performance DNS queries
- Network efficiency
- Used ONLY for client-side tool (not server-side)

**Node.js 18+** - Frontend (React)
- Web UI for management console
- Real-time updates and dashboards
- React 18+ with TypeScript
- Responsive design and accessibility

### Version Management

**Format**: Semantic versioning `vMajor.Minor.Patch` (e.g., `v2.1.0`)
- **Major**: Breaking API changes, incompatibilities
- **Minor**: New features, enhancements, new endpoints
- **Patch**: Bug fixes, security patches, documentation

**Characteristics**:
- ALL four services share same version number
- No epoch64 timestamps in version file (unlike project-template)
- Single `.version` file in repository root
- Format: Plain text, single line, no 'v' prefix stored
- Updated before release: `echo "2.1.0" > .version`

**Versioning Tools**:
- Automatic version tagging in CI/CD
- Semantic versioning enforced in GitHub Actions
- Pre-release tags: `vX.X.X-beta` (main) / `vX.X.X-alpha` (features)
- Release tags: `vX.X.X` + `latest`

---

## Code Quality Standards

### Universal Requirements

All code MUST:
- ✅ Pass linting without exceptions
- ✅ Achieve 80%+ test coverage
- ✅ Include comprehensive error handling
- ✅ Have appropriate logging
- ✅ Follow security-first design
- ✅ Have type hints (Python/Go/TypeScript)
- ✅ Avoid hardcoded credentials
- ✅ Follow PEP 8 (Python), Go idioms, ESLint rules

### Python 3.13 Standards

**Required Tools**:
- black (code formatting)
- isort (import sorting)
- flake8 (linting)
- mypy (type checking)
- bandit (security analysis)
- pytest (unit testing)

**Style Guidelines**:
```python
"""Module docstring describing purpose."""

from typing import Optional, List, Dict
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass(slots=True)
class DNSRecord:
    """Represents a DNS record."""
    domain: str
    record_type: str
    value: str
    ttl: int

def resolve_dns(domain: str, record_type: str = "A") -> Optional[str]:
    """Resolve DNS record for domain.

    Args:
        domain: Domain name to resolve
        record_type: DNS record type (A, AAAA, MX, etc.)

    Returns:
        Resolved IP address or None if not found

    Raises:
        ValueError: If domain format is invalid
    """
    if not domain:
        raise ValueError("Domain cannot be empty")

    logger.info(f"Resolving {record_type} record for {domain}")
    # Implementation
```

**Requirements**:
- PEP 8 style guide
- PEP 257 docstrings (module, class, function level)
- PEP 484 type hints (mandatory for all functions)
- Dataclasses with `slots=True` for memory efficiency
- Asyncio for I/O-bound operations
- Threading for blocking I/O
- Multiprocessing for CPU-bound tasks

### Go 1.23 Standards

**Required Tools**:
- golangci-lint (comprehensive linting)
- gosec (security analysis)
- go fmt (code formatting)
- go test -race (race detector enabled)

**Style Guidelines**:
```go
package main

import (
    "context"
    "errors"
    "log"
)

type DNSQuery struct {
    Domain    string
    Type      string
    Timeout   int
}

type Resolver interface {
    Resolve(ctx context.Context, query DNSQuery) (string, error)
}

func Resolve(ctx context.Context, domain, recordType string) (string, error) {
    if domain == "" {
        return "", errors.New("domain cannot be empty")
    }

    log.Printf("Resolving %s record for %s", recordType, domain)
    // Implementation
    return "", nil
}
```

**Requirements**:
- Go formatting (gofmt -s)
- Proper error handling (no panic for recoverable errors)
- Interface-based design
- Context propagation for cancellation/timeouts
- Race detector enabled in tests
- Cross-platform compatibility (build for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64, windows/arm64)

### TypeScript/React Standards

**Required Tools**:
- ESLint (linting)
- Prettier (code formatting)
- TypeScript (type checking)
- Jest (testing)
- npm audit (dependency security)

**Component Pattern**:
```typescript
/**
 * DNS resolver component for web interface
 */

import React, { useState } from 'react';
import type { DNSRecord, QueryResult } from './types';

interface ResolverProps {
    onResolve: (domain: string) => Promise<DNSRecord[]>;
}

/**
 * DNSResolver provides user interface for DNS queries
 */
export const DNSResolver: React.FC<ResolverProps> = ({ onResolve }) => {
    const [domain, setDomain] = useState<string>('');
    const [results, setResults] = useState<DNSRecord[]>([]);

    const handleResolve = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!domain.trim()) {
            console.error('Domain required');
            return;
        }

        try {
            const data = await onResolve(domain);
            setResults(data);
        } catch (error) {
            console.error('Resolution failed:', error);
        }
    };

    return (
        <form onSubmit={handleResolve}>
            {/* JSX content */}
        </form>
    );
};
```

**Requirements**:
- TypeScript mandatory (no untyped .js files)
- Props typing via interfaces
- Async/await for async operations
- Error boundary components
- 80%+ test coverage with Jest
- Functional components with hooks

---

## Service-Specific Standards

### DNS Server (Python 3.13)

**Key Requirements**:
- RFC 1035 DNS protocol compliance
- LDAP integration with proper DN handling
- Redis/Valkey caching with TTL management
- py4web web framework for console
- PyDAL (mandatory) + SQLAlchemy (init only) for database
- Selective DNS routing by user/group
- Threat intelligence IOC blocking
- Prometheus metrics endpoint
- Async request handling
- mTLS certificate validation

**Critical Implementation Files**:
- `dns-server/bins/server_optimized.py` - Community edition server
- `dns-server/bins/server_premium_integrated.py` - Enterprise edition
- `dns-server/bins/selective_dns_routing.py` - Per-user DNS filtering
- `dns-server/bins/ioc_manager.py` - Threat intelligence management
- `dns-server/bins/cert_manager.py` - mTLS certificate handling
- `dns-server/requirements.txt` - All Python dependencies

**Docker Requirement** (MANDATORY):
- Base image: `ubuntu:24.04` (for python-ldap lber.h header)
- Python: 3.13 via deadsnakes PPA
- Virtual environment: `/app/venv` with all dependencies

### DNS Client (Go 1.23)

**Key Requirements**:
- Cross-platform support (Windows, macOS, Linux; AMD64, ARM64)
- TLS certificate validation
- Connection pooling and timeout handling
- CLI argument parsing with sensible defaults
- License validation with 24-hour offline cache
- Graceful error handling and fallback logic
- Configuration file support
- Prometheus metrics (optional)

**Critical Files**:
- `dns-client/main.go` - Entry point
- `dns-client/go.mod` - Dependency management (Go 1.23)
- `dns-client/Dockerfile` - Container for packaging

**Cross-Compilation Targets**:
- Linux: amd64, arm64
- macOS: amd64, arm64 (can create universal binary)
- Windows: amd64, arm64

### Manager Service (Python 3.13)

**Key Requirements**:
- User and token lifecycle management
- Role-based access control (RBAC)
- Configuration distribution API
- Audit logging for compliance
- Database schema management (SQLAlchemy init + PyDAL ops)
- py4web native REST API
- Permission-based visibility filtering

**Critical Files**:
- `manager/app.py` - Application entry point
- `manager/models/` - Data models and schema
- `manager/requirements.txt` - Dependencies

### Frontend (React 18+ with TypeScript)

**Key Requirements**:
- Responsive web interface
- Real-time status updates via WebSocket or polling
- User authentication integration
- Token and group management UI
- Zone and record management
- Analytics dashboard
- WCAG 2.1 accessibility compliance
- Error handling with user feedback

**Critical Files**:
- `manager/frontend/package.json` - Dependencies
- `manager/frontend/src/` - React components
- `manager/frontend/tsconfig.json` - TypeScript configuration

---

## Security Standards

### Input Validation

**MANDATORY**: ALL external inputs MUST be validated

**DNS Server Validation**:
```python
import re

# Validate domain format (RFC 1035 compliant)
def validate_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        raise ValueError("Invalid domain length")

    pattern = r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$'
    if not re.match(pattern, domain.lower()):
        raise ValueError("Invalid domain format")
    return True

# Validate DNS record type
ALLOWED_TYPES = {'A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS', 'SOA', 'PTR'}
if record_type not in ALLOWED_TYPES:
    raise ValueError(f"Unsupported record type: {record_type}")
```

**DNS Client Validation**:
```go
import "net"

// Validate domain length (RFC 1035 limit)
if len(domain) > 253 {
    return fmt.Errorf("domain length exceeds 253 characters")
}

// Validate IP addresses
if ip := net.ParseIP(ipStr); ip == nil {
    return fmt.Errorf("invalid IP address: %s", ipStr)
}
```

### Authentication & Authorization

**Requirements**:
- Token-based authentication for all API endpoints
- LDAP integration for enterprise authentication
- Role-based access control (RBAC)
- Session timeouts (configurable via env)
- Secure password hashing (bcrypt minimum, argon2id preferred)
- Multi-factor authentication support (via Flask-Security-Too)
- Audit logging of all access attempts
- JWT token validation with expiration

**License Enforcement**:
- Check license status before enabling premium features
- Graceful degradation for unlicensed features
- Real-time validation via license server API
- Cached validation for offline resilience

### Dependency Security

**Python**:
```bash
# Check for vulnerabilities before every commit
pip install bandit safety
bandit -r dns-server/ dns-client/ manager/
safety check
```

**Go**:
```bash
# Verify Go module security
go mod audit
gosec ./...
```

**Node.js**:
```bash
# Check npm package vulnerabilities
npm audit --audit-level=high
npm audit fix  # If safe
```

### Secrets Management

**MANDATORY RULES**:
- NEVER commit `.env` files
- NEVER hardcode credentials in source
- Use environment variables exclusively
- Rotate credentials regularly
- Audit secret access
- Use GitHub Secrets for CI/CD

**Files to Exclude** (ensure in .gitignore):
```
.env
.env.local
.env.*.local
certs/private/
tokens/
secrets/
*.key
*.pem
```

### HTTPS/TLS

**Requirements**:
- TLS 1.2 minimum (prefer TLS 1.3)
- Valid certificates for all services
- Certificate rotation automation
- HTTPS enforcement
- HSTS headers on all responses
- Certificate pinning (where applicable)

**mTLS Configuration**:
- Enable via `ENABLE_MTLS=true`
- Enforce via `MTLS_ENFORCE=true` (requires client cert)
- CA certificate path: `MTLS_CA_CERT`
- ECC keys preferred: `USE_ECC_KEYS=true`

---

## Testing Requirements

### Unit Testing

**Python (DNS Server, Manager)**:
```python
def test_resolve_dns_valid_domain():
    """Test DNS resolution for valid domain."""
    result = resolve_dns("example.com", "A")
    assert result is not None
    assert re.match(r'^\d+\.\d+\.\d+\.\d+$', result)

def test_resolve_dns_invalid_domain():
    """Test DNS resolution raises for invalid domain."""
    with pytest.raises(ValueError):
        resolve_dns("invalid..domain", "A")
```

**Go (DNS Client)**:
```go
func TestResolve(t *testing.T) {
    tests := []struct {
        name    string
        domain  string
        wantErr bool
    }{
        {name: "valid", domain: "example.com", wantErr: false},
        {name: "invalid", domain: "invalid..com", wantErr: true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            _, err := Resolve(context.Background(), tt.domain, "A")
            if (err != nil) != tt.wantErr {
                t.Errorf("Resolve() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```

**JavaScript (Frontend)**:
```typescript
describe('DNSResolver', () => {
    it('should resolve valid domain', async () => {
        const mockResolve = jest.fn().mockResolvedValue([
            { domain: 'example.com', type: 'A', value: '93.184.216.34' }
        ]);

        render(<DNSResolver onResolve={mockResolve} />);
        const input = screen.getByRole('textbox');
        await userEvent.type(input, 'example.com');
        await userEvent.click(screen.getByRole('button'));

        expect(mockResolve).toHaveBeenCalledWith('example.com');
    });
});
```

**Coverage Targets**:
- Minimum 80% code coverage
- 100% for security-critical code
- All error paths tested
- Edge cases covered
- No external network calls in unit tests (use mocks)

### Integration Testing

**Scope**:
- Service-to-service communication (DNS client ↔ DNS server)
- Database operations (CRUD with PyDAL)
- LDAP authentication flow
- Redis/Valkey cache operations
- License server validation
- License feature gating

### Docker Testing

**Validation**:
- Image builds successfully without errors
- Required binaries present and executable
- Correct language versions installed
- Required libraries available (python-ldap for Python containers)
- Service ports accessible

---

## Database Standards

### Hybrid Database Approach (MANDATORY)

Squawk implements a hybrid strategy combining SQLAlchemy and PyDAL:

**SQLAlchemy** - Initialization & Migrations Only:
- Schema definition and table creation
- Complex database migrations
- Relationship mapping and constraints
- Initial data seeding
- NOT used for day-to-day operations

**PyDAL** - Day-to-Day Operations (PRIMARY INTERFACE):
- All CRUD operations
- Query building and execution
- Dynamic table access
- Real-time data manipulation
- Connection pooling management
- Transaction handling

### Database Types

**Supported DB_TYPE Values** (via environment variable):
- `postgres` - PostgreSQL (recommended for production)
- `mysql` - MySQL/MariaDB (supports Galera clustering)
- `sqlite` - SQLite (development/testing only)

**Configuration Example**:
```bash
export DB_TYPE=postgres
export DB_URL=postgresql://user:password@localhost/squawk
export DB_POOL_SIZE=10
```

### PyDAL Usage Pattern

```python
from pydal import DAL, Field

# Initialize PyDAL with connection pooling
db = DAL(
    db_url=os.getenv('DB_URL'),
    pool_size=int(os.getenv('DB_POOL_SIZE', '10')),
    migrate_enabled=True,
    check_reserved=['all'],
    lazy_tables=True
)

# Define tables
db.define_table('tokens',
    Field('token', 'string', unique=True),
    Field('user_id', 'integer'),
    Field('created_at', 'datetime', default=datetime.now),
    migrate=True
)

# CRUD operations with PyDAL
new_token = db.tokens.insert(token='...', user_id=123)
tokens = db(db.tokens.user_id == 123).select()
db(db.tokens.id == token_id).update(expires_at=expiry)
db(db.tokens.id == token_id).delete()
db.commit()
```

### Connection Pooling

**Requirements**:
- MANDATORY for production
- Configured via `DB_POOL_SIZE` environment variable
- Default: 10 connections
- PyDAL handles pool management automatically
- Retry logic with exponential backoff

### MariaDB Galera Cluster Requirements

When using MySQL with Galera for high availability:

**Configuration** (mandatory in my.cnf):
```ini
[mysqld]
wsrep_on=ON
wsrep_provider=/usr/lib/galera/libgalera_smm.so
wsrep_cluster_address="gcomm://node1,node2,node3"
wsrep_node_address="<LOCAL_IP>"
wsrep_node_name="<NODE_NAME>"
wsrep_sync_wait=1
innodb_autoinc_lock_mode=2
binlog_format=ROW
log_bin=ON
```

**Squawk Requirements**:
- Read-committed isolation level (required)
- ALL tables MUST have explicit primary keys
- Avoid large transactions (>1GB); chunk operations
- Implement retry logic for WSREP_NOT_READY errors

---

## API Standards

### REST API Versioning

**URL Structure** (MANDATORY):
- Format: `/api/v{major}/endpoint`
- Examples: `/api/v1/users`, `/api/v1/auth/login`
- Semantic versioning for major versions only
- Version prefix in URL path (never query parameters)

**Version Lifecycle**:
- Current version: Actively developed, fully supported
- Previous version (N-1): Bug fixes, security patches only
- Older versions (N-2+): Deprecated with warning headers

**Deprecation Headers**:
```python
response.headers['Deprecation'] = 'true'
response.headers['Sunset'] = 'Sun, 01 Jan 2026 00:00:00 GMT'
response.headers['Link'] = '</api/v2/endpoint>; rel="successor-version"'
response.headers['Warning'] = '299 - "v1 API is deprecated, use v2 instead"'
```

### Protocol Support (MANDATORY)

All services MUST support:
- REST API with JSON (HTTP/1.1, HTTP/2, HTTP/3/QUIC optional)
- gRPC (optional but recommended for high-performance)
- Health check endpoints: `/health` or `/healthz`
- Prometheus metrics endpoint: `/metrics`

---

## Docker Standards

### Base Images

**Python Services** (MANDATORY):
```dockerfile
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y \
    python3.13 python3.13-dev python3.13-venv \
    libldap-dev libsasl2-dev libldap2-dev \
    && rm -rf /var/lib/apt/lists/*
```

**Go Services**:
```dockerfile
FROM golang:1.23-alpine AS builder
FROM debian:bookworm-slim AS runtime
```

### Multi-Stage Builds

```dockerfile
# Build stage
FROM ubuntu:24.04 AS builder
RUN python3.13 -m venv /app/venv
COPY requirements.txt .
RUN /app/venv/bin/pip install -r requirements.txt

# Runtime stage
FROM ubuntu:24.04
COPY --from=builder /app/venv /app/venv
ENV PATH="/app/venv/bin:$PATH"
```

### Docker Compose Standards

**Development** (docker-compose.dev.yml):
- Use named Docker networks (not host ports when possible)
- Only expose necessary ports
- Mount source code as volumes
- Use environment files for configuration

**Production** (docker-compose.yml):
- No hardcoded credentials
- Use docker secrets or environment variables
- Resource limits defined
- Health checks for all services

---

## Git Workflow

**MANDATORY RULES**:
- **NEVER commit automatically** unless explicitly requested
- **NEVER push to remote** under any circumstances
- **ONLY commit when explicitly asked** by user
- Use feature branches for development
- Require PR reviews before merge to main
- All CI checks MUST pass before merge

**Commit Message Format**:
- First line: Concise summary (50 chars max)
- Blank line
- Detailed explanation (if needed)
- Reference related issues: "Fixes #123"
- Sign-off: "Signed-off-by: Name <email>"

---

## CI/CD Compliance

**Pre-Commit Requirements**:
1. **Linting**: black, isort, flake8, mypy (Python)
2. **Security**: bandit (Python), gosec (Go), npm audit (Node.js)
3. **Tests**: pytest, go test -race, Jest - all pass
4. **Coverage**: Verify ≥80%
5. **Docker**: Build successfully
6. **Secrets**: Scan for hardcoded credentials

**Build Naming Convention**:
- Version release: `service:vX.X.X-beta` (main) / `vX.X.X-alpha` (features)
- Regular build: `service:beta-<epoch64>` (main) / `alpha-<epoch64>` (features)
- Release tag: `service:vX.X.X` + `latest`

**Mandatory Security Scanning**:
- bandit (Python): HIGH/CRITICAL findings block build
- gosec (Go): HIGH/CRITICAL findings block build
- npm audit (Node.js): HIGH/CRITICAL findings block build
- Trivy (Docker images): HIGH/CRITICAL findings block deployment

---

## Quality Checklist

Before committing, verify:
- ✅ Code passes local linting
- ✅ Tests pass locally (80%+ coverage)
- ✅ Security scan passes (no HIGH/CRITICAL)
- ✅ No hardcoded secrets
- ✅ Error handling complete
- ✅ Logging appropriate
- ✅ Documentation updated
- ✅ Database schema migrations included
- ✅ Docker builds successfully
- ✅ Version bumped (if applicable)

Before creating PR:
- ✅ Branch created from develop
- ✅ All commits are clean
- ✅ Commit messages clear and descriptive
- ✅ Related tests included

Before merging PR:
- ✅ All CI checks pass
- ✅ Approved by at least one reviewer
- ✅ Conflicts resolved
- ✅ Documentation complete
- ✅ CHANGELOG.md updated
- ✅ `.version` updated (if releasing)

---

## Tools Reference

| Tool | Language | Purpose | Command |
|------|----------|---------|---------|
| black | Python | Formatting | `black .` |
| isort | Python | Import sorting | `isort .` |
| flake8 | Python | Linting | `flake8 .` |
| mypy | Python | Type checking | `mypy .` |
| bandit | Python | Security | `bandit -r .` |
| pytest | Python | Testing | `pytest --cov=.` |
| golangci-lint | Go | Linting | `golangci-lint run` |
| gosec | Go | Security | `gosec ./...` |
| go test | Go | Testing | `go test -v -race ./...` |
| ESLint | TypeScript | Linting | `npm run lint` |
| Prettier | TypeScript | Formatting | `npm run format` |
| Jest | TypeScript | Testing | `npm test` |
| npm audit | Node.js | Security | `npm audit --audit-level=high` |

---

**Last Updated**: 2025-12-18
**Maintained by**: Squawk DNS Team
**Related**: [CLAUDE.md](../CLAUDE.md), [WORKFLOWS.md](WORKFLOWS.md)
