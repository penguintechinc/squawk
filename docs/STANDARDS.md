# Squawk DNS Project Development & CI/CD Standards

This document outlines development standards, code quality requirements, and CI/CD compliance for Squawk DNS and its four integrated services.

## Table of Contents

1. [Version Management](#version-management)
2. [Code Quality Standards](#code-quality-standards)
3. [Service-Specific Standards](#service-specific-standards)
4. [Security Standards](#security-standards)
5. [Testing Standards](#testing-standards)
6. [CI/CD Compliance](#cicd-compliance)
7. [Documentation Standards](#documentation-standards)

## Version Management

### Version File Format

Squawk uses semantic versioning: `vMajor.Minor.Patch`

**Examples**:
- `v2.1.0` - Current release
- `v2.0.0` - Major release (breaking changes)
- `v2.0.5` - Patch release (bug fixes)

**Note**: Unlike some projects, Squawk version file does NOT include Epoch64 timestamps for build identification.

### Version Increment Rules

| Type | Change | Example |
|------|--------|---------|
| Major | Breaking API changes, removed features | v1.x.x → v2.0.0 |
| Minor | New features, enhancements | v2.0.x → v2.1.0 |
| Patch | Bug fixes, security patches | v2.0.0 → v2.0.1 |

### Synchronized Service Versioning

All four services share the same version:
- DNS Server uses `.version`
- DNS Client uses `.version`
- Manager Service uses `.version`
- Frontend Service uses `.version`

**Multi-Release Strategy**:
- DNS Server can release independently via `server-release.yml`
- DNS Client can release independently via `go-client-release.yml`
- Synchronized releases for major versions
- Feature branches per component

## Code Quality Standards

### Universal Requirements

All code MUST:
- ✅ Pass linting without exceptions
- ✅ Include comprehensive error handling
- ✅ Have appropriate logging
- ✅ Follow security-first design
- ✅ Have tests covering critical paths
- ✅ Avoid hardcoded credentials
- ✅ Use typed variables

### Python Standards (DNS Server, Manager)

**Version**: Python 3.13

**Required Tools**:
- black (code formatting)
- isort (import sorting)
- flake8 (linting)
- mypy (type checking)
- bandit (security)
- pytest (testing)

**Code Style Guidelines**:

```python
"""Module docstring describing service purpose."""

from typing import Optional, Dict, List
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class DNSRecord:
    """Represents a DNS record with domain and IP."""
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

**Standards**:
- PEP 8 code style
- PEP 257 docstrings
- PEP 484 type hints (mandatory)
- 80%+ test coverage
- No external network calls in unit tests
- Mock all external dependencies

**Special Considerations**:
- LDAP module (python-ldap) requires ubuntu:24.04 base image
- Virtual environment mandatory in Docker
- Asyncio patterns for high concurrency
- PyDAL for database abstraction

### Go Standards (DNS Client)

**Version**: Go 1.23+

**Required Tools**:
- golangci-lint
- gosec
- go fmt
- go vet
- go test

**Code Style Guidelines**:

```go
package main

import (
    "context"
    "errors"
    "fmt"
    "log"
)

// DNSQuery represents a DNS query request
type DNSQuery struct {
    Domain    string
    Type      string
    Timeout   int
}

// Resolver handles DNS resolution
type Resolver interface {
    Resolve(ctx context.Context, query DNSQuery) (string, error)
}

// Resolve queries DNS server for domain
func Resolve(ctx context.Context, domain, recordType string) (string, error) {
    if domain == "" {
        return "", errors.New("domain cannot be empty")
    }

    log.Printf("Resolving %s record for %s", recordType, domain)
    // Implementation
    return "", nil
}
```

**Standards**:
- Go formatting (gofmt -s)
- Error handling mandatory
- Interface-based design
- 80%+ test coverage
- Race detector enabled: `go test -race`
- Cross-platform compatibility

**Cross-Compilation**:
- Linux: amd64, arm64
- macOS: amd64, arm64 (universal binary)
- Windows: amd64, arm64

### JavaScript/Node.js Standards (Frontend, Manager)

**Version**: Node.js 18+, TypeScript

**Required Tools**:
- ESLint
- Prettier
- TypeScript
- Jest
- npm audit

**Code Style Guidelines**:

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

**Standards**:
- TypeScript mandatory (no .js files in type-sensitive code)
- Type annotations required for all functions
- 80%+ test coverage with Jest
- Async/await for async operations
- Error boundary components
- Props typing via interfaces

## Service-Specific Standards

### DNS Server (Python)

**Key Requirements**:
- RFC 1035 DNS protocol compliance
- LDAP integration for authentication
- Redis/Valkey caching support
- py4web web framework
- PyDAL database abstraction
- Async request handling
- Prometheus metrics endpoint
- Comprehensive logging

**Critical Files**:
- `dns-server/bins/server_optimized.py` - Main server
- `dns-server/requirements.txt` - Dependencies
- `dns-server/Dockerfile` - Container definition

**Security Standards**:
- Input validation for all DNS queries
- Rate limiting implementation
- mTLS certificate validation
- Token-based authentication
- SQL injection prevention via PyDAL
- LDAP injection prevention

### DNS Client (Go)

**Key Requirements**:
- Query DNS servers efficiently
- Support multiple record types
- Connection pooling
- Configuration file support
- CLI argument parsing
- Cross-platform binary distribution
- Graceful error handling

**Critical Files**:
- `dns-client/go.mod` - Dependency management
- `dns-client/main.go` - Entry point
- `dns-client/cmd/` - Command implementations

**Security Standards**:
- TLS certificate validation
- Input sanitization
- Secure credential handling
- No hardcoded secrets

### Manager Service (Python)

**Key Requirements**:
- User and organization management
- Token lifecycle management
- Configuration distribution
- API endpoint management
- Role-based access control
- Audit logging
- Database schema management

**Critical Files**:
- `manager/app.py` - Application entry
- `manager/models/` - Data models
- `manager/requirements.txt` - Dependencies

### Frontend Service (JavaScript/React)

**Key Requirements**:
- Responsive web interface
- Real-time status updates
- User authentication integration
- Configuration management UI
- Analytics dashboard
- Error handling and notifications
- Accessibility compliance (WCAG 2.1)

**Critical Files**:
- `manager/frontend/package.json` - Dependencies
- `manager/frontend/src/` - Source code
- `manager/frontend/tsconfig.json` - TypeScript config

## Security Standards

### Input Validation

**Rule**: ALL external inputs MUST be validated

**DNS Server Examples**:
```python
# Validate domain format
if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$', domain):
    raise ValueError("Invalid domain format")

# Validate DNS record type
allowed_types = ['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS', 'SOA']
if record_type not in allowed_types:
    raise ValueError(f"Unsupported record type: {record_type}")
```

**DNS Client Examples**:
```go
// Validate domain
if len(domain) > 253 {
    return fmt.Errorf("domain length exceeds 253 characters")
}

// Validate IP addresses
if !net.ParseIP(ip).IsValid() {
    return fmt.Errorf("invalid IP address: %s", ip)
}
```

### Authentication & Authorization

**Requirements**:
- Token-based authentication for API
- LDAP integration for enterprise auth
- Role-based access control (RBAC)
- Session timeouts
- Secure password hashing (bcrypt minimum)
- Multi-factor authentication support
- Audit logging of access attempts

### Dependency Security

**Python**:
```bash
# Check for vulnerabilities
pip install safety
safety check

# Update bandit config
# .bandit configuration for exclusions
```

**Go**:
```bash
# Check for vulnerabilities
go mod audit

# Update gosec rules
gosec -conf .gosec.json ./...
```

**Node.js**:
```bash
# Check for vulnerabilities
npm audit

# Fix automatically if safe
npm audit fix

# Review before fixing
npm audit fix --audit-level=high
```

### Secrets Management

**Rules**:
- NEVER commit `.env` files
- Use environment variables for secrets
- Rotate credentials regularly
- Audit secret access
- Use GitHub Secrets for CI/CD
- Encrypt sensitive data at rest

**Files to Exclude**:
```gitignore
.env
.env.local
.env.*.local
certs/private/
tokens/
secrets/
```

### HTTPS/TLS

**Requirements**:
- TLS 1.2 minimum (prefer TLS 1.3)
- Valid certificates for all services
- Certificate rotation automation
- HTTPS enforcement
- HSTS headers
- Certificate pinning (where applicable)

## Testing Standards

### Unit Testing

**Python (DNS Server)**:
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

### Integration Testing

**Scope**:
- Service-to-service communication
- Database operations
- LDAP authentication flow
- Cache operations
- External API integration

### Docker Testing

**Validation**:
- Image builds successfully
- Required binaries present
- Correct language versions
- Required libraries available
- Service ports accessible

## CI/CD Compliance

### Mandatory Checks

✅ **Must Pass**:
- Linting (black, flake8, ESLint)
- Type checking (mypy, TypeScript)
- Unit tests (pytest, Jest, go test)
- Security scanning (bandit, gosec, Trivy)
- Coverage thresholds (80%+)
- Docker builds

❌ **Prohibited**:
- Committed build artifacts
- Disabled security checks
- Skipped failing tests
- Hardcoded configuration
- Passwords in code

### Pull Request Requirements

Before merge to main:
1. ✅ All CI checks pass
2. ✅ Code review approval (minimum 1)
3. ✅ Security scan passes
4. ✅ Test coverage ≥80%
5. ✅ Documentation updated
6. ✅ Version bumped (if applicable)

### Release Workflow

1. Update `.version` file
2. Update CHANGELOG.md
3. Merge to main
4. Create GitHub Release
5. Workflows publish artifacts
6. Services deploy automatically

## Documentation Standards

### Code Comments

**Python**:
```python
# Single-line comments explain WHY, not WHAT
total = sum(values)  # Use built-in sum() for optimization

def calculate_checksum(data: bytes) -> str:
    """Calculate SHA256 checksum of data.

    This uses hashlib.sha256 rather than manual implementation
    for security and performance reasons.

    Args:
        data: Binary data to checksum

    Returns:
        Hex-encoded checksum string
    """
```

**Go**:
```go
// CalculateChecksum computes SHA256 hash of data
//
// This uses crypto/sha256 for security rather than manual
// implementation to prevent timing attacks.
func CalculateChecksum(data []byte) string {
    // Implementation
}
```

### Project Documentation

**Required Files**:
- README.md (overview, quick start)
- CONTRIBUTING.md (contribution guidelines)
- docs/WORKFLOWS.md (this section's counterpart)
- docs/STANDARDS.md (this file)
- CHANGELOG.md (version history)
- docs/API.md (API documentation)

### API Documentation

- Endpoint descriptions
- Request/response examples
- Authentication requirements
- Error codes and meanings
- Rate limiting details

## Compliance Checklist

Before committing:
- ✅ Code passes local linting
- ✅ Tests pass locally
- ✅ Coverage ≥80%
- ✅ Security scan passes
- ✅ No hardcoded secrets
- ✅ Error handling complete
- ✅ Logging appropriate
- ✅ Documentation updated
- ✅ Related issues linked
- ✅ Version updated (if applicable)

Before creating PR:
- ✅ Branch created from develop
- ✅ All commits are clean
- ✅ Commit messages clear
- ✅ Related tests included

Before merging PR:
- ✅ All CI passes
- ✅ Approved by reviewer
- ✅ Conflicts resolved
- ✅ Documentation complete
- ✅ CHANGELOG updated

## Tools Reference

| Tool | Languages | Purpose | Command |
|------|-----------|---------|---------|
| black | Python | Formatting | `black .` |
| flake8 | Python | Linting | `flake8 .` |
| mypy | Python | Type checking | `mypy .` |
| bandit | Python | Security | `bandit -r .` |
| pytest | Python | Testing | `pytest` |
| golangci-lint | Go | Linting | `golangci-lint run` |
| gosec | Go | Security | `gosec ./...` |
| go test | Go | Testing | `go test -race ./...` |
| ESLint | JavaScript | Linting | `npm run lint` |
| Prettier | JavaScript | Formatting | `npm run format` |
| TypeScript | JavaScript | Type checking | `npm run typecheck` |
| Jest | JavaScript | Testing | `npm test` |

## References

- [PEP 8 Style Guide](https://www.python.org/dev/peps/pep-0008/)
- [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- [Effective Go](https://golang.org/doc/effective_go)
- [TypeScript Handbook](https://www.typescriptlang.org/docs/)
- [DNS RFC 1035](https://tools.ietf.org/html/rfc1035)
- [LDAP RFC 4511](https://tools.ietf.org/html/rfc4511)
- [Semantic Versioning](https://semver.org/)
