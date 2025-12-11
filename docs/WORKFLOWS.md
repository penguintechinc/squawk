# Squawk DNS Project CI/CD Workflows

This document describes all GitHub Actions workflows for the Squawk DNS project, implementing `.WORKFLOW` compliance standards across four major services.

## Project Structure Overview

Squawk is a comprehensive DNS system with four integrated services:

1. **DNS Server** (Python) - Core DNS resolution service with enterprise features
2. **DNS Client** (Go) - CLI client for DNS queries and configuration
3. **Manager Service** (Python/JavaScript) - Administrative interface and API
4. **Frontend Service** (JavaScript/Node.js) - Web console and UI

## Workflow Overview

### Primary Workflows

| Workflow | File | Trigger | Purpose |
|----------|------|---------|---------|
| Build & Test | `.github/workflows/build.yml` | Push/PR to main/develop | Multi-service builds and unit tests |
| Version Monitoring | `.github/workflows/version-monitor.yml` | .version changes | Version validation and consistency |
| Release | `.github/workflows/release.yml` | GitHub Release published | Docker image publishing |
| Server Release | `.github/workflows/server-release.yml` | Manual trigger | DNS Server specific release |
| Client Release | `.github/workflows/go-client-release.yml` | Manual trigger | Go Client specific release |
| Push | `.github/workflows/push.yml` | Push to main | Docker build and registry push |
| Cron | `.github/workflows/cron.yml` | Daily 2 AM UTC | Scheduled maintenance |
| GitStream | `.github/workflows/gitstream.yml` | Code analysis | Automated code review |

## .WORKFLOW Compliance

### Version Management System

**Version File Format**: `vMajor.Minor.Patch` (e.g., `v2.1.0`)

**Version Monitoring (version-monitor.yml)**

Triggers on `.version` file changes:
- Validates semantic versioning format
- Checks consistency across four services
- Scans Python/Go security concerns
- Verifies all service components are present

**Service Verification Checks**:
- DNS Server: `dns-server/bins/server_optimized.py`
- DNS Client (Go): `dns-client/go.mod`
- Manager Service: Project structure
- Frontend Service: `manager/frontend/package.json`

## Build & Test Workflow

### build.yml Execution Flow

**Jobs:**
1. `build-and-test` - Unit tests and Docker builds
2. `docker-multi-build` - Multi-target Docker image testing
3. `security-scanning` - Python/Go security analysis

### Build-and-Test Job

**Purpose**: Run unit tests on DNS Server

**Steps**:
1. Checkout code
2. Build DNS Server Docker image
3. Run pytest tests in container
4. Verify test environment

**Environment**:
```dockerfile
SQUAWK_ENV=test
PYTHON_VERSION=3.13
```

### Docker-Multi-Build Job

**Purpose**: Test unified Docker images for each service

**Builds**:
- `dns-server` - Python-based DNS server
- `dns-client` - Go-based CLI client

**Validation**:
- Python 3.13 present
- Virtual environment functional
- python-ldap library available (DNS Server)
- dns.resolver library available (DNS Client)

### Security Scanning Job

**Tools**:
- **bandit** (Python): Vulnerability detection
- **gosec** (Go): Go-specific security scanning
- **Trivy**: Filesystem vulnerability scanning

**Coverage**:
- Python DNS Server code
- Go DNS Client code
- Dependencies for all services
- Container images

## Service-Specific Workflows

### DNS Server Release (server-release.yml)

**Trigger**: Manual workflow dispatch

**Features**:
- Builds optimized DNS Server container
- Publishes to Docker registries
- Tags with version information
- Generates server-specific release notes

**Release Artifacts**:
- Docker image: `squawk-dns-server:version`
- Container registry: ghcr.io and Docker Hub
- Release notes: Server feature highlights

### Go Client Release (go-client-release.yml)

**Trigger**: Manual workflow dispatch

**Features**:
- Builds cross-platform Go binaries
- Compiles for multiple architectures
- Publishes release artifacts
- Generates client-specific documentation

**Platforms**:
- Linux (amd64, arm64)
- macOS (amd64, arm64)
- Windows (amd64, arm64)

**Artifacts**:
- Native binaries per platform
- Checksums for verification
- Installation instructions

## Release Management

### Release Workflow (release.yml)

**Trigger**: GitHub Release published

**Steps**:
1. Log into Docker registries
2. Extract metadata from release
3. Build and push container images
4. Generate release notes
5. Publish static release tags

**Registry Targets**:
- Docker Hub: `penguincloud/squawk`
- GHCR: `ghcr.io/penguincloud/squawk`

### Multi-Release Strategy

Squawk supports simultaneous releases:
- DNS Server releases independently
- Go Client releases independently
- Synchronized major version releases
- Component-specific versioning

## Dependency Management

### Update Strategy

**Python Dependencies** (DNS Server, Manager):
- requirements.txt pinned versions
- Monthly review schedule
- Security vulnerability scanning
- Bandit security analysis

**Go Dependencies** (DNS Client):
- go.mod version management
- gosec security scanning
- Regular Go version updates (currently 1.23+)

**Node.js Dependencies** (Frontend):
- package.json/package-lock.json
- npm audit vulnerability checking
- Regular package updates

## Security Scanning Standards

### Python Security (bandit)

**Scope**: DNS Server, Manager, all Python code

**Detection Coverage**:
- Hardcoded passwords
- SQL injection patterns
- Insecure pickle/deserialization
- Weak cryptography
- Insecure LDAP implementations

**Configuration**:
```bash
bandit -r . --format json --output bandit-results.json
```

### Go Security (gosec)

**Scope**: DNS Client, any Go utilities

**Detection Coverage**:
- SQL injection vulnerabilities
- Weak cryptography
- Hardcoded credentials
- Command injection risks
- Unsafe functions

**Configuration**:
```bash
gosec -no-fail -fmt json -out gosec-results.json ./...
```

### Trivy Filesystem Scanning

**Coverage**:
- Container images
- Dependencies
- Build artifacts
- Configuration files

**Supported Images**:
- DNS Server container
- DNS Client container
- Manager container
- Frontend container

## Testing Strategy

### Unit Testing

**DNS Server (Python)**:
- pytest framework
- Mocked LDAP/network calls
- DNS protocol validation
- Token/auth system tests
- Database query tests

**DNS Client (Go)**:
- Go testing framework
- Mocked server responses
- CLI argument validation
- Configuration parsing tests

**Manager & Frontend (JavaScript)**:
- Jest testing framework
- Component unit tests
- API endpoint tests
- UI interaction tests

### Integration Testing

Runs after unit tests:
- Multi-service interaction
- Database integration
- API endpoint functionality
- DNS resolution end-to-end

### Docker Testing

Validates container builds:
- Image builds successfully
- Required binaries present
- Correct Python version
- Required libraries (python-ldap, dns.resolver)
- Service ports accessible

## Environment Configuration

### Build Environment Variables

```yaml
PYTHON_VERSION: '3.13'
GO_VERSION: '1.23'
NODE_VERSION: '18'
```

### DNS Server Environment

```bash
# Server Configuration
PORT: 8080
MAX_WORKERS: 100
MAX_CONCURRENT_REQUESTS: 1000

# Cache Configuration
CACHE_ENABLED: true
CACHE_TTL: 300
REDIS_URL: redis://localhost:6379

# Testing
SQUAWK_ENV: test
LICENSE_KEY: TEST-LICENSE-KEY
```

### DNS Client Environment

```bash
# Client Configuration
SQUAWK_SERVER_URL: https://dns.example.com
SQUAWK_AUTH_TOKEN: client-token
LOG_LEVEL: INFO
```

## Local Workflow Execution

### Pre-commit Checks

Before pushing code:

**Python services**:
```bash
# Install dependencies
pip install -r requirements.txt
pip install bandit[toml] black isort flake8 mypy pytest

# Format
black .
isort .

# Lint
flake8 .
mypy .

# Security
bandit -r .

# Test
pytest
```

**Go client**:
```bash
# Build
go build ./...

# Test
go test -v -race ./...

# Security
gosec ./...

# Lint
golangci-lint run
```

**Node.js frontend**:
```bash
# Install
npm install

# Lint
npm run lint

# Test
npm test

# Build
npm run build
```

## Performance Optimization

### Caching Strategies

- Python dependencies cached in `~/.cache/pip`
- Go modules cached via GitHub Actions
- Docker layer caching for faster builds
- Node.js package cache

### Parallel Execution

- Unit tests run in parallel when possible
- DNS Server and Client tests independent
- Manager and Frontend tests independent
- Security scanning parallel with builds

### Conditional Execution

- Tests skip if no relevant changes
- Docker builds only on main branch
- Security scans always run
- Release workflows manual or release-triggered

## Troubleshooting Guide

### Version Validation Failures

If `.version` validation fails:
1. Check format: `vMajor.Minor.Patch` (no build timestamp for squawk)
2. Ensure no extra whitespace
3. Verify semantic versioning increment rules
4. Check example: `v2.1.0` not `2.1.0`

### Service Build Failures

**DNS Server Docker Build Fails**:
- Check Python 3.13 availability in base image
- Verify ubuntu:24.04 base image (required for python-ldap)
- Check LDAP development headers present
- Review ldap imports in Python files

**Go Client Build Fails**:
- Verify go.mod syntax
- Check Go 1.23+ compatibility
- Ensure all imports resolvable
- Run `go mod tidy` locally

**Frontend Build Fails**:
- Check Node.js 18+ available
- Verify package.json syntax
- Check npm dependency conflicts
- Run `npm ci` for clean install

### Security Scan False Positives

**Suppress bandit warnings**:
```python
# nosec: B101
```

**Suppress gosec warnings**:
```go
// #nosec G101
```

### Test Failures

If tests pass locally but fail in CI:
1. Check environment variable differences
2. Verify Docker service availability (Redis)
3. Check database connectivity (if applicable)
4. Review timing-sensitive tests
5. Check file path assumptions (use absolute paths)

## Continuous Integration Best Practices

### Commit Message Standards

- Reference issue numbers: `Closes #123`
- Describe changes clearly
- Keep subject under 50 characters
- Include scope: `dns-server:`, `dns-client:`, `manager:`, `frontend:`

### Pull Request Process

1. Create feature branch from develop
2. Implement changes with tests
3. Run local tests (`./scripts/test.sh`)
4. Ensure CI passes
5. Request code review
6. Address feedback
7. Merge to develop

### Release Process

1. Merge features to develop
2. Create release branch: `release/v2.1.0`
3. Update `.version` file
4. Update CHANGELOG.md
5. Create pull request to main
6. Merge with squash commit
7. Create GitHub Release
8. Workflows publish artifacts automatically

## Documentation

For additional information:
- **DNS Server**: `dns-server/README.md`
- **DNS Client**: `dns-client/README.md`
- **Manager**: `manager/README.md`
- **Architecture**: `docs/OVERVIEW.md`
- **Development**: `CONTRIBUTING.md`

## Further Reading

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Bandit Security Scanner](https://bandit.readthedocs.io/)
- [gosec Go Security Checker](https://github.com/securego/gosec)
- [Trivy Vulnerability Scanner](https://github.com/aquasecurity/trivy)
- [DNS RFC 1035](https://tools.ietf.org/html/rfc1035)
