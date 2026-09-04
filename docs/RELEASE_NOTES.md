# Squawk DNS System Release Notes

This document contains release notes for all Squawk DNS components. Each component has its own versioning starting from v1.0.0.

---

## go-client (Go DNS Client)

High-performance DNS-over-HTTPS client written in Go

### v1.0.0

**Release Date**: August 2025
**Release Type**: Initial Release
**Breaking Changes**: None

#### Overview

Complete high-performance DNS client written in Go with comprehensive DNS-over-HTTPS functionality.

#### Performance Metrics
- **Cold Start**: ~10ms (10x faster than Python)
- **Memory Usage**: ~15MB (50% reduction)
- **Binary Size**: Single ~10MB executable
- **Concurrency**: Native goroutine support

#### Key Features
- Full DNS-over-HTTPS (DoH) support with HTTP/2
- mTLS authentication with ECC and RSA certificates
- Local DNS forwarding (UDP/TCP to DoH)
- YAML configuration file support
- Cross-platform binaries (Linux, macOS, Windows)
- Docker multi-architecture support
- Multiple server failover with automatic health checking
- DNS loop prevention with IP address validation
- RFC 1035 compliant DNS name validation
- Punycode (IDN) domain support
- Legacy public DNS support (Google DNS, Cloudflare)

#### Security Features
- ECC certificates with P-384 curve default
- mTLS authentication
- Certificate bundle downloads from web console
- Safe integer conversions to prevent overflow vulnerabilities
- Secure file permissions (0600) for sensitive config

#### Multiple Server Failover
- Automatic failover with configurable retry logic
- Round-robin server selection
- Health monitoring and availability tracking
- Error aggregation and reporting
- Seamless server switching

#### DNS Validation
- RFC 1035 compliance checking
- Label validation (max 63 chars per label, 253 total)
- Character filtering against injection attacks
- IDN support with Punycode handling
- Record type validation (A, AAAA, CNAME, MX, etc.)
- Special case handling (.arpa reverse DNS, IPv4 addresses)

#### Environment Variables
```bash
# Basic Configuration
SQUAWK_SERVER_URL=https://dns.example.com:8443
SQUAWK_AUTH_TOKEN=your-token-here
SQUAWK_DOMAIN=example.com
SQUAWK_RECORD_TYPE=A

# mTLS Configuration
SQUAWK_CLIENT_CERT=path/to/cert.pem
SQUAWK_CLIENT_KEY=path/to/key.pem
SQUAWK_CA_CERT=path/to/ca.pem
SQUAWK_VERIFY_SSL=true

# Multiple Server Support
SQUAWK_SERVER_URLS=https://192.168.1.100:8443,https://192.168.1.101:8443
SQUAWK_MAX_RETRIES=6
SQUAWK_RETRY_DELAY=2

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json
```

#### Release Artifacts
- **Binaries**: Linux (AMD64/ARM64), macOS (Universal), Windows
- **Docker Images**: Multi-architecture (linux/amd64, linux/arm64)
- **Package Format**: Single executable with no dependencies

#### Security Enhancements
- Zero security issues from gosec scanner
- Safe integer conversions to prevent overflow
- Updated file permissions to 0600 for sensitive files
- Comprehensive DNS validation

#### Bug Fixes
- DNS loop prevention with IP address validation
- URL path normalization for public DNS providers
- Certificate validation edge cases
- Error handling and aggregation for multiple servers
- Configuration parsing for comma-delimited server lists

#### Known Issues
- Windows service installation requires administrator privileges
- Some IDN domains may not validate correctly
- HTTP/3 support experimental in some environments

#### Testing & Quality
- Comprehensive test suites
- Security scanning with gosec
- Load testing capabilities
- Code coverage target: 80%+
- golangci-lint integration

#### Documentation
- Configuration guide with environment variables
- API documentation
- Architecture guide
- Security best practices

---

## dns-server (DNS Server)

Python-based DNS-over-HTTPS server with caching, IOC blocking, and mTLS

### v1.0.0

**Release Date**: August 2025
**Release Type**: Initial Release
**Breaking Changes**: None

#### Overview

Production-ready DNS-over-HTTPS server with advanced threat intelligence, enterprise authentication, and comprehensive security features.

#### Core Features
- DNS-over-HTTPS (DoH) support with HTTP/2
- Distributed caching with Redis/Valkey support
- mTLS authentication with ECC certificates
- Advanced threat intelligence integration
- IOC blocking with multiple feed formats
- User and token-based access control
- Web-based administration console

#### Performance & Scalability
- **Requests/sec**: 1000+ sustained
- **Concurrent Connections**: 1000+
- **Cache Hit Rate**: 95%
- **Response Time**: <100ms average

#### Advanced Threat Intelligence Integration

##### Threat Feed Support
- TAXII 2.x / STIX 2.1 format
- OpenIOC format
- TXT, CSV, JSON, XML formats
- YARA and Snort rule support
- Custom threat intelligence formats

##### TAXII 2.x Client Architecture
- Automatic API root and collection discovery
- Multiple authentication methods (Bearer token, Basic Auth, API key)
- Incremental synchronization with timestamp filtering
- Comprehensive retry logic with exponential backoff
- Configurable SSL verification

##### OpenIOC Format Support
- Complete IOC XML parsing
- Network indicator extraction
- CIDR notation and IP range support
- Metadata and attribution preservation
- URL domain extraction

##### IOC Processing Engine
- Multi-format parser supporting 8+ threat intelligence formats
- Intelligent confidence scoring
- Contextual extraction and threat attribution
- In-memory caching with database persistence
- Real-time integration without service restart

##### Community Threat Intelligence (FREE)
- 1 configurable threat intelligence feed
- Pre-configured popular feed templates
- Automatic updates (1-24 hour intervals)
- Real-time DNS blocking

##### Enterprise Threat Intelligence
- Unlimited number of threat sources
- Advanced parsing of complex STIX relationships
- Priority processing with faster update cycles
- Custom feed development support

#### Authentication & Security

##### Multi-Factor Authentication (MFA)
- TOTP (Google Authenticator compatible)
- Backup codes for account recovery
- QR code generation for easy setup
- Per-user MFA configuration

##### Single Sign-On (SSO)
- SAML 2.0 integration
- LDAP/Active Directory support
- OAuth2 capabilities
- Secure session management

##### Advanced Certificate Management
- ECC certificates with P-384 curve (default)
- Automatic self-signed certificate generation
- Certificate bundle downloads
- Dual authentication (bearer token + client certificate)
- Custom certificate authority support

##### Token-Based Access Control
- Individual user tokens with unique identifiers
- Group-based permission system
- Token-specific IOC overrides
- Per-token query logging and analytics

##### Brute Force Protection
- Configurable lockout thresholds (default: 5 attempts)
- IP-based tracking and blocking (default: 30 minutes)
- Email notifications for security events
- Admin unlock capabilities
- Complete audit logging

#### DNS Security & Filtering

##### DNS Blackholing
- Maravento blacklist integration (2M+ domains)
- Automatic daily updates from GitHub
- Custom domain/IP blocking
- Whitelist override functionality
- Real-time updates without restart

##### Selective DNS Routing (Enterprise)
- Per-user/group DNS access control
- Private and public DNS entry separation
- User identity-based filtering
- Secure authorization model

#### Caching & Performance

##### Advanced Caching
- Redis/Valkey distributed cache support
- TLS encryption for cache communication
- Password-protected cache access
- Configurable TTL per record
- Automatic failover between cache backends

##### High-Performance Architecture
- Asyncio/Uvloop optimization
- Multi-threaded processing
- Connection pooling
- Load balancing across servers

#### HTTP/3 Support
- QUIC protocol support
- Reduced latency
- Connection migration
- Improved reliability for packet loss

#### Infrastructure & Operations

##### Comprehensive Logging
- Real IP detection (REALIP/X-FORWARDED-FOR)
- UDP Syslog (RFC 3164 compliant)
- JSON structured logging
- Security event logging
- Performance metrics collection

##### Service Integration
- systemd service support
- Health checks and monitoring
- Automatic restart capabilities
- Comprehensive logging output

#### Database Support
- SQLite (default)
- PostgreSQL
- MySQL
- Automatic schema migrations
- Connection pooling
- ACID compliance

#### Web Console Features
- Modern responsive Bootstrap 5 UI
- Certificate management and downloads
- User and role management
- Domain blacklist/whitelist interface
- Real-time statistics dashboard
- API token generation
- Security settings configuration

#### Environment Variables

##### Server Configuration
```bash
PORT=8080
MAX_WORKERS=100
MAX_CONCURRENT_REQUESTS=1000
AUTH_TOKEN=your-token-here
USE_NEW_AUTH=true
DB_TYPE=sqlite
DB_URL=sqlite:///squawk.db
```

##### Cache Configuration
```bash
CACHE_ENABLED=true
CACHE_TTL=300
VALKEY_URL=redis://localhost:6379
CACHE_PREFIX=squawk:dns:
```

##### Threat Intelligence
```bash
ENABLE_THREAT_INTEL=true
THREAT_FEED_UPDATE_HOURS=6
MAX_COMMUNITY_FEEDS=1
TAXII_SERVER_URL=https://taxii-server.com/taxii2/
TAXII_COLLECTION_ID=indicators
TAXII_AUTH_TYPE=bearer
TAXII_TOKEN=your-token-here
```

##### Blacklist Configuration
```bash
ENABLE_BLACKLIST=true
BLACKLIST_UPDATE_HOURS=24
MARAVENTO_URL=https://github.com/maravento/blackweb
```

##### mTLS Configuration
```bash
ENABLE_MTLS=true
MTLS_ENFORCE=false
MTLS_CA_CERT=certs/ca.crt
USE_ECC_KEYS=true
ECC_CURVE=SECP384R1
CA_VALIDITY_DAYS=3650
CERT_VALIDITY_DAYS=365
```

##### Logging Configuration
```bash
LOG_LEVEL=INFO
LOG_FORMAT=json
LOG_FILE=/var/log/squawk/server.log
ENABLE_SYSLOG=false
SYSLOG_HOST=localhost
SYSLOG_PORT=514
```

#### Database Schema

Core tables:
- `users`: User accounts and authentication
- `tokens`: API tokens and authentication tokens
- `groups`: Access control groups
- `user_groups`: User to group mappings
- `domains`: DNS domains and zones
- `dns_records`: Individual DNS records
- `ioc_feeds`: Threat intelligence feed configurations
- `ioc_entries`: Individual threat indicators
- `ioc_overrides`: User/token specific overrides
- `audit_logs`: Security and access logging

#### Release Artifacts
- **Docker Images**: Multi-architecture containers
- **Python Packages**: pip-installable modules
- **Database**: Automatic migrations on startup
- **Configuration**: Environment variable based

#### Build & CI/CD
- Python 3.13 standardization
- Docker virtual environment isolation
- GitHub Actions integration
- Multi-platform build support
- Docker multi-stage builds

#### Testing & Quality
- Comprehensive test suites
- Security scanning with Bandit
- Load testing capabilities
- Code coverage target: 80%+
- flake8 linting

#### Documentation
- API documentation with OpenAPI specs
- Architecture guide
- Configuration reference
- Security best practices
- Troubleshooting guide

---

## docker-client (Python DNS Client)

Python DNS client for Docker environments

### v1.0.0

**Release Date**: August 2025
**Release Type**: Initial Release
**Breaking Changes**: None

#### Overview

Docker-optimized Python DNS client with full DNS-over-HTTPS functionality and enterprise authentication support.

#### Key Features
- Full DNS-over-HTTPS (DoH) support with HTTP/2
- mTLS authentication
- Multiple server failover
- RFC 1035 compliant DNS validation
- Containerized deployment
- Comprehensive logging
- Configuration via environment variables

#### Performance Characteristics
- Typical startup: 500-1000ms
- Memory footprint: 50-100MB
- Multi-process support
- Asyncio optimization

#### Security Features
- mTLS authentication with certificate validation
- Token-based API authentication
- Secure configuration handling
- Certificate bundle support
- SSL verification options

#### Multiple Server Support
- Automatic failover between servers
- Configurable retry logic
- Round-robin load distribution
- Health monitoring
- Error aggregation

#### DNS Validation
- RFC 1035 compliance checking
- Label validation and formatting
- Character filtering for security
- IDN/Punycode support
- Special case handling

#### Environment Variables
```bash
# Server Configuration
SQUAWK_SERVER_URL=https://dns.example.com:8443
SQUAWK_AUTH_TOKEN=your-token-here
SQUAWK_DOMAIN=example.com
SQUAWK_RECORD_TYPE=A

# mTLS Configuration
SQUAWK_CLIENT_CERT=/app/certs/client.pem
SQUAWK_CLIENT_KEY=/app/certs/client-key.pem
SQUAWK_CA_CERT=/app/certs/ca.pem
SQUAWK_VERIFY_SSL=true

# Multiple Servers
SQUAWK_SERVER_URLS=https://server1:8443,https://server2:8443
SQUAWK_MAX_RETRIES=3
SQUAWK_RETRY_DELAY=1

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json
```

#### Docker Integration
- Ubuntu 24.04 LTS base image
- Python 3.13 from deadsnakes PPA
- Virtual environment isolation
- Multi-architecture support (amd64, arm64)
- Health check capabilities

#### Dependencies
- aiohttp for HTTP/2 support
- cryptography for TLS
- pyyaml for configuration
- Python standard library DNS support

#### Configuration
- YAML configuration files
- Environment variable overrides
- Default configurations
- Custom server definitions

#### Release Artifacts
- **Docker Image**: Multi-architecture (linux/amd64, linux/arm64)
- **Python Package**: pip-installable
- **Configuration Examples**: YAML templates

#### Testing & Quality
- Unit test suite
- Integration tests
- Security scanning
- Code coverage

#### Documentation
- Configuration guide
- Docker deployment guide
- Troubleshooting guide
- Examples and use cases

---

## webui (Web Console)

Flask-based web administration console

### v1.0.0

**Release Date**: August 2025
**Release Type**: Initial Release
**Breaking Changes**: None

#### Overview

Modern, responsive web administration console for Squawk DNS server management with Bootstrap 5 UI and comprehensive feature support.

#### Core Features
- Modern responsive Bootstrap 5 interface
- User and authentication management
- Token and API key management
- Domain blacklist/whitelist configuration
- Real-time statistics and monitoring
- Certificate management and downloads
- Security settings configuration
- Multi-user support with role-based access

#### Web Console Features

##### User Management
- User account creation and deletion
- Password management
- Role-based access control
- User profile management
- Activity logging

##### Token & API Management
- API token generation
- Token revocation
- Token expiration policies
- Usage tracking and analytics
- Token scope management

##### Domain Management
- Blacklist configuration interface
- Whitelist management
- Domain group management
- Bulk import/export
- Search and filtering

##### Certificate Management
- mTLS certificate downloads
- Bundle generation (certificates + keys)
- Certificate renewal
- Public key infrastructure support
- CA certificate management

##### Statistics & Monitoring
- Real-time DNS query statistics
- Top domains and query types
- Response time metrics
- Cache hit rates
- User activity dashboards

##### Security Configuration
- MFA setup and management
- SSO configuration
- Brute force protection settings
- Password policies
- Security event logging

##### Threat Intelligence
- Feed configuration interface
- IOC override management
- Feed statistics and performance
- Update history tracking

#### Technology Stack
- Flask web framework
- Bootstrap 5 UI framework
- SQLAlchemy ORM
- Jinja2 templating
- Session management

#### Security Features
- Session-based authentication
- CSRF protection
- SQL injection prevention
- XSS protection
- Secure cookie handling
- Rate limiting
- Input validation

#### Responsive Design
- Mobile-friendly interface
- Touch-optimized controls
- Responsive navigation
- Adaptive layouts
- Cross-browser compatibility

#### Database Integration
- SQLAlchemy ORM support
- Multi-database backend support
- Transaction management
- Data validation
- Connection pooling

#### Environment Variables
```bash
# Flask Configuration
FLASK_APP=app.py
FLASK_ENV=production
SECRET_KEY=your-secret-key-here
DEBUG=false

# Database
DB_TYPE=sqlite
DB_URL=sqlite:///squawk.db

# Authentication
AUTH_ENABLED=true
SESSION_TIMEOUT=3600
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION=1800

# Security
ENABLE_HTTPS=true
SECURE_COOKIES=true
TRUSTED_PROXIES=127.0.0.1,::1

# Logging
LOG_LEVEL=INFO
LOG_FILE=/var/log/squawk/webui.log
```

#### Templates & Components
- Responsive navigation bar
- Dashboard overview
- User management pages
- Domain configuration forms
- Certificate download interface
- Statistics and charts
- Error pages
- Login and authentication pages

#### Features by Page

##### Dashboard
- Overview statistics
- Recent activity
- Quick links to key functions
- System health status
- Performance metrics

##### User Management
- User list and search
- Create/edit/delete users
- Password reset
- Role assignment
- Activity history

##### API Tokens
- Token creation and management
- Token usage tracking
- Expiration management
- Scope configuration

##### Domain Management
- Blacklist configuration
- Whitelist management
- Bulk operations
- Import/export functionality

##### Certificates
- Certificate download
- Bundle generation
- Certificate details
- Renewal management

##### Settings
- Server configuration
- Security policies
- Notification settings
- Logging preferences
- Theme selection

#### Release Artifacts
- **Docker Image**: Flask application container
- **Python Package**: pip-installable module
- **Static Assets**: CSS, JavaScript, images
- **Templates**: Jinja2 HTML templates

#### Build & Deployment
- Python 3.13 support
- Docker containerization
- Virtual environment isolation
- systemd service support
- Nginx reverse proxy compatible

#### Testing & Quality
- Unit tests
- Integration tests
- Security scanning
- Code coverage target: 80%+
- flake8 linting

#### Documentation
- User guide
- Administration guide
- Configuration reference
- API documentation
- Troubleshooting guide

#### Accessibility
- WCAG 2.1 compliance
- Keyboard navigation
- Screen reader support
- High contrast options
- Semantic HTML

#### Performance
- Optimized assets
- Caching strategies
- Efficient database queries
- Connection pooling
- CDN-ready static files

#### Browser Support
- Chrome/Chromium (latest)
- Firefox (latest)
- Safari (latest)
- Edge (latest)
- Mobile browsers

---

## Enterprise Features (Cross-Component)

### v2.1.x Security Hardening

**Release Date**: September 2026
**Release Type**: Security hardening (cross-component)
**Breaking Changes**: Refresh tokens and deployment-domain tokens minted before v2.1.x are no longer accepted — users re-login once and domain tokens are rolled over after upgrade.

Squawk v2.1.x hardens the authentication and operational surface across the
manager, DNS, NTP, and DHCP services, and the web console.

#### Secrets at rest
- DNS resolver tokens and DNS-server join keys are stored as **SHA-256 hashes** (unique, indexed) and looked up by hash — the plaintext value is shown **only once**, at creation/regeneration.
- Per-server `jwt_secret` values and machine-client secrets are **Fernet-encrypted at rest**.

#### Authentication & session hardening
- Login rate limiter is **proxy-aware (ProxyFix)** — spoofing `X-Forwarded-For` no longer bypasses limits.
- Per-endpoint rate limits on login, token, refresh, and MFA endpoints, plus **account lockout** (with exponential backoff) on repeated failed logins.
- **Refresh tokens are single-use and rotate** on every refresh; reuse of a rotated token is rejected (surfaces token theft).
- The **MFA pre-auth token is single-use**.
- OIDC/OAuth2 SSO logins **bypass TOTP** (the identity provider owns MFA). **SAML 2.0 assertion signatures are now cryptographically verified** (pysaml2 + xmlsec1, shipped in the image); the SAML path is likewise designed to delegate MFA to the IdP.

#### Web console
- The React web console stores JWTs in **HttpOnly + Secure + SameSite cookies** with **CSRF double-submit** protection — tokens are never placed in browser `localStorage`.

#### DNS server
- `/metrics` and `/status` now **require a valid JWT bearer token** (previously unauthenticated); `/health` stays open for probes.
- Metrics no longer expose raw token values — query "source" labels are hashed.
- Per-source **rate limiting is on by default** and the distributed (Valkey) backend **fails closed**.

#### gRPC (manager)
- gRPC requires a server JWT **and TLS**; the server refuses to start insecurely unless `SQUAWK_GRPC_INSECURE=true` is set explicitly (dev/local only).

#### NTP / DHCP
- NTP: NTS-KE requires an `ntp:client` JWT scope, NTS authenticators are cryptographically verified, and **TLS 1.3** is enforced.
- DHCP: requested IP, MAC address, and hostname are validated (format + in-pool-range + conflict/binding checks) before a lease is issued.

#### Audit logging
- The full auth lifecycle is audit-logged: login, token refresh, logout, machine token grant, MFA verify, SSO login, SAML, and SCIM user provisioning.

#### CI / supply chain
- **CodeQL** scanning runs across `python`, `go`, and `javascript-typescript`.
- **bandit** and **gosec** run as enforced, build-gating security scans.
- dns-server test coverage is gated at **90%** (`--cov-fail-under=90`); the build fails below the threshold.

### v2.1.0 Licensing & Features

#### Enterprise Tiers

##### Community Edition (Free)
- Basic DNS resolution and caching
- Standard DNS-over-HTTPS support
- mTLS authentication
- 1 threat intelligence feed
- Basic web console
- Community support via GitHub

##### Enterprise Self-Hosted ($5/user/month)
- All Community features
- Unlimited threat intelligence feeds
- Selective DNS routing with per-user/group access
- Advanced token management
- Multi-tenant architecture
- SAML/LDAP/SSO integration
- Priority DNS processing
- Enhanced caching
- Technical support with SLA
- Self-managed infrastructure

##### Enterprise Cloud-Hosted ($7/user/month)
- All Self-Hosted features
- Managed infrastructure by Penguin Technologies
- 99.9% SLA guarantee
- Automatic updates with zero-downtime
- 24/7 monitoring and incident response
- Compliance reporting (SOC2, HIPAA, GDPR)
- Global CDN infrastructure
- Advanced threat intelligence curation
- Custom integrations and development
- 24/7 dedicated support

#### Selective DNS Routing (Enterprise)
- Per-user/group DNS access control
- Private and public DNS entry separation
- Token-based identity mapping
- Group membership management
- Visibility levels for DNS records
- Per-record access control

#### Advanced Analytics (Enterprise)
- Query tracking per user
- Usage reports (daily, weekly, monthly)
- Performance metrics
- Compliance reporting
- Custom dashboards

#### Compliance & Monitoring (Cloud-Hosted)
- SOC2 Type II compliance
- HIPAA healthcare data protection
- GDPR EU data protection
- Custom compliance reporting
- 24/7 security monitoring
- SIEM integration
- Advanced threat detection

---

## System Requirements

### Go Client
- Linux, macOS, Windows
- No additional dependencies

### DNS Server
- Python 3.13
- Redis/Valkey (optional, for caching)
- PostgreSQL/MySQL (optional, for production)
- Ubuntu 24.04 LTS recommended for Docker

### Python Client
- Python 3.13
- aiohttp, cryptography, pyyaml
- Docker recommended for deployment

### Web Console
- Python 3.13
- Flask, SQLAlchemy
- Modern web browser

---

## Support & Documentation

- **GitHub Issues**: https://github.com/penguintechinc/squawk/issues
- **Documentation**: https://docs.squawkdns.com
- **Email**: support@penguintech.group

---

## License

GNU AGPL v3 - See LICENSE.md for details
