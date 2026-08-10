[![Build](https://github.com/penguintechinc/squawk/actions/workflows/build.yml/badge.svg)](https://github.com/penguintechinc/squawk/actions/workflows/build.yml) [![Server Release](https://github.com/penguintechinc/squawk/actions/workflows/server-release.yml/badge.svg)](https://github.com/penguintechinc/squawk/actions/workflows/server-release.yml) [![codecov](https://codecov.io/gh/penguintechinc/squawk/branch/main/graph/badge.svg)](https://codecov.io/gh/penguintechinc/squawk) [![version](https://img.shields.io/badge/version-2.1.1-blue.svg)](https://semver.org)

```
                    ____
                .-~    ~-.
           .--~'        '~.
         .~'       ___    '~.
        /         (o o)      \         ____
       |     ___   \_/   ___  |       /
       |    (   '~-----~'   ) |      /  SQUAWK!
       \     '~-._______.-~' /      <
        '~.       ___       .~'      \   DNS-over-HTTPS with Secure Authentication for clientless applications
          '~-._  (__) _.-~'           \____
              '~~---~~'

```

# Squawk - DNS-over-HTTPS Proxy System

Squawk is a secure, scalable DNS-over-HTTPS (DoH) proxy system that provides authenticated DNS resolution services with fine-grained access control. It consists of both server and client components that enable secure DNS queries over HTTPS with token-based authentication and domain-level access restrictions.

## Features

### Core Functionality
- **DNS-over-HTTPS (DoH) Support**: Secure DNS resolution using HTTPS protocol with HTTP/3 support
- **High Performance**: Async architecture supporting thousands of requests per second
- **Token-Based Authentication**: Bearer token authentication for access control
- **Domain Access Control**: Fine-grained permissions allowing specific tokens to access specific domains
- **Local DNS Forwarding**: Client can act as local DNS forwarder on port 53 (UDP/TCP)
- **TLS/SSL Support**: Optional SSL/TLS encryption for enhanced security
- **Database Integration**: Support for persistent token and domain permission storage
- **Web Management Console**: Py4web-based interface for managing tokens and permissions
- **System Tray Integration**: Cross-platform desktop system tray icon for easy management
- **Automatic System Service**: Install as system service/daemon with automatic DNS configuration

### Performance & Caching
- **Valkey/Redis Caching**: High-performance caching with configurable TTL
- **In-Memory Fallback**: Automatic fallback to in-memory cache if Redis/Valkey unavailable
- **Multi-threading Support**: Utilizes multiple workers for optimal performance
- **Async I/O**: Built on asyncio for non-blocking operations
- **HTTP/3 Support**: Latest protocol support for improved performance

### Security Features
- **DNS Blackholing**: Block malicious domains and IPs
- **Maravento Blacklist Integration**: Automatic updates from Maravento blackweb list
- **Custom Blacklists**: Admin-managed domain and IP blocking
- **Dual Authentication**: Requires both Bearer token AND client certificate when fully activated
- **Mutual TLS (mTLS)**: ECC-based client certificate authentication for maximum security
- **Automatic Certificate Generation**: Built-in CA and certificate management
- **Certificate Revocation**: Revoke compromised client certificates
- **Multi-Factor Authentication (MFA)**: Google Authenticator TOTP support with backup codes
- **Single Sign-On (SSO)**: SAML, LDAP, and OAuth2 integration
- **Account Security**: Failed attempt lockouts, session management, and audit logging
- **Domain validation and sanitization**: Prevent DNS injection attacks
- **Token-based access restrictions**: Fine-grained access control
- **Per-domain access control lists**: Granular permission management
- **SSL/TLS support**: Encrypted communications with HTTP/3
- **Input validation**: Comprehensive security checks
- **Asymmetric JWT (ES256/RS256)**: Manager-signed, public-key-verified tokens with required tenant claim
- **Signed images + SBOM**: cosign keyless signatures and SPDX SBOM attestation on release images

For enterprise deployment hardening — asymmetric JWT key setup, tenant isolation,
image signature verification, Kubernetes runtime hardening, and Renovate — see
[docs/ENTERPRISE_SECURITY.md](docs/ENTERPRISE_SECURITY.md).

## Architecture

### Components

1. **DNS Server** (`dns-server/`)
   - HTTP/HTTPS server handling DNS queries
   - Token authentication and validation
   - Domain access control enforcement
   - Database integration for token management
   - Web console for administration

2. **DNS Client** (`dns-client/`)
   - DNS-over-HTTPS client
   - Local DNS forwarding capabilities (port 53)
   - Support for both UDP and TCP
   - Kubernetes integration support
   - Configuration file support

3. **Web Console** (`web/`)
   - Py4web-based administration interface
   - Token management
   - Domain permission configuration
   - Real-time monitoring and logging

## Installation

### Quick Install (Recommended)

The easiest way to install Squawk is using the automated installer:

```bash
# Install with default settings
sudo python3 install.py install

# Install with custom server
sudo SQUAWK_SERVER_URL=https://dns.example.com SQUAWK_AUTH_TOKEN=your-token python3 install.py install

# Uninstall
sudo python3 install.py uninstall
```

The installer will:
- Install all dependencies
- Set up Squawk as a system service/daemon
- Configure your system DNS to use Squawk
- Create a system tray icon (on desktop systems)
- Start the service automatically

### Using Docker (Recommended)

Squawk now uses Ubuntu 22.04 LTS as the base image with separated Docker configurations for better modularity.

#### Quick Start with Docker Compose

```bash
# Start all core services (DNS server, web console, client, and cache)
docker-compose up -d

# Start with PostgreSQL for enterprise deployments
docker-compose --profile postgres up -d

# Start with Prometheus and Grafana monitoring
docker-compose --profile monitoring up -d

# View logs
docker-compose logs -f dns-server
```

#### Building Individual Components

```bash
# Build and run DNS server only
cd dns-server
docker-compose up -d

# Build and run DNS client only
cd dns-client
docker-compose up -d
```

#### Docker Images

The project provides separate Docker images:
- `squawk-dns-server`: DNS-over-HTTPS server with enterprise features
- `squawk-dns-client`: DNS client forwarder

Both images are based on Ubuntu 22.04 LTS and include automatic fallback for enterprise features if dependencies fail to install.

### Manual Installation

#### Server Setup

```bash
cd dns-server
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Standard server
python bins/server.py -p 8080

# Optimized server with caching and blacklist support
ENABLE_BLACKLIST=true VALKEY_URL=redis://localhost:6379 python bins/server_optimized.py -p 8080
```

#### Client Setup

```bash
cd dns-client
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# CLI usage
python bins/client.py -d example.com -s http://localhost:8080

# System tray application
python bins/systray.py -c config.yaml
```

## Configuration

### Environment Variables

All configuration is done via environment variables:

#### Server Configuration
- `PORT`: Server port (default: 8080)
- `MAX_WORKERS`: Number of worker processes (default: 100)
- `MAX_CONCURRENT_REQUESTS`: Max concurrent DNS requests (default: 1000)
- `AUTH_TOKEN`: Legacy authentication token
- `USE_NEW_AUTH`: Enable new token management system (true/false)
- `DB_TYPE`: Database type for auth
- `DB_URL`: Database connection URL

#### Cache Configuration
- `CACHE_ENABLED`: Enable caching (default: true)
- `CACHE_TTL`: Cache TTL in seconds (default: 300)
- `VALKEY_URL` or `REDIS_URL`: Valkey/Redis connection URL (e.g., rediss://user:pass@host:6380/0)
- `CACHE_PREFIX`: Cache key prefix (default: squawk:dns:)
- `REDIS_USERNAME`: Redis/Valkey username for authentication
- `REDIS_PASSWORD`: Redis/Valkey password for authentication
- `REDIS_USE_TLS`: Enable TLS encryption for Redis/Valkey (default: true)
- `REDIS_TLS_CERT_FILE`: Client certificate file for Redis/Valkey TLS
- `REDIS_TLS_KEY_FILE`: Client private key file for Redis/Valkey TLS
- `REDIS_TLS_CA_FILE`: CA certificate file for Redis/Valkey TLS verification
- `REDIS_TLS_VERIFY_MODE`: TLS verification mode: required, optional, none (default: required)

#### mTLS Configuration
- `ENABLE_MTLS`: Enable mutual TLS authentication (default: false)
- `MTLS_ENFORCE`: Require client certificates (default: false)
- `MTLS_CA_CERT`: CA certificate path for client verification (default: certs/ca.crt)
- `CERT_DIR`: Certificate storage directory (default: certs)

#### Blacklist Configuration
- `ENABLE_BLACKLIST`: Enable Maravento blacklist (default: false)
- `BLACKLIST_UPDATE_HOURS`: Update interval in hours (default: 24)

#### Brute Force Protection
- `BRUTE_FORCE_PROTECTION`: Enable brute force protection (default: true)
- `MAX_LOGIN_ATTEMPTS`: Maximum failed login attempts before lockout (default: 5)
- `LOCKOUT_DURATION_MINUTES`: Account lockout duration in minutes (default: 30)

#### Email Notifications
- `ENABLE_EMAIL_NOTIFICATIONS`: Enable email notifications for security events (default: false)
- `SMTP_SERVER`: SMTP server hostname (default: localhost)
- `SMTP_PORT`: SMTP server port (default: 587)
- `SMTP_USERNAME`: SMTP username for authentication
- `SMTP_PASSWORD`: SMTP password for authentication
- `SMTP_USE_TLS`: Enable TLS for SMTP connection (default: true)
- `SMTP_FROM_EMAIL`: From email address (default: noreply@squawk-dns.local)
- `ADMIN_EMAIL`: Administrator email for security alerts

#### Client Configuration
- `SQUAWK_SERVER_URL`: DNS server URL (default: https://dns.google/resolve)
- `SQUAWK_AUTH_TOKEN`: Authentication token
- `SQUAWK_DOMAIN`: Default domain to query
- `SQUAWK_RECORD_TYPE`: Default DNS record type (default: A)
- `SQUAWK_CLIENT_CERT`: Client certificate path for mTLS
- `SQUAWK_CLIENT_KEY`: Client private key path for mTLS
- `SQUAWK_CA_CERT`: CA certificate path for verification
- `SQUAWK_VERIFY_SSL`: Enable SSL verification (true/false)
- `SQUAWK_CONSOLE_URL`: Admin console URL (default: http://localhost:8080/dns_console)
- `LOG_LEVEL`: Logging level (default: INFO)

#### Logging Configuration
- `LOG_LEVEL`: Logging level - DEBUG, INFO, WARNING, ERROR (default: INFO)
- `LOG_FORMAT`: Log format - json or text (default: json)
- `LOG_FILE`: Log file path (optional)
- `TRUSTED_PROXIES`: Comma-separated trusted proxy IP ranges for real IP detection

#### Syslog Configuration
- `ENABLE_SYSLOG`: Enable UDP syslog forwarding (default: false)
- `SYSLOG_HOST`: Syslog server hostname/IP (default: localhost)
- `SYSLOG_PORT`: Syslog server port (default: 514)
- `SYSLOG_FACILITY`: Syslog facility number (default: 16)

### Server Configuration

The server accepts the following command-line arguments:

```bash
python server_optimized.py [options]
  -t, --token <token>   : Authentication token for API access
  -p, --port <port>     : Port to listen on (default: 8080)
  -k, --key <keyfile>   : SSL key file path
  -c, --cert <certfile> : SSL certificate file path
  -d, --dbtype <type>   : Database type (sqlite, postgres, mysql)
  -u, --dburl <url>     : Database connection URL
  -n, --newauth         : Use new token management system
```

Example with all features:
```bash
ENABLE_BLACKLIST=true VALKEY_URL=redis://localhost:6379 CACHE_TTL=600 \
python server_optimized.py -p 8443 -k server.key -c server.crt -n
```

### Client Configuration

The client accepts the following command-line arguments:

```bash
python client.py [options]
  -d, --domain <domain>    : Domain to query
  -t, --type <type>        : DNS record type (default: A)
  -s, --server <url>       : DNS server URL
  -a, --auth <token>       : Authentication token
  -c, --config <file>      : Configuration file path
  -u, --udp                : Enable UDP forwarding on port 53
  -T, --tcp                : Enable TCP forwarding on port 53
```

Example with authentication:
```bash
python client.py -d example.com -s https://dns.example.com:8443 -a your-token-here
```

### Configuration File Format

The client supports YAML configuration files:

```yaml
domain: example.com
type: A
server: https://dns.example.com:8443
auth: your-token-here
```

## Token Management

### Database Schema

The system uses a simple database schema for token management:

```sql
CREATE TABLE auth (
    id INTEGER PRIMARY KEY,
    token VARCHAR(255) NOT NULL,
    domain TEXT NOT NULL
);
```

### Domain Permissions

Tokens can be assigned to specific domains:
- Use `*` for wildcard (access to all domains)
- Use comma-separated list for multiple domains: `example.com,test.com`
- Domains are validated against a regex pattern for security

## API Endpoints

### DNS Query Endpoint

```
GET /dns-query?name=<domain>&type=<record_type>
Headers:
  Authorization: Bearer <token>
```

Response format:
```json
{
  "Status": 0,
  "Answer": [
    {
      "name": "example.com",
      "data": "93.184.216.34"
    }
  ]
}
```

## Web Console

The Flask-based console provides:

- **Token Management**: Create, update, delete authentication tokens
- **Domain Permissions**: Assign domains to tokens with granular control
- **Blacklist Management**: Manage blocked domains and IPs
- **Activity Monitoring**: View DNS query logs and statistics
- **System Configuration**: Manage server settings and parameters
- **Cache Statistics**: Monitor cache performance and hit rates
- **Health Monitoring**: Real-time system health and performance metrics
- **Threat Intelligence**: Monitor IOC feeds and threat blocking
- **Selective DNS Routing**: Per-user/group DNS access control

Access the console at: `http://localhost:8005`

### Screenshots

#### Login Page
![Login](docs/screenshots/login.png)

#### Dashboard
![Dashboard](docs/screenshots/dashboard.png)

#### DNS Query Logs
![Queries](docs/screenshots/queries.png)

#### User Management
![Users](docs/screenshots/users.png)

#### Group Management
![Groups](docs/screenshots/groups.png)

#### DNS Zones
![Zones](docs/screenshots/zones.png)

#### DNS Records
![Records](docs/screenshots/records.png)

#### Permissions
![Permissions](docs/screenshots/permissions.png)

#### IOC Management
![IOC](docs/screenshots/ioc.png)

#### Threat Intelligence
![Threats](docs/screenshots/threats.png)

#### Blocked Queries
![Blocked](docs/screenshots/blocked.png)

#### System Logs
![Logs](docs/screenshots/logs.png)

#### Cache Management
![Cache](docs/screenshots/cache.png)

#### System Configuration
![Config](docs/screenshots/config.png)

#### Analytics
![Analytics](docs/screenshots/analytics.png)

### Admin Features

- **DNS Blackholing**: Block malicious domains at DNS level
- **Maravento Integration**: Automatic updates from Maravento blackweb list
- **Custom Blacklists**: Add/remove domains and IPs manually
- **Certificate Management**: Generate and manage TLS certificates for mTLS
- **Real-time Updates**: Changes take effect immediately without restart

### Default Credentials

The admin console comes with a default administrator account:

- **Email**: `admin@localhost`
- **Password**: `admin123`

**IMPORTANT**: Please change these credentials immediately after your first login using the "Profile" or "Users" section.

## Logging and Monitoring

Squawk provides comprehensive logging with real client IP detection and syslog support:

### Request Logging
- **Real IP Detection**: Automatically detects client IP from X-Forwarded-For, X-Real-IP, CF-Connecting-IP headers
- **Proxy Support**: Configurable trusted proxy ranges for accurate IP extraction
- **Comprehensive Metrics**: Processing time, cache hits, response sizes, authentication info
- **Security Events**: Failed authentication attempts, blocked requests, certificate issues

### Log Format Examples

**JSON Format:**
```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "event_type": "dns_query",
  "client_ip": "203.0.113.45",
  "query_name": "example.com",
  "query_type": "A",
  "response_status": "success",
  "response_code": 200,
  "processing_time_ms": 15.67,
  "cache_hit": false,
  "blocked": false,
  "auth_method": "bearer_token+client_cert"
}
```

**Text Format:**
```
2024-01-15 10:30:45 - DNS Query: 203.0.113.45 -> example.com (A) -> success (200) [15.67ms]
```

### Syslog Integration

Forward logs to centralized syslog servers:

```bash
# Enable syslog forwarding
ENABLE_SYSLOG=true SYSLOG_HOST=logs.company.com SYSLOG_PORT=514 \
python server_optimized.py -k certs/server.key -c certs/server.crt
```

**Syslog Message Format:**
```
<134>Jan 15 10:30:45 dns-server squawk-dns: client_ip=203.0.113.45 query=example.com type=A status=success code=200 time=15.67ms
```

### Environment Variables for Logging

```bash
# Logging configuration
LOG_LEVEL=INFO                    # DEBUG, INFO, WARNING, ERROR
LOG_FORMAT=json                   # json or text
LOG_FILE=/var/log/squawk-dns.log  # Optional file logging

# Real IP detection
TRUSTED_PROXIES=127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,1.2.3.4

# Syslog forwarding
ENABLE_SYSLOG=true
SYSLOG_HOST=syslog.company.com
SYSLOG_PORT=514
SYSLOG_FACILITY=16                # Local use facility
```

## Multi-Factor Authentication (MFA) Setup

Squawk supports Google Authenticator TOTP-based MFA for enhanced account security.

### Enabling MFA

1. **Access MFA Settings:**
   ```
   http://localhost:8080/dns_console/mfa/setup
   ```

2. **Setup Process:**
   - Generate a new MFA secret
   - Scan QR code with your authenticator app (Google Authenticator, Authy, etc.)
   - Save backup recovery codes in a secure location
   - Verify setup with a test code

3. **MFA Configuration:**
   ```bash
   # Require MFA for all users
   REQUIRE_MFA=true

   # Customize MFA issuer name
   MFA_ISSUER="Your Company DNS"
   ```

### Using MFA

- After login, users with MFA enabled must provide a 6-digit TOTP code
- Backup codes can be used if the authenticator is unavailable
- Failed attempts result in temporary account lockout (5 attempts = 30 minute lock)

### MFA Features

- **TOTP Support**: Compatible with Google Authenticator, Authy, Microsoft Authenticator
- **Backup Codes**: 10 single-use recovery codes generated during setup
- **Account Lockout**: Protection against brute force attacks
- **Audit Logging**: All MFA events logged for security monitoring
- **Session Management**: MFA verification tied to browser sessions

## Single Sign-On (SSO) Configuration

Squawk supports enterprise SSO integration with SAML, LDAP, and OAuth2 providers.

### Enabling SSO

```bash
# Enable SSO system
ENABLE_SSO=true

# Set default SSO provider type
SSO_PROVIDER=saml  # saml, ldap, or oauth2
```

### SSO Provider Configuration

Access the SSO configuration interface:
```
http://localhost:8080/dns_console/admin/sso
```

#### SAML 2.0 Configuration

```json
{
  "sso_url": "https://idp.company.com/sso/saml",
  "sls_url": "https://idp.company.com/slo/saml",
  "entity_id": "squawk-dns",
  "x509cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "attribute_mapping": {
    "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "first_name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
    "last_name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
  }
}
```

#### LDAP/Active Directory Configuration

```json
{
  "server": "ldap://dc.company.com:389",
  "base_dn": "dc=company,dc=com",
  "user_dn": "cn=users,dc=company,dc=com",
  "bind_user": "cn=squawk,cn=users,dc=company,dc=com",
  "bind_password": "service-account-password",
  "user_filter": "(sAMAccountName={username})",
  "group_filter": "(member={user_dn})",
  "admin_groups": ["cn=dns-admins,cn=groups,dc=company,dc=com"],
  "attribute_mapping": {
    "email": "mail",
    "first_name": "givenName",
    "last_name": "sn"
  }
}
```

#### OAuth 2.0 Configuration

```json
{
  "client_id": "squawk-dns-client-id",
  "client_secret": "client-secret-here",
  "auth_url": "https://oauth.company.com/oauth/authorize",
  "token_url": "https://oauth.company.com/oauth/token",
  "userinfo_url": "https://oauth.company.com/oauth/userinfo",
  "scopes": ["openid", "profile", "email"],
  "redirect_uri": "https://dns.company.com/dns_console/auth/oauth/callback"
}
```

### SSO Login URLs

Once configured, users can access SSO login at:
```
http://localhost:8080/dns_console/auth/sso/login/{provider-name}
```

### User Management

- **Registration Control**: `ALLOW_REGISTRATION=true/false`
- **Auto-provisioning**: Users created automatically on first SSO login
- **Role Mapping**: Map LDAP groups or SAML attributes to admin roles
- **Session Security**: Secure session management with configurable timeouts

## Advanced Security Features

### Brute Force Protection

Squawk includes comprehensive protection against brute force attacks:

```bash
# Enable brute force protection
BRUTE_FORCE_PROTECTION=true

# Configure thresholds (defaults shown)
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION_MINUTES=30
```

**Features:**
- **Account Lockout**: Automatically locks accounts after failed attempts
- **IP-based Protection**: Additional protection based on source IP
- **Progressive Delays**: Increasing delays between failed attempts
- **Automatic Unlock**: Accounts unlock after configured duration
- **Audit Logging**: All login attempts logged for security monitoring

### Email Security Notifications

Configure automatic email alerts for security events:

```bash
# Enable email notifications
ENABLE_EMAIL_NOTIFICATIONS=true

# SMTP configuration
SMTP_SERVER=smtp.company.com
SMTP_PORT=587
SMTP_USERNAME=squawk-dns@company.com
SMTP_PASSWORD=your-smtp-password
SMTP_USE_TLS=true
SMTP_FROM_EMAIL=squawk-dns@company.com
ADMIN_EMAIL=security@company.com
```

**Notification Types:**
- **Account Lockouts**: User and admin notifications when accounts are locked
- **Suspicious Activity**: Failed login attempts from new IPs
- **Certificate Events**: Certificate generation, revocation, and expiration alerts
- **System Security**: Unauthorized access attempts and configuration changes

### Redis/Valkey Security

Secure your cache backend with TLS encryption and authentication:

```bash
# PRODUCTION CONFIGURATION (Recommended)
# Use TLS-secured connection string with authentication
VALKEY_URL=rediss://username:password@cache.company.com:6380/0

# Or configure individual security settings
REDIS_USERNAME=squawk_cache_user
REDIS_PASSWORD=secure_cache_password
REDIS_USE_TLS=true
REDIS_TLS_CA_FILE=/path/to/redis-ca.crt
REDIS_TLS_CERT_FILE=/path/to/client.crt
REDIS_TLS_KEY_FILE=/path/to/client.key
REDIS_TLS_VERIFY_MODE=required
```

**Security Benefits:**
- **Encrypted Communication**: All cache traffic encrypted with TLS
- **Authentication**: Username/password authentication to prevent unauthorized access
- **Certificate-based Auth**: Optional client certificate authentication
- **Connection Validation**: Verify server certificates to prevent MITM attacks

#### Development/Testing Configuration

⚠️ **WARNING**: The following configuration is **ONLY** for development/testing and should **NEVER** be used in production:

```bash
# DEVELOPMENT/TESTING ONLY - Insecure configuration
REDIS_URL=redis://localhost:6379
REDIS_USE_TLS=false
REDIS_TLS_VERIFY_MODE=none
# No authentication - DO NOT USE IN PRODUCTION
```

**Production Security Checklist:**
- ✅ Use `rediss://` or `valkeys://` connection strings for TLS
- ✅ Configure `REDIS_USERNAME` and `REDIS_PASSWORD`
- ✅ Set `REDIS_USE_TLS=true`
- ✅ Use `REDIS_TLS_VERIFY_MODE=required`
- ✅ Configure TLS certificates for mutual authentication
- ❌ Never disable TLS verification in production
- ❌ Never use unencrypted connections in production

## mTLS Configuration Guide

### Server Setup with mTLS

1. **Initialize Certificates:**
```bash
# Generate CA and server certificates
python dns-server/bins/cert_manager.py init

# Or initialize with custom hostname
python dns-server/bins/cert_manager.py server --hostname dns.example.com --ip 192.168.1.10
```

2. **Start Server with mTLS:**
```bash
# Enable mTLS with optional client certificates
ENABLE_MTLS=true python dns-server/bins/server_optimized.py -k certs/server.key -c certs/server.crt -m

# Enforce client certificates (strict mTLS with dual authentication)
# Requires BOTH Bearer token AND client certificate
ENABLE_MTLS=true MTLS_ENFORCE=true python dns-server/bins/server_optimized.py -k certs/server.key -c certs/server.crt -m
```

### Client Certificate Generation

By default, certificates use ECC (Elliptic Curve Cryptography) for better security and performance:

```bash
# Generate ECC client certificate (default P-384 curve)
python dns-server/bins/cert_manager.py client client-001 --email client@example.com

# Use different ECC curve
ECC_CURVE=SECP256R1 python dns-server/bins/cert_manager.py client client-001

# Force RSA certificates (not recommended)
USE_ECC_KEYS=false python dns-server/bins/cert_manager.py client client-001

# List all client certificates
python dns-server/bins/cert_manager.py list

# Revoke a client certificate
python dns-server/bins/cert_manager.py revoke client-001
```

**ECC vs RSA Benefits:**
- ECC P-384 provides equivalent security to RSA 7680-bit keys
- Faster certificate verification
- Smaller certificate and key files
- Better performance on mobile/embedded devices

### Client Setup with mTLS

When MTLS_ENFORCE=true, clients must provide BOTH authentication token AND client certificate:

```bash
# Dual authentication: Bearer token + Client certificate
python dns-client/bins/client.py -d example.com -s https://dns.server:8443 \
  -a "your-bearer-token" \
  --ca-cert certs/ca.crt \
  --client-cert certs/clients/client-001.crt \
  --client-key certs/clients/client-001.key

# Or use environment variables for all configuration
export SQUAWK_SERVER_URL=https://dns.server:8443
export SQUAWK_AUTH_TOKEN=your-bearer-token
export SQUAWK_DOMAIN=example.com
export SQUAWK_CA_CERT=certs/ca.crt
export SQUAWK_CLIENT_CERT=certs/clients/client-001.crt
export SQUAWK_CLIENT_KEY=certs/clients/client-001.key
export SQUAWK_VERIFY_SSL=true
python dns-client/bins/client.py

# Legacy environment variable names also supported
export CA_CERT_PATH=certs/ca.crt
export CLIENT_CERT_PATH=certs/clients/client-001.crt
export CLIENT_KEY_PATH=certs/clients/client-001.key
```

### Web Console Certificate Management

Access certificate management at: `http://localhost:8080/dns_console/certificates`

- Initialize CA and server certificates
- Generate client certificates
- **Download complete client bundles**: ZIP files containing CA cert, client cert, client key, PKCS#12 bundle, and configuration examples
- Download individual certificates and PKCS#12 bundles
- Revoke compromised certificates
- View certificate information and expiration dates

#### Certificate Download Options

Each client certificate provides multiple download options:
- **Bundle Download**: Complete ZIP package with all necessary files and configuration examples
- **Individual Files**: Certificate (.crt), private key (.key), PKCS#12 bundle (.p12)
- **Configuration Templates**: Ready-to-use environment variables and command examples

## Security Considerations

1. **Always use TLS/SSL** in production environments
2. **Enable mTLS** for maximum security with client certificate authentication
3. **Rotate certificates regularly** - default validity is 1 year for server/client certs
4. **Revoke compromised certificates** immediately using the web console
5. **Protect private keys** - stored with 600 permissions by default
6. **Monitor certificate expiration** and renew before expiry
7. **Use strong, random tokens** for authentication
8. **Validate all input** to prevent injection attacks
9. **Keep the system updated** with security patches

## Development

### Project Structure

```
Squawk/
├── dns-server/          # Server component
│   ├── bins/            # Executable scripts
│   ├── web/             # Py4web application
│   └── tests/           # Unit tests
├── dns-client/          # Client component
│   ├── bins/            # Executable scripts
│   └── tests/           # Unit tests
├── docs/                # Documentation
├── docker-compose.yml   # Docker configuration
└── README.md           # This file
```

### Running Tests

```bash
# All tests
pytest

# Server tests
cd dns-server
python tests/unittests.py

# Client tests
cd dns-client
python tests/unittests.py

# New feature tests
pytest tests/test_blacklist.py
pytest tests/test_cache.py
pytest tests/test_installer.py
```

### Performance Testing

```bash
# Load testing with k6
k6 run tests/load-test.js

# Benchmark caching
CACHE_ENABLED=true VALKEY_URL=redis://localhost:6379 python tests/benchmark_cache.py
```

## Why Squawk?

### Built-in Security
- Token-based authentication out of the box
- Domain-level access control
- TLS/SSL support for encrypted communications
- Input validation and sanitization

### Scalability
- Microservices architecture
- Horizontal scaling support
- Database backend for persistent storage
- Lightweight and efficient

### Flexibility
- Multiple deployment options (Docker, standalone, Kubernetes)
- Configurable authentication methods
- Support for various database backends
- Extensible architecture

### Active Development
- Regular updates and security patches
- Community-driven development
- Professional support available

## Contributors

### PTG
- Maintainer: creatorsemailhere@penguintech.group
- General: info@penguintech.group

### Community
- Contributions welcome! Please see CONTRIBUTING.md

## Resources

- Documentation: [docs.squawkdns.com](https://docs.squawkdns.com) (also available locally in `./docs/`)
- Premium Support: https://support.penguintech.group
- Community Issues: [GitHub Issues](https://github.com/penguintechinc/squawk/issues)

## License

See LICENSE.md in the docs folder for licensing information.

## Roadmap

- [x] Multi-factor authentication support ✅
- [x] Single Sign-On (SSO) integration ✅
- [x] Advanced caching with Valkey/Redis ✅
- [x] mTLS client certificate authentication ✅
- [x] DNS blackholing and blacklist management ✅
- [x] Comprehensive logging and audit trails ✅
- [ ] Enhanced Web UI with real-time monitoring
- [ ] Support for additional DNS record types
- [ ] API rate limiting and quotas
- [ ] Prometheus metrics integration
- [ ] GraphQL API support
- [ ] DNS-over-TLS (DoT) support
- [ ] Kubernetes operator for easy deployment
- [ ] Load balancing and failover support
