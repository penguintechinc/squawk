- to memorize
# important-instruction-reminders
Do what has been asked; nothing more, nothing less.
NEVER create files unless they're absolutely necessary for achieving your goal.
ALWAYS prefer editing an existing file to creating a new one.
NEVER proactively create documentation files (*.md) or README files. Only create documentation files if explicitly requested by the User.

# Python Version Standard
ALL Python-based builds and deployments MUST use Python 3.13. This includes:
- Dockerfiles
- CI/CD workflows
- Requirements files
- Local development environments

# Go Version Standard
ALL Go-based builds and deployments MUST use Go 1.23. This includes:
- go.mod files: `go 1.23.0` (no explicit toolchain specification)
- CI/CD workflows: `GO_VERSION: '1.23'`
- Local development environments
- NEVER specify a higher toolchain version that conflicts with GitHub Actions golangci-lint
- This prevents "Go language version used to build golangci-lint is lower than targeted Go version" errors

# Go Security Tools Standard
For Go security scanning, ALWAYS use the official and actively maintained repositories:
- **gosec**: Use `github.com/securego/gosec/v2/cmd/gosec@latest` (8,401+ stars, actively maintained)
- NEVER use `github.com/securecodewarrior/gosec` (repository does not exist)
- Verify repository status before adding new security tools to workflows

# Docker Container Architecture
Each Python component is built as its own separate Docker container image:
- DNS Server: Separate container with server-specific dependencies
- DNS Client (Python): Separate container with client-specific dependencies
- Testing Environment: Separate container with development/testing tools
- Production Environment: Separate optimized container for production deployments

# Docker Base Image Standard
ALL Docker containers MUST use Ubuntu 24.04 LTS as the base image with Python 3.13 from deadsnakes PPA.
This is REQUIRED because:
- python-ldap compilation requires lber.h header which is missing in Debian-based images
- Ubuntu provides proper LDAP development packages (libldap-dev, libldap2-dev, libsasl2-dev)
- deadsnakes PPA provides reliable Python 3.13 installation on Ubuntu
- DO NOT use python:3.13-slim or other Debian-based images due to LDAP header issues

# Docker Build Testing
ALWAYS test Dockerfile changes by running a build before committing:
- Run `docker build -f <dockerfile-path> -t <test-tag> <context-path>` after ANY Dockerfile modification
- Verify the build completes successfully without errors
- Test critical functionality (python-ldap import, package installations)
- Only commit after successful build verification

# Docker Virtual Environment Standard
ALL Docker containers MUST use Python virtual environments to avoid system package conflicts. This prevents issues with packages like blinker that may conflict with system versions.

Requirements:
- Use `python3.13 -m venv /app/venv` to create virtual environment
- Install packages using `/app/venv/bin/pip install` instead of system pip
- Set `ENV PATH="/app/venv/bin:$PATH"` to make venv the default
- Never use `--break-system-packages` flag - virtual environments eliminate the need
- Ensures clean dependency isolation and prevents system package conflicts

# Environment Variable Configuration
ALL user configuration for Squawk DNS is done via environment variables:

## Server Configuration
- `PORT`: Server port (default: 8080)
- `MAX_WORKERS`: Number of worker processes (default: 100)
- `MAX_CONCURRENT_REQUESTS`: Max concurrent DNS requests (default: 1000)
- `AUTH_TOKEN`: Legacy authentication token
- `USE_NEW_AUTH`: Enable new token management system (true/false)
- `DB_TYPE`: Database type for auth
- `DB_URL`: Database connection URL

## Cache Configuration
- `CACHE_ENABLED`: Enable caching (default: true)
- `CACHE_TTL`: Cache TTL in seconds (default: 300)
- `VALKEY_URL` or `REDIS_URL`: Valkey/Redis connection URL (e.g., redis://localhost:6379)
- `CACHE_PREFIX`: Cache key prefix (default: squawk:dns:)

## Blacklist Configuration
- `ENABLE_BLACKLIST`: Enable Maravento blacklist (default: false)
- `BLACKLIST_UPDATE_HOURS`: Update interval in hours (default: 24)

## Client Configuration
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

## Feature Flags (Go Client)
- `SQUAWK_FEATURES`: Enabled features, comma-separated (default: dns) - Options: dns,dhcp,ntp
- `SQUAWK_COMMUNICATION`: Communication protocol (default: http2) - Options: http1 (REST), http2 (gRPC), http3 (QUIC)

## DHCP Client Configuration (Go Client)
- `SQUAWK_DHCP_SERVER_URL`: DHCP server URL (default: https://localhost:8081)
- `SQUAWK_DHCP_INTERFACE`: Network interface for DHCP intercept
- `SQUAWK_DHCP_INTERCEPT`: Enable DHCP port interception (true/false, requires root)
- `SQUAWK_DHCP_LEASE_FILE`: Path to lease storage file (default: /var/lib/squawk/dhcp.leases)

## NTP Client Configuration (Go Client)
- `SQUAWK_NTP_SERVER_URL`: NTP/NTS server URL (default: https://localhost:8082)
- `SQUAWK_NTP_PORT`: Local NTP port for interception (default: 123)
- `SQUAWK_NTP_INTERCEPT`: Enable NTP port interception (true/false, requires root)
- `SQUAWK_NTP_SYNC_INTERVAL`: Time sync interval in seconds (default: 3600)

## DHCP Server Configuration
- `DHCP_PORT`: DHCP server port (default: 8081)
- `DHCP_POOL_SUBNET`: DHCP pool subnet (default: 192.168.1.0/24)
- `DHCP_POOL_START`: Pool start IP (default: 192.168.1.100)
- `DHCP_POOL_END`: Pool end IP (default: 192.168.1.200)
- `DHCP_GATEWAY`: Default gateway (default: 192.168.1.1)
- `DHCP_DNS_SERVERS`: DNS servers, comma-separated (default: 8.8.8.8,8.8.4.4)
- `DHCP_LEASE_TIME`: Lease time in seconds (default: 86400)
- `AUTH_REQUIRED`: Require authentication (default: true)
- `SHARED_AUTH_URL`: DNS server URL for auth validation (default: http://localhost:8080)

## NTP Server Configuration
- `NTP_PORT`: NTP server port (default: 8082)
- `NTS_KE_PORT`: NTS Key Establishment port (default: 4460)
- `UPSTREAM_NTP`: Upstream NTP server (default: pool.ntp.org)
- `AUTH_REQUIRED`: Require authentication (default: true)
- `SHARED_AUTH_URL`: DNS server URL for auth validation (default: http://localhost:8080)

## Logging Configuration
- `LOG_LEVEL`: Logging level - DEBUG, INFO, WARNING, ERROR (default: INFO)
- `LOG_FORMAT`: Log format - json or text (default: json)
- `LOG_FILE`: Log file path (optional)
- `TRUSTED_PROXIES`: Comma-separated trusted proxy IP ranges (default: 127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16)

## Syslog Configuration
- `ENABLE_SYSLOG`: Enable UDP syslog forwarding (default: false)
- `SYSLOG_HOST`: Syslog server hostname/IP (default: localhost)
- `SYSLOG_PORT`: Syslog server port (default: 514)
- `SYSLOG_FACILITY`: Syslog facility number (default: 16)

## mTLS Configuration
- `ENABLE_MTLS`: Enable mutual TLS authentication (default: false)
- `MTLS_ENFORCE`: Require client certificates (default: false)
- `MTLS_CA_CERT`: CA certificate path for client verification (default: certs/ca.crt)
- `CERT_DIR`: Certificate storage directory (default: certs)

## TLS Certificate Configuration
- `USE_ECC_KEYS`: Use ECC keys instead of RSA (default: true)
- `ECC_CURVE`: ECC curve to use - SECP256R1, SECP384R1, SECP521R1 (default: SECP384R1)
- `CA_VALIDITY_DAYS`: CA certificate validity period (default: 3650)
- `CERT_VALIDITY_DAYS`: Server/client certificate validity (default: 365)
- `TLS_ADDITIONAL_HOSTS`: Additional hostnames for server cert (comma-separated)
- `CLIENT_CERT_PATH`: Client certificate path for mTLS
- `CLIENT_KEY_PATH`: Client private key path for mTLS
- `CA_CERT_PATH`: CA certificate path for verification

Note: ECC certificates provide equivalent security to RSA with smaller key sizes and better performance.

# System Tray Client Configuration
The desktop system tray application (dns-client/bins/systray.py) provides enhanced functionality:

## System Tray Features
- **Health Monitoring**: Real-time DNS server health checks every 30 seconds
- **Visual Health Status**: Icon colors indicate server health (green=healthy, yellow=degraded, red=unhealthy)
- **Smart Notifications**: Automatic alerts when DNS servers become unreachable
- **DNS Fallback**: One-click fallback to original DHCP DNS servers for captive portals
- **Manual Health Check**: On-demand server connectivity verification

## DNS Fallback System
- Automatically detects original DNS servers from system configuration
- Supports Windows, macOS, and Linux platforms
- Essential for hotel/airport WiFi captive portals
- Restores DNS settings on application exit

# Release Automation
Automated GitHub CI/CD release pipeline with comprehensive release notes:

## Release Notes Integration
- **Script**: `.github/scripts/extract-release-notes.sh`
- **Source**: `docs/RELEASE_NOTES.md` 
- **Automation**: Both client and server releases automatically include full release notes
- **Components**: Separate release processes for Go client (-client) and DNS server (-server)

## Release Process
1. Version updates in `.version` file trigger releases
2. Automatic extraction of release notes from documentation
3. Component-specific quick start guides included
4. Platform-specific installation instructions
5. GitHub releases created with comprehensive documentation

# Subscription Licensing System
Squawk DNS now includes a comprehensive subscription-based licensing system for premium features:

## License Server Configuration
- **Repository**: https://github.com/PenguinCloud/license-server - Shared license server for all Penguin Technologies products
- **Domain**: `license.squawkdns.com` - hardcoded license server domain
- **Technology**: py4web-based license management portal
- **Database**: PostgreSQL for license and token storage
- **Authentication**: Sales team access only (no customer portal)
- **Multi-Product**: Handles licensing for Squawk DNS and other Penguin Technologies products

## License Management
- **Sales Portal**: `/sales/dashboard` - Create and manage customer licenses (sales team only)
- **License Format**: `SQWK-XXXX-XXXX-XXXX-XXXX-YYYY` (with checksum validation)
- **License Distribution**: Sales team emails license keys directly to customers
- **Customer Access**: Customers do NOT access license.squawkdns.com directly

## DNS Server License Integration
- **License Validation**: `USE_LICENSE_SERVER=true` enables subscription validation
- **Server Flag**: `--license-server` or `-l` enables license mode
- **Token Validation**: Real-time validation via license server API endpoints
- **Environment**: `LICENSE_SERVER_URL=https://license.squawkdns.com`

## Go Client License Integration
- **Daily Validation**: License checked once per day (not per query)
- **Smart Caching**: 24-hour cache minimizes license server load
- **Offline Resilience**: Falls back to cached validation if license server unavailable
- **Backward Compatibility**: Works without license (with warnings)

## License Environment Variables
- `SQUAWK_LICENSE_SERVER_URL`: License server URL (default: https://license.squawkdns.com)
- `SQUAWK_LICENSE_KEY`: Customer license key for evaluation/setup
- `SQUAWK_USER_TOKEN`: Individual user token (preferred for production)
- `SQUAWK_VALIDATE_ONLINE`: Enable online validation vs cache-only (default: true)
- `SQUAWK_LICENSE_CACHE_TIME`: Cache time in minutes (default: 1440 = 24 hours)
- `USE_LICENSE_SERVER`: Enable license server validation in DNS server (default: false)
- `LICENSE_KEY`: DNS server license key for validation

## Feature Comparison by Edition

### Community Edition (Free)
- Basic DNS resolution
- Standard DNS-over-HTTPS support
- mTLS authentication
- Basic caching
- Single-token authentication
- 1 threat intelligence feed
- Basic web console

### Enterprise Self-Hosted ($5/user/month)
- **All Community Features**
- **Selective DNS Routing**: Per-user/group access to private and public DNS entries
- **Advanced Token Management**: Individual user tokens with usage tracking
- **Priority DNS Resolution**: Faster query processing for licensed users
- **Enhanced Caching**: Advanced cache optimization and performance tuning
- **Unlimited Threat Intelligence**: No feed limits, advanced parsers
- **Multi-tenant Architecture**: Secure isolation between different user groups
- **SAML/LDAP/SSO Integration**: Enterprise identity provider integration
- **SCIM Provisioning**: Automated user provisioning and deprovisioning
- **Technical Support**: Professional support and assistance
- **Self-Managed**: Customer controls infrastructure and updates

### Enterprise Cloud-Hosted ($7/user/month)
- **All Self-Hosted Features**
- **Managed Infrastructure**: Penguin Technologies operates and maintains servers
- **99.9% SLA**: Guaranteed uptime with redundant infrastructure
- **Automatic Updates**: Zero-downtime updates and security patches
- **Advanced Monitoring**: 24/7 monitoring with proactive alerting
- **Compliance Reporting**: SOC2, HIPAA, GDPR automated compliance reports
- **24/7 Support**: Dedicated support team with guaranteed response times
- **Global Infrastructure**: Multi-region deployment with CDN edge locations
- **Advanced Threat Intel**: Curated and enhanced threat intelligence feeds
- **Custom Development**: Dedicated engineering resources for custom features
- **Enterprise Monitoring**: Advanced logging, alerting, and SIEM integration
- **Priority Processing**: Highest priority request processing across all users

## Key Enterprise Benefit: Selective DNS Routing
The major advantage of enterprise licensing is the ability to have **one secure DNS endpoint that selectively provides private and public DNS entries based on user or group permissions**:
- Internal users get access to both private corporate DNS entries AND public internet DNS
- External users only get public DNS resolution
- Different user groups can have different levels of DNS access
- Secure authentication ensures only authorized users can resolve private DNS entries
- Single DNS infrastructure serves multiple security contexts

# Selective DNS Routing Architecture
The selective DNS routing system is built on a token-based identity and group membership model:

## Core Concept
- **Individual User Tokens**: Each user has a unique token generated when created on the platform
- **Group Membership**: Tokens map to groups (configured manually or via IDP integration)
- **Permission-Based Response**: Groups determine which DNS zones/entries are visible to users
- **Single Endpoint**: Same DNS server endpoint serves different responses based on user's group membership

## Token Management System
### User Token Creation
- Each user receives a unique authentication token
- Tokens are mapped to user identity and group memberships
- Token validation occurs on every DNS request

### Group Types
- **INTERNAL**: Full access to private + public DNS (company employees)
- **EXTERNAL**: Public DNS only (general internet users)  
- **PARTNER**: Limited private zones + public DNS (business partners)
- **CONTRACTOR**: Specific private zones + public DNS (contractors)
- **ADMIN**: Full access + management capabilities

## DNS Zone Visibility
### Visibility Levels
- **PUBLIC**: Visible to all users (example.com, google.com)
- **INTERNAL**: Visible to internal groups only (intranet.company.com)
- **RESTRICTED**: Visible to specific groups only (secure.company.com)
- **PRIVATE**: Visible to admins only (admin.company.com)

### Response Filtering
1. User makes DNS request with authentication token
2. System identifies user's group memberships
3. DNS resolver checks if requested domain is accessible to user's groups
4. Returns appropriate response:
   - **Authorized**: Returns actual DNS records
   - **Unauthorized**: Returns NXDOMAIN (domain appears to not exist)

## IDP Integration (Enterprise Only)
### SAML Integration
- Maps SAML assertion groups to internal Squawk DNS groups
- Automatic group assignment based on IDP group membership
- Real-time group sync during authentication

### LDAP Integration  
- Queries LDAP directory for user group memberships
- Maps LDAP groups to internal DNS access groups
- Supports nested group structures

### SCIM Provisioning
- Automated user creation and deprovisioning
- Group membership synchronization
- Lifecycle management integration

## Database Schema
### Core Tables
- `tokens`: Individual user authentication tokens
- `groups`: Access control groups with permissions
- `user_groups`: Many-to-many mapping of users to groups
- `dns_zones`: DNS zones with visibility settings
- `dns_records`: Individual DNS records with per-record visibility
- `group_zone_permissions`: Group access permissions to DNS zones

### IDP Integration Tables
- `idp_group_mappings`: Maps IDP groups to local groups
- `saml_assertions`: Cached SAML group data
- `ldap_sync_log`: LDAP synchronization audit trail

# Enterprise Feature Implementation
All enterprise features are implemented with proper license enforcement across two enterprise tiers:

## Enterprise Tier Structure

### Community Edition (Free)
- Basic DNS resolution and caching
- Single threat intelligence feed (1 feed limit)
- Standard DNS-over-HTTPS support
- mTLS authentication
- Basic web console

### Enterprise Self-Hosted ($5/user/month)
- All Community features
- Unlimited threat intelligence feeds
- Advanced token management
- Selective DNS routing
- Priority DNS resolution
- Enhanced caching and analytics
- Technical support
- Multi-tenant architecture
- SAML/LDAP/SSO integration
- Self-managed infrastructure

### Enterprise Cloud-Hosted ($7/user/month)  
- All Self-Hosted features
- Penguin Technologies managed infrastructure
- 99.9% SLA with redundancy
- Automatic updates and patching
- Advanced monitoring and alerting
- Compliance reporting (SOC2, HIPAA, GDPR)
- 24/7 managed support
- Global CDN and edge locations
- Advanced threat intelligence curation
- Custom integrations and development

## License Enforcement Model
- **Feature Gates**: Each feature tier checks appropriate license status before activation
- **Graceful Degradation**: Unlicensed features return appropriate error messages with upgrade prompts
- **Real-time Validation**: License status checked via license server API
- **Offline Resilience**: Cached license validation for temporary connectivity loss
- **Tier Detection**: Automatic detection of Self-Hosted vs Cloud-Hosted licensing

## Priority DNS Resolution
- **Request Queuing**: Enterprise users get priority in processing queue
- **Performance Tiers**: Different response time guarantees based on license
- **Load Balancing**: Enterprise requests bypass rate limits

## Enhanced Caching
- **Extended TTLs**: Enterprise users get longer cache retention
- **Predictive Prefetching**: AI-based query prediction for common patterns
- **Premium Cache Layer**: Separate high-performance cache for licensed users

## Analytics & Reporting
- **Query Tracking**: Detailed logging of all DNS requests per user
- **Usage Reports**: Daily, weekly, monthly usage analytics
- **Performance Metrics**: Response times, cache hit rates, error analysis
- **Compliance Reports**: Automated generation of regulatory compliance reports

## Multi-Tenant Architecture
- **Tenant Isolation**: Complete DNS namespace separation per organization
- **Resource Quotas**: Per-tenant limits on queries, users, zones
- **Custom Configurations**: Tenant-specific DNS policies and settings

## Enterprise Monitoring
- **Security Audit Logs**: Comprehensive logging of all authentication and access events
- **SIEM Integration**: Export logs in CEF, LEEF, and JSON formats
- **Alert Rules**: Configurable thresholds for error rates, response times
- **Compliance Dashboards**: Real-time visibility into security posture

# Server Implementation Files
## Core Server Files
- `dns-server/bins/server_optimized.py`: Standard community server
- `dns-server/bins/server_premium_integrated.py`: Enterprise server with all features
- `dns-server/bins/premium_features.py`: Core enterprise functionality module
- `dns-server/bins/selective_dns_routing.py`: User/group-based DNS filtering

## Feature Modules
- `cache_manager.py`: Enhanced caching with enterprise features
- `cert_manager.py`: mTLS certificate management
- `request_logger.py`: Advanced logging and analytics
- Web console: Token and group management interface

# GitHub Issues Implementation Status
All open GitHub issues have been addressed with full implementations:

## Issue #24: Local DNS Fallback ✅ **IMPLEMENTED**
- **File**: `dns-client/bins/systray.py`
- **Features**: Automatic fallback to DHCP DNS servers for captive portals
- **Platforms**: Windows (netsh), macOS (networksetup), Linux (manual)
- **Integration**: One-click toggle in system tray application

## Issue #23: Per User Token ✅ **IMPLEMENTED** 
- **File**: `dns-server/bins/selective_dns_routing.py`
- **Features**: Individual user tokens with group-based permissions
- **JWT Integration**: Token validation with user identity mapping
- **Audit Trail**: Per-user query logging and analytics

## Issue #17: WHOIS Lookup Section ✅ **IMPLEMENTED**
- **File**: `dns-server/bins/whois_manager.py` 
- **Features**: Domain and IP WHOIS lookups with PostgreSQL caching
- **Web Interface**: Searchable interface via py4web forms and grids
- **API**: RESTful endpoints for programmatic access
- **Caching**: Monthly cleanup with configurable retention policies

## Issue #16: IOC API Management ✅ **IMPLEMENTED**
- **File**: `dns-server/bins/ioc_manager.py`
- **Features**: Per-token IOC overrides (allow/block specific domains/IPs)
- **Scope Control**: User-specific, token-specific, or global overrides
- **API**: Full CRUD operations via REST API
- **Integration**: Works with existing authentication and mTLS

## Issue #15: IOC/Threat Intelligence Blocking ✅ **IMPLEMENTED**
- **File**: `dns-server/bins/ioc_manager.py`
- **Feed Sources**: abuse.ch URLhaus, Malware Domains, Spamhaus DBL, Emerging Threats, Feodo Tracker
- **Real-time Updates**: Automatic feed updates with configurable intervals
- **Performance**: In-memory caching for fast lookup performance
- **Override System**: User-specific allow/block overrides

## Issue #14: Prometheus/Grafana Stats ✅ **IMPLEMENTED**
- **File**: `dns-server/bins/prometheus_metrics.py`
- **Metrics**: DNS queries, response times, cache hits, top domains, user analytics
- **Integration**: Native Prometheus metrics endpoint at `/metrics`
- **Dashboard Ready**: Compatible with Grafana for visualization
- **Performance**: Background collection with minimal overhead

## Issue #10: Client Configuration Pull ✅ **IMPLEMENTED**
- **File**: `dns-server/bins/client_config_api.py` and `py4web_extended_app.py`
- **Features**: JWT-based client authentication with deployment domains
- **Security Integration**: Uses existing token authentication and mTLS
- **API**: Native py4web REST API for configuration management
- **Role-based Access**: Client-Reader, Client-Maintainer, Domain-Admin roles
- **Py4web Integration**: Native forms, grids, and REST endpoints

# Py4web Integration
All new features utilize py4web's native capabilities:

## Native REST API
- **Publisher**: Automatic CRUD operations for database tables
- **Authentication**: Integrated with py4web auth system
- **CORS**: Cross-origin request support for web interfaces

## Web Interface Components
- **Forms**: FormStyleBulma for consistent UI across all features
- **Grids**: Automatic data grids with search, sort, and pagination
- **Dashboard**: Combined statistics view with real-time data

## Background Tasks
- **Scheduler**: Automatic IOC feed updates, cache cleanup, client maintenance
- **Async Support**: Full asyncio integration for non-blocking operations

## Security Integration
- **Authentication**: Seamless integration with existing token system
- **mTLS Support**: Certificate validation for client configuration API
- **Permission System**: Role-based access control for all features

# License Requirements by Feature

## Community Edition Features (Free)
- Basic DNS resolution and caching
- Standard DNS-over-HTTPS support  
- mTLS authentication
- Single threat intelligence feed
- Basic web console
- Community support via GitHub

## Enterprise Self-Hosted Features ($5/user/month)
- **All Community Features**
- **SAML/SSO**: Enterprise identity provider integration
- **SCIM Provisioning**: Automated user management
- **Advanced Analytics**: Detailed reporting and compliance features
- **Priority Support**: Professional support with SLA guarantees
- **Multi-tenant**: Organization-level isolation and management
- **Unlimited Threat Intel**: No limits on threat intelligence feeds
- **Selective DNS Routing**: Per-user/group access control
- **Self-Managed Infrastructure**: Customer controls deployment and updates

## Enterprise Cloud-Hosted Exclusive Features ($7/user/month)

### 🏢 Managed Infrastructure
- **Penguin Technologies Operated**: Professional DevOps team manages all infrastructure
- **Multi-Region Deployment**: Geographically distributed servers for optimal performance
- **Auto-Scaling**: Automatic resource scaling based on demand
- **High Availability**: 99.9% uptime SLA with redundant infrastructure
- **Disaster Recovery**: Automated backup and recovery procedures

### 🔄 Automatic Operations
- **Zero-Downtime Updates**: Seamless rolling updates without service interruption
- **Security Patching**: Automatic security updates and vulnerability management
- **Configuration Management**: Centralized configuration with change tracking
- **Health Monitoring**: 24/7 automated monitoring with proactive alerting

### 📊 Advanced Monitoring & Alerting
- **Real-Time Dashboards**: Live system performance and usage metrics
- **Predictive Analytics**: AI-powered capacity planning and performance optimization
- **Custom Alerting**: Configurable alerts for performance, security, and availability
- **Incident Response**: Dedicated NOC team for 24/7 incident management

### 📋 Compliance & Reporting
- **SOC2 Type II**: Automated SOC2 compliance reporting and audits
- **HIPAA Compliance**: Healthcare data protection with encrypted storage
- **GDPR Compliance**: EU data protection with data residency controls
- **Custom Compliance**: Support for industry-specific compliance requirements
- **Audit Trails**: Comprehensive logging for regulatory compliance

### 🌐 Global Performance Infrastructure
- **CDN Integration**: Cloudflare-powered global content delivery network
- **Edge Locations**: DNS resolution from geographically closest locations
- **Anycast Network**: Automatic routing to optimal servers
- **Network Optimization**: Premium network peering for reduced latency

### 🎯 Advanced Threat Intelligence
- **Curated Feeds**: Professional threat intelligence curation and validation
- **Custom Threat Intel**: Penguin Technologies proprietary threat research
- **Real-Time Updates**: Sub-minute threat intelligence updates
- **Threat Attribution**: Enhanced context and attribution for security events
- **Custom IOC Integration**: Private threat intelligence feed integration

### 👥 Dedicated Support & Development
- **24/7 Dedicated Support**: Guaranteed response times with escalation procedures
- **Dedicated Customer Success Manager**: Personal account management
- **Custom Feature Development**: Dedicated engineering resources for customer-specific needs
- **Priority Feature Requests**: Influence on product roadmap and feature prioritization
- **Direct Engineering Access**: Direct communication with development team

### 🔐 Enterprise Security Enhancements
- **Advanced Threat Detection**: ML-based anomaly detection and threat hunting
- **Zero Trust Architecture**: Identity-based access with continuous verification
- **Security Operations Center**: 24/7 security monitoring and incident response
- **Penetration Testing**: Regular security assessments and vulnerability testing
- **Threat Intelligence Sharing**: Bi-directional threat intelligence with customers

# Important Notes
- **Documentation Domain**: All documentation references should use `squawkdns.com`
- **Web Console**: Default available at `http://localhost:8000/dns_console`
- **License Portal**: Sales team only at `https://license.squawkdns.com/sales/dashboard` (internal access)
- **Health Monitoring**: System tray provides real-time server health status
- **DNS Validation**: All components implement RFC 1035 compliant validation
- **Multi-Server Support**: Clients support multiple DNS servers with automatic failover

# Git Workflow
ALWAYS commit all changes when completing work or making significant modifications to ensure proper version control and deployment tracking.