# Squawk DNS: Manager + DNS Server Implementation Guide

## Overview

This implementation provides a complete Manager + DNS Server microservices architecture for Squawk DNS v2.1.0.

## Architecture

```
┌─────────────────────────────────────┐
│  Frontend (React/NodeJS)            │
│  - User/token management UI         │
│  - DNS server fleet monitoring      │
│  - Analytics dashboard              │
└─────────────┬───────────────────────┘
              │ HTTPS/WebSocket
┌─────────────▼───────────────────────┐
│  Manager API (Flask/PyDAL)          │
│  - Authentication & Global RBAC     │
│  - DNS server registration          │
│  - 64-char hex join key validation  │
│  - JWT token issuance               │
│  - Config/IOC feed distribution     │
└─────────────┬───────────────────────┘
              │ Join Key → JWT
    ┌─────────┴──────────┬──────────────┐
┌───▼────────┐  ┌────────▼──┐  ┌────────▼──┐
│ DNS Server │  │ DNS Server│  │ DNS Server│
│ Instance 1 │  │ Instance 2│  │ Instance N│
```

## Directory Structure

```
squawk/
├── manager/
│   ├── backend/          # Flask API server
│   │   ├── app/
│   │   │   ├── blueprints/      # API routes
│   │   │   ├── models/          # Database models
│   │   │   ├── services/        # Business logic
│   │   │   ├── middleware/      # Auth, RBAC
│   │   │   ├── protos/          # gRPC definitions
│   │   │   └── utils/
│   │   ├── Dockerfile
│   │   ├── requirements.txt
│   │   └── wsgi.py
│   ├── frontend/         # React dashboard
│   │   ├── src/
│   │   ├── Dockerfile
│   │   └── package.json
│   ├── tests/
│   │   └── test_api.py          # API integration tests
│   └── tools/
│       └── screenshot.py        # Documentation screenshots
├── dns-server/
│   ├── app/
│   │   ├── services/
│   │   │   ├── manager_client.py     # Manager API client
│   │   │   ├── dns_resolver.py       # DNS resolution
│   │   │   ├── cache_manager.py      # Redis/Valkey cache
│   │   │   ├── ioc_checker.py        # IOC/threat intel
│   │   │   ├── selective_router.py   # Zone permissions
│   │   │   └── metrics_reporter.py   # Metrics tracking
│   │   ├── utils/
│   │   │   └── resilience.py         # Graceful degradation
│   │   ├── storage/                  # Config/JWT cache
│   │   ├── config.py
│   │   ├── main.py                   # Quart application
│   │   └── grpc_server.py            # gRPC service
│   ├── protos/
│   │   └── dns_query_service.proto
│   ├── tests/
│   │   └── test_dns_server.py
│   ├── Dockerfile.dns-server
│   └── requirements-dns-server.txt
├── docker-compose-manager.yml
└── .env.example
```

## Components Implemented

### DNS Server (/home/penguin/code/squawk/dns-server/)

#### Core Services
- **manager_client.py**: Manager API communication
  - `register()`: Register with Manager using join key
  - `refresh_jwt()`: Refresh JWT before expiration
  - `sync_config()`: Fetch zones, IOC feeds from Manager
  - `heartbeat()`: Send metrics to Manager
  - `save_to_cache()` / `load_from_cache()`: Persistent cache

- **dns_resolver.py**: DNS resolution using dnspython
  - `resolve()`: Resolve DNS queries (A, AAAA, CNAME, MX, TXT)
  - `resolve_custom_zone()`: Resolve from Manager-provided zones

- **cache_manager.py**: Redis/Valkey caching
  - `get()` / `set()`: Cache DNS results
  - Cache hit/miss tracking

- **ioc_checker.py**: IOC/threat intelligence
  - `is_blocked()`: Check domain against IOC feeds
  - `load_feeds()`: Load feeds from Manager config

- **selective_router.py**: Zone-based access control
  - `check_zone_permission()`: Verify user can access zone
  - Visibility rules: public/internal/restricted/private

- **metrics_reporter.py**: Metrics collection
  - `record_query()`, `record_cache_hit()`, etc.
  - `get_metrics()`: Return metrics for heartbeat

#### Resilience
- **resilience.py**: Graceful degradation
  - `check_mode()`: Determine operational mode
    - **normal**: Full functionality, Manager available
    - **cached**: Manager down, use cached config (24h TTL)
    - **degraded**: Cache expired, public-only DNS
  - `should_serve_zone()`: Zone access based on mode

#### Main Application
- **main.py**: Quart async application
  - `/dns/query`: DNS-over-HTTPS endpoint
  - `/health`: Health check
  - `/metrics`: Prometheus metrics
  - `/status`: Detailed status
  - Background tasks: config sync, heartbeat

- **grpc_server.py**: gRPC DNS query service
  - `Query()`: Single DNS query
  - `BatchQuery()`: Multiple queries
  - `StreamQuery()`: Bidirectional streaming

### Manager Backend (/home/penguin/code/squawk/manager/backend/)

#### Configuration
- Dockerfile: Python 3.13 on Ubuntu 24.04
- requirements.txt: Flask, PyDAL, gRPC, etc.
- wsgi.py: Gunicorn entry point

#### API Structure (to be implemented by Agent 1)
- **blueprints/**:
  - `auth.py`: POST /api/v1/auth/login
  - `dns_servers.py`: DNS server registration/management
  - `users.py`, `teams.py`, `zones.py`: CRUD operations
  - `config.py`: GET /api/v1/dns-servers/{id}/config

- **models/**:
  - `auth.py`: User, Token, Group, Role
  - `dns_server.py`: DNSServer, JoinKey
  - `dns.py`: DNSZone, DNSRecord
  - `team.py`: Team, TeamMember

- **services/**:
  - `auth_service.py`: JWT generation/validation
  - `join_key_service.py`: 64-char hex key generation
  - `config_service.py`: DNS server config distribution

- **protos/**:
  - `manager_service.proto`: gRPC service definition

### Tests

#### Manager API Tests (/home/penguin/code/squawk/manager/tests/test_api.py)
- `test_health_check()`: Health endpoint
- `test_login_success()` / `test_login_failure()`: Authentication
- `test_create_dns_server()`: DNS server creation with join key
- `test_dns_server_registration()`: Registration flow
- `test_list_users_authorized()`: RBAC enforcement
- `test_create_team()`, `test_create_zone()`: CRUD operations
- `test_rbac_team_isolation()`: Team-level access control

#### DNS Server Tests (/home/penguin/code/squawk/dns-server/tests/test_dns_server.py)
- `test_health_check()`: Health endpoint
- `test_dns_query_public()`: Public DNS resolution
- `test_dns_query_with_token()`: Authenticated queries
- `test_dns_query_private_zone_authorized()`: Zone access control
- `test_ioc_blocking()`: IOC feed blocking
- `test_cache_hit()`: Cache functionality
- `test_resilience_degraded_mode()`: Graceful degradation

### Docker Infrastructure

#### docker-compose-manager.yml
Services:
- **postgres**: PostgreSQL 16 for Manager database
- **valkey**: Redis-compatible cache
- **manager-backend**: Flask API on port 5000
- **manager-frontend**: React UI on port 3000
- **dns-server-1**: DNS instance on port 8080, 50052 (gRPC)
- **dns-server-2**: DNS instance on port 8081, 50053 (gRPC)

#### .env.example
Configuration template:
- Database passwords
- JWT secrets
- DNS server join keys (generate with `secrets.token_hex(32)`)

### Tools

#### screenshot.py (/home/penguin/code/squawk/manager/tools/screenshot.py)
Playwright-based screenshot capture for documentation:
- Automated login
- Captures all Manager UI pages
- Saves to docs/screenshots/
- Usage: `python screenshot.py --url http://localhost:3000`

## Setup Instructions

### 1. Generate Join Keys

```bash
python -c "import secrets; print('DNS_SERVER_1_JOIN_KEY=' + secrets.token_hex(32))"
python -c "import secrets; print('DNS_SERVER_2_JOIN_KEY=' + secrets.token_hex(32))"
```

### 2. Create .env File

```bash
cp .env.example .env
# Edit .env and add generated join keys
```

### 3. Build and Run

```bash
# Build all services
docker-compose -f docker-compose-manager.yml build

# Start all services
docker-compose -f docker-compose-manager.yml up -d

# Check status
docker-compose -f docker-compose-manager.yml ps
```

### 4. Access Services

- Manager Frontend: http://localhost:3000
- Manager API: http://localhost:5000
- DNS Server 1: http://localhost:8080
- DNS Server 2: http://localhost:8081
- PostgreSQL: localhost:5432
- Valkey: localhost:6379

## Testing

### Run Manager API Tests

```bash
cd manager/tests
pip install pytest requests
pytest test_api.py -v
```

### Run DNS Server Tests

```bash
cd dns-server/tests
pip install pytest requests
pytest test_dns_server.py -v
```

## Resilience Strategy

### Operational Modes

1. **Normal Mode**
   - Manager available
   - Full functionality
   - Real-time config sync
   - JWT tokens valid

2. **Cached Mode**
   - Manager unreachable
   - Use cached config (24h TTL)
   - Enforce cached permissions
   - Continue serving DNS queries
   - Periodic reconnection attempts

3. **Degraded Mode**
   - Manager unreachable
   - Cache expired (>24h)
   - Public-only DNS
   - No zone-based filtering
   - Basic DNS resolution only

### Transition Flow

```
NORMAL → (Manager down) → CACHED → (Cache expires) → DEGRADED
   ↑                                                       |
   └──────────── (Manager reconnects) ────────────────────┘
```

## DNS Server Registration Flow

1. **Manager**: Create DNS server entry, generate 64-char join key
2. **DNS Server**: Start with JOIN_KEY environment variable
3. **DNS Server**: POST /api/v1/dns-servers/register with join key
4. **Manager**: Validate join key, generate JWT token
5. **Manager**: Return JWT + server ID + initial config
6. **DNS Server**: Cache JWT and config to disk
7. **DNS Server**: Periodic sync and heartbeat with JWT

## RBAC Model

### Global Roles
- **SystemAdmin**: Full access to all resources
- **OrgAdmin**: Manage organization, teams, users
- **UserManager**: Create/edit users
- **Viewer**: Read-only access

### Team Roles
- **TeamAdmin**: Manage team zones, members
- **TeamMember**: Access team zones
- **TeamViewer**: Read-only team access

### Zone Visibility
- **public**: Accessible to all
- **internal**: Accessible to team members
- **restricted**: Accessible to specific teams only
- **private**: Admin-only access

## API Endpoints

### Manager API

#### Authentication
- `POST /api/v1/auth/login`: Login with username/password
- `POST /api/v1/auth/refresh`: Refresh JWT token

#### DNS Server Management
- `GET /api/v1/dns-servers`: List DNS servers
- `POST /api/v1/dns-servers`: Create DNS server (get join key)
- `POST /api/v1/dns-servers/register`: Register with join key
- `GET /api/v1/dns-servers/{id}/config`: Get server config
- `POST /api/v1/dns-servers/{id}/heartbeat`: Send heartbeat

#### User Management
- `GET /api/v1/users`: List users
- `POST /api/v1/users`: Create user
- `PUT /api/v1/users/{id}`: Update user
- `DELETE /api/v1/users/{id}`: Delete user

#### Team Management
- `GET /api/v1/teams`: List teams
- `POST /api/v1/teams`: Create team
- `GET /api/v1/teams/{id}/members`: List team members
- `POST /api/v1/teams/{id}/members`: Add team member

#### DNS Zone Management
- `GET /api/v1/zones`: List zones
- `POST /api/v1/zones`: Create zone
- `PUT /api/v1/zones/{id}`: Update zone
- `DELETE /api/v1/zones/{id}`: Delete zone
- `GET /api/v1/zones/{id}/records`: List zone records

### DNS Server API

#### DNS Queries
- `GET /dns/query?name={domain}&type={type}`: DNS-over-HTTPS query
- `GET /health`: Health check
- `GET /metrics`: Prometheus metrics
- `GET /status`: Detailed status

#### gRPC Endpoints
- `Query()`: Single DNS query
- `BatchQuery()`: Multiple queries
- `StreamQuery()`: Streaming queries
- `HealthCheck()`: gRPC health check

## Performance Optimizations

### Manager Backend
- Gunicorn with gevent workers (4 workers)
- Redis caching for JWT validations
- Database connection pooling
- Response compression

### DNS Server
- Local Redis cache for DNS results
- Async DNS resolution (dnspython)
- In-memory IOC cache
- Config caching (reduce Manager calls)
- Batch metrics reporting

## Security

### Join Key Security
- 64-char hex keys (256-bit entropy)
- One-time use (revoked after registration)
- TLS-only transmission

### JWT Security
- Short expiration (15min Manager, 24h DNS)
- Unique secret per DNS server
- Signature validation on every request

### RBAC Enforcement
- Permission checks at Manager and DNS server
- Team isolation at database level
- Audit logging for privilege escalation

## Next Steps

1. **Agent 1**: Implement Manager Backend
   - Flask app factory
   - PyDAL models
   - API blueprints
   - Authentication service
   - Join key service
   - RBAC middleware

2. **Agent 2**: Implement Manager Frontend
   - React app with TypeScript
   - Material-UI components
   - Authentication flow
   - DNS server fleet management
   - User/team/zone management
   - Real-time WebSocket updates

3. **Integration Testing**
   - Run full test suite
   - Test resilience scenarios
   - Performance testing
   - RBAC verification

4. **Documentation**
   - Capture UI screenshots
   - Update README.md
   - API documentation
   - Deployment guide

## Files Created

### DNS Server
- `/home/penguin/code/squawk/dns-server/app/config.py`
- `/home/penguin/code/squawk/dns-server/app/main.py`
- `/home/penguin/code/squawk/dns-server/app/grpc_server.py`
- `/home/penguin/code/squawk/dns-server/app/services/manager_client.py`
- `/home/penguin/code/squawk/dns-server/app/services/dns_resolver.py`
- `/home/penguin/code/squawk/dns-server/app/services/cache_manager.py`
- `/home/penguin/code/squawk/dns-server/app/services/ioc_checker.py`
- `/home/penguin/code/squawk/dns-server/app/services/selective_router.py`
- `/home/penguin/code/squawk/dns-server/app/services/metrics_reporter.py`
- `/home/penguin/code/squawk/dns-server/app/utils/resilience.py`
- `/home/penguin/code/squawk/dns-server/protos/dns_query_service.proto`
- `/home/penguin/code/squawk/dns-server/requirements-dns-server.txt`
- `/home/penguin/code/squawk/dns-server/Dockerfile.dns-server`
- `/home/penguin/code/squawk/dns-server/tests/test_dns_server.py`

### Manager
- `/home/penguin/code/squawk/manager/backend/Dockerfile`
- `/home/penguin/code/squawk/manager/backend/requirements.txt`
- `/home/penguin/code/squawk/manager/backend/wsgi.py`
- `/home/penguin/code/squawk/manager/backend/app/protos/manager_service.proto`
- `/home/penguin/code/squawk/manager/tests/test_api.py`
- `/home/penguin/code/squawk/manager/tools/screenshot.py`

### Infrastructure
- `/home/penguin/code/squawk/docker-compose-manager.yml`
- `/home/penguin/code/squawk/.env.example`
- `/home/penguin/code/squawk/IMPLEMENTATION_GUIDE.md`

## Reference

- Architecture Plan: `/home/penguin/.claude/plans/vectorized-gliding-owl.md`
- Project Configuration: `/home/penguin/code/squawk/CLAUDE.md`
