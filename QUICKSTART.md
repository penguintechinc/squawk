# Squawk DNS Manager + DNS Server - Quick Start

## What You Have

A complete implementation of:
- **DNS Server**: Python 3.13 async application with Manager integration
- **Manager Infrastructure**: Docker setup for Flask backend + React frontend
- **Test Suites**: Comprehensive API and DNS server tests
- **Documentation**: Detailed implementation guides

## Directory Overview

```
squawk/
├── dns-server/          ✅ COMPLETE - Full implementation
│   ├── app/            14 Python files (services, utils, main app)
│   ├── protos/         gRPC definitions
│   ├── tests/          DNS server test suite
│   └── Dockerfile.dns-server
│
├── manager/
│   ├── backend/        ✅ READY - Structure + dependencies
│   │   ├── app/        (Agent 1 to implement)
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   ├── frontend/       (Agent 2 to implement)
│   ├── tests/          ✅ COMPLETE - API test suite
│   └── tools/          ✅ COMPLETE - Screenshot tool
│
└── docker-compose-manager.yml  ✅ COMPLETE - Full orchestration
```

## Quick Start (5 Steps)

### 1. Generate Join Keys
```bash
cd /home/penguin/code/squawk
python -c "import secrets; print('DNS_SERVER_1_JOIN_KEY=' + secrets.token_hex(32))"
python -c "import secrets; print('DNS_SERVER_2_JOIN_KEY=' + secrets.token_hex(32))"
```

### 2. Create .env File
```bash
cp .env.example .env
# Edit .env and paste the join keys from step 1
```

### 3. Build Services
```bash
docker-compose -f docker-compose-manager.yml build
```

### 4. Start Services
```bash
docker-compose -f docker-compose-manager.yml up -d
```

### 5. Verify
```bash
# Check all services are running
docker-compose -f docker-compose-manager.yml ps

# Test DNS Server 1
curl http://localhost:8080/health

# Test DNS Server 2
curl http://localhost:8081/health
```

## Service URLs

Once running:
- **Manager API**: http://localhost:5000
- **Manager UI**: http://localhost:3000
- **DNS Server 1**: http://localhost:8080 (gRPC: 50052, DNS: 5353)
- **DNS Server 2**: http://localhost:8081 (gRPC: 50053, DNS: 5354)
- **PostgreSQL**: localhost:5432
- **Valkey**: localhost:6379

## DNS Query Examples

### Query DNS Server Directly
```bash
# Query Google's DNS via DNS Server 1
curl "http://localhost:8080/dns/query?name=google.com&type=A"

# Query with authentication (after Manager is implemented)
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:8080/dns/query?name=internal.company.com&type=A"
```

### Check Metrics

As of v2.1.x the `/metrics` and `/status` endpoints require a valid JWT bearer
token (previously unauthenticated). `/health` remains open for probes.

```bash
curl -H "Authorization: Bearer YOUR_JWT" http://localhost:8080/metrics
```

### Check Status
```bash
curl -H "Authorization: Bearer YOUR_JWT" http://localhost:8080/status | jq
```

## Running Tests

### Manager API Tests
```bash
cd /home/penguin/code/squawk/manager/tests
pip install pytest requests
pytest test_api.py -v -s
```

### DNS Server Tests
```bash
cd /home/penguin/code/squawk/dns-server/tests
pip install pytest requests
pytest test_dns_server.py -v -s
```

## Architecture

```
┌──────────────┐         ┌──────────────┐
│   Client     │────────>│  DNS Server  │
│              │         │   Instance   │
└──────────────┘         └──────┬───────┘
                                │
                         ┌──────▼───────┐
                         │   Manager    │
                         │   Backend    │
                         └──────┬───────┘
                                │
                    ┌───────────┼───────────┐
                    │                       │
              ┌─────▼─────┐         ┌─────▼─────┐
              │ PostgreSQL│         │  Valkey   │
              │           │         │  (Cache)  │
              └───────────┘         └───────────┘
```

## DNS Server Features

### Implemented ✅
- Manager API client (registration, sync, heartbeat)
- DNS resolution (A, AAAA, CNAME, MX, TXT)
- Redis/Valkey caching
- IOC/threat intelligence blocking
- Zone-based access control
- Graceful degradation (normal → cached → degraded)
- Metrics (Prometheus format)
- gRPC service
- Health checks
- Persistent config cache

### Resilience Modes
- **Normal**: Full functionality, Manager available
- **Cached**: Manager down, uses 24h cached config
- **Degraded**: Cache expired, public DNS only

## Manager Backend (To Be Implemented)

Agent 1 needs to implement:
- Flask app factory (`app/__init__.py`)
- PyDAL models (`app/models/`)
- API blueprints (`app/blueprints/`)
- Authentication service (`app/services/auth_service.py`)
- Join key service (`app/services/join_key_service.py`)
- RBAC middleware (`app/middleware/rbac.py`)

Files ready:
- ✅ Dockerfile
- ✅ requirements.txt
- ✅ wsgi.py
- ✅ gRPC proto definitions

## Manager Frontend (To Be Implemented)

Agent 2 needs to implement:
- React app with TypeScript
- Material-UI components
- Authentication flow
- DNS server fleet management
- User/team/zone management
- Real-time updates

## Troubleshooting

### DNS Server Won't Start
```bash
# Check logs
docker-compose -f docker-compose-manager.yml logs dns-server-1

# Common issues:
# - Missing JOIN_KEY in .env
# - Manager backend not running
# - Valkey not accessible
```

### Manager Backend Not Starting
```bash
# Check logs
docker-compose -f docker-compose-manager.yml logs manager-backend

# Common issues:
# - PostgreSQL not ready
# - Missing environment variables
# - Database migration needed
```

### Database Connection Issues
```bash
# Check PostgreSQL
docker-compose -f docker-compose-manager.yml exec postgres psql -U squawk -d squawk_manager

# Check tables (after Manager implements models)
# \dt
```

### Cache Issues
```bash
# Check Valkey/Redis
docker-compose -f docker-compose-manager.yml exec valkey valkey-cli ping

# Clear cache
docker-compose -f docker-compose-manager.yml exec valkey valkey-cli FLUSHALL
```

## Development Workflow

### Make Changes to DNS Server
```bash
# Edit files in dns-server/app/
# Rebuild container
docker-compose -f docker-compose-manager.yml build dns-server-1
docker-compose -f docker-compose-manager.yml up -d dns-server-1
```

### View Logs
```bash
# All services
docker-compose -f docker-compose-manager.yml logs -f

# Specific service
docker-compose -f docker-compose-manager.yml logs -f dns-server-1
```

### Stop Services
```bash
docker-compose -f docker-compose-manager.yml down
```

### Clean Up
```bash
# Stop and remove volumes
docker-compose -f docker-compose-manager.yml down -v
```

## Next Steps

### For Agent 1 (Manager Backend)
1. Review `/home/penguin/code/squawk/IMPLEMENTATION_GUIDE.md`
2. Review Manager API endpoints section
3. Implement Flask application in `manager/backend/app/`
4. Test with `manager/tests/test_api.py`

### For Agent 2 (Manager Frontend)
1. Review Manager backend API endpoints
2. Create React application in `manager/frontend/`
3. Implement UI components for DNS server fleet
4. Add real-time status updates

### For Integration Testing
1. Start all services
2. Run Manager API tests
3. Run DNS Server tests
4. Test resilience scenarios
5. Performance testing

## Documentation

Detailed documentation available:
- **IMPLEMENTATION_GUIDE.md**: Complete technical documentation (16KB)
- **AGENT3_DELIVERABLES.md**: File-by-file breakdown (10KB)
- **AGENT3_SUMMARY.md**: Implementation summary (10KB)
- **Architecture Plan**: `/home/penguin/.claude/plans/vectorized-gliding-owl.md`
- **Project Config**: `/home/penguin/code/squawk/CLAUDE.md`

## Support

For questions or issues:
1. Check IMPLEMENTATION_GUIDE.md
2. Review architecture plan
3. Check Docker logs
4. Verify environment variables
5. Test individual components

## Success Checklist

- [ ] Join keys generated and added to .env
- [ ] All services start successfully
- [ ] DNS Server 1 health check passes
- [ ] DNS Server 2 health check passes
- [ ] Public DNS queries work
- [ ] Metrics endpoint returns data
- [ ] Manager backend tests ready (after Agent 1)
- [ ] Manager frontend connects (after Agent 2)
- [ ] Integration tests pass (after both agents)

---

**Ready for**: Agent 1 (Manager Backend) and Agent 2 (Manager Frontend)

**Status**: DNS Server ✅ COMPLETE | Manager Backend ⏳ PENDING | Manager Frontend ⏳ PENDING
