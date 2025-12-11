# Squawk DNS Manager Backend

Flask-based control plane for Squawk DNS with PyDAL database abstraction.

## Features

- **Authentication**: JWT-based authentication with bcrypt password hashing
- **RBAC**: Global roles (SystemAdmin, OrgAdmin, UserManager, Viewer) and team roles (TeamAdmin, TeamMember, TeamViewer)
- **DNS Server Management**: Register and manage multiple DNS servers with 64-char hex join keys
- **Zone Management**: Create and manage DNS zones with selective visibility
- **IOC Feed Management**: Configure threat intelligence feeds
- **Analytics**: Query statistics and performance metrics
- **Token Management**: API tokens for DNS authentication
- **License Integration**: Enterprise feature gating with license server
- **gRPC API**: High-performance gRPC endpoints for DNS server communication

## Quick Start

### 1. Install Dependencies

```bash
cd manager/backend
python3.13 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your configuration
```

### 3. Initialize Database

```bash
python init_db.py
```

This creates:
- Database tables
- Default admin user (username: `admin`, password: `admin123`)
- Example team and DNS zone

### 4. Run Development Server

```bash
# REST API only
python wsgi.py

# With gRPC server
python app/grpc_server.py
```

### 5. Run Production Server

```bash
gunicorn --workers=4 --worker-class=gevent --bind=0.0.0.0:5000 wsgi:app
```

## API Endpoints

### Authentication
- `POST /api/v1/auth/login` - Login with username/password
- `POST /api/v1/auth/refresh` - Refresh access token
- `POST /api/v1/auth/logout` - Logout
- `GET /api/v1/auth/me` - Get current user info

### User Management (SystemAdmin, UserManager)
- `GET /api/v1/users` - List users
- `POST /api/v1/users` - Create user
- `GET /api/v1/users/{id}` - Get user
- `PUT /api/v1/users/{id}` - Update user
- `DELETE /api/v1/users/{id}` - Delete user

### Team Management
- `GET /api/v1/teams` - List teams
- `POST /api/v1/teams` - Create team (OrgAdmin)
- `GET /api/v1/teams/{id}` - Get team
- `PUT /api/v1/teams/{id}` - Update team
- `DELETE /api/v1/teams/{id}` - Delete team
- `GET /api/v1/teams/{id}/members` - List members
- `POST /api/v1/teams/{id}/members` - Add member
- `PUT /api/v1/teams/{id}/members/{user_id}` - Update member role
- `DELETE /api/v1/teams/{id}/members/{user_id}` - Remove member

### DNS Server Management
- `GET /api/v1/dns-servers` - List servers
- `POST /api/v1/dns-servers` - Create server (generates join key)
- `GET /api/v1/dns-servers/{id}` - Get server
- `DELETE /api/v1/dns-servers/{id}` - Delete server
- `POST /api/v1/dns-servers/register` - Register server with join key
- `GET /api/v1/dns-servers/{id}/config` - Get server config (requires server JWT)
- `POST /api/v1/dns-servers/{id}/heartbeat` - Send heartbeat
- `GET /api/v1/dns-servers/{id}/metrics` - Get server metrics

### DNS Zone Management
- `GET /api/v1/zones` - List zones
- `POST /api/v1/zones` - Create zone
- `GET /api/v1/zones/{id}` - Get zone with records
- `PUT /api/v1/zones/{id}` - Update zone
- `DELETE /api/v1/zones/{id}` - Delete zone
- `GET /api/v1/zones/{id}/records` - List records
- `POST /api/v1/zones/{id}/records` - Create record
- `PUT /api/v1/zones/{id}/records/{record_id}` - Update record
- `DELETE /api/v1/zones/{id}/records/{record_id}` - Delete record

### IOC Feed Management
- `GET /api/v1/ioc-feeds` - List feeds
- `POST /api/v1/ioc-feeds` - Create feed (SystemAdmin)
- `GET /api/v1/ioc-feeds/{id}` - Get feed
- `PUT /api/v1/ioc-feeds/{id}` - Update feed
- `DELETE /api/v1/ioc-feeds/{id}` - Delete feed
- `POST /api/v1/ioc-feeds/{id}/sync` - Trigger sync

### Token Management
- `GET /api/v1/tokens` - List tokens
- `POST /api/v1/tokens` - Create token
- `GET /api/v1/tokens/{id}` - Get token
- `PUT /api/v1/tokens/{id}` - Update token
- `DELETE /api/v1/tokens/{id}` - Delete token
- `POST /api/v1/tokens/{id}/revoke` - Revoke token
- `POST /api/v1/tokens/{id}/regenerate` - Regenerate token value

### Analytics
- `GET /api/v1/analytics/queries` - Query analytics
- `GET /api/v1/analytics/performance` - Performance metrics
- `GET /api/v1/analytics/servers` - Per-server analytics
- `GET /api/v1/analytics/summary` - Overall summary

## Database Support

PyDAL supports multiple databases:

- **SQLite** (default): `sqlite://storage.db`
- **PostgreSQL**: `postgresql://user:pass@host:port/database`
- **MySQL**: `mysql://user:pass@host:port/database`

## Environment Variables

See `.env.example` for all configuration options.

## Architecture

### Components

1. **Flask App Factory** (`app/__init__.py`): Creates and configures Flask application
2. **PyDAL Models** (`app/models/`): Database table definitions
3. **Services** (`app/services/`): Business logic layer
4. **Blueprints** (`app/blueprints/`): REST API endpoints
5. **Middleware** (`app/middleware/`): Authentication and RBAC
6. **gRPC Server** (`app/grpc_server.py`): High-performance DNS server communication

### Security

- **Password Hashing**: bcrypt with automatic salting
- **JWT Tokens**: 15-minute access tokens, 7-day refresh tokens
- **Server JWT**: 24-hour tokens with server-specific secrets
- **Join Keys**: 64-character hex keys (256-bit entropy)
- **RBAC**: Multi-level permission system (global + team)

## Development

### Run Tests

```bash
pytest tests/ -v
```

### Database Migrations

PyDAL automatically handles migrations. To reset:

```bash
rm -rf databases/
python init_db.py
```

### gRPC Proto Compilation

```bash
python -m grpc_tools.protoc \
    -I./app/protos \
    --python_out=./app/protos \
    --grpc_python_out=./app/protos \
    ./app/protos/manager_service.proto
```

## Docker Deployment

```bash
# Build image
docker build -t squawk-manager-backend .

# Run container
docker run -d \
    -p 5000:5000 \
    -p 50051:50051 \
    -e DB_URL=postgresql://user:pass@db:5432/squawk \
    -e REDIS_URL=redis://redis:6379 \
    -e SECRET_KEY=your-secret-key \
    -e JWT_SECRET_KEY=your-jwt-secret \
    squawk-manager-backend
```

## License Server Integration

Enterprise features (SSO/SAML/LDAP) require a valid license key:

```bash
USE_LICENSE_SERVER=true
LICENSE_SERVER_URL=https://license.squawkdns.com
PENGUINTECH_LICENSE_KEY=PENG-XXXX-XXXX-XXXX-XXXX-ABCD
```

Community features work without a license key.

## Support

- **Documentation**: See main project README
- **Issues**: https://github.com/PenguinCloud/squawk-dns/issues
- **License**: See LICENSE file
