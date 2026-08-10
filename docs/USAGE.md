
# Squawk DNS-over-HTTPS Proxy - Usage Guide

## Table of Contents
1. [Quick Start](#quick-start)
2. [Installation Methods](#installation-methods)
3. [Configuration](#configuration)
4. [Token Management](#token-management)
5. [DNS Query Examples](#dns-query-examples)
6. [Client Configuration](#client-configuration)
7. [Advanced Usage](#advanced-usage)
8. [Troubleshooting](#troubleshooting)
9. [Performance Tuning](#performance-tuning)
10. [Security Best Practices](#security-best-practices)

## Quick Start

### Minimal Setup (Development)

```bash
# Clone the repository
git clone https://github.com/penguintechinc/squawk.git
cd Squawk

# Start with web console
cd dns-server
./start_console.sh

# Access web console at http://localhost:8000/dns_console
# DNS server available at http://localhost:8080
```

### Production Setup

```bash
# Using Docker
docker-compose up -d

# Or with custom configuration
docker run -d \
  -p 8443:8443 \
  -v /path/to/certs:/certs \
  -v /path/to/db:/data \
  penguintech/squawk:latest \
  --cert /certs/server.crt \
  --key /certs/server.key \
  --new-auth
```

## Installation Methods

### Docker Installation (Ubuntu 22.04 LTS Based)

Squawk now uses separated Docker configurations with Ubuntu 22.04 LTS as the base image for better reliability and modularity.

#### Quick Start with Docker Compose

```bash
# Clone the repository
git clone https://github.com/penguintechinc/squawk.git
cd Squawk

# Start all core services (DNS server, web console, client, cache)
docker-compose up -d

# Start with PostgreSQL for enterprise
docker-compose --profile postgres up -d

# Start with monitoring (Prometheus/Grafana)
docker-compose --profile monitoring up -d

# View logs
docker-compose logs -f dns-server
```

#### Building Individual Components

```bash
# DNS Server only
cd dns-server
docker build -t squawk-dns-server:latest .
docker run -d \
  -p 8080:8080 \
  -e PORT=8080 \
  -e USE_NEW_AUTH=true \
  -v $(pwd)/data:/app/data \
  squawk-dns-server:latest

# DNS Client only
cd dns-client
docker build -t squawk-dns-client:latest .
docker run -d \
  --cap-add=NET_ADMIN \
  -p 53:53/udp -p 53:53/tcp \
  -e SQUAWK_SERVER_URL=https://dns.yourdomain.com:8443 \
  -e SQUAWK_AUTH_TOKEN=your-token \
  squawk-dns-client:latest
```

### Docker Compose Configuration

```yaml
version: "3.8"
services:
  dns-server:
    build:
      context: ./dns-server
      dockerfile: Dockerfile
    image: squawk-dns-server:latest
    ports:
      - "8080:8080"
      - "8443:8443"
    environment:
      - PORT=8080
      - USE_NEW_AUTH=true
      - CACHE_ENABLED=true
      - VALKEY_URL=redis://valkey:6379
    volumes:
      - ./dns-server/data:/app/data
      - ./dns-server/certs:/app/certs
    restart: unless-stopped

  web-console:
    image: squawk-dns-server:latest
    command: ["sh", "-c", "cd /app/web && python3 -m py4web run apps --host 0.0.0.0 --port 8000"]
    ports:
      - "8000:8000"
    depends_on:
      - dns-server

  dns-client:
    build:
      context: ./dns-client
      dockerfile: Dockerfile
    image: squawk-dns-client:latest
    cap_add:
      - NET_ADMIN
    ports:
      - "53:53/udp"
      - "53:53/tcp"
    environment:
      - SQUAWK_SERVER_URL=http://dns-server:8080
      - SQUAWK_AUTH_TOKEN=your-token
    depends_on:
      - dns-server

  valkey:
    image: valkey/valkey:latest
    volumes:
      - valkey-data:/data

volumes:
  valkey-data:
```

### Helm Chart

```bash
# Add Helm repository
helm repo add penguintech https://charts.penguintech.group
helm repo update

# Install with default values
helm install squawk penguintech/squawk

# Install with custom values
helm install squawk penguintech/squawk \
  --set dns.port=8443 \
  --set console.enabled=true \
  --set persistence.enabled=true \
  --set ingress.enabled=true \
  --set ingress.hostname=dns.example.com
```

### Terraform

```hcl
# main.tf
module "squawk_dns" {
  source = "github.com/PenguinCloud/terraform-squawk"

  dns_port = 8443
  console_port = 8000
  enable_ssl = true
  cert_path = "/certs/server.crt"
  key_path = "/certs/server.key"

  database = {
    type = "postgres"
    url = "postgresql://user:pass@db.example.com/squawk"
  }

  tokens = [
    {
      name = "production"
      domains = ["*.example.com"]
    },
    {
      name = "development"
      domains = ["*.dev.example.com"]
    }
  ]
}
```

## Storage / Persistence

### Required Volumes for Persistence

```yaml
volumes:
  # Database storage (required)
  - /data/db:/app/data/db

  # Configuration files (required)
  - /data/config:/app/config

  # SSL certificates (required for HTTPS)
  - /data/certs:/app/certs
```

### Optional Volumes for Advanced Usage

```yaml
volumes:
  # Custom py4web apps
  - /custom/apps:/app/web/apps

  # Log files
  - /var/log/squawk:/app/logs

  # Cache directory
  - /data/cache:/app/cache

  # Backup directory
  - /data/backups:/app/backups
```

## Options

### Environment Variables

```bash
# Core Configuration
SQUAWK_PORT=8080                    # DNS server port
SQUAWK_CONSOLE_PORT=8000           # Web console port
USE_NEW_AUTH=true                   # Enable token management system

# SSL Configuration
SSL_ENABLED=true                    # Enable SSL/TLS
SSL_CERT=/certs/server.crt         # Certificate path
SSL_KEY=/certs/server.key          # Private key path

# Database Configuration
DB_TYPE=sqlite                      # Database type (sqlite, mysql, postgres)
DB_URL=dns_auth.db                 # Database connection string
DB_POOL_SIZE=10                     # Connection pool size

# Authentication
DEFAULT_TOKEN=                      # Default auth token (legacy mode)
TOKEN_EXPIRY=86400                  # Token expiry in seconds
REQUIRE_AUTH=true                   # Require authentication

# DNS Configuration
UPSTREAM_DNS=8.8.8.8,8.8.4.4       # Upstream DNS servers
DNS_CACHE_TTL=300                   # Cache TTL in seconds
DNS_TIMEOUT=5                       # Query timeout in seconds

# Logging
LOG_LEVEL=INFO                      # Log level (DEBUG, INFO, WARNING, ERROR)
LOG_FILE=/app/logs/dns.log         # Log file path
LOG_ROTATE=daily                    # Log rotation (daily, weekly, size)
LOG_RETAIN=30                       # Days to retain logs

# Performance
MAX_CONNECTIONS=1000                # Maximum concurrent connections
WORKER_THREADS=4                    # Number of worker threads
CACHE_SIZE=10000                    # Maximum cache entries
```

### Command Line Arguments

```bash
# Server arguments
python server.py [options]
  -p, --port PORT          # Server port (default: 8080)
  -a, --auth TOKEN         # Legacy auth token
  -k, --key FILE           # SSL key file
  -c, --cert FILE          # SSL certificate file
  -d, --dbtype TYPE        # Database type
  -u, --dburl URL          # Database URL
  -n, --new-auth           # Use new token system
  --debug                  # Enable debug mode
  --workers NUM            # Number of workers

# Client arguments
python client.py [options]
  -d, --domain DOMAIN      # Domain to query
  -t, --type TYPE          # Record type (A, AAAA, MX, etc.)
  -s, --server URL         # DNS server URL
  -a, --auth TOKEN         # Authentication token
  -c, --config FILE        # Configuration file
  -u, --udp                # Enable UDP forwarding
  -T, --tcp                # Enable TCP forwarding
  --cache                  # Enable response caching
  --timeout SECONDS        # Query timeout
```

## Token Management

### Creating Tokens via Web Console

1. Navigate to `http://localhost:8000/dns_console`
2. Go to "Tokens" → "Create New Token"
3. Enter token details and save

### Managing Tokens via CLI

```bash
# Create token
curl -X POST http://localhost:8000/dns_console/api/tokens \
  -H "Content-Type: application/json" \
  -d '{"name": "my-service", "domains": ["example.com"]}'

# List tokens
curl http://localhost:8000/dns_console/api/tokens

# Validate token
curl http://localhost:8000/dns_console/api/validate/TOKEN_VALUE
```

## DNS Query Examples

### Basic Queries

```bash
# A record
curl -H "Authorization: Bearer TOKEN" \
     "http://localhost:8080/dns-query?name=example.com&type=A"

# Multiple record types
for type in A AAAA MX TXT NS; do
  curl -H "Authorization: Bearer TOKEN" \
       "http://localhost:8080/dns-query?name=example.com&type=$type"
done
```

### Using Python Client

```python
from dns_client import DNSOverHTTPSClient

client = DNSOverHTTPSClient(
    dns_server_url="https://dns.example.com:8443",
    auth_token="your-token"
)

result = client.query("example.com", "A")
print(result)
```

## Client Configuration

### System Integration (Linux)

```bash
# Install as system resolver
sudo cp dns-client/bins/client.py /usr/local/bin/squawk-dns
sudo chmod +x /usr/local/bin/squawk-dns

# Configure systemd
cat > /etc/systemd/system/squawk-dns.service << EOF
[Unit]
Description=Squawk DNS Client
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/squawk-dns -c /etc/squawk/client.yml -u -T
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now squawk-dns
```

### Client Configuration File

```yaml
# client.yml
server: https://dns.example.com:8443
auth: your-token-here
cache:
  enabled: true
  ttl: 300
forwarding:
  udp: true
  tcp: true
  port: 53
logging:
  level: INFO
  file: /var/log/squawk-client.log
```

## Advanced Usage

### High Availability Setup

```yaml
# docker-compose-ha.yml
version: "3.8"
services:
  dns1:
    image: penguintech/squawk:latest
    environment:
      - NODE_ID=1
      - CLUSTER_NODES=dns2,dns3

  dns2:
    image: penguintech/squawk:latest
    environment:
      - NODE_ID=2
      - CLUSTER_NODES=dns1,dns3

  dns3:
    image: penguintech/squawk:latest
    environment:
      - NODE_ID=3
      - CLUSTER_NODES=dns1,dns2

  haproxy:
    image: haproxy:latest
    ports:
      - "8443:8443"
    volumes:
      - ./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg
```

### Custom Authentication Plugin

```python
# custom_auth.py
class CustomAuthPlugin:
    def authenticate(self, token, domain):
        # Custom authentication logic
        if self.check_ldap(token):
            return True
        if self.check_oauth(token):
            return True
        return False

    def check_ldap(self, token):
        # LDAP authentication
        pass

    def check_oauth(self, token):
        # OAuth validation
        pass
```

## Troubleshooting

### Common Issues

1. **Token not working**
   - Check token is active in console
   - Verify domain permissions
   - Review query logs

2. **SSL errors**
   - Verify certificate validity
   - Check certificate chain
   - Ensure correct file permissions

3. **Performance issues**
   - Increase worker threads
   - Enable caching
   - Check database indexes

### Debug Commands

```bash
# Test connectivity
curl -v http://localhost:8080/health

# Check logs
docker logs squawk-dns

# Database queries
sqlite3 /data/dns_auth.db "SELECT * FROM tokens;"

# Network diagnostics
netstat -tlnp | grep 8080
```

## Performance Tuning

### Database Optimization

```sql
-- Add indexes
CREATE INDEX idx_tokens_active ON tokens(active);
CREATE INDEX idx_query_logs_timestamp ON query_logs(timestamp);

-- Vacuum database (SQLite)
VACUUM;

-- Analyze tables
ANALYZE;
```

### Caching Configuration

```yaml
cache:
  backend: redis
  redis:
    host: localhost
    port: 6379
    db: 0
  ttl: 300
  max_entries: 10000
```

## Security Best Practices

1. **Always use HTTPS in production**
2. **Rotate tokens regularly**
3. **Enable audit logging**
4. **Implement rate limiting**
5. **Use strong tokens (32+ characters)**
6. **Restrict network access**
7. **Regular security updates**
8. **Monitor for anomalies**

## Support

- Documentation: `/docs` directory
- Issues: GitHub Issues
- Email: support@penguintech.group
- Community: Discord/Slack channels
