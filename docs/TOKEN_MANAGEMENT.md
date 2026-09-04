# Token Management System Documentation

## Overview

The Squawk DNS Server now includes a comprehensive token management system that allows fine-grained control over which tokens can access which domains. This replaces the single-token authentication system with a more flexible multi-token approach.

## Features

- **Multiple Tokens**: Create and manage unlimited authentication tokens
- **Domain-Based Permissions**: Assign specific domains to specific tokens
- **Wildcard Support**: Use `*` to grant access to all domains
- **Web Console**: User-friendly interface for managing tokens and permissions
- **Activity Logging**: Track all DNS queries with detailed logs
- **API Access**: RESTful API for programmatic management

## Getting Started

### 1. Starting the System

```bash
# Using the startup script (recommended)
cd dns-server
./start_console.sh

# Or manually start both services
# Terminal 1: Start py4web
cd dns-server/web
py4web run apps --host 0.0.0.0 --port 8000

# Terminal 2: Start DNS server with new auth
cd dns-server
python bins/server.py -p 8080 -n
```

### 2. Accessing the Web Console

Open your browser and navigate to: `http://localhost:8000/dns_console`

### 3. Creating Your First Token

1. Navigate to the **Tokens** page
2. Click **Create New Token**
3. Enter a name and description
4. The system will generate a secure token automatically
5. Click **Create Token**

> **Copy the token now — it is shown only once.** As of v2.1.x tokens are stored
> as SHA-256 hashes at rest and looked up by hash. The plaintext value is
> displayed a single time at creation (and on regeneration); it cannot be
> retrieved later. Lost a token? Regenerate it.

### 4. Assigning Domain Permissions

1. After creating a token, click **Edit** next to it
2. In the **Domain Permissions** section, add domains
3. You can add:
   - `*` - Wildcard access to all domains
   - `example.com` - Access to example.com and all subdomains
   - `api.example.com` - Access to specific subdomain

### 5. Using Tokens with DNS Queries

```bash
# Using curl
curl -H "Authorization: Bearer YOUR_TOKEN_HERE" \
     "http://localhost:8080/dns-query?name=example.com&type=A"

# Using the DNS client
python dns-client/bins/client.py \
  -d example.com \
  -s http://localhost:8080 \
  -a YOUR_TOKEN_HERE
```

## Permission Model

### Domain Matching Rules

1. **Exact Match**: Token has permission for the exact domain
2. **Parent Domain**: Token has permission for a parent domain
   - Token has `example.com` → Can access `sub.example.com`
3. **Wildcard**: Token has `*` → Can access any domain

### Token States

- **Active**: Token can be used for authentication
- **Inactive**: Token is disabled but not deleted
- **Last Used**: Timestamp of last successful query

## Web Console Pages

### Dashboard (`/dns_console`)
- Overview statistics
- Recent query activity
- Quick action buttons

### Tokens (`/dns_console/tokens`)
- List all tokens
- Create new tokens
- Edit/delete existing tokens
- View token metadata (the plaintext token value is shown only once, at creation — it is stored hashed and cannot be displayed again)

### Domains (`/dns_console/domains`)
- Manage allowed domains
- Add new domains
- View which tokens have access

### Permissions (`/dns_console/permissions`)
- Matrix view of token-domain permissions
- Click checkboxes to toggle permissions
- Changes save automatically

### Logs (`/dns_console/logs`)
- View all DNS query attempts
- Filter by status (allowed/denied)
- Pagination for large datasets

## API Endpoints

### Check Permission
```
POST /dns_console/api/check_permission
Content-Type: application/json

{
  "token": "your-token-here",
  "domain": "example.com"
}

Response:
{
  "allowed": true
}
```

### List Tokens
```
GET /dns_console/api/tokens

Response:
{
  "tokens": [
    {
      "id": 1,
      "name": "Production API",
      "created_at": "2024-01-01T00:00:00",
      "domains": ["example.com", "api.example.com"]
    }
  ]
}
```

> The list/detail responses **never** return the plaintext token — it is stored
> hashed and returned only once, in the create/regenerate response.

### Validate Token
```
GET /dns_console/api/validate/YOUR_TOKEN_HERE

Response:
{
  "valid": true,
  "name": "Token Name",
  "domains": ["example.com", "*"]
}
```

## Security Considerations

1. **Token Storage**: The server stores only a SHA-256 hash of each token (looked up by hash); the plaintext is shown once at creation. Store your copy securely and never commit it to version control
2. **HTTPS**: Always use HTTPS in production environments
3. **Token Rotation**: Regularly rotate tokens for enhanced security
4. **Audit Logs**: Monitor the query logs for suspicious activity
5. **Principle of Least Privilege**: Only grant necessary domain permissions

## Migration from Legacy System

If you have an existing single-token setup:

1. Start the server with the new auth flag: `python server.py -p 8080 -n`
2. Access the web console
3. Create a new token with the same value as your old token
4. Assign it wildcard (`*`) permission to maintain compatibility
5. Gradually create more specific tokens and permissions

## Troubleshooting

### Token Not Working
- Check if token is active in the console
- Verify domain permissions are correctly assigned
- Check logs for denied requests

### Console Not Loading
- Ensure py4web is running on port 8000
- Check for port conflicts
- Verify database permissions

### Database Issues
- Database is stored at: `dns-server/web/apps/dns_console/databases/dns_auth.db`
- Delete this file to reset the system
- Backup regularly for production use

## Example Scenarios

### Scenario 1: Development vs Production Tokens

```
Token: dev-token
Domains: *.dev.example.com, localhost

Token: prod-token
Domains: *.example.com, *.api.example.com

Token: monitoring-token
Domains: * (wildcard for monitoring all services)
```

### Scenario 2: Per-Customer Access

```
Token: customer-a-token
Domains: customer-a.example.com, api.customer-a.example.com

Token: customer-b-token
Domains: customer-b.example.com, api.customer-b.example.com
```

### Scenario 3: Service-Based Access

```
Token: web-service-token
Domains: web.example.com, cdn.example.com

Token: api-service-token
Domains: api.example.com, api-internal.example.com

Token: database-service-token
Domains: db.example.com, db-replica.example.com
```

## Best Practices

1. **Naming Convention**: Use descriptive token names (e.g., `prod-web-api`, `dev-testing`)
2. **Documentation**: Document which services use which tokens
3. **Regular Audits**: Review token permissions quarterly
4. **Monitoring**: Set up alerts for denied requests
5. **Backup**: Regular database backups of token configurations

## Support

For issues or questions:
- Check the logs at `/dns_console/logs`
- Review the README.md for general setup
- Contact support at info@penguintech.group
