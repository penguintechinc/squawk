# Squawk API Documentation

## Table of Contents

1. [Overview](#overview)
2. [Authentication](#authentication)
3. [DNS Query API](#dns-query-api)
4. [Token Management API](#token-management-api)
5. [Domain Management API](#domain-management-api)
6. [Permission Management API](#permission-management-api)
7. [DHCP Management API](#dhcp-management-api)
8. [Time Synchronization API](#time-synchronization-api)
9. [Monitoring & Logs API](#monitoring--logs-api)
10. [Error Handling](#error-handling)
11. [Rate Limiting](#rate-limiting)
12. [SDK Examples](#sdk-examples)

## Overview

The Squawk API provides comprehensive access to network infrastructure services including DNS-over-HTTPS, DHCP management, and Time Synchronization (PTP/NTP) with fine-grained authentication and permission management. The API follows RESTful principles and returns JSON responses.

### Base URLs

> **Note:** The URLs using `example.com` below are placeholders for documentation purposes. Replace them with your actual deployment URLs in production and staging environments.
```
Production:  https://dns.example.com
Staging:     https://staging-dns.example.com
Local Dev:   http://localhost:8080
Web Console: http://localhost:8000/dns_console
```

### API Versioning

All API endpoints are versioned. The current version is `v1`.

```
https://dns.example.com/api/v1/
http://localhost:8000/dns_console/api/
```

### Content Type

All requests and responses use JSON format:

```
Content-Type: application/json
Accept: application/json
```

## Authentication

### Bearer Token Authentication

All API requests require authentication via Bearer tokens in the Authorization header.

```http
Authorization: Bearer your-token-here
```

### Token Formats

- **DNS Server Tokens**: Used for DNS queries
- **Admin Tokens**: Used for management operations via web console

```bash
# DNS Query with token
curl -H "Authorization: Bearer abc123def456" \
     "https://dns.example.com/dns-query?name=example.com&type=A"

# Management API with admin token
curl -H "Authorization: Bearer admin-token-789" \
     "http://localhost:8000/dns_console/api/tokens"
```

## DNS Query API

### DNS over HTTPS (DoH) Endpoint

Resolve DNS queries using the DNS-over-HTTPS protocol (RFC 8484).

#### Endpoint

```
GET /dns-query
```

#### Parameters

| Parameter | Type   | Required | Description              | Example    |
|-----------|--------|----------|--------------------------|------------|
| name      | string | Yes      | Domain name to resolve   | example.com |
| type      | string | No       | DNS record type (default: A) | A, AAAA, MX, TXT, NS, CNAME |

#### Request Examples

```bash
# Basic A record query
curl -H "Authorization: Bearer TOKEN" \
     "https://dns.example.com/dns-query?name=example.com&type=A"

# AAAA record query
curl -H "Authorization: Bearer TOKEN" \
     "https://dns.example.com/dns-query?name=example.com&type=AAAA"

# MX record query
curl -H "Authorization: Bearer TOKEN" \
     "https://dns.example.com/dns-query?name=example.com&type=MX"

# TXT record query
curl -H "Authorization: Bearer TOKEN" \
     "https://dns.example.com/dns-query?name=example.com&type=TXT"
```

#### Response Format

```json
{
  "Status": 0,
  "Answer": [
    {
      "name": "example.com",
      "type": "A",
      "data": "93.184.216.34"
    }
  ]
}
```

#### Error Response

```json
{
  "Status": 2,
  "Comment": "Name resolution failed"
}
```

#### Status Codes

| Status | Description |
|--------|-------------|
| 0      | Success     |
| 1      | Format Error |
| 2      | Server Failure |
| 3      | Name Error (domain not found) |
| 5      | Refused     |

## Token Management API

### List Tokens

Retrieve all authentication tokens.

#### Endpoint

```
GET /dns_console/api/tokens
```

#### Response

```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "name": "Production API",
      "token": "abc123def456...",
      "active": true,
      "created_at": "2024-01-01T00:00:00Z",
      "last_used": "2024-01-02T12:30:00Z",
      "domains": ["example.com", "*.api.example.com"]
    },
    {
      "id": 2,
      "name": "Development",
      "token": "dev789xyz123...",
      "active": true,
      "created_at": "2024-01-01T00:00:00Z",
      "last_used": null,
      "domains": ["*.dev.example.com"]
    }
  ]
}
```

### Create Token

Create a new authentication token.

#### Endpoint

```
POST /dns_console/api/tokens
```

#### Request Body

```json
{
  "name": "My New Token",
  "description": "Token for production API access",
  "domains": ["example.com", "*.subdomain.example.com"]
}
```

#### Parameters

| Parameter   | Type     | Required | Description |
|-------------|----------|----------|-------------|
| name        | string   | Yes      | Human-readable token name |
| description | string   | No       | Token purpose description |
| domains     | string[] | No       | Initial domain permissions |

#### Response

```json
{
  "success": true,
  "data": {
    "id": 3,
    "token": "newly-generated-token-value",
    "name": "My New Token",
    "description": "Token for production API access",
    "active": true,
    "created_at": "2024-01-03T10:00:00Z"
  },
  "message": "Token created successfully"
}
```

### Get Token Details

Retrieve details for a specific token.

#### Endpoint

```
GET /dns_console/api/tokens/{id}
```

#### Response

```json
{
  "success": true,
  "data": {
    "id": 1,
    "name": "Production API",
    "token": "abc123def456...",
    "description": "Main production token",
    "active": true,
    "created_at": "2024-01-01T00:00:00Z",
    "last_used": "2024-01-02T12:30:00Z",
    "domains": [
      {
        "id": 1,
        "name": "example.com",
        "description": "Main domain"
      },
      {
        "id": 2,
        "name": "*.api.example.com",
        "description": "API subdomains"
      }
    ],
    "usage_stats": {
      "queries_today": 1250,
      "queries_week": 8750,
      "queries_month": 35000
    }
  }
}
```

### Update Token

Update an existing token's properties.

#### Endpoint

```
PUT /dns_console/api/tokens/{id}
```

#### Request Body

```json
{
  "name": "Updated Token Name",
  "description": "Updated description",
  "active": true
}
```

#### Response

```json
{
  "success": true,
  "data": {
    "id": 1,
    "name": "Updated Token Name",
    "description": "Updated description",
    "active": true
  },
  "message": "Token updated successfully"
}
```

### Delete Token

Permanently delete a token.

#### Endpoint

```
DELETE /dns_console/api/tokens/{id}
```

#### Response

```json
{
  "success": true,
  "message": "Token deleted successfully"
}
```

### Validate Token

Validate a token and retrieve its permissions.

#### Endpoint

```
GET /dns_console/api/validate/{token_value}
```

#### Response

```json
{
  "success": true,
  "data": {
    "valid": true,
    "token": {
      "id": 1,
      "name": "Production API",
      "active": true,
      "domains": ["example.com", "*.api.example.com"]
    }
  }
}
```

## Domain Management API

### List Domains

Retrieve all managed domains.

#### Endpoint

```
GET /dns_console/api/domains
```

#### Response

```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "name": "example.com",
      "description": "Main company domain",
      "created_at": "2024-01-01T00:00:00Z",
      "token_count": 3
    },
    {
      "id": 2,
      "name": "*.api.example.com",
      "description": "API subdomain wildcard",
      "created_at": "2024-01-01T00:00:00Z",
      "token_count": 1
    },
    {
      "id": 3,
      "name": "*",
      "description": "Wildcard - all domains",
      "created_at": "2024-01-01T00:00:00Z",
      "token_count": 1
    }
  ]
}
```

### Create Domain

Add a new domain to the system.

#### Endpoint

```
POST /dns_console/api/domains
```

#### Request Body

```json
{
  "name": "new-domain.com",
  "description": "Description of the domain's purpose"
}
```

#### Response

```json
{
  "success": true,
  "data": {
    "id": 4,
    "name": "new-domain.com",
    "description": "Description of the domain's purpose",
    "created_at": "2024-01-03T10:00:00Z"
  },
  "message": "Domain added successfully"
}
```

### Update Domain

Update domain information.

#### Endpoint

```
PUT /dns_console/api/domains/{id}
```

#### Request Body

```json
{
  "name": "updated-domain.com",
  "description": "Updated description"
}
```

#### Response

```json
{
  "success": true,
  "data": {
    "id": 4,
    "name": "updated-domain.com",
    "description": "Updated description"
  },
  "message": "Domain updated successfully"
}
```

### Delete Domain

Remove a domain and all associated permissions.

#### Endpoint

```
DELETE /dns_console/api/domains/{id}
```

#### Response

```json
{
  "success": true,
  "message": "Domain deleted successfully"
}
```

## Permission Management API

### List All Permissions

Get the complete permission matrix.

#### Endpoint

```
GET /dns_console/api/permissions
```

#### Response

```json
{
  "success": true,
  "data": {
    "tokens": [
      {
        "id": 1,
        "name": "Production API",
        "active": true
      },
      {
        "id": 2,
        "name": "Development",
        "active": true
      }
    ],
    "domains": [
      {
        "id": 1,
        "name": "example.com"
      },
      {
        "id": 2,
        "name": "*.api.example.com"
      }
    ],
    "permissions": [
      {
        "token_id": 1,
        "domain_id": 1,
        "granted_at": "2024-01-01T00:00:00Z"
      },
      {
        "token_id": 1,
        "domain_id": 2,
        "granted_at": "2024-01-01T00:00:00Z"
      },
      {
        "token_id": 2,
        "domain_id": 2,
        "granted_at": "2024-01-02T00:00:00Z"
      }
    ]
  }
}
```

### Grant Permission

Grant a token permission to access a domain.

#### Endpoint

```
POST /dns_console/api/permissions
```

#### Request Body

```json
{
  "token_id": 1,
  "domain_id": 3
}
```

#### Response

```json
{
  "success": true,
  "data": {
    "token_id": 1,
    "domain_id": 3,
    "granted_at": "2024-01-03T10:00:00Z"
  },
  "message": "Permission granted successfully"
}
```

### Revoke Permission

Remove a token's permission to access a domain.

#### Endpoint

```
DELETE /dns_console/api/permissions/{token_id}/{domain_id}
```

#### Response

```json
{
  "success": true,
  "message": "Permission revoked successfully"
}
```

### Toggle Permission

Toggle a permission on/off (used by web interface).

#### Endpoint

```
POST /dns_console/api/permissions/toggle
```

#### Request Body

```json
{
  "token_id": 1,
  "domain_id": 2
}
```

#### Response

```json
{
  "success": true,
  "data": {
    "new_state": false,
    "action": "revoked"
  },
  "message": "Permission toggled successfully"
}
```

### Check Permission

Check if a token has permission for a specific domain.

#### Endpoint

```
POST /dns_console/api/check_permission
```

#### Request Body

```json
{
  "token": "abc123def456",
  "domain": "example.com"
}
```

#### Response

```json
{
  "allowed": true
}
```

#### Error Response

```json
{
  "error": "Missing token or domain"
}
```

## Web Console Management API

The web console provides additional management endpoints for administrative operations.

### Permissions Matrix Toggle

Toggle permissions between tokens and domains via AJAX.

#### Endpoint

```
POST /dns_console/permissions/toggle
```

#### Request Body

```json
{
  "token_id": 1,
  "domain_id": 2
}
```

#### Response

```json
{
  "success": true,
  "new_state": false
}
```

#### Error Response

```json
{
  "success": false,
  "error": "Missing parameters"
}
```

### Blacklist Management

#### Add Domain to Blacklist

```
POST /dns_console/blacklist/domain/add
```

**Form Data:**
- `domain`: Domain to block (string, required)
- `reason`: Reason for blocking (string, optional)
- `added_by`: Administrator name (string, optional)

#### Add IP to Blacklist

```
POST /dns_console/blacklist/ip/add
```

**Form Data:**
- `ip`: IP address to block (string, required)
- `reason`: Reason for blocking (string, optional)
- `added_by`: Administrator name (string, optional)

#### Remove Domain from Blacklist

```
GET /dns_console/blacklist/domain/delete/<domain_id:int>
```

#### Remove IP from Blacklist

```
GET /dns_console/blacklist/ip/delete/<ip_id:int>
```

### Certificate Management

#### Initialize CA and Server Certificates

```
POST /dns_console/certificates/init
```

**Form Data:**
- `force`: Force regeneration of existing certificates (boolean, optional)
- `hostname`: Server hostname for certificate (string, optional)
- `ip_addresses`: Comma-separated IP addresses (string, optional)

#### Generate Client Certificate

```
POST /dns_console/certificates/client/new
```

**Form Data:**
- `client_name`: Name for the client certificate (string, required)
- `email`: Client email address (string, optional)
- `force`: Force regeneration if exists (boolean, optional)

#### Revoke Client Certificate

```
GET /dns_console/certificates/client/revoke/<client_name>
```

#### Download Certificates

Download CA certificate:
```
GET /dns_console/certificates/download/ca
```

Download client certificate:
```
GET /dns_console/certificates/download/client/<client_name>/cert
```

Download client private key:
```
GET /dns_console/certificates/download/client/<client_name>/key
```

Download client PKCS#12 bundle:
```
GET /dns_console/certificates/download/client/<client_name>/p12
```

Download complete client bundle (ZIP):
```
GET /dns_console/certificates/download/client/<client_name>/bundle
```

### MFA (Multi-Factor Authentication)

#### Setup MFA

```
GET/POST /dns_console/mfa/setup
```

**POST Actions:**
- `action=generate`: Generate new MFA secret and QR code
- `action=verify`: Verify MFA token and enable MFA
- `action=disable`: Disable MFA (requires password)

#### Verify MFA

```
GET/POST /dns_console/mfa/verify
```

**POST Form Data:**
- `token`: TOTP token or 8-character backup code (string, required)

### SSO (Single Sign-On) Management

#### SSO Configuration (Admin Only)

```
GET/POST /dns_console/admin/sso
```

**POST Actions:**
- `action=add_provider`: Add new SSO provider
- `action=toggle_provider`: Enable/disable SSO provider

**Add Provider Form Data:**
- `name`: Provider name (string, required)
- `provider_type`: Type (saml, ldap, oauth2) (string, required)
- `config`: JSON configuration (string, required)

#### Initiate SSO Login

```
GET /dns_console/auth/sso/login/<provider>
```

#### LDAP Authentication

```
GET/POST /dns_console/auth/sso/ldap
```

**POST Form Data:**
- `username`: LDAP username (string, required)
- `password`: LDAP password (string, required)

## py4web Built-in Authentication API

The web console uses py4web's built-in authentication system which provides standard user management endpoints.

### User Authentication

#### Login

```
POST /dns_console/auth/login
```

**Form Data:**
- `email`: User email address (string, required)
- `password`: User password (string, required)

#### Response

```json
{
  "user": {
    "id": 1,
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe"
  },
  "token": "session_token_here"
}
```

#### Logout

```
POST /dns_console/auth/logout
```

#### Register New User

```
POST /dns_console/auth/register
```

**Form Data:**
- `email`: Email address (string, required)
- `password`: Password (string, required)
- `first_name`: First name (string, optional)
- `last_name`: Last name (string, optional)

### User Profile Management

#### Get Current User Profile

```
GET /dns_console/auth/profile
```

#### Response

```json
{
  "id": 1,
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "created_on": "2025-01-01T00:00:00Z",
  "sso": false
}
```

#### Update User Profile

```
POST /dns_console/auth/profile
```

**Form Data:**
- `first_name`: First name (string, optional)
- `last_name`: Last name (string, optional)
- `password`: New password (string, optional)

### Password Management

#### Change Password

```
POST /dns_console/auth/change_password
```

**Form Data:**
- `old_password`: Current password (string, required)
- `new_password`: New password (string, required)

#### Request Password Reset

```
POST /dns_console/auth/request_reset_password
```

**Form Data:**
- `email`: User email address (string, required)

#### Reset Password

```
POST /dns_console/auth/reset_password
```

**Form Data:**
- `token`: Password reset token (string, required)
- `new_password`: New password (string, required)

### User Management (Admin Only)

#### List Users

```
GET /dns_console/auth/api/users
```

**Query Parameters:**
- `page`: Page number (integer, optional, default: 1)
- `per_page`: Users per page (integer, optional, default: 20)

#### Response

```json
{
  "users": [
    {
      "id": 1,
      "email": "admin@example.com",
      "first_name": "Admin",
      "last_name": "User",
      "created_on": "2025-01-01T00:00:00Z",
      "sso": false
    }
  ],
  "page": 1,
  "per_page": 20,
  "total": 15
}
```

#### Get User Details

```
GET /dns_console/auth/api/users/<user_id>
```

#### Update User (Admin)

```
PUT /dns_console/auth/api/users/<user_id>
```

**JSON Body:**
```json
{
  "email": "updated@example.com",
  "first_name": "Updated",
  "last_name": "Name",
  "active": true
}
```

#### Delete User (Admin)

```
DELETE /dns_console/auth/api/users/<user_id>
```

### Session Management

#### Verify Session

```
GET /dns_console/auth/api/verify
```

Returns current session status and user information.

#### Response

```json
{
  "valid": true,
  "user": {
    "id": 1,
    "email": "user@example.com"
  }
}
```

### Group Management

#### List Groups

```
GET /dns_console/auth/api/groups
```

#### Create Group

```
POST /dns_console/auth/api/groups
```

**JSON Body:**
```json
{
  "role": "admin",
  "description": "Administrator group"
}
```

#### Add User to Group

```
POST /dns_console/auth/api/groups/<group_id>/members
```

**JSON Body:**
```json
{
  "user_id": 1
}
```

## Main DNS Server API

The main DNS server provides core DNS resolution and administrative endpoints.

### DNS Resolution

#### DNS-over-HTTPS Query

```
GET/POST /dns-query
```

**Query Parameters:**
- `name`: Domain name to resolve (string, required)
- `type`: DNS record type (string, optional, default: A)

### Administrative Endpoints

#### Blacklist Management

```
GET/POST/DELETE /admin/blacklist
```

Administrative interface for managing the DNS blacklist.

#### Health Check

```
GET /health
```

Returns server health status and metrics.

#### Response

```json
{
  "status": "healthy",
  "version": "1.1.2",
  "uptime_seconds": 86400,
  "cache_enabled": true,
  "blacklist_enabled": true,
  "mtls_enabled": true
}
```

## DHCP Management API

The DHCP API provides comprehensive IP address pool management, lease tracking, and static reservations with team-based access control.

### List DHCP Pools

Get all DHCP pools visible to the authenticated user.

#### Endpoint

```
GET /api/v1/dhcp/pools
```

#### Query Parameters

| Parameter | Type    | Description | Example |
|-----------|---------|-------------|---------|
| team_id   | integer | Filter by team | 1 |
| active    | boolean | Filter by active status | true |

#### Response

```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "name": "Office Network",
      "network": "192.168.1.0/24",
      "range_start": "192.168.1.100",
      "range_end": "192.168.1.200",
      "gateway": "192.168.1.1",
      "dns_servers": ["192.168.1.1", "8.8.8.8"],
      "ntp_servers": ["time.internal.local"],
      "domain_name": "office.local",
      "lease_duration": 86400,
      "team_id": 1,
      "active": true,
      "available_ips": 85,
      "leased_ips": 15,
      "reserved_ips": 5
    }
  ]
}
```

### Create DHCP Pool

Create a new IP address pool.

#### Endpoint

```
POST /api/v1/dhcp/pools
```

#### Request Body

```json
{
  "name": "Guest Network",
  "network": "10.10.0.0/24",
  "range_start": "10.10.0.50",
  "range_end": "10.10.0.200",
  "gateway": "10.10.0.1",
  "dns_servers": ["10.10.0.1"],
  "ntp_servers": ["time.squawk.local"],
  "domain_name": "guest.local",
  "lease_duration": 3600,
  "team_id": 2
}
```

#### Response

```json
{
  "success": true,
  "data": {
    "id": 2,
    "name": "Guest Network",
    "network": "10.10.0.0/24",
    "range_start": "10.10.0.50",
    "range_end": "10.10.0.200",
    "gateway": "10.10.0.1",
    "dns_servers": ["10.10.0.1"],
    "ntp_servers": ["time.squawk.local"],
    "domain_name": "guest.local",
    "lease_duration": 3600,
    "team_id": 2,
    "active": true,
    "created_at": "2026-01-05T10:00:00Z"
  },
  "message": "DHCP pool created successfully"
}
```

### Get Pool Details

Get detailed information about a specific pool.

#### Endpoint

```
GET /api/v1/dhcp/pools/{pool_id}
```

#### Response

```json
{
  "success": true,
  "data": {
    "id": 1,
    "name": "Office Network",
    "network": "192.168.1.0/24",
    "range_start": "192.168.1.100",
    "range_end": "192.168.1.200",
    "gateway": "192.168.1.1",
    "dns_servers": ["192.168.1.1", "8.8.8.8"],
    "ntp_servers": ["time.internal.local"],
    "domain_name": "office.local",
    "lease_duration": 86400,
    "team_id": 1,
    "active": true,
    "statistics": {
      "total_ips": 101,
      "available_ips": 85,
      "leased_ips": 15,
      "reserved_ips": 5,
      "utilization_percent": 19.8
    }
  }
}
```

### Update DHCP Pool

Update pool configuration.

#### Endpoint

```
PUT /api/v1/dhcp/pools/{pool_id}
```

#### Request Body

```json
{
  "name": "Office Network - Updated",
  "lease_duration": 43200,
  "dns_servers": ["192.168.1.1", "1.1.1.1"],
  "active": true
}
```

### Delete DHCP Pool

Delete a pool (releases all active leases).

#### Endpoint

```
DELETE /api/v1/dhcp/pools/{pool_id}
```

### List Pool Leases

Get all active leases for a pool.

#### Endpoint

```
GET /api/v1/dhcp/pools/{pool_id}/leases
```

#### Query Parameters

| Parameter | Type   | Description | Example |
|-----------|--------|-------------|---------|
| status    | string | Filter by status (active, expired, released) | active |
| mac       | string | Filter by MAC address | AA:BB:CC:DD:EE:FF |

#### Response

```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "pool_id": 1,
      "mac_address": "AA:BB:CC:DD:EE:FF",
      "ip_address": "192.168.1.105",
      "hostname": "workstation-01",
      "lease_start": "2026-01-05T08:00:00Z",
      "lease_end": "2026-01-06T08:00:00Z",
      "status": "active",
      "remaining_seconds": 72000
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 50,
    "total": 15
  }
}
```

### Release Lease

Manually release a lease before expiration.

#### Endpoint

```
DELETE /api/v1/dhcp/pools/{pool_id}/leases/{lease_id}
```

#### Response

```json
{
  "success": true,
  "message": "Lease released successfully",
  "data": {
    "ip_address": "192.168.1.105",
    "mac_address": "AA:BB:CC:DD:EE:FF"
  }
}
```

### List Reservations

Get all static IP reservations.

#### Endpoint

```
GET /api/v1/dhcp/reservations
```

#### Query Parameters

| Parameter | Type    | Description | Example |
|-----------|---------|-------------|---------|
| pool_id   | integer | Filter by pool | 1 |

#### Response

```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "pool_id": 1,
      "mac_address": "00:11:22:33:44:55",
      "ip_address": "192.168.1.10",
      "hostname": "printer-main",
      "description": "Main office printer",
      "created_at": "2026-01-01T00:00:00Z"
    }
  ]
}
```

### Create Reservation

Create a static IP reservation.

#### Endpoint

```
POST /api/v1/dhcp/reservations
```

#### Request Body

```json
{
  "pool_id": 1,
  "mac_address": "00:11:22:33:44:66",
  "ip_address": "192.168.1.11",
  "hostname": "server-backup",
  "description": "Backup server static IP"
}
```

### Delete Reservation

Remove a static reservation.

#### Endpoint

```
DELETE /api/v1/dhcp/reservations/{reservation_id}
```

---

## Time Synchronization API

The Time API provides management of time servers using PTP (IEEE 1588) as primary and NTPv4 as fallback, with team-based access control.

### List Time Servers

Get all time servers visible to the authenticated user.

#### Endpoint

```
GET /api/v1/time/servers
```

#### Query Parameters

| Parameter | Type    | Description | Example |
|-----------|---------|-------------|---------|
| protocol  | string  | Filter by protocol (ptp, ntp) | ptp |
| team_id   | integer | Filter by team | 1 |
| active    | boolean | Filter by active status | true |

#### Response

```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "name": "Primary PTP Server",
      "server_url": "ptp://time.internal.local",
      "protocol": "ptp",
      "stratum": 1,
      "priority": 100,
      "team_id": 1,
      "active": true,
      "status": "synchronized",
      "last_sync": "2026-01-05T10:00:00Z",
      "offset_ms": 0.0012,
      "delay_ms": 0.0045
    },
    {
      "id": 2,
      "name": "NTP Fallback",
      "server_url": "ntp://time.google.com",
      "protocol": "ntp",
      "stratum": 2,
      "priority": 200,
      "team_id": 1,
      "active": true,
      "status": "synchronized",
      "last_sync": "2026-01-05T09:59:58Z",
      "offset_ms": 1.234,
      "delay_ms": 15.678
    }
  ]
}
```

### Create Time Server

Add a new time server.

#### Endpoint

```
POST /api/v1/time/servers
```

#### Request Body

```json
{
  "name": "Datacenter PTP Master",
  "server_url": "ptp://192.168.100.1",
  "protocol": "ptp",
  "stratum": 1,
  "priority": 50,
  "team_id": 1,
  "ptp_config": {
    "domain": 0,
    "transport": "udp",
    "delay_mechanism": "e2e"
  }
}
```

#### Response

```json
{
  "success": true,
  "data": {
    "id": 3,
    "name": "Datacenter PTP Master",
    "server_url": "ptp://192.168.100.1",
    "protocol": "ptp",
    "stratum": 1,
    "priority": 50,
    "team_id": 1,
    "active": true,
    "created_at": "2026-01-05T10:00:00Z"
  },
  "message": "Time server created successfully"
}
```

### Get Time Server Details

Get detailed information about a time server.

#### Endpoint

```
GET /api/v1/time/servers/{server_id}
```

#### Response

```json
{
  "success": true,
  "data": {
    "id": 1,
    "name": "Primary PTP Server",
    "server_url": "ptp://time.internal.local",
    "protocol": "ptp",
    "stratum": 1,
    "priority": 100,
    "team_id": 1,
    "active": true,
    "status": "synchronized",
    "statistics": {
      "uptime_seconds": 86400,
      "sync_count": 86400,
      "sync_failures": 0,
      "avg_offset_ms": 0.0015,
      "max_offset_ms": 0.0089,
      "avg_delay_ms": 0.0048
    },
    "ptp_config": {
      "domain": 0,
      "transport": "udp",
      "delay_mechanism": "e2e",
      "announce_interval": 1,
      "sync_interval": 0
    }
  }
}
```

### Update Time Server

Update time server configuration.

#### Endpoint

```
PUT /api/v1/time/servers/{server_id}
```

#### Request Body

```json
{
  "name": "Primary PTP Server - Updated",
  "priority": 75,
  "active": true
}
```

### Delete Time Server

Remove a time server.

#### Endpoint

```
DELETE /api/v1/time/servers/{server_id}
```

### Get Current Time Status

Get the current time synchronization status.

#### Endpoint

```
GET /api/v1/time/status
```

#### Response

```json
{
  "success": true,
  "data": {
    "current_time": "2026-01-05T10:00:00.000000Z",
    "synchronized": true,
    "active_source": {
      "id": 1,
      "name": "Primary PTP Server",
      "protocol": "ptp",
      "stratum": 1
    },
    "offset_ms": 0.0012,
    "delay_ms": 0.0045,
    "last_sync": "2026-01-05T10:00:00Z",
    "fallback_available": true
  }
}
```

### Force Time Sync

Trigger immediate time synchronization.

#### Endpoint

```
POST /api/v1/time/sync
```

#### Request Body (optional)

```json
{
  "server_id": 1
}
```

#### Response

```json
{
  "success": true,
  "data": {
    "synced_from": "Primary PTP Server",
    "protocol": "ptp",
    "offset_before_ms": 1.234,
    "offset_after_ms": 0.001,
    "adjustment_ms": -1.233
  },
  "message": "Time synchronized successfully"
}
```

### Get Time Sync Logs

Get historical time synchronization logs.

#### Endpoint

```
GET /api/v1/time/logs
```

#### Query Parameters

| Parameter  | Type    | Description | Example |
|------------|---------|-------------|---------|
| server_id  | integer | Filter by server | 1 |
| start_date | string  | Start date (ISO 8601) | 2026-01-01T00:00:00Z |
| end_date   | string  | End date (ISO 8601) | 2026-01-05T23:59:59Z |
| status     | string  | Filter by status (success, failed) | success |

#### Response

```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "server_id": 1,
      "server_name": "Primary PTP Server",
      "protocol": "ptp",
      "offset_ms": 0.0012,
      "delay_ms": 0.0045,
      "status": "success",
      "timestamp": "2026-01-05T10:00:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 100,
    "total": 86400
  }
}
```

---

## Monitoring & Logs API

### System Health

Check system health and status.

#### Endpoint

```
GET /api/health
```

#### Response

```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "version": "1.2.0",
    "uptime": 86400,
    "components": {
      "database": "healthy",
      "dns_resolver": "healthy",
      "authentication": "healthy"
    },
    "metrics": {
      "requests_per_second": 125,
      "average_response_time": 45,
      "active_tokens": 15,
      "queries_today": 125000
    }
  }
}
```

### System Statistics

Get detailed system statistics.

#### Endpoint

```
GET /dns_console/api/stats
```

#### Response

```json
{
  "success": true,
  "data": {
    "tokens": {
      "total": 25,
      "active": 20,
      "inactive": 5
    },
    "domains": {
      "total": 45,
      "wildcards": 3
    },
    "queries": {
      "today": 125000,
      "week": 875000,
      "month": 3500000
    },
    "performance": {
      "avg_response_time_ms": 45,
      "cache_hit_rate": 0.85,
      "uptime_percentage": 99.97
    },
    "top_domains": [
      {
        "domain": "api.example.com",
        "queries": 25000
      },
      {
        "domain": "example.com",
        "queries": 15000
      }
    ],
    "top_tokens": [
      {
        "token_name": "Production API",
        "queries": 45000
      },
      {
        "token_name": "Mobile App",
        "queries": 30000
      }
    ]
  }
}
```

### Query Logs

Retrieve DNS query logs with filtering and pagination.

#### Endpoint

```
GET /dns_console/api/logs
```

#### Query Parameters

| Parameter | Type    | Description | Example |
|-----------|---------|-------------|---------|
| page      | integer | Page number (default: 1) | 1 |
| per_page  | integer | Records per page (default: 50, max: 1000) | 100 |
| token_id  | integer | Filter by token ID | 123 |
| domain    | string  | Filter by domain | example.com |
| status    | string  | Filter by status (allowed/denied/error) | allowed |
| start_date| string  | Start date (ISO 8601) | 2024-01-01T00:00:00Z |
| end_date  | string  | End date (ISO 8601) | 2024-01-31T23:59:59Z |

#### Request Example

```bash
curl -H "Authorization: Bearer TOKEN" \
     "http://localhost:8000/dns_console/api/logs?page=1&per_page=50&status=allowed&domain=example.com"
```

#### Response

```json
{
  "success": true,
  "data": {
    "logs": [
      {
        "id": 12345,
        "timestamp": "2024-01-03T10:00:00Z",
        "token_name": "Production API",
        "domain_queried": "example.com",
        "query_type": "A",
        "status": "allowed",
        "client_ip": "192.168.1.100",
        "response_time_ms": 45
      },
      {
        "id": 12344,
        "timestamp": "2024-01-03T09:59:58Z",
        "token_name": "Development",
        "domain_queried": "test.example.com",
        "query_type": "AAAA",
        "status": "denied",
        "client_ip": "10.0.1.50",
        "response_time_ms": 12
      }
    ],
    "pagination": {
      "page": 1,
      "per_page": 50,
      "total": 125000,
      "pages": 2500,
      "has_next": true,
      "has_prev": false
    },
    "filters": {
      "status": "allowed",
      "domain": "example.com"
    }
  }
}
```

### Export Logs

Export logs in various formats.

#### Endpoint

```
GET /dns_console/api/logs/export
```

#### Query Parameters

| Parameter | Type   | Description | Example |
|-----------|--------|-------------|---------|
| format    | string | Export format (csv, json, xlsx) | csv |
| start_date| string | Start date | 2024-01-01T00:00:00Z |
| end_date  | string | End date | 2024-01-31T23:59:59Z |

#### Response

Returns file download with appropriate Content-Type header.

```bash
curl -H "Authorization: Bearer TOKEN" \
     "http://localhost:8000/dns_console/api/logs/export?format=csv&start_date=2024-01-01T00:00:00Z" \
     -o query_logs.csv
```

## Error Handling

### Standard Error Response Format

All API errors follow a consistent format:

```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": {
      "field": "specific_field",
      "constraint": "validation_rule"
    }
  },
  "request_id": "req_123456789"
}
```

### HTTP Status Codes

| Code | Meaning | Description |
|------|---------|-------------|
| 200  | OK | Request successful |
| 201  | Created | Resource created successfully |
| 400  | Bad Request | Invalid request parameters |
| 401  | Unauthorized | Authentication required |
| 403  | Forbidden | Insufficient permissions |
| 404  | Not Found | Resource not found |
| 409  | Conflict | Resource already exists |
| 429  | Too Many Requests | Rate limit exceeded |
| 500  | Internal Server Error | Server error |

### Error Codes

| Code | Description |
|------|-------------|
| INVALID_TOKEN | Authentication token is invalid |
| TOKEN_EXPIRED | Token has expired |
| PERMISSION_DENIED | Insufficient permissions |
| DOMAIN_NOT_FOUND | Requested domain not found |
| VALIDATION_ERROR | Input validation failed |
| RATE_LIMIT_EXCEEDED | Too many requests |
| DNS_RESOLUTION_FAILED | DNS query failed |
| DATABASE_ERROR | Database operation failed |

### Error Examples

#### Authentication Error

```json
{
  "success": false,
  "error": {
    "code": "INVALID_TOKEN",
    "message": "Authentication token is invalid or expired",
    "details": {
      "token_format": "invalid"
    }
  },
  "request_id": "req_auth_001"
}
```

#### Validation Error

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Token name is required and must be unique",
    "details": {
      "field": "name",
      "constraint": "required_unique"
    }
  },
  "request_id": "req_val_002"
}
```

#### Permission Error

```json
{
  "success": false,
  "error": {
    "code": "PERMISSION_DENIED",
    "message": "Token does not have permission to access this domain",
    "details": {
      "token": "abc123...",
      "domain": "restricted.example.com",
      "required_permission": "domain_access"
    }
  },
  "request_id": "req_perm_003"
}
```

## Rate Limiting

### Rate Limit Headers

API responses include rate limiting information:

```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 742
X-RateLimit-Reset: 1640995200
X-RateLimit-Window: 3600
```

### Default Rate Limits

| Endpoint Type | Limit | Window |
|---------------|-------|--------|
| DNS Queries | 1000 requests | Per hour |
| Management API | 100 requests | Per hour |
| Authentication | 20 attempts | Per minute |

### Rate Limit Exceeded Response

```json
{
  "success": false,
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Too many requests. Please try again later.",
    "details": {
      "limit": 1000,
      "window": 3600,
      "retry_after": 1800
    }
  },
  "request_id": "req_rate_001"
}
```

## SDK Examples

### Python SDK

```python
import requests
import json
from typing import Dict, List, Optional

class SquawkClient:
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        })

    def dns_query(self, domain: str, record_type: str = 'A') -> Dict:
        """Perform DNS query"""
        url = f"{self.base_url}/dns-query"
        params = {'name': domain, 'type': record_type}

        response = self.session.get(url, params=params)
        response.raise_for_status()
        return response.json()

    def list_tokens(self) -> List[Dict]:
        """List all tokens"""
        url = f"{self.base_url}/dns_console/api/tokens"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()['data']

    def create_token(self, name: str, description: str = None,
                    domains: List[str] = None) -> Dict:
        """Create new token"""
        url = f"{self.base_url}/dns_console/api/tokens"
        payload = {'name': name}

        if description:
            payload['description'] = description
        if domains:
            payload['domains'] = domains

        response = self.session.post(url, json=payload)
        response.raise_for_status()
        return response.json()['data']

    def grant_permission(self, token_id: int, domain_id: int) -> bool:
        """Grant domain permission to token"""
        url = f"{self.base_url}/dns_console/api/permissions"
        payload = {'token_id': token_id, 'domain_id': domain_id}

        response = self.session.post(url, json=payload)
        response.raise_for_status()
        return response.json()['success']

# Usage example
client = SquawkClient('https://dns.example.com', 'your-admin-token')

# Perform DNS query
result = client.dns_query('example.com', 'A')
print(f"IP: {result['Answer'][0]['data']}")

# Create new token
token = client.create_token(
    name='Mobile App Token',
    description='Token for mobile application',
    domains=['api.example.com', 'cdn.example.com']
)
print(f"New token: {token['token']}")
```

### JavaScript SDK

```javascript
class SquawkClient {
    constructor(baseUrl, token) {
        this.baseUrl = baseUrl.replace(/\/$/, '');
        this.token = token;
        this.headers = {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        };
    }

    async dnsQuery(domain, recordType = 'A') {
        const url = `${this.baseUrl}/dns-query?name=${domain}&type=${recordType}`;
        const response = await fetch(url, {
            headers: this.headers
        });

        if (!response.ok) {
            throw new Error(`DNS query failed: ${response.statusText}`);
        }

        return await response.json();
    }

    async listTokens() {
        const url = `${this.baseUrl}/dns_console/api/tokens`;
        const response = await fetch(url, {
            headers: this.headers
        });

        if (!response.ok) {
            throw new Error(`Failed to list tokens: ${response.statusText}`);
        }

        const data = await response.json();
        return data.data;
    }

    async createToken(name, description = null, domains = null) {
        const url = `${this.baseUrl}/dns_console/api/tokens`;
        const payload = { name };

        if (description) payload.description = description;
        if (domains) payload.domains = domains;

        const response = await fetch(url, {
            method: 'POST',
            headers: this.headers,
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            throw new Error(`Failed to create token: ${response.statusText}`);
        }

        const data = await response.json();
        return data.data;
    }

    async getQueryLogs(options = {}) {
        const params = new URLSearchParams();

        Object.entries(options).forEach(([key, value]) => {
            if (value !== null && value !== undefined) {
                params.append(key, value);
            }
        });

        const url = `${this.baseUrl}/dns_console/api/logs?${params}`;
        const response = await fetch(url, {
            headers: this.headers
        });

        if (!response.ok) {
            throw new Error(`Failed to get logs: ${response.statusText}`);
        }

        return await response.json();
    }
}

// Usage example
const client = new SquawkClient('https://dns.example.com', 'your-admin-token');

// Perform DNS query
client.dnsQuery('example.com', 'A')
    .then(result => {
        console.log('IP:', result.Answer[0].data);
    })
    .catch(error => {
        console.error('DNS query failed:', error);
    });

// Create token
client.createToken('Web App Token', 'Token for web application', ['example.com'])
    .then(token => {
        console.log('New token:', token.token);
    })
    .catch(error => {
        console.error('Token creation failed:', error);
    });

// Get recent logs
client.getQueryLogs({
    per_page: 100,
    status: 'allowed',
    start_date: '2024-01-01T00:00:00Z'
}).then(logs => {
    console.log('Query logs:', logs.data.logs);
}).catch(error => {
    console.error('Failed to get logs:', error);
});
```

### Go SDK

```go
package squawk

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "net/url"
    "time"
)

type Client struct {
    BaseURL    string
    Token      string
    HTTPClient *http.Client
}

type DNSResponse struct {
    Status int `json:"Status"`
    Answer []struct {
        Name string `json:"name"`
        Type string `json:"type"`
        Data string `json:"data"`
    } `json:"Answer"`
}

type Token struct {
    ID          int       `json:"id"`
    Name        string    `json:"name"`
    Token       string    `json:"token"`
    Description string    `json:"description"`
    Active      bool      `json:"active"`
    CreatedAt   time.Time `json:"created_at"`
}

func NewClient(baseURL, token string) *Client {
    return &Client{
        BaseURL:    baseURL,
        Token:      token,
        HTTPClient: &http.Client{Timeout: 30 * time.Second},
    }
}

func (c *Client) DNSQuery(domain, recordType string) (*DNSResponse, error) {
    u, _ := url.Parse(c.BaseURL + "/dns-query")
    q := u.Query()
    q.Set("name", domain)
    q.Set("type", recordType)
    u.RawQuery = q.Encode()

    req, err := http.NewRequest("GET", u.String(), nil)
    if err != nil {
        return nil, err
    }

    req.Header.Set("Authorization", "Bearer "+c.Token)

    resp, err := c.HTTPClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("DNS query failed: %s", resp.Status)
    }

    var result DNSResponse
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }

    return &result, nil
}

func (c *Client) CreateToken(name, description string, domains []string) (*Token, error) {
    payload := map[string]interface{}{
        "name":        name,
        "description": description,
        "domains":     domains,
    }

    jsonPayload, err := json.Marshal(payload)
    if err != nil {
        return nil, err
    }

    req, err := http.NewRequest("POST", c.BaseURL+"/dns_console/api/tokens",
                               bytes.NewBuffer(jsonPayload))
    if err != nil {
        return nil, err
    }

    req.Header.Set("Authorization", "Bearer "+c.Token)
    req.Header.Set("Content-Type", "application/json")

    resp, err := c.HTTPClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusCreated {
        return nil, fmt.Errorf("create token failed: %s", resp.Status)
    }

    var result struct {
        Success bool   `json:"success"`
        Data    *Token `json:"data"`
    }

    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }

    return result.Data, nil
}

// Usage example
func main() {
    client := NewClient("https://dns.example.com", "your-admin-token")

    // DNS query
    result, err := client.DNSQuery("example.com", "A")
    if err != nil {
        panic(err)
    }

    if len(result.Answer) > 0 {
        fmt.Printf("IP: %s\n", result.Answer[0].Data)
    }

    // Create token
    token, err := client.CreateToken("Go App Token", "Token for Go application",
                                    []string{"api.example.com"})
    if err != nil {
        panic(err)
    }

    fmt.Printf("New token: %s\n", token.Token)
}
```

This comprehensive API documentation provides all the information needed to integrate with the Squawk DNS system, from basic DNS queries to advanced token and permission management.
