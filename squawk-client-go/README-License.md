# Squawk DNS Client (Go) - License Integration

The Go DNS client now requires a valid Squawk DNS license to operate. This enables premium DNS features and per-user token management.

## License Configuration

### Environment Variables

Set these environment variables to configure your license:

```bash
# Option 1: Use your license key (for evaluation)
export SQUAWK_LICENSE_KEY="SQWK-XXXX-XXXX-XXXX-XXXX-XXXX"

# Option 2: Use your user token (recommended for production)
export SQUAWK_USER_TOKEN="your-user-token-from-license-portal"

# License server (default: https://license.squawkdns.com)
export SQUAWK_LICENSE_SERVER_URL="https://license.squawkdns.com"

# Validation settings
export SQUAWK_VALIDATE_ONLINE="true"        # Validate online vs cache-only
export SQUAWK_LICENSE_CACHE_TIME="1440"     # Cache time in minutes (24 hours)
```

### Configuration File

Add to your YAML config file:

```yaml
license:
  server_url: "https://license.squawkdns.com"
  license_key: "SQWK-XXXX-XXXX-XXXX-XXXX-XXXX"  # OR
  user_token: "your-user-token"                  # Preferred for production
  validate_online: true
  cache_time: 1440  # 24 hours
```

## Getting Your License

1. **Purchase a License**: Contact sales for a Squawk DNS license
2. **Receive License Key**: You'll receive a license key via email
3. **Access Portal**: Visit https://license.squawkdns.com/portal/login
4. **Generate Token**: Login with your license key + email to create user tokens

## Daily Validation

The client validates your license:
- **First run**: Always validates online
- **Daily**: Validates once per day online
- **Cached**: Uses cached validation between daily checks
- **Offline**: Falls back to cache if license server is unavailable

This ensures minimal performance impact while maintaining license compliance.

## Usage Examples

### Basic DNS Query with License

```bash
# Set your user token
export SQUAWK_USER_TOKEN="your-token-here"

# Query DNS
squawk-dns-client -d example.com -t A
```

### DNS Forwarding Service

```bash
# Set your license
export SQUAWK_USER_TOKEN="your-token-here"

# Start DNS forwarder
squawk-dns-client forward --udp --tcp
```

### License Management Commands

```bash
# Check license status
squawk-dns-client license status

# Open license portal
squawk-dns-client license portal
```

## Features Enabled by License

With a valid license, you get:
- Premium DNS resolution
- Advanced caching and performance optimization
- Priority query processing
- Extended query limits
- Detailed analytics and logging
- Technical support

## License Types

### License Key
- Use for initial setup and evaluation
- Shared across organization
- Limited to license holder's email

### User Tokens
- Individual tokens per user
- Better security and tracking
- Recommended for production
- Generate via license portal

## Troubleshooting

### License Validation Failed

```bash
# Check license status
squawk-dns-client license status -v

# Common issues:
# 1. License expired - renew via portal
# 2. Network connectivity - check firewall
# 3. Invalid token - regenerate via portal
```

### Offline Operation

```bash
# Enable offline mode (cache-only)
export SQUAWK_VALIDATE_ONLINE="false"

# Client will use cached validation results
squawk-dns-client -d example.com
```

### Configuration Issues

```bash
# Show current configuration
squawk-dns-client config show

# Generate example config
squawk-dns-client config generate
```

## Migration from Legacy Auth

If you're upgrading from legacy token auth:

1. **Keep existing**: `SQUAWK_AUTH_TOKEN` still works
2. **Add license**: Set `SQUAWK_USER_TOKEN` for license-based auth
3. **Priority**: User token takes precedence over legacy token
4. **Transition**: Gradually migrate to user tokens

## Security Best Practices

1. **Use User Tokens**: Prefer user tokens over license keys in production
2. **Token Rotation**: Regularly generate new tokens via portal
3. **Environment Variables**: Store tokens in secure environment variables
4. **Least Privilege**: Each user should have their own token
5. **Monitor Usage**: Review token usage in license portal

## Support

For license issues:
- Visit: https://license.squawkdns.com/portal/login
- Sales: Contact your sales representative
- Technical: Check logs with `-v` flag for details