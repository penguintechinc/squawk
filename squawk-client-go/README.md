# Squawk DNS Client (Go)

A high-performance DNS-over-HTTPS client written in Go, providing 1:1 feature parity with the Python client. Supports mTLS authentication, local DNS forwarding, and comprehensive configuration options.

## Features

### Core Functionality
- **DNS-over-HTTPS (DoH) Support**: Secure DNS resolution using HTTPS protocol
- **mTLS Authentication**: Mutual TLS support with client certificate authentication
- **Bearer Token Auth**: Support for bearer token authentication
- **Local DNS Forwarding**: Forward traditional DNS queries (UDP/TCP) to DoH
- **Configuration Files**: YAML configuration file support
- **Environment Variables**: Full environment variable configuration
- **Cross-Platform**: Builds for Linux, macOS, and Windows

### Security Features
- **TLS Certificate Verification**: Configurable SSL/TLS verification
- **Client Certificate Support**: mTLS with ECC and RSA certificates
- **Secure Defaults**: SSL verification enabled by default
- **CA Certificate Validation**: Custom CA certificate support

### Performance
- **HTTP/2 Support**: Leverages HTTP/2 for improved performance
- **Concurrent Processing**: Efficient handling of multiple requests
- **Connection Pooling**: Reuses connections for better performance
- **Timeout Management**: Configurable timeouts and graceful handling

## Installation

### Build from Source

```bash
# Clone the repository
git clone https://github.com/penguintechinc/squawk.git
cd squawk/dns-client-go

# Install dependencies
make deps

# Build for current platform
make build

# Build for all platforms
make build-all
```

### Pre-built Binaries

Download pre-built binaries from the releases page or build using:

```bash
make package
```

## Quick Start

### Basic DNS Query

```bash
# Simple DNS query (uses Google DNS by default)
./squawk-dns-client -d example.com

# Query specific record type
./squawk-dns-client -d example.com -t AAAA

# Using public DNS providers (automatic path normalization)
./squawk-dns-client -d example.com -s https://dns.google.com
./squawk-dns-client -d example.com -s https://cloudflare-dns.com
./squawk-dns-client -d example.com -s https://1.1.1.1
./squawk-dns-client -d example.com -s https://dns.quad9.net

# With authentication (use IP address for custom servers)
./squawk-dns-client -d example.com -s https://192.168.1.100:8443 -a your-token-here
```

### mTLS Authentication

```bash
# Using mTLS with client certificates (use IP address for custom servers)
./squawk-dns-client \
  -d example.com \
  -s https://192.168.1.100:8443 \
  -a your-bearer-token \
  --ca-cert ca.crt \
  --client-cert client.crt \
  --client-key client.key
```

### DNS Forwarding

```bash
# Start DNS forwarder (requires sudo for port 53, use IP address to prevent loops)
sudo ./squawk-dns-client forward -s https://192.168.1.100:8443 -a your-token

# Forward UDP only
sudo ./squawk-dns-client -u -s https://192.168.1.100:8443

# Forward both UDP and TCP
sudo ./squawk-dns-client -u -T -s https://192.168.1.100:8443
```

## Public DNS Providers

The client has built-in support for major public DNS-over-HTTPS providers with automatic URL normalization:

### Supported Providers

| Provider | URL | Auto-Path | IP Alternative |
|----------|-----|-----------|----------------|
| Google DNS | `https://dns.google.com` | `/resolve` | `8.8.8.8`, `8.8.4.4` |
| Google DNS (legacy) | `https://dns.google` | `/resolve` | `8.8.8.8`, `8.8.4.4` |
| Cloudflare | `https://cloudflare-dns.com` | `/dns-query` | `1.1.1.1`, `1.0.0.1` |
| Cloudflare (IP) | `https://1.1.1.1` | `/dns-query` | N/A |
| Quad9 | `https://dns.quad9.net` | `/dns-query` | `9.9.9.9` |
| OpenDNS | `https://doh.opendns.com` | `/dns-query` | `208.67.222.222` |
| NextDNS | `https://dns.nextdns.io` | Varies | Varies |
| CleanBrowsing | `https://doh.cleanbrowsing.org` | `/dns-query` | `185.228.168.168` |

### Usage Examples

```bash
# Google DNS (both forms work)
./squawk-dns-client -d example.com -s https://dns.google.com
./squawk-dns-client -d example.com -s https://dns.google

# Cloudflare (hostname or IP)
./squawk-dns-client -d example.com -s https://cloudflare-dns.com
./squawk-dns-client -d example.com -s https://1.1.1.1

# Multiple public providers with failover
export SQUAWK_SERVER_URLS="https://dns.google.com,https://1.1.1.1,https://dns.quad9.net"
./squawk-dns-client -d example.com
```

### Automatic Path Correction

The client automatically appends the correct path for known providers:
- Google: `/resolve` (not `/dns-query`)
- Cloudflare: `/dns-query`
- Quad9: `/dns-query`

This means these are equivalent:
```bash
# These all work correctly:
-s https://dns.google.com
-s https://dns.google.com/
-s https://dns.google.com/resolve
```

## Configuration

### Environment Variables

All configuration options can be set via environment variables:

```bash
# Server and authentication
export SQUAWK_SERVER_URL=https://192.168.1.100:8443
export SQUAWK_AUTH_TOKEN=your-bearer-token-here
export SQUAWK_DOMAIN=example.com
export SQUAWK_RECORD_TYPE=A

# Multiple servers with automatic failover (comma-separated)
export SQUAWK_SERVER_URLS="https://192.168.1.100:8443,https://192.168.1.101:8443,https://10.0.0.50:8443"
export SQUAWK_MAX_RETRIES=6
export SQUAWK_RETRY_DELAY=2

# mTLS configuration
export SQUAWK_CLIENT_CERT=/path/to/client.crt
export SQUAWK_CLIENT_KEY=/path/to/client.key
export SQUAWK_CA_CERT=/path/to/ca.crt
export SQUAWK_VERIFY_SSL=true

# DNS forwarding
export SQUAWK_UDP_ADDRESS=127.0.0.1:53
export SQUAWK_TCP_ADDRESS=127.0.0.1:53
export SQUAWK_LISTEN_UDP=true
export SQUAWK_LISTEN_TCP=true

# Logging
export LOG_LEVEL=INFO
```

#### Legacy Environment Variable Support

The Go client also supports legacy environment variable names for compatibility:

```bash
export CLIENT_CERT_PATH=/path/to/client.crt
export CLIENT_KEY_PATH=/path/to/client.key
export CA_CERT_PATH=/path/to/ca.crt
```

### Configuration File

Create a YAML configuration file:

```yaml
# squawk-client.yaml
domain: example.com
record_type: A
log_level: INFO

client:
  server_url: https://dns.example.com:8443
  auth_token: your-bearer-token-here
  client_cert: /path/to/client.crt
  client_key: /path/to/client.key
  ca_cert: /path/to/ca.crt
  verify_ssl: true

forwarder:
  udp_address: 127.0.0.1:53
  tcp_address: 127.0.0.1:53
  listen_udp: true
  listen_tcp: true
```

Use the configuration file:

```bash
./squawk-dns-client -c squawk-client.yaml
```

Generate an example configuration:

```bash
./squawk-dns-client config generate squawk-client.yaml
```

## Command Reference

### Main Commands

```bash
# Perform DNS query
squawk-dns-client [flags]

# Start DNS forwarding service
squawk-dns-client forward [flags]

# Configuration management
squawk-dns-client config <subcommand>

# Version information
squawk-dns-client version
```

### Global Flags

```bash
-c, --config string       Configuration file path
-v, --verbose             Enable verbose output
-h, --help               Help for commands
    --version            Show version information
```

### DNS Query Flags

```bash
-d, --domain string       Domain to query (required)
-t, --type string         DNS record type (default "A")
-j, --json               Output in JSON format
```

### Server Connection Flags

```bash
-s, --server string       DNS server URL
-a, --auth string         Authentication token
```

### mTLS Flags

```bash
    --client-cert string  Client certificate file for mTLS
    --client-key string   Client private key file for mTLS
    --ca-cert string      CA certificate file for server verification
    --verify-ssl          Verify SSL/TLS certificates (default true)
```

### DNS Forwarding Flags

```bash
-u, --udp                Enable UDP DNS forwarding on port 53
-T, --tcp                Enable TCP DNS forwarding on port 53
```

### Configuration Commands

```bash
# Show current configuration
squawk-dns-client config show

# Show environment variables
squawk-dns-client config env

# Generate example configuration
squawk-dns-client config generate [filename]
```

## Examples

### Development Setup

```bash
# Build and run example query
make build
make run-example

# Run with custom server
make run ARGS="-d example.com -s https://your-dns-server.com:8443 -a your-token"

# Generate and use config file
make config-example
./bin/squawk-dns-client -c squawk-client.yaml -d example.com
```

### Production Deployment

```bash
# Build production binary
make build VERSION=1.0.0

# Create systemd service for DNS forwarding
sudo ./squawk-dns-client forward \
  --config /etc/squawk/client.yaml \
  --verbose
```

### mTLS Setup

```bash
# Download certificate bundle from web console
# Extract to /etc/squawk/certs/

# Configure environment
export SQUAWK_SERVER_URL=https://dns.company.com:8443
export SQUAWK_AUTH_TOKEN=your-bearer-token
export SQUAWK_CA_CERT=/etc/squawk/certs/ca.crt
export SQUAWK_CLIENT_CERT=/etc/squawk/certs/client.crt
export SQUAWK_CLIENT_KEY=/etc/squawk/certs/client.key

# Test connectivity
./squawk-dns-client -d example.com -v

# Start forwarder with mTLS
sudo ./squawk-dns-client forward -v
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: squawk-dns-client
spec:
  replicas: 1
  selector:
    matchLabels:
      app: squawk-dns-client
  template:
    metadata:
      labels:
        app: squawk-dns-client
    spec:
      containers:
      - name: squawk-dns-client
        image: squawk-dns-client:latest
        env:
        - name: SQUAWK_SERVER_URL
          value: "https://dns.company.com:8443"
        - name: SQUAWK_AUTH_TOKEN
          valueFrom:
            secretKeyRef:
              name: squawk-auth
              key: token
        volumeMounts:
        - name: certs
          mountPath: /etc/squawk/certs
          readOnly: true
        ports:
        - containerPort: 53
          protocol: UDP
        - containerPort: 53
          protocol: TCP
      volumes:
      - name: certs
        secret:
          secretName: squawk-client-certs
```

## Development

### Building

```bash
# Install dependencies
make deps

# Format code
make fmt

# Run linter
make lint

# Run tests
make test

# Run tests with coverage
make test-coverage

# Security scan
make security

# Run benchmarks
make bench
```

### Cross-Platform Building

```bash
# Build for specific platform
make build GOOS=linux GOARCH=amd64

# Build all platforms
make build-all

# Create release packages
make package VERSION=1.2.3
```

## Compatibility

The Go client provides 1:1 feature parity with the Python client:

| Feature | Python Client | Go Client |
|---------|---------------|-----------|
| DNS-over-HTTPS | ✅ | ✅ |
| Bearer Token Auth | ✅ | ✅ |
| mTLS Support | ✅ | ✅ |
| UDP/TCP Forwarding | ✅ | ✅ |
| Configuration Files | ✅ (YAML) | ✅ (YAML) |
| Environment Variables | ✅ | ✅ |
| SSL Verification | ✅ | ✅ |
| JSON Output | ✅ | ✅ |
| Verbose Logging | ✅ | ✅ |

### Command Line Equivalence

Python to Go command translation:

```bash
# Python
python client.py -d example.com -s https://dns.server:8443 -a token

# Go
./squawk-dns-client -d example.com -s https://dns.server:8443 -a token
```

```bash
# Python with mTLS
python client.py -d example.com -s https://dns.server:8443 \
  --ca-cert ca.crt --client-cert client.crt --client-key client.key

# Go with mTLS
./squawk-dns-client -d example.com -s https://dns.server:8443 \
  --ca-cert ca.crt --client-cert client.crt --client-key client.key
```

## Performance

The Go client provides superior performance compared to the Python client:

- **Cold Start**: ~10ms vs ~100ms (Python)
- **Memory Usage**: ~15MB vs ~30MB (Python)
- **Concurrent Requests**: Native goroutine support
- **Binary Size**: Single ~10MB binary vs Python + dependencies

## Security Considerations

1. **Always use TLS/SSL** in production environments
2. **Enable certificate verification** (default: enabled)
3. **Use mTLS** for maximum security with client certificates
4. **Protect private keys** with appropriate file permissions (600)
5. **Regularly rotate** authentication tokens and certificates
6. **Monitor logs** for suspicious activity
7. **Keep binaries updated** with security patches

## Preventing DNS Loops

⚠️ **Important**: When using DNS forwarding mode, always use IP addresses (not hostnames) for your DNS server URL to prevent infinite DNS resolution loops.

### ✅ Correct Usage
```bash
# Use IP address for custom DNS servers
sudo ./squawk-dns-client forward -s https://192.168.1.100:8443

# IPv6 addresses are also supported
sudo ./squawk-dns-client forward -s https://[2001:db8::1]:8443
```

### ❌ Incorrect Usage (Will Cause Loops)
```bash
# DON'T use hostname for custom DNS servers in forwarding mode
sudo ./squawk-dns-client forward -s https://my-dns-server.example.com:8443
```

### Special Cases
- **localhost** - Allowed for development
- **Public DNS providers** - Allowed with warnings (dns.google, cloudflare-dns.com, etc.)
- **Query-only mode** - Hostname validation is less strict since it doesn't create forwarding loops

## Multiple Server Failover

The Go client supports multiple DNS servers with automatic failover for high availability:

### Configuration Options

#### YAML Configuration
```yaml
client:
  # Multiple servers with automatic failover
  server_urls:
    - "https://192.168.1.100:8443"
    - "https://192.168.1.101:8443" 
    - "https://10.0.0.50:8443"
  
  # Failover settings
  max_retries: 6        # Total retry attempts (default: servers * 2)
  retry_delay: 2        # Seconds between retries (default: 2)
```

#### Environment Variables
```bash
# Multiple servers (comma-separated)
export SQUAWK_SERVER_URLS="https://192.168.1.100:8443,https://192.168.1.101:8443,https://10.0.0.50:8443"
export SQUAWK_MAX_RETRIES=6
export SQUAWK_RETRY_DELAY=2
```

#### Command Line
```bash
# Using single server
./squawk-dns-client -d example.com -s https://192.168.1.100:8443

# Multiple servers require config file or environment variables
export SQUAWK_SERVER_URLS="https://192.168.1.100:8443,https://192.168.1.101:8443"
./squawk-dns-client -d example.com
```

### Failover Behavior

1. **Round-robin selection** - Cycles through servers in order
2. **Automatic retry** - Tries each server multiple times
3. **Configurable delays** - Waitable delays between attempts
4. **Error aggregation** - Reports all server failures
5. **Immediate success** - Returns as soon as any server responds

### Use Cases

- **Load balancing** across multiple DNS servers
- **High availability** when servers go offline
- **Geographic distribution** for reduced latency
- **Redundancy** for critical applications

## Troubleshooting

### Common Issues

**Certificate verification errors:**
```bash
# Disable SSL verification for testing (NOT for production)
./squawk-dns-client -d example.com --verify-ssl=false
```

**Permission denied on port 53:**
```bash
# DNS forwarding requires root privileges
sudo ./squawk-dns-client forward
```

**Configuration not loading:**
```bash
# Check configuration syntax
./squawk-dns-client config show -c your-config.yaml
```

### Debug Mode

```bash
# Enable verbose output
./squawk-dns-client -v -d example.com

# Show environment variables
./squawk-dns-client config env
```

## License

See LICENSE.md in the parent directory for licensing information.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `make test`
5. Run linting: `make lint fmt`
6. Submit a pull request

For more information, see the main project documentation.

## Resources

- **Documentation**: [docs.squawkdns.com](https://docs.squawkdns.com)
- **GitHub Issues**: [Report Issues](https://github.com/penguintechinc/squawk/issues)
- **Main Project**: [Squawk DNS System](../README.md)