# Squawk DNS Client gRPC Update

## Overview

Both the Python and Go DNS clients have been updated to support the new gRPC DNS query service, providing better performance and efficiency when communicating with Squawk DNS servers in the new Manager/DNS Server architecture.

## Key Features Added

### 1. gRPC Protocol Support
- **Automatic Protocol Detection**: Clients automatically detect and use gRPC when the server URL uses `grpc://` scheme
- **Backward Compatibility**: REST DNS-over-HTTPS (DoH) remains the fallback protocol
- **Performance**: gRPC provides better throughput and lower latency for batch queries

### 2. Batch Query Support
- Query multiple domains efficiently with a single gRPC request
- Parallel query execution with configurable concurrency limits
- Ideal for DNS lookups of large domain lists

### 3. Health Check Support
- Real-time server health verification
- Status indicators: UNKNOWN, SERVING, NOT_SERVING, SERVICE_UNKNOWN

### 4. Authentication Token Support
- Bearer token authentication for both gRPC and REST protocols
- Tokens passed in request headers/metadata

---

## Python Client Updates

### Files Modified/Created

- `/home/penguin/code/squawk/dns-client/bins/client.py` - Added gRPC support
- `/home/penguin/code/squawk/dns-client/requirements.txt` - Added gRPC dependencies
- `/home/penguin/code/squawk/dns-client/protos/dns_query_service.proto` - Proto definitions
- `/home/penguin/code/squawk/dns-client/examples/query_example.py` - Usage examples

### New Dependencies

```
grpcio>=1.60.0
grpcio-tools>=1.60.0
protobuf>=4.25.0
```

Install with:
```bash
pip install -r dns-client/requirements.txt
```

### Usage Examples

#### Single Query (gRPC)
```python
from bins.client import SquawkDNSGrpcClient

client = SquawkDNSGrpcClient(
    server_url='grpc://localhost:50052',
    token='your-auth-token',
    use_grpc=True
)

result = client.query('example.com', 'A')
print(f"IP: {result['Answer'][0]['data']}")
client.close()
```

#### Batch Query
```python
domains = ['google.com', 'github.com', 'cloudflare.com']
results = client.batch_query(domains, record_type='A')

for domain, result in zip(domains, results):
    print(f"{domain}: {result['Answer'][0]['data']}")
```

#### Health Check
```python
health = client.health_check()
print(f"Server status: {health['status']}")
```

#### REST Fallback
```python
client = SquawkDNSGrpcClient(
    server_url='https://localhost:8443/dns/query',
    token='your-token',
    use_grpc=False  # Use REST
)
```

### Command-Line Interface

```bash
# Single query
python bins/client.py -d example.com -s grpc://localhost:50052

# Batch query from file
python bins/client.py -b domains.txt -s grpc://localhost:50052

# REST DNS-over-HTTPS
python bins/client.py -d example.com -s https://localhost:8443/dns/query

# With authentication
python bins/client.py -d example.com -s grpc://localhost:50052 -a your-token

# Disable gRPC (use REST only)
python bins/client.py -d example.com -s grpc://localhost:50052 --no-grpc
```

---

## Go Client Updates

### Files Modified/Created

- `/home/penguin/code/squawk/dns-client-go/cmd/squawk-dns-client/main.go` - Added gRPC support
- `/home/penguin/code/squawk/dns-client-go/go.mod` - Added gRPC dependencies
- `/home/penguin/code/squawk/dns-client-go/pkg/grpc/client.go` - gRPC client implementation
- `/home/penguin/code/squawk/dns-client-go/pkg/grpc/dns_query_service.pb.go` - Protobuf types
- `/home/penguin/code/squawk/dns-client-go/pkg/grpc/dns_query_service_grpc.pb.go` - gRPC service stubs
- `/home/penguin/code/squawk/dns-client-go/protos/dns_query_service.proto` - Proto definitions
- `/home/penguin/code/squawk/dns-client-go/examples/query/main.go` - Usage examples

### New Dependencies

```go
require (
    google.golang.org/grpc v1.60.0
    google.golang.org/protobuf v1.32.0
)
```

Update with:
```bash
cd dns-client-go
go mod tidy
```

### Usage Examples

#### Single Query (gRPC)
```go
package main

import (
    "context"
    grpcclient "github.com/penguintechinc/squawk/dns-client-go/pkg/grpc"
)

func main() {
    client, _ := grpcclient.NewDNSClient("localhost:50052", "token")
    defer client.Close()

    ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
    result, _ := client.Query(ctx, "example.com", "A")

    if len(result.Answers) > 0 {
        fmt.Println(result.Answers[0].Data)
    }
}
```

#### Batch Query
```go
domains := []string{"google.com", "github.com", "cloudflare.com"}
results, _ := client.BatchQuery(ctx, domains, "A")

for i, domain := range domains {
    fmt.Printf("%s -> %s\n", domain, results[i].Answers[0].Data)
}
```

#### Health Check
```go
healthy, _ := client.HealthCheck(ctx)
if healthy {
    fmt.Println("Server is healthy")
}
```

### Command-Line Interface

```bash
# Single query with gRPC
./squawk-dns-client -d example.com -s grpc://localhost:50052

# Batch query from file
./squawk-dns-client -b domains.txt -s grpc://localhost:50052

# REST DNS-over-HTTPS
./squawk-dns-client -d example.com -s https://localhost:8443/dns/query

# With authentication token
./squawk-dns-client -d example.com -s grpc://localhost:50052 -a your-token

# Verbose output
./squawk-dns-client -d example.com -s grpc://localhost:50052 -v

# JSON output
./squawk-dns-client -d example.com -s grpc://localhost:50052 -j

# Disable gRPC (use REST only)
./squawk-dns-client -d example.com -s grpc://localhost:50052 --grpc=false
```

---

## Environment Variables

Both clients support environment variables for configuration:

```bash
# Server URL (supports grpc:// or https://)
export SQUAWK_SERVER_URL=grpc://localhost:50052

# Authentication token
export SQUAWK_AUTH_TOKEN=your-token-here

# Domain to query
export SQUAWK_DOMAIN=example.com

# DNS record type
export SQUAWK_RECORD_TYPE=A

# Logging level
export LOG_LEVEL=INFO
```

---

## Protocol Support Matrix

| Feature | gRPC | REST (DoH) |
|---------|------|-----------|
| Single Query | Yes | Yes |
| Batch Query | Yes | Fallback to sequential |
| Health Check | Yes | Limited |
| Streaming | Yes | No |
| mTLS | Planned | Yes |
| Token Auth | Yes | Yes |

---

## Migration Guide

### Updating from REST to gRPC

1. **Update Server URL**:
   ```bash
   # Old (REST)
   SQUAWK_SERVER_URL=https://dns.example.com:8443/dns/query

   # New (gRPC)
   SQUAWK_SERVER_URL=grpc://dns.example.com:50052
   ```

2. **Client automatically handles fallback**:
   - If gRPC is unavailable, client falls back to REST
   - No code changes required

3. **Performance improvements**:
   - Batch queries execute in parallel
   - gRPC multiplexing reduces connection overhead
   - Protobuf encoding is more efficient

---

## Architecture Details

### gRPC Service Definition

The DNS Query Service provides the following RPCs:

```proto
service DNSQueryService {
  rpc Query(QueryRequest) returns (QueryResponse);
  rpc BatchQuery(BatchQueryRequest) returns (BatchQueryResponse);
  rpc StreamQuery(stream QueryRequest) returns (stream QueryResponse);
  rpc HealthCheck(HealthCheckRequest) returns (HealthCheckResponse);
}
```

### Request/Response Structure

**QueryRequest**:
- `name`: Domain name (string)
- `type`: DNS record type (A, AAAA, MX, etc.)
- `token`: Authentication token (optional)
- `dnssec_ok`: DNSSEC validation requested (boolean)
- `check_disabled`: Bypass cache/IOC checking (boolean)
- `client_subnet`: EDNS Client Subnet (optional)

**QueryResponse**:
- `status`: Response status (0=NOERROR, 2=SERVFAIL, 3=NXDOMAIN)
- `answers`: List of DNS answers
- `authority`: Authority records
- `additional`: Additional records
- `metadata`: Query metadata (timestamp, response time, cache status, etc.)

---

## Troubleshooting

### Connection Issues

```python
# Python - Enable verbose logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Go - Use verbose flag
./squawk-dns-client -d example.com -s grpc://localhost:50052 -v
```

### Fallback Behavior

If gRPC fails:
1. Client logs a warning
2. Automatically falls back to REST if available
3. If REST also unavailable, query fails with appropriate error

### Port Issues

- **Default gRPC port**: 50052
- **Default REST port**: 8443

Verify server is listening:
```bash
# Check gRPC port
nc -zv localhost 50052

# Check REST port
curl -k https://localhost:8443/dns/query?name=example.com&type=A
```

---

## Performance Considerations

### Batch Query Optimization

- **Batch Size**: Test with 10-100 domains per batch
- **Concurrency**: Default max_concurrent=10
- **Timeout**: Scales with batch size (base 30s + 3s per 10 domains)

### Connection Pooling

Both clients maintain persistent connections:
- Python: Reuse client instance for multiple queries
- Go: Single client supports concurrent queries

Example (Python):
```python
client = SquawkDNSGrpcClient(server_url, token)
# Reuse for multiple queries
for domain in domains:
    result = client.query(domain)
# Close when done
client.close()
```

Example (Go):
```go
client, _ := grpcclient.NewDNSClient(addr, token)
defer client.Close()

// Concurrent queries (goroutines)
for _, domain := range domains {
    go func(d string) {
        client.Query(ctx, d, "A")
    }(domain)
}
```

---

## Future Enhancements

- [ ] mTLS support for gRPC
- [ ] Streaming DNS queries (bi-directional)
- [ ] Connection pooling optimization
- [ ] Metrics and tracing integration
- [ ] DNS request prioritization

---

## Support

For issues or questions:
1. Check the examples in `examples/` directory
2. Enable verbose logging with `-v` flag
3. Verify server connectivity: `nc -zv host port`
4. Review logs for authentication or protocol errors

---

## Summary

The gRPC updates provide significant performance improvements while maintaining full backward compatibility with existing REST-based deployments. Choose gRPC for high-volume DNS queries and REST for simple, occasional lookups.
