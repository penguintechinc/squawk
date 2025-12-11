# gRPC DNS Client Quick Start

## Installation

### Python Client

```bash
cd dns-client
pip install -r requirements.txt
```

### Go Client

```bash
cd dns-client-go
go mod tidy
```

---

## Basic Usage

### Python - Single Query

```bash
python bins/client.py -d example.com -s grpc://localhost:50052 -a your-token
```

### Python - Batch Query

Create `domains.txt`:
```
google.com
github.com
cloudflare.com
```

```bash
python bins/client.py -b domains.txt -s grpc://localhost:50052
```

### Go - Single Query

```bash
./squawk-dns-client -d example.com -s grpc://localhost:50052 -a your-token
```

### Go - Batch Query

```bash
./squawk-dns-client -b domains.txt -s grpc://localhost:50052
```

---

## Environment Configuration

```bash
export SQUAWK_SERVER_URL=grpc://localhost:50052
export SQUAWK_AUTH_TOKEN=your-token
export SQUAWK_DOMAIN=example.com
```

Then run without flags:
```bash
# Python
python bins/client.py

# Go
./squawk-dns-client
```

---

## Protocol Selection

### Use gRPC (Recommended)
```
grpc://host:port           # Default port 50052
grpc://host:custom-port    # Custom port
```

### Use REST (Fallback)
```
https://host:port/path     # Standard HTTPS endpoint
http://host:port/path      # HTTP endpoint
```

Clients automatically detect and use the correct protocol.

---

## Output Formats

### Default (Human-Readable)
```bash
python bins/client.py -d example.com -s grpc://localhost:50052
```

Output:
```
Query: example.com (A)
Status: 0
Answers:
  example.com -> 93.184.216.34 (TTL: 3599)
```

### JSON Output
```bash
python bins/client.py -d example.com -s grpc://localhost:50052 -j
```

Output:
```json
{
  "Status": 0,
  "Answer": [
    {
      "name": "example.com",
      "type": "A",
      "TTL": 3599,
      "data": "93.184.216.34"
    }
  ]
}
```

---

## Performance Tips

1. **Batch Queries**: Use batch mode for multiple lookups
2. **Connection Reuse**: Keep client open for multiple queries
3. **Timeouts**: Increase timeout for slow networks
4. **Concurrency**: Use batch mode with higher `max_concurrent` values

---

## Troubleshooting

### Connection Refused
```bash
# Check if server is running
nc -zv localhost 50052

# Verify server logs
tail -f /var/log/squawk/dns-server.log
```

### Authentication Failed
```bash
# Verify token
echo $SQUAWK_AUTH_TOKEN

# Check server config
cat /etc/squawk/config.yaml
```

### Slow Queries
```bash
# Check network latency
ping server-host

# Use verbose mode
python bins/client.py -d example.com -s grpc://localhost:50052 -v
```

---

## Common Commands

| Task | Python | Go |
|------|--------|-----|
| Single query | `python bins/client.py -d example.com` | `./squawk-dns-client -d example.com` |
| Batch query | `python bins/client.py -b file.txt` | `./squawk-dns-client -b file.txt` |
| With token | `... -a token` | `... -a token` |
| JSON output | `... -j` | `... -j` |
| Verbose | `... -v` | `... -v` |
| Check server | `python bins/systray.py` | N/A |

---

## Protocol Comparison

| Feature | gRPC | REST |
|---------|------|------|
| Performance | Fast | Good |
| Batch Queries | Native | Sequential |
| Streaming | Yes | No |
| Setup | Simple | Simple |
| Debugging | gRPCurl | curl |
| Firewall Friendly | HTTP/2 | HTTP/1.1 |

---

## Next Steps

1. Review examples:
   - Python: `/dns-client/examples/query_example.py`
   - Go: `/dns-client-go/examples/query/main.go`

2. Configure authentication:
   - Set `SQUAWK_AUTH_TOKEN` environment variable
   - Or use `-a token` flag

3. Test connectivity:
   ```bash
   # Python
   python bins/client.py -d example.com -s grpc://localhost:50052 -v

   # Go
   ./squawk-dns-client -d example.com -s grpc://localhost:50052 -v
   ```

4. Integrate into your application using the client libraries

---

## Documentation

For detailed information, see:
- `/DNS_CLIENT_GRPC_UPDATE.md` - Comprehensive guide
- `protos/dns_query_service.proto` - Protocol definition
- `examples/` directories - Working code examples

---
