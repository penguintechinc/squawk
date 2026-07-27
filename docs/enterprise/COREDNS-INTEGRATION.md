# CoreDNS Integration

## Squawk as Upstream DoH Resolver

Squawk dns-server exposes a DNS-over-HTTPS endpoint that CoreDNS can forward queries to. This allows in-cluster DNS (CoreDNS) to offload resolution to Squawk with authentication and access control.

## Squawk Service & Ports

From the Helm chart (k8s/helm/squawk/templates/dns-server-service.yml):

```yaml
apiVersion: v1
kind: Service
metadata:
  name: dns-server
  namespace: squawk
spec:
  type: ClusterIP
  ports:
  - name: doh
    port: 8080
    targetPort: 8080
    protocol: TCP
```

**Endpoint:** `http://dns-server.squawk.svc.cluster.local:8080/dns-query` (DoH/HTTP endpoint)

**Note:** Squawk currently exposes DoH (HTTP-based DNS) only. Standard UDP port 53 DNS is NOT available in the chart deployment. CoreDNS can forward via the DoH endpoint or use squawk-dns-client (k8s-dns sidecar) for UDP forwarding.

## CoreDNS Configuration

### Option A: Forward via squawk-dns-client (K8s DNS Sidecar)

Squawk includes a k8s-dns component that integrates with CoreDNS:

```yaml
# CoreDNS ConfigMap
apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns
  namespace: kube-system
data:
  Corefile: |
    .:53 {
      errors
      health
      ready
      kubernetes cluster.local in-addr.arpa ip6.arpa {
        pods insecure
        fallthrough in-addr.arpa ip6.arpa
      }
      # Forward to Squawk k8s-dns (listens on 5300)
      forward . dns-client.squawk.svc.cluster.local:5300 {
        policy round_robin
        max_fails 2
        health_uri /health
        health_port 5300
      }
      prometheus :9153
      loop
      reload
    }
```

**How it works:**
1. CoreDNS forwards unknown domains to `dns-client.squawk.svc.cluster.local:5300`
2. squawk-dns-client (K8s DNS sidecar) queries squawk dns-server via HTTP
3. dns-server authenticates via JWT (Bearer token in HTTP Authorization header)
4. Response cached in Valkey and returned to CoreDNS

### Option B: Direct DoH Forward to squawk dns-server

If CoreDNS has DoH support (newer versions), forward directly:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns
  namespace: kube-system
data:
  Corefile: |
    .:53 {
      errors
      health
      ready
      kubernetes cluster.local in-addr.arpa ip6.arpa {
        pods insecure
        fallthrough in-addr.arpa ip6.arpa
      }
      # Forward via DoH (requires CoreDNS with DoH plugin)
      forward . https://dns-server.squawk.svc.cluster.local:8080/dns-query {
        policy round_robin
        max_fails 2
        # Bearer token for authentication
        header Authorization "Bearer <JWT-token>"
      }
      prometheus :9153
      loop
      reload
    }
```

**Note:** As of CoreDNS v1.10, DoH forwarding may require additional plugins or a proxy sidecar.

## JWT Authentication Setup

Both options require a valid JWT token from the Squawk manager:

1. **Issue token via manager:**

```bash
# Request token from Squawk manager API (port 5000)
curl -X POST http://manager.squawk.svc.cluster.local:5000/api/v1/tokens \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin-token>" \
  -d '{"name": "coredns-upstream", "scopes": ["dns:query"]}'

# Response:
# {"token": "eyJhbGc...", "created": "2025-01-15T..."}
```

2. **Store token in K8s Secret:**

```bash
kubectl create secret generic squawk-dns-token \
  -n kube-system \
  --from-literal=token=eyJhbGc...
```

3. **Reference in CoreDNS ConfigMap:**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns
  namespace: kube-system
data:
  Corefile: |
    .:53 {
      forward . dns-client.squawk.svc.cluster.local:5300 {
        policy round_robin
      }
    }
```

Or for direct DoH:

```yaml
# Update deployment to mount secret and inject Bearer token
# (Requires wrapper script or sidecar to add header)
```

## Deployment Example

### Step 1: Deploy Squawk

```bash
helm install squawk ./k8s/helm/squawk \
  --namespace squawk --create-namespace \
  --values k8s/helm/squawk/values.yaml \
  --values k8s/helm/squawk/production.yml
```

### Step 2: Issue CoreDNS JWT Token

```bash
ADMIN_TOKEN=$(kubectl get secret -n squawk manager-admin-token -o jsonpath='{.data.token}' | base64 -d)

COREDNS_TOKEN=$(curl -s -X POST http://manager.squawk.svc.cluster.local:5000/api/v1/tokens \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -d '{"name": "coredns", "scopes": ["dns:query"], "tenant_id": "default"}' | jq -r .token)

echo $COREDNS_TOKEN
```

### Step 3: Store in CoreDNS Namespace

```bash
kubectl create secret generic squawk-dns-token \
  -n kube-system \
  --from-literal=token=${COREDNS_TOKEN}
```

### Step 4: Update CoreDNS ConfigMap

```bash
kubectl patch configmap coredns -n kube-system --type merge -p '{
  "data": {
    "Corefile": ".:53 {\n  errors\n  health\n  ready\n  kubernetes cluster.local in-addr.arpa ip6.arpa {\n    pods insecure\n    fallthrough in-addr.arpa ip6.arpa\n  }\n  forward . dns-client.squawk.svc.cluster.local:5300 {\n    policy round_robin\n    max_fails 2\n  }\n  prometheus :9153\n  loop\n  reload\n}\n"
  }
}'
```

### Step 5: Verify DNS Resolution

```bash
# Test from any pod
kubectl run -it --rm test-dns --image=busybox --restart=Never -- \
  nslookup google.com

# Watch logs
kubectl logs -n squawk deployment/dns-server -f

# Check cache hit rate
curl http://dns-server.squawk.svc.cluster.local:8080/metrics | grep cache_hits
```

## Stub Domain Configuration (Single Domain)

If forwarding only specific domains to Squawk (not all upstream):

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns
  namespace: kube-system
data:
  Corefile: |
    .:53 {
      errors
      health
      ready
      kubernetes cluster.local in-addr.arpa ip6.arpa {
        pods insecure
        fallthrough in-addr.arpa ip6.arpa
      }
      # Default upstream (Google)
      forward . 8.8.8.8:53 8.8.4.4:53
      prometheus :9153
    }
    
    # Stub domain: special.example.com -> Squawk only
    special.example.com:53 {
      errors
      forward . dns-client.squawk.svc.cluster.local:5300 {
        policy round_robin
      }
    }
```

## Port Summary

| Service | Port | Protocol | Purpose |
|---------|------|----------|---------|
| **dns-server** | 8080 | HTTP | DoH endpoint (`/dns-query`) |
| **dns-client** | 5300 | UDP | Traditional DNS forwarding |
| **manager** | 5000 | HTTP | Token issuance, admin API |
| **manager** | 50051 | gRPC | Zone updates (internal) |

## Troubleshooting

### DNS Resolution Fails

```bash
# Check CoreDNS logs
kubectl logs -n kube-system deployment/coredns

# Verify Squawk dns-server is running
kubectl get pods -n squawk
kubectl logs -n squawk deployment/dns-server

# Test direct connection
kubectl run -it --rm test-conn --image=curlimages/curl --restart=Never -- \
  curl -v http://dns-server.squawk.svc.cluster.local:8080/health

# Check token validity
kubectl get secret -n kube-system squawk-dns-token -o jsonpath='{.data.token}' | base64 -d | jq .
```

### Token Expired / 401 Errors

```bash
# Reissue token
ADMIN_TOKEN=$(kubectl get secret -n squawk manager-admin-token -o jsonpath='{.data.token}' | base64 -d)

NEW_TOKEN=$(curl -s -X POST http://manager.squawk.svc.cluster.local:5000/api/v1/tokens \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name": "coredns", "scopes": ["dns:query"]}' | jq -r .token)

kubectl patch secret squawk-dns-token -n kube-system --type merge -p "{\"data\":{\"token\":\"$(echo $NEW_TOKEN | base64 -w0)\"}}"

# Restart CoreDNS to pick up new token
kubectl rollout restart deployment/coredns -n kube-system
```

### High Latency / Cache Misses

- Verify Valkey is running: `kubectl logs -n squawk deployment/valkey`
- Check dns-server replicas: `kubectl get pods -n squawk -l app.kubernetes.io/component=dns-server`
- Scale up dns-server if cache hit rate is low: `kubectl scale deployment dns-server -n squawk --replicas=5`

