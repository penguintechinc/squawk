# Squawk Kubernetes Manifests

Kubernetes deployment manifests for Squawk DNS platform targeting the dal2-beta cluster.

## Architecture

- **Namespace**: squawk
- **Components**:
  - DNS Server (2 replicas) - Core DNS/DoH service
  - Flask API (2 replicas) - Management API
  - WebUI (2 replicas) - React frontend
  - Valkey (1 replica) - Redis-compatible cache

## Prerequisites

1. Kubernetes cluster access (dal2-beta)
2. kubectl configured
3. Pre-existing TLS secret: `penguintech-wildcard-tls` in squawk namespace
4. NGINX Ingress Controller installed
5. Docker images built and available:
   - `squawk-dns-server:latest`
   - `squawk-flask-api:latest`
   - `squawk-dns-webui:latest`

## Deployment

### Quick Deploy

Apply all manifests in order:

```bash
kubectl apply -f namespace.yaml
kubectl apply -f valkey-deployment.yaml
kubectl apply -f valkey-service.yaml
kubectl apply -f dns-server-deployment.yaml
kubectl apply -f dns-server-service.yaml
kubectl apply -f flask-api-deployment.yaml
kubectl apply -f flask-api-service.yaml
kubectl apply -f webui-deployment.yaml
kubectl apply -f webui-service.yaml
kubectl apply -f ingress.yaml
```

Or apply all at once:

```bash
kubectl apply -f .
```

### Verify Deployment

```bash
# Check namespace
kubectl get namespace squawk

# Check all pods
kubectl get pods -n squawk

# Check services
kubectl get svc -n squawk

# Check ingress
kubectl get ingress -n squawk

# View pod logs
kubectl logs -n squawk -l app.kubernetes.io/component=dns-server
kubectl logs -n squawk -l app.kubernetes.io/component=api
kubectl logs -n squawk -l app.kubernetes.io/component=frontend
```

## Configuration

### Environment Variables

**DNS Server:**
- `VALKEY_HOST`: valkey
- `VALKEY_PORT`: 6379
- `LOG_LEVEL`: info
- `DNS_PORT`: 53
- `DOH_PORT`: 8080

**Flask API:**
- `DATABASE_URL`: sqlite:////data/squawk.db
- `SECRET_KEY`: From secret (optional)
- `LOG_LEVEL`: info
- `FLASK_ENV`: production
- `VALKEY_HOST`: valkey
- `VALKEY_PORT`: 6379

**WebUI:**
- `LOG_LEVEL`: info
- `API_URL`: http://flask-api:8000
- `NODE_ENV`: production

### Resource Limits

| Component | CPU Request | CPU Limit | Memory Request | Memory Limit |
|-----------|-------------|-----------|----------------|--------------|
| DNS Server | 200m | 1000m | 256Mi | 1Gi |
| Flask API | 200m | 1000m | 256Mi | 1Gi |
| WebUI | 100m | 500m | 128Mi | 512Mi |
| Valkey | 100m | 500m | 128Mi | 512Mi |

## Ingress Routes

Host: `squawk.penguintech.io`

- `/` → WebUI (port 3000)
- `/api/v1/*` → Flask API (port 8000)
- `/dns-query` → DNS Server DoH (port 8080)
- `/health` → DNS Server health (port 8080)

TLS enabled with `penguintech-wildcard-tls` certificate.

## Scaling

Scale deployments as needed:

```bash
# Scale DNS servers
kubectl scale deployment dns-server -n squawk --replicas=3

# Scale API
kubectl scale deployment flask-api -n squawk --replicas=3

# Scale WebUI
kubectl scale deployment webui -n squawk --replicas=3
```

## Secrets

Create the Flask API secret if needed:

```bash
kubectl create secret generic squawk-secrets \
  -n squawk \
  --from-literal=secret-key=$(openssl rand -base64 32)
```

## Health Checks

All deployments include:
- **Liveness Probes**: Detect and restart unhealthy containers
- **Readiness Probes**: Control traffic routing to ready pods

Health endpoints:
- DNS Server: `http://dns-server:8080/health`
- Flask API: `http://flask-api:8000/api/v1/health`
- WebUI: `http://webui:3000/`

## Rolling Updates

All deployments use RollingUpdate strategy:
- `maxUnavailable: 0` - No downtime during updates
- `maxSurge: 1` - One extra pod during rollout

Update image:

```bash
kubectl set image deployment/dns-server \
  dns-server=squawk-dns-server:v1.0.0 \
  -n squawk
```

## Troubleshooting

### Pod not starting

```bash
# Check pod events
kubectl describe pod <pod-name> -n squawk

# View logs
kubectl logs <pod-name> -n squawk

# Get previous logs if crashed
kubectl logs <pod-name> -n squawk --previous
```

### Service connectivity issues

```bash
# Test service from another pod
kubectl run -it --rm debug --image=busybox --restart=Never -n squawk -- sh
# Inside pod:
wget -O- http://flask-api:8000/api/v1/health
```

### Ingress not working

```bash
# Check ingress status
kubectl describe ingress squawk -n squawk

# Verify TLS secret exists
kubectl get secret penguintech-wildcard-tls -n squawk

# Check NGINX ingress logs
kubectl logs -n ingress-nginx -l app.kubernetes.io/component=controller
```

## Cleanup

Remove all resources:

```bash
kubectl delete -f .
kubectl delete namespace squawk
```

Or remove selectively:

```bash
kubectl delete ingress squawk -n squawk
kubectl delete deployment --all -n squawk
kubectl delete service --all -n squawk
```
