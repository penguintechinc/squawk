# Squawk Kustomize Configuration

Kustomize-based deployment structure for Squawk DNS platform with environment-specific overlays.

## Directory Structure

```
k8s/kustomize/
├── base/                 # Base configuration referencing manifests
│   └── kustomization.yaml
├── overlays/
│   ├── alpha/           # Development environment
│   │   └── kustomization.yaml
│   └── beta/            # Staging/Production-like environment
│       └── kustomization.yaml
└── README.md
```

## Environments

### Base Configuration

The base kustomization references all manifest files from `k8s/manifests/`:
- Namespace, ConfigMap, Secret
- Deployments: DNS Server, Flask API, WebUI, DNS Client, Valkey
- Services and Ingress

**Location**: `k8s/kustomize/base/kustomization.yaml`

### Alpha Environment (Development)

**Namespace**: `squawk-alpha`

Configuration:
- DNS Server: 1 replica, local images (`squawk/dns-server:latest`), Never pull policy
- Flask API: 1 replica, local images, DEBUG enabled, development mode
- WebUI: 1 replica, local images
- DNS Client: 1 replica, local images
- Valkey: 1 replica, minimal resources

Log Level: `debug` for all services

**Location**: `k8s/kustomize/overlays/alpha/kustomization.yaml`

### Beta Environment (Production-like)

**Namespace**: `squawk-beta`

Configuration:
- DNS Server: 2 replicas, registry images (`registry-dal2.penguintech.io/squawk/dns-server:beta-latest`)
- Flask API: 2 replicas, registry images, production mode
- WebUI: 2 replicas, registry images
- DNS Client: 1 replica, registry images
- Valkey: 1 replica, standard resources

Log Level: `info` for all services
Image Pull Policy: `Always`

**Location**: `k8s/kustomize/overlays/beta/kustomization.yaml`

## Usage

### Build Manifests (Preview)

```bash
# Alpha environment
kustomize build k8s/kustomize/overlays/alpha > alpha-manifest.yaml

# Beta environment
kustomize build k8s/kustomize/overlays/beta > beta-manifest.yaml
```

### Deploy with Kustomize

```bash
# Alpha deployment
kubectl apply -k k8s/kustomize/overlays/alpha

# Beta deployment
kubectl apply -k k8s/kustomize/overlays/beta
```

### Deploy with Helm (Recommended)

Use the provided deploy script for a complete deployment pipeline:

```bash
# Full deployment with automatic image build and push
./scripts/deploy-beta.sh

# Deploy with custom tag
./scripts/deploy-beta.sh --tag beta-v1.2.3

# Build specific service only
./scripts/deploy-beta.sh --service flask-api

# Preview without deploying
./scripts/deploy-beta.sh --dry-run

# Rollback to previous release
./scripts/deploy-beta.sh --rollback

# Get help
./scripts/deploy-beta.sh --help
```

## Service Overview

### DNS Server
- **Name**: `dns-server`
- **Image**: `squawk/dns-server` (alpha) or `registry-dal2.penguintech.io/squawk/dns-server` (beta)
- **Ports**: 53 (DNS UDP/TCP), 8080 (DoH/API)
- **Health**: `/health` on port 8080

### Flask API
- **Name**: `flask-api`
- **Image**: `squawk/flask-api` (alpha) or `registry-dal2.penguintech.io/squawk/flask-api` (beta)
- **Port**: 8000
- **Health**: `/api/v1/health` on port 8000

### WebUI (React Frontend)
- **Name**: `webui`
- **Image**: `squawk/dns-webui` (alpha) or `registry-dal2.penguintech.io/squawk/dns-webui` (beta)
- **Port**: 3000
- **Health**: Root path `/`

### DNS Client
- **Name**: `dns-client`
- **Image**: `squawk/dns-client` (alpha) or `registry-dal2.penguintech.io/squawk/dns-client` (beta)
- **Port**: 5353 (DNS forwarder)
- **Capabilities**: NET_ADMIN (required)

### Valkey (Cache)
- **Name**: `valkey`
- **Image**: `valkey/valkey:latest`
- **Port**: 6379
- **Storage**: In-memory key-value cache

## Customization

### Modify Replica Counts

Edit the overlay's `replicas` section:

```yaml
replicas:
  - name: dns-server
    count: 3
  - name: flask-api
    count: 3
```

### Override Environment Variables

Edit the overlay's `patches` section to modify deployment environment variables:

```yaml
- op: add
  path: /spec/template/spec/containers/0/env/-
  value:
    name: NEW_VAR
    value: "new-value"
```

### Change Image Tags

Edit the overlay's `images` section:

```yaml
images:
  - name: squawk-dns-server
    newName: my-registry/squawk/dns-server
    newTag: custom-tag
```

## Deployment Flow

1. **Build Images** (optional):
   ```bash
   ./scripts/deploy-beta.sh
   ```

2. **Verify Manifests**:
   ```bash
   kustomize build k8s/kustomize/overlays/beta
   ```

3. **Deploy**:
   ```bash
   kubectl apply -k k8s/kustomize/overlays/beta
   ```

4. **Monitor**:
   ```bash
   kubectl get pods -n squawk-beta -w
   kubectl logs -f deployment/dns-server -n squawk-beta
   ```

## Requirements

- `kustomize` 5.0+
- `kubectl` 1.21+
- `helm` 3.0+ (for deploy script)
- `docker` (for image building)
- Kubernetes cluster with dal2-beta context
- Access to `registry-dal2.penguintech.io` (for beta)

## Troubleshooting

### Check Generated Manifests

```bash
# See what kustomize will apply
kustomize build k8s/kustomize/overlays/beta | less

# Validate manifests
kustomize build k8s/kustomize/overlays/beta | kubectl apply -f - --dry-run=client
```

### View Specific Resource

```bash
# Show only DNS server deployment
kustomize build k8s/kustomize/overlays/beta | kubectl get -f - -o yaml deployment/dns-server
```

### Patch Verification

```bash
# Build and grep for specific field
kustomize build k8s/kustomize/overlays/beta | grep -A5 "LOG_LEVEL"
```

## Documentation

- **Helm Chart**: See `k8s/helm/squawk/` for Helm-based deployments
- **Manifests**: See `k8s/manifests/` for raw Kubernetes manifests
- **Deploy Script**: See `scripts/deploy-beta.sh` for automated deployment

## See Also

- [Kustomize Official Documentation](https://kustomize.io/)
- [Kubernetes Overlays Pattern](https://kubernetes.io/docs/tasks/manage-kubernetes-objects/kustomization/)
- Helm values: `k8s/helm/squawk/values.yaml`, `values-alpha.yaml`, `values-beta.yaml`
