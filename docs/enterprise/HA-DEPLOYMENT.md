# High Availability Deployment

## Service Replicas

Current Helm defaults (chart values.yaml):

| Service | Replicas | Persistence | Notes |
|---------|----------|-------------|-------|
| **manager** | 1 | PostgreSQL external | Singleton; single leader only |
| **dns-server** | 2 | Valkey cache | Stateless; scale horizontally |
| **dhcp-server** | 3 | Valkey state | Stateless; replicas share pool |
| **ntp-server** | 3 | None | Stateless |
| **valkey** | 1 | In-memory | Cache; ephemeral |

**Production recommendation:**
- `dns-server`: 3+ replicas minimum for quorum-based failover
- `dhcp-server`: 3+ replicas (odd number prevents split-brain on DHCP state)
- `ntp-server`: 3+ replicas (NTP requires 3+ peers for clock discipline)
- `manager`: 1 (scaling to 2+ requires distributed consensus, not yet implemented)
- `valkey`: 1 or 3 (if high cache hit rate expected, use Valkey Cluster for HA)

## Pod Disruption Budget (PDB)

PDB support is coming in a parallel chart update. Use template below to enforce minimum availability during cluster maintenance:

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: dns-server-pdb
  namespace: squawk
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app.kubernetes.io/name: squawk
      app.kubernetes.io/component: dns-server
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: dhcp-server-pdb
  namespace: squawk
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app.kubernetes.io/name: squawk
      app.kubernetes.io/component: dhcp-server
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: ntp-server-pdb
  namespace: squawk
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app.kubernetes.io/name: squawk
      app.kubernetes.io/component: ntp-server
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: valkey-pdb
  namespace: squawk
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: squawk
      app.kubernetes.io/component: cache
```

## Horizontal Pod Autoscaler (HPA)

HPA support is coming in a parallel chart update. Use template for CPU/memory-driven scaling:

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: dns-server-hpa
  namespace: squawk
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: dns-server
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 75
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 50
        periodSeconds: 15
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 25
        periodSeconds: 60
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: dhcp-server-hpa
  namespace: squawk
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: dhcp-server
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 75
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 45
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
```

## DNS Data-Plane Horizontal Scaling

### Multiple Replicas Behind Service

All dns-server replicas expose the same `/dns-query` endpoint on port 8080. K8s Service round-robins:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: dns-server
  namespace: squawk
spec:
  type: ClusterIP
  sessionAffinity: None  # Round-robin load balancing
  ports:
  - name: doh
    port: 8080
    targetPort: 8080
    protocol: TCP
  selector:
    app.kubernetes.io/name: squawk
    app.kubernetes.io/component: dns-server
```

Clients (k8s-dns, dns-client, external) query `http://dns-server.squawk.svc.cluster.local:8080/dns-query`.

**Query behavior:**
- Each replica caches independently (no shared cache between dns-server pods)
- Cache hit rate ~60-80% per pod on typical workloads
- On replica failure, in-flight queries retry to surviving replicas within seconds

### Multi-Region / Anycast DoH Deployment

For geographic distribution, deploy Squawk to multiple K8s clusters with shared upstream PostgreSQL:

```
┌─────────────────────────────────────────────────────┐
│ Cluster A (us-west-2)                               │
│  dns-server (3x)  ──────────────────┐                │
│  dhcp-server (3x) ────────────────┐  │                │
│  manager (1x)  ────────────┐       │  │                │
└──────────────────────┬──────────────┼──┼────────────────┘
                       │      ↓       ↓  ↓
┌──────────────────────┼──────────────────────────────┐
│ PostgreSQL (managed service, multi-AZ replication)  │
│ - eu-west-1 primary                                 │
│ - us-west-2 replica (read-only for dns-server)      │
└──────────────────────────────────────────────────────┘
                       ↑
┌──────────────────────┼──────────────────────────────┐
│ Cluster B (eu-west-1)                                │
│  dns-server (3x)  ───────────────┐                   │
│  dhcp-server (3x) ──────────────┐ │                   │
│  manager (1x) ────────────┐      │ │                   │
└──────────────────────┬────────────┼─────────────────────┘
                       └─→ Primary DB
```

**Anycast ingress:**
- Both regions serve DoH at `dns.example.com` (separate Ingress per cluster)
- Client resolves `dns.example.com` → nearest region via Geo-DNS or GeoIP-based Anycast
- Each region's dns-server replicas share a local Valkey cache
- DHCP state: Replicas in both regions can serve (active/active) or primary region only (active/passive)

**Manager deployment:**
- Primary cluster (eu-west-1): Active manager, writes to PostgreSQL primary
- Secondary cluster (us-west-2): Standby manager (optional, not serving requests) or offline

**Failover:**
- If primary region fails, secondary becomes primary (update manager, DNS entries)
- PostgreSQL failover: managed by RDS/Cloud SQL multi-AZ replication or external tool (e.g., Patroni)

## NTP HA Notes

NTP (SNTP in Squawk) runs on port 11123 (UDP). For HA:

- **3+ replicas minimum** (NTP clock discipline requires 3+ sources)
- Deploy to separate nodes if possible (`podAntiAffinity: preferred`)
- Each replica independently serves time (no shared state)
- Clients (time.example.com) resolves to all 3 replicas via SRV records or simple A record + client-side retry

```yaml
apiVersion: v1
kind: Service
metadata:
  name: ntp-server
  namespace: squawk
spec:
  type: ClusterIP
  clusterIP: None  # Headless for direct pod access
  ports:
  - name: ntp
    port: 11123
    targetPort: 11123
    protocol: UDP
  selector:
    app.kubernetes.io/name: squawk
    app.kubernetes.io/component: ntp-server
---
apiVersion: policy/v1
kind: PodAntiAffinity
metadata:
  name: ntp-server-anti-affinity
spec:
  affinity:
    podAntiAffinity:
      preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchExpressions:
            - key: app.kubernetes.io/component
              operator: In
              values: [ntp-server]
          topologyKey: kubernetes.io/hostname
```

## DHCP HA: Lease State & Failover

DHCP is stateful: client leases must persist across failover to avoid duplicate IPs.

**Active/Passive (single primary):**
- One DHCP replica (pod) serves all clients
- Others standby
- Shared Valkey stores lease state
- On primary failure: Secondary pod takes over, queries Valkey, resumes serving leases
- **Loss of Valkey = loss of lease state** (client conflict recovery via DHCP conflict detection)

**Lease recovery after Valkey loss:**
- Clients retry DHCP DISCOVER (no lease = new assignment)
- Old lease binding times out (default ~24h based on LEASE_TIME env var)
- Duplicate prevention: DHCP servers check for conflicts via ARP

**Active/Active (not currently supported):**
- Multiple DHCP replicas assign from disjoint pool ranges
- Pool subnet partitioning (Replica A: 192.168.1.100-150, Replica B: 192.168.1.151-200)
- Requires non-overlapping pool config per replica
- **Current deployment uses shared pool (Active/Passive recommended)**

**Recommendation:** Deploy 3 DHCP replicas with `minAvailable: 1` PDB. Valkey must be highly available (Valkey Cluster or Redis Cluster if planning Active/Active).

## Valkey HA (Optional)

For production high-cache-hit workloads, upgrade Valkey to a cluster:

```yaml
# Enable via chart update (parallel branch)
valkey:
  cluster:
    enabled: true
    nodes: 6  # 3 masters + 3 replicas
  resources:
    requests:
      cpu: 200m
      memory: 256Mi
    limits:
      cpu: 1000m
      memory: 2Gi
```

Alternative: Managed Redis/Valkey (AWS ElastiCache, GCP Memorystore, Azure Cache) auto-handles HA.

