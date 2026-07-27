# Enterprise Operations Guides

Comprehensive guides for operating Squawk in production environments.

## Contents

### [DR-BACKUP.md](DR-BACKUP.md) — Disaster Recovery & Backup
- PostgreSQL backup via `pg_dump` and restoration
- Kubernetes CronJob backup manifest with retention policies
- Valkey persistence stance (ephemeral cache, no persistence needed)
- RPO/RTO table per component (tokens, zones, cache)
- Monthly restore-drill checklist and off-site archival

### [HA-DEPLOYMENT.md](HA-DEPLOYMENT.md) — High Availability Deployment
- Replica counts per service (dns-server 3+, dhcp-server 3+, ntp-server 3+)
- Pod Disruption Budget (PDB) and Horizontal Pod Autoscaler (HPA) templates
- DNS data-plane horizontal scaling behind K8s Service
- Multi-region/anycast DoH deployment patterns with shared PostgreSQL
- NTP HA (3+ replicas required for clock discipline)
- DHCP HA caveats: active/passive recommended, lease state persistence via Valkey
- Valkey cluster upgrade path for high cache-hit workloads

### [SUPPLY-CHAIN-VERIFICATION.md](SUPPLY-CHAIN-VERIFICATION.md) — Supply Chain Verification
- Image signing details: cosign keyless + GitHub OIDC
- Verifying image signatures with `cosign verify`
- Inspecting SBOM attestations and scanning for vulnerabilities
- Kyverno ClusterPolicy template for admission-time signature enforcement
- Dependency scanning with Grype, Snyk, OSV
- Monthly supply chain audit checklist

### [COREDNS-INTEGRATION.md](COREDNS-INTEGRATION.md) — CoreDNS Integration
- Squawk as an upstream resolver for in-cluster DNS
- CoreDNS ConfigMap examples (Option A: via dns-client sidecar, Option B: direct DoH)
- JWT authentication setup for CoreDNS → Squawk forwarding
- Stub domain configuration (single domain forwarding)
- Port reference table (DoH 8080, UDP 5300, API 5000)
- Troubleshooting guide: resolution failures, token expiry, latency

## Quick Start

For a production deployment:

1. **Backup:** Set up the CronJob from [DR-BACKUP.md](DR-BACKUP.md) immediately
2. **HA:** Deploy 3+ replicas per service using PDB templates in [HA-DEPLOYMENT.md](HA-DEPLOYMENT.md)
3. **Verification:** Enforce image signatures via Kyverno policy in [SUPPLY-CHAIN-VERIFICATION.md](SUPPLY-CHAIN-VERIFICATION.md)
4. **Integration:** If using CoreDNS, forward via [COREDNS-INTEGRATION.md](COREDNS-INTEGRATION.md)

## Environments

These guides apply to:
- **Beta** (`dal2-beta`): Test HA/DR procedures
- **Gamma** (`dal2-gamma`): Staging supply chain verification
- **Production** (`{repo}-prod`): Full enforcement of all practices

## See Also

- [docs/ARCHITECTURE.md](../ARCHITECTURE.md) — System architecture and design
- [docs/DEVELOPMENT.md](../DEVELOPMENT.md) — Local development setup
- [docs/TESTING.md](../TESTING.md) — Testing practices
