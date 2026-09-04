"""
Beta (dal2.penguintech.io K8s Cluster) Smoke Tests

Post-deployment verification against internal Kubernetes cluster.
Tests that services work correctly when deployed to K8s.

Includes:
- Service health checks
- Core page load verification
- Core API endpoint verification
- Authentication flow tests

Does NOT include:
- Build verification (already deployed)
- Load/stress tests (production-like environment)
- Database direct tests (access via APIs only)

Run with: make smoke-beta
"""
