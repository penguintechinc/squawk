# Supply Chain Verification

Squawk images are signed with cosign using GitHub OIDC (keyless) and include SPDX SBOM attestations. This guide covers verification and enforcement.

## Image Signing

Every Squawk image pushed to ghcr.io/penguintechinc/squawk is signed by CI/CD (see `.github/workflows/push.yml`):

```bash
# CI signing (automated)
cosign sign --yes ghcr.io/penguintechinc/squawk@sha256:<digest>
cosign attest --yes --predicate sbom-server.spdx.json --type spdxjson \
  ghcr.io/penguintechinc/squawk@sha256:<digest>
```

**Signing identity:** GitHub Actions workflow in penguintechinc/squawk repository, using the OIDC token issued by GitHub.

## Verifying Image Signatures

### Prerequisites

```bash
# Install cosign
curl -sLo /usr/local/bin/cosign https://github.com/sigstore/cosign/releases/download/v2.x.x/cosign-linux-amd64
chmod +x /usr/local/bin/cosign

# Install syft (for SBOM inspection)
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
```

### Verify Signature

```bash
# Verify signature using GitHub OIDC identity
cosign verify \
  --certificate-identity https://github.com/penguintechinc/squawk/.github/workflows/push.yml@refs/heads/v1.0.x \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/penguintechinc/squawk:v1.0.0

# Output (signature valid)
Verification successful!
```

**Certificate identity breakdown:**
- **Workflow file:** `.github/workflows/push.yml` (exact workflow signing the image)
- **Branch/ref:** `refs/heads/v1.0.x` (release branch) or `refs/heads/main` (gamma builds)
- **OIDC issuer:** GitHub Actions token issuer

### Inspect SBOM Attestation

```bash
# Download and inspect SBOM
cosign download attestation \
  --attestation-type spdxjson \
  ghcr.io/penguintechinc/squawk:v1.0.0 > sbom.spdx.json

# Verify SBOM is signed
cosign verify-attestation \
  --certificate-identity https://github.com/penguintechinc/squawk/.github/workflows/push.yml@refs/heads/v1.0.x \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --attestation-type spdxjson \
  ghcr.io/penguintechinc/squawk:v1.0.0 | jq '.payload | @base64d | fromjson'

# Inspect SBOM contents (check dependencies, licenses)
syft /tmp/sbom.spdx.json
# Or parse raw SBOM:
jq '.components[] | "\(.name):\(.version)"' sbom.spdx.json
```

## Kyverno ClusterPolicy for Image Signature Verification

Deploy this Kyverno policy to enforce signature verification at admission time. Adapt the certificate identity and branch names for your deployment:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-squawk-image-signatures
spec:
  validationFailureAction: audit  # Change to 'enforce' once validated in your cluster
  webhookTimeoutSeconds: 30
  failurePolicy: fail
  rules:
  - name: check-squawk-signature
    match:
      resources:
        kinds:
        - Pod
        - Deployment
        - StatefulSet
        - DaemonSet
        - Job
        - CronJob
    verifyImages:
    - imageReferences:
      - ghcr.io/penguintechinc/squawk*
      - ghcr.io/penguintechinc/squawk-dns-client*
      - ghcr.io/penguintechinc/squawk-k8s-dns*
      attestations:
      - name: spdxjson
        attestationPattern: |
          (predicateType == "https://spdx.dev/Document/spdx-v2.3.json")
      - name: sbom-check
        conditions:
        - all:
          - key: "{{ attestation.spdxjson.components[].name }}"
            operator: AnyNotIn
            value:
            - vulnerable-dependency-name  # Add known bad dependencies here
      verifySignature:
        keyless:
          signatureFormat: cosign
          provider: github
          identities:
          - issuer: https://token.actions.githubusercontent.com
            subject: https://github.com/penguintechinc/squawk/.github/workflows/push.yml@refs/heads/v1.0.x
          - issuer: https://token.actions.githubusercontent.com
            subject: https://github.com/penguintechinc/squawk/.github/workflows/push.yml@refs/heads/main
      mutateDigest: true
      mutateImage: true
  - name: audit-unsigned
    match:
      resources:
        kinds:
        - Pod
    validate:
      message: "Unsigned Squawk images must be reviewed and tested before deployment"
      pattern:
        spec:
          containers:
          - image: ghcr.io/penguintechinc/squawk*
            |(image): '?@ ?# Image lacks signature verification'
---
apiVersion: v1
kind: Namespace
metadata:
  name: squawk
  labels:
    # Label to enable policy (optional)
    pod-security.kubernetes.io/enforce: baseline
---
# Bind policy to squawk namespace (optional; by default applies cluster-wide)
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-squawk-image-signatures-ns-bound
spec:
  validationFailureAction: audit
  rules:
  - name: check-squawk-signature-ns
    match:
      resources:
        kinds:
        - Pod
        namespaceSelector:
          matchLabels:
            pod-security.kubernetes.io/enforce: baseline
    verifyImages:
    - imageReferences:
      - ghcr.io/penguintechinc/squawk*
      verifySignature:
        keyless:
          signatureFormat: cosign
          provider: github
          identities:
          - issuer: https://token.actions.githubusercontent.com
            subject: https://github.com/penguintechinc/squawk/.github/workflows/push.yml@refs/heads/v*.*.x
```

## Deployment Steps

1. **Install Kyverno** (if not already present):

```bash
kubectl apply -f https://github.com/kyverno/kyverno/releases/download/v1.12.0/install.yaml
```

2. **Deploy the policy**:

```bash
kubectl apply -f verify-squawk-images-policy.yaml
```

3. **Validate policy works**:

```bash
# Test with an unsigned image (should audit/fail)
kubectl run test-unsigned --image=ghcr.io/penguintechinc/squawk:latest -n squawk
# Verify event logged:
kubectl describe pod test-unsigned -n squawk | grep -i kyverno

# Clean up test
kubectl delete pod test-unsigned -n squawk
```

4. **Switch to enforcement** (after validation):

```bash
kubectl patch clusterpolicy verify-squawk-image-signatures \
  --type='json' -p='[{"op": "replace", "path": "/spec/validationFailureAction", "value":"enforce"}]'
```

## SBOM Dependency Scanning

Squawk's SBOM includes all dependencies (Go modules, system libraries). Integrate with vulnerability scanners:

```bash
# Using Anchore Grype (local scanning)
grype sbom.spdx.json --fail-on high

# Using Snyk (cloud-based)
snyk sbom --file sbom.spdx.json

# Using OSV (Google open-source scanner)
osv-scanner --sbom sbom.spdx.json
```

Add to your CI/CD:

```yaml
# GitHub Actions example
- name: Scan SBOM for vulnerabilities
  uses: anchore/scan-action@v4
  with:
    sbom: sbom.spdx.json
    fail-build: true
    severity-cutoff: high
```

## Policies & Audit Log

- **All unsigned images**: Logged as audit events in Kyverno; optionally blocked
- **Signed images from unknown workflows**: Blocked at admission
- **Signed images with vulnerable dependencies (SBOM check)**: Audit or block based on policy
- **Audit log location**: `kubectl logs -n kyverno deployment/kyverno`

## Testing Supply Chain

**Monthly:** Verify signature chain end-to-end:

1. Pull latest release image
2. Verify signature: `cosign verify --certificate-identity=... ghcr.io/penguintechinc/squawk:v1.0.X`
3. Download SBOM: `cosign download attestation --attestation-type spdxjson ghcr.io/...`
4. Scan SBOM: `grype sbom.spdx.json --fail-on high`
5. Deploy to staging: Verify Kyverno allows it (signature + SBOM check pass)
6. Document findings
