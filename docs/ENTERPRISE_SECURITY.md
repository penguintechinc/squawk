# Enterprise Security & Deployment Hardening

This guide covers the enterprise-grade security controls added in the `v2.1.x`
line and how to operate them: asymmetric JWT signing, tenant isolation,
supply-chain verification (signed images + SBOM attestation), Kubernetes
runtime hardening, and automated dependency pinning.

> **Audience:** operators deploying Squawk to a production/enterprise cluster.
> For a feature overview see [System Architecture](ARCHITECTURE.md); for the
> auth model see [Token Management](TOKEN_MANAGEMENT.md).

---

## 1. Asymmetric JWT signing (ES256 default, RS256 fallback)

Squawk uses **asymmetric** JWT signing. The **manager** holds a private key and
signs user access/refresh tokens; every verifier service (**dns-server**,
**dhcp-server**, **ntp-server**) holds only the **public** key and verifies
signatures with it. A verifier can never mint a token — it has no private key.

- **Default algorithm:** `ES256` (ECDSA, NIST P-256) — small keys, fast verify.
- **Fallback algorithm:** `RS256` (RSA-2048) — use only where ES256 is not
  available in a client/toolchain.
- Verifiers accept **`ES256` and `RS256` only**. `HS256` and the `none` alg are
  rejected, which blocks the classic *public-key-as-HMAC* algorithm-confusion
  attack.

### Mandatory claims

Every user token carries and every verifier **requires**:

| Claim    | Meaning                                  | Enforced |
|----------|------------------------------------------|----------|
| `sub`    | Subject (user UUID)                      | signed   |
| `iss`    | Issuer — default `squawk-manager`        | verified |
| `aud`    | Audience — default `squawk`              | verified |
| `exp`    | Expiry                                   | required |
| `iat`    | Issued-at                                | required |
| `tenant` | Tenant id — **non-empty**                | required, fail-closed |
| `scope`  | Space-delimited `resource:action` scopes | authz    |

A token with a missing/empty `tenant`, a wrong `iss`/`aud`, an unexpected alg,
or a bad signature is rejected. If a verifier has **no public key configured**
it **fails closed** (denies everything) rather than falling through.

### Generate a keypair

Use the helper script (never commit the resulting `.pem` files — they are
gitignored):

```bash
# ES256 (default)
./scripts/gen-jwt-keys.sh --output /tmp/squawk-jwt-keys

# RS256 fallback, or both
./scripts/gen-jwt-keys.sh --rs256-only --output /tmp/squawk-jwt-keys
./scripts/gen-jwt-keys.sh --both        --output /tmp/squawk-jwt-keys
```

Produces `jwt_private_key_es256.pem` (manager only) and
`jwt_public_key_es256.pem` (manager + all verifiers).

### Configuration reference

| Env var                                 | Service         | Default          | Notes |
|-----------------------------------------|-----------------|------------------|-------|
| `JWT_ALGORITHM`                         | all             | `ES256`          | `ES256` or `RS256` |
| `JWT_ISSUER`                            | all             | `squawk-manager` | must match across services |
| `JWT_AUDIENCE`                          | all             | `squawk`         | must match across services |
| `JWT_PRIVATE_KEY` / `JWT_PRIVATE_KEY_FILE` | manager      | —                | signer only; PEM inline or file path |
| `JWT_PUBLIC_KEY` / `JWT_PUBLIC_KEY_FILE`   | all          | —                | verify key; PEM inline or file path |
| `JWT_PUBLIC_KEYS_DIR`                   | all (verifiers) | —                | directory of `.pem` files for key rotation overlap; loads all keys indexed by kid |
| `TENANT_ID`                             | manager         | `default`        | tenant stamped into issued tokens |
| `SECRET_KEY`                            | manager         | — (required in prod) | Flask session secret |

`*_FILE` variants win when set and are the recommended path in Kubernetes
(compatible with `readOnlyRootFilesystem: true`). Public keys are read at
**verification time**, so rotating the Secret does not require a pod restart.

In **ProductionConfig** the manager fails fast at startup if `SECRET_KEY`,
`JWT_PRIVATE_KEY`, or `JWT_PUBLIC_KEY` is unset — no insecure defaults ship.
Development/Test configs generate an **ephemeral** ES256 keypair in-process so
local runs work with zero setup (never use those in production).

### Kubernetes deployment

Both the Helm chart (`k8s/helm/squawk`) and the Kustomize base
(`k8s/kustomize/base`) reference a single Secret named **`squawk-jwt-keys`** with
two standardized data keys:

```bash
kubectl create secret generic squawk-jwt-keys -n squawk \
  --from-file=jwt-private-key=/tmp/squawk-jwt-keys/jwt_private_key_es256.pem \
  --from-file=jwt-public-key=/tmp/squawk-jwt-keys/jwt_public_key_es256.pem
```

- **Manager** mounts both keys at `/etc/squawk/jwt` and sets
  `JWT_PRIVATE_KEY_FILE` + `JWT_PUBLIC_KEY_FILE`.
- **Verifiers** mount the *same* Secret but use `items:` to project **only**
  `jwt-public-key` into the pod — the private key never enters a verifier pod.

Helm values (`k8s/helm/squawk/values.yaml`):

```yaml
jwt:
  secretName: squawk-jwt-keys
  algorithm: ES256
  issuer: squawk-manager
  audience: squawk
  mountPath: /etc/squawk/jwt
```

See `k8s/squawk-jwt-keys.example.yml` for the Secret shape (placeholder only —
for Sealed Secrets / External Secrets input). Prefer `kubectl create secret
--from-file` so raw key material never lands in a YAML file on disk.

### Key rotation

1. Generate a new keypair.
2. Update the `squawk-jwt-keys` Secret (`kubectl create secret ... --dry-run
   -o yaml | kubectl apply -f -`).
3. Verifiers pick up the new public key on next verification (no restart).
4. Restart the **manager** so it signs with the new private key.

For zero-downtime rotation, publish the new public key to verifiers first, then
cut the manager over to the new private key.

### Key rotation with kid (key ID) support

Every JWT issued by the manager includes a `kid` (key ID) header—the first 16 hex
characters of SHA-256 over the public key's DER-encoded SubjectPublicKeyInfo. This
enables seamless key rotation without flag-day cutoffs.

**Rotation runbook (graceful overlap):**

1. **Generate new keypair** and store in secrets manager (e.g., `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY`).
2. **Distribute new public key to verifiers** (dns-server, dhcp-server, ntp-server):
   - Place `.pem` files in a directory (e.g., `/etc/squawk/jwt-keys/`)
   - Set `JWT_PUBLIC_KEYS_DIR` env var to that directory
   - Or use `JWT_PUBLIC_KEY_FILE` for a single key (backward compat)
   - Verifiers load keys at startup and on environment changes (no restart needed if using env var override)
3. **Wait for propagation** (a few seconds; verifiers try all loaded keys for kid-less tokens)
4. **Switch manager to new private key**:
   - Update `JWT_PRIVATE_KEY` env var or secret
   - Restart manager (new tokens issued with new key's kid)
5. **Monitor for old-key rejections** (should be none if overlap window is long enough):
   - Old tokens still verifiable against old public key in `JWT_PUBLIC_KEYS_DIR`
   - New tokens carry new kid, matched to new public key
6. **Retire old public key** (after TTL of longest-lived token):
   - Remove old `.pem` from `JWT_PUBLIC_KEYS_DIR`
   - Restart verifiers if not using env-var reload

**Backward compatibility:** tokens without `kid` (legacy, pre-rotation) try all
loaded keys. This enables seamless upgrades — old tokens remain valid throughout
rotation and can coexist with kid-bearing tokens.

### AWS KMS signing (Enterprise tier)

**Pluggable signing providers** allow the manager to delegate private key operations
to an external Key Management Service (KMS) instead of storing keys on disk. The
**LocalPemProvider** (default) uses local PEM files; the **AwsKmsProvider** uses
AWS KMS for signing operations.

AWS KMS integration (Enterprise license tier required):
- Private key never touches disk or memory in plaintext
- Signing operations delegated to AWS KMS via the Sign API
- Public key fetched once at startup (cached)
- kid computed from the public key, enabling seamless rotation

**Configuration:**

| Env var                | Default   | Notes |
|------------------------|-----------|-------|
| `JWT_SIGNING_PROVIDER` | `local`   | `local` (PEM file) or `aws_kms` (AWS KMS) |
| `AWS_KMS_KEY_ID`       | —         | KMS key ARN or alias (required for aws_kms) |
| `AWS_DEFAULT_REGION`   | —         | AWS region (or use IRSA/credentials) |

**Selecting AWS KMS:**

```bash
# At manager startup:
export JWT_SIGNING_PROVIDER=aws_kms
export AWS_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012
# AWS credentials: use IRSA (Kubernetes) or env vars (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
```

Fail-fast behavior:
- Enterprise license not detected → ValueError at startup
- AWS_KMS_KEY_ID not set → ValueError at startup
- boto3 not installed → ImportError at provider init
- KMS connectivity loss → error logged, requests fail (not retried)

**Rotation with AwsKmsProvider:**

1. **Create a new KMS key** in AWS (or rotate the existing key's material via AWS KMS key rotation).
2. **Update DNS_PRIVATE_KEY_ID** to the new key ARN/alias.
3. **Restart the manager** — new tokens are signed with the new key's kid.
4. **Verifiers pick up the new kid** at token validation time (no restart needed if using `JWT_PUBLIC_KEYS_DIR`).
5. **Monitor for old-key rejections** — there should be none if the overlap window is long enough (all old tokens cached/replayable with old public key).
6. **Retire old key** — after TTL of longest-lived token passes, optionally schedule KMS key deletion.

The public key is fetched once at manager startup and cached in memory. To pick up a
new public key (e.g., after KMS key rotation), restart the manager.

Comparison: **LocalPemProvider** vs **AwsKmsProvider**

| Aspect | LocalPemProvider | AwsKmsProvider |
|--------|------------------|----------------|
| **Private key storage** | PEM file (disk/Secret) | AWS KMS (HSM-backed) |
| **Startup time** | Immediate | ~1-2s (KMS API call) |
| **Signing latency** | <1ms (in-process) | 100-200ms (KMS RPC) |
| **Key rotation** | Manual (update Secret) | AWS KMS key rotation or new key selection |
| **Audit trail** | App logs | AWS CloudTrail (KMS Sign calls) |
| **License** | Any tier | Enterprise only |

### Deployment-domain tokens

Long-lived **deployment-domain** tokens (used by the client-config pull flow) are
signed with the *same* asymmetric scheme — the manager's private key (ES256/RS256),
standard `iat`/`exp` claims, and `iss`/`aud`. They are verified with the public key
plus a database cross-check; HS256/none are rejected.

> **Upgrade note:** deployment-domain tokens minted before `v2.1.x` were HS256.
> After upgrading, roll each domain's token over (Domain-Admin `rollover_jwt`
> permission / `rollover_domain_jwt`) to re-issue it under the asymmetric key.
> This also fixes a latent multi-replica bug where a per-process random secret
> made tokens unverifiable across manager replicas/restarts.

### Refresh-token rotation and revocation

Refresh tokens are **single-use**: every call to `/api/v1/auth/refresh` revokes
the presented token (by its `jti`) and issues a new access + refresh pair —
reuse of a rotated token returns 401, which also surfaces token theft (a stolen
token dies the moment either party refreshes). Logout (`/api/v1/auth/logout`
with the `refreshToken` in the body) revokes the refresh token server-side, so
it can no longer mint access tokens; the 15-minute access token simply ages
out. Revocations live in the `revoked_token` denylist (Alembic `007`); rows for
already-expired tokens are purged opportunistically.

> **Upgrade note:** refresh tokens minted before `v2.1.x` rotation carry no
> `jti` and are no longer accepted — users re-login once after upgrade.

### API response hygiene

- **Security headers on every response** (including errors): `X-Content-Type-
  Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy:
  default-src 'none'; frame-ancestors 'none'`, `Referrer-Policy: no-referrer`,
  and HSTS (`max-age=31536000; includeSubDomains`).
- **No internal detail in error responses** — exception text (paths, DB
  errors) is logged server-side with full tracebacks; clients receive generic
  messages only.

### Scope-based authorization (roles are scope bundles)

Authorization decisions are made on **scopes only** — never role names. A user's
role is a convenience bundle that the manager **expands into concrete
`resource:action` scopes at token issuance**, emitting them in the token's
`scope` claim. Middleware checks the `scope` claim; `global_role`/`team_roles`
remain on the token for audit and per-team membership checks.

| Global role  | Scope bundle (summary)                                             |
|--------------|-------------------------------------------------------------------|
| SystemAdmin  | every `*:write` / `*:admin` scope + `admin:super` + all `*:read`   |
| OrgAdmin     | `servers:write` `teams:write` `time:write` `dhcp:write` + reads    |
| UserManager  | `users:write` + reads                                             |
| Viewer       | `*:read` only                                                     |

Endpoints declare the scope they need (e.g. `@requires_scope('servers:write')`);
the super-admin bypass for team/zone access checks the `admin:super` scope, not
the `SystemAdmin` role name. Bundle definitions live in one place
(`app/services/scopes.py`), so entitlements are auditable and adjustable
centrally.

---

## 2. Tenant isolation

Every token must carry a non-empty `tenant` claim; verifiers reject tokens
without one (fail-closed). The manager stamps `TENANT_ID` (default `default`)
into every token it issues. This is the foundation for multi-tenant deployments —
all downstream authorization and data access is expected to be scoped to the
token's tenant. Single-tenant deployments simply run with `TENANT_ID=default`.

> **Roadmap:** per-tenant data partitioning (an `org`/tenant column on
> `auth_user` and tenant-scoped queries) is tracked as a follow-up. Today the
> claim is issued, transported, and required end-to-end.

---

## 3. Supply-chain: signed images + SBOM attestation

Release images are **keyless-signed** with [cosign](https://docs.sigstore.dev/)
(Sigstore / GitHub OIDC — no long-lived signing keys) and ship an **SBOM**
(SPDX-JSON via Syft) attached as a cosign attestation. Signing targets the
**multi-arch image index digest**, so the signature covers every architecture.

Signed on release: `dns-server`, `dhcp-server`, `ntp-server`, the Python
dns-client, and the Go `squawk-dns-client`.

### Verify a signature

```bash
IMAGE=ghcr.io/penguintechinc/squawk/dns-server:v2.1.1

cosign verify "$IMAGE" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity-regexp='^https://github.com/penguintechinc/squawk/\.github/workflows/.+'
```

### Verify the SBOM attestation

```bash
cosign verify-attestation "$IMAGE" --type spdxjson \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity-regexp='^https://github.com/penguintechinc/squawk/\.github/workflows/.+' \
  | jq -r '.payload | @base64d | fromjson | .predicate.name'
```

Enterprises can enforce this at admission time (e.g. a Kyverno/Sigstore policy
controller) so only cosign-verified Squawk images run in the cluster.

---

## 4. Kubernetes runtime hardening

All first-party workloads (Helm + Kustomize) run with a restrictive
`securityContext`:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: [ALL]
  seccompProfile:
    type: RuntimeDefault
```

`seccompProfile: RuntimeDefault` applies the container runtime's default syscall
filter to every pod. Combined with the read-only root filesystem and dropped
capabilities, this gives a minimal syscall/permission surface. JWT keys are the
only secret material mounted, read-only, at `/etc/squawk/jwt`.

---

## 5. Automated dependency pinning (Renovate)

`renovate.json` keeps dependencies immutable and current:

- **`pinDigests: true`** — external container images are pinned to `@sha256:`
  digests; Renovate opens PRs to bump them.
- **`vulnerabilityAlerts`** — security-driven updates are surfaced as PRs.
- First-party (PenguinTech) images are tracked by tag; external images always by
  digest, matching the house dependency-pinning standard.

Merging Renovate PRs keeps base images patched without manual digest edits.

---

## 6. Service-to-service authentication (SPIFFE/mTLS)

DNS/DHCP/time servers authenticating **to the manager** prefer a SPIFFE/mTLS
identity over the legacy per-server JWT (a long-lived static shared secret —
the anti-pattern the standard forbids between services).

**Identity scheme** (penguintech infra standard):

```
spiffe://<trust_domain>/<env>/<service>[/<instance>]
```

A DNS server presents `spiffe://penguintech.io/<env>/dns-server/<server_id>`.

**How it works:** the service mesh / gateway (Envoy, Istio) terminates mTLS with
the peer's short-lived X.509-SVID and forwards the verified SPIFFE ID in the
`X-Forwarded-Client-Cert` (XFCC) header. The manager's `server_token_required`
path resolves that identity first: it validates the trust domain and the
`<env>/dns-server/<server_id>` scheme (fail-closed on any mismatch) and, on
success, authenticates the server **without** any shared secret. When no SPIFFE
identity is present it falls back to the legacy server JWT and logs that the
static-secret path was used.

**Configuration:**

| Env var               | Default            | Purpose                                   |
|-----------------------|--------------------|-------------------------------------------|
| `SPIFFE_ENABLED`      | `false`            | Enable SPIFFE/mTLS server auth (opt-in)   |
| `SPIFFE_TRUST_DOMAIN` | `penguintech.io`   | Accepted trust domain                     |
| `SPIFFE_XFCC_HEADER`  | `X-Forwarded-Client-Cert` | Mesh-injected peer-identity header |

> **Trust boundary (why it defaults off):** XFCC is a client-supplied header.
> Trusting it is safe **only** when the mesh sidecar injects it, **strips any
> inbound copy**, and the manager is not directly reachable by clients.
> Otherwise a caller could forge the header and impersonate any server — an
> auth bypass. `SPIFFE_ENABLED` therefore defaults to `false`; turn it on only
> in a deployment that meets those conditions. Never enable it on a
> directly-exposed listener.

**Operational follow-up (SPIRE):** deploy a SPIRE server + agents to issue the
SVIDs and register the DNS-server workloads under the above SPIFFE paths, and
configure the mesh to forward XFCC. Once every server authenticates via SPIFFE,
the per-server JWT secret can be retired.

---

## Quick operator checklist

- [ ] Generate an ES256 keypair with `scripts/gen-jwt-keys.sh`.
- [ ] Create the `squawk-jwt-keys` Secret (`--from-file`, never commit PEMs).
- [ ] Set `SECRET_KEY` (manager) from your secrets manager.
- [ ] Confirm `JWT_ISSUER`/`JWT_AUDIENCE` match across all services.
- [ ] Set `TENANT_ID` for the deployment (or leave `default`).
- [ ] `cosign verify` the images you deploy (optionally enforce at admission).
- [ ] Confirm pods report `runAsNonRoot` + `seccompProfile: RuntimeDefault`.
- [ ] Enable Renovate PRs for digest/vulnerability updates.
- [ ] Set `SPIFFE_TRUST_DOMAIN`; ensure the mesh forwards XFCC and the manager is not directly reachable.
