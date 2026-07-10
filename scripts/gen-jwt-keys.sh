#!/bin/bash
#
# Generate JWT keypairs for asymmetric signing (ES256 and RS256).
#
# Usage:
#   ./scripts/gen-jwt-keys.sh                    # Generate ES256 keypair (default)
#   ./scripts/gen-jwt-keys.sh --es256-only       # Generate ES256 only
#   ./scripts/gen-jwt-keys.sh --rs256-only       # Generate RS256 only (fallback)
#   ./scripts/gen-jwt-keys.sh --both             # Generate both ES256 and RS256
#   ./scripts/gen-jwt-keys.sh --output /path/to  # Specify output directory
#
# Output files (never committed):
#   - jwt_private_key_es256.pem       (PKCS#8 private key, P-256 curve)
#   - jwt_public_key_es256.pem        (SubjectPublicKeyInfo public key)
#   - jwt_private_key_rs256.pem       (PKCS#8 private key, 2048 bits)
#   - jwt_public_key_rs256.pem        (SubjectPublicKeyInfo public key)
#
# Deployment (Kubernetes — k8s/helm/squawk and k8s/kustomize/base):
#   Both the Helm chart and Kustomize base reference a single Secret named
#   `squawk-jwt-keys` with two standardized data keys (regardless of which
#   algorithm you generated):
#     - jwt-private-key   (PEM, manager/signer only)
#     - jwt-public-key    (PEM, manager + all verifiers)
#
#   Manager (signer):     reads jwt-private-key + jwt-public-key
#   dns-server, dhcp-server, ntp-server (verifiers): read ONLY jwt-public-key
#
#   Create the Secret directly from the generated PEM files — rename via
#   `--from-file=<secret-key>=<local-file>` so the Secret data key matches
#   the standardized name (not the on-disk filename):
#
#   kubectl create secret generic squawk-jwt-keys -n squawk \
#     --from-file=jwt-private-key=jwt_private_key_es256.pem \
#     --from-file=jwt-public-key=jwt_public_key_es256.pem
#
#   See k8s/squawk-jwt-keys.example.yml for the Secret shape (placeholder
#   only — REPLACE with real PEM content, never commit it).
#
#   Both deployment methods mount this Secret read-only at /etc/squawk/jwt
#   (compatible with readOnlyRootFilesystem: true) and set:
#     Manager:   JWT_PRIVATE_KEY_FILE=/etc/squawk/jwt/jwt-private-key
#                JWT_PUBLIC_KEY_FILE=/etc/squawk/jwt/jwt-public-key
#     Verifiers: JWT_PUBLIC_KEY_FILE=/etc/squawk/jwt/jwt-public-key
#   Plus JWT_ALGORITHM (default ES256), JWT_ISSUER (default squawk-manager),
#   JWT_AUDIENCE (default squawk), and TENANT_ID (manager only, default
#   "default") — all overridable via the Helm chart's `jwt:` values block.
#

set -euo pipefail

OUTPUT_DIR="."
ALGORITHM="es256"  # default

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --es256-only)
            ALGORITHM="es256"
            shift
            ;;
        --rs256-only)
            ALGORITHM="rs256"
            shift
            ;;
        --both)
            ALGORITHM="both"
            shift
            ;;
        --output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

echo "Generating JWT keypairs in: $OUTPUT_DIR"

# Generate ES256 keypair (NIST P-256 curve)
if [[ "$ALGORITHM" == "es256" || "$ALGORITHM" == "both" ]]; then
    echo "  → Generating ES256 (NIST P-256) keypair..."

    # Generate EC private key
    openssl ecparam -name prime256v1 -genkey -noout \
        -out "$OUTPUT_DIR/jwt_private_key_es256.pem"

    # Convert to PKCS#8 format
    openssl pkcs8 -topk8 -nocrypt \
        -in "$OUTPUT_DIR/jwt_private_key_es256.pem" \
        -out "$OUTPUT_DIR/jwt_private_key_es256_temp.pem"
    mv "$OUTPUT_DIR/jwt_private_key_es256_temp.pem" "$OUTPUT_DIR/jwt_private_key_es256.pem"

    # Extract public key
    openssl ec -in "$OUTPUT_DIR/jwt_private_key_es256.pem" -pubout \
        -out "$OUTPUT_DIR/jwt_public_key_es256.pem"

    echo "    ✓ ES256 private key: $OUTPUT_DIR/jwt_private_key_es256.pem"
    echo "    ✓ ES256 public key: $OUTPUT_DIR/jwt_public_key_es256.pem"
fi

# Generate RS256 keypair (RSA 2048-bit)
if [[ "$ALGORITHM" == "rs256" || "$ALGORITHM" == "both" ]]; then
    echo "  → Generating RS256 (RSA 2048) keypair..."

    # Generate RSA private key
    openssl genrsa -out "$OUTPUT_DIR/jwt_private_key_rs256.pem" 2048

    # Convert to PKCS#8 format
    openssl pkcs8 -topk8 -nocrypt \
        -in "$OUTPUT_DIR/jwt_private_key_rs256.pem" \
        -out "$OUTPUT_DIR/jwt_private_key_rs256_temp.pem"
    mv "$OUTPUT_DIR/jwt_private_key_rs256_temp.pem" "$OUTPUT_DIR/jwt_private_key_rs256.pem"

    # Extract public key
    openssl rsa -in "$OUTPUT_DIR/jwt_private_key_rs256.pem" -pubout \
        -out "$OUTPUT_DIR/jwt_public_key_rs256.pem"

    echo "    ✓ RS256 private key: $OUTPUT_DIR/jwt_private_key_rs256.pem"
    echo "    ✓ RS256 public key: $OUTPUT_DIR/jwt_public_key_rs256.pem"
fi

echo ""
echo "Keys generated successfully."
echo ""
echo "Next steps:"
echo "  1. NEVER commit .pem files to git (already gitignored)."
echo "  2. Kubernetes (k8s/helm/squawk, k8s/kustomize/base): create the"
echo "     squawk-jwt-keys Secret directly from these files:"
echo ""
echo "     kubectl create secret generic squawk-jwt-keys -n squawk \\"
echo "       --from-file=jwt-private-key=$OUTPUT_DIR/jwt_private_key_es256.pem \\"
echo "       --from-file=jwt-public-key=$OUTPUT_DIR/jwt_public_key_es256.pem"
echo ""
echo "     See k8s/squawk-jwt-keys.example.yml for the Secret shape."
echo ""
echo "  3. Local/dev (no Kubernetes):"
echo "     Manager:"
echo "       export JWT_PRIVATE_KEY_FILE=/path/to/jwt_private_key_es256.pem"
echo "       export JWT_PUBLIC_KEY_FILE=/path/to/jwt_public_key_es256.pem"
echo ""
echo "     All services (dns-server, dhcp-server, ntp-server):"
echo "       export JWT_PUBLIC_KEY_FILE=/path/to/jwt_public_key_es256.pem"
echo ""
