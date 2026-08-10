#!/bin/bash
set -e

# Script to extract release notes from RELEASE_NOTES.md and create release body
# Usage: extract-release-notes.sh [client|server] [version] [output_file]

COMPONENT=${1:-"client"}
VERSION=${2:-"unknown"}
OUTPUT_FILE=${3:-"release_body.md"}
RELEASE_NOTES_FILE="docs/RELEASE_NOTES.md"

echo "Extracting release notes for $COMPONENT v$VERSION"

# Create the release body file
cat > "$OUTPUT_FILE" << EOF
# Squawk DNS ${COMPONENT^} v${VERSION}

## 🚀 Complete Release Information

For detailed information about this release, including all features, security enhancements, bug fixes, and technical improvements, please see the comprehensive release notes below.

---

EOF

# Check if release notes file exists
if [ -f "$RELEASE_NOTES_FILE" ]; then
    echo "Found release notes file: $RELEASE_NOTES_FILE"

    # Extract the first 400 lines to avoid hitting GitHub's limit
    echo "Extracting content from release notes..."
    head -n 400 "$RELEASE_NOTES_FILE" >> "$OUTPUT_FILE"

    # Add footer
    cat >> "$OUTPUT_FILE" << EOF

---

## 📦 Component-Specific Information

EOF

    if [ "$COMPONENT" = "client" ]; then
        cat >> "$OUTPUT_FILE" << EOF
### Go Client Features
- **High Performance**: ~10ms cold start, ~15MB memory usage
- **Cross-Platform**: Linux (AMD64/ARM64), macOS (Universal), Windows
- **Package Options**: Native binaries, Docker images, Debian packages
- **1:1 Feature Parity**: Full compatibility with Python client

### Quick Start
\`\`\`bash
# Docker
docker run -p 53:53/udp -p 53:53/tcp \\
  -e SQUAWK_SERVER_URL=https://your-server:8443 \\
  -e SQUAWK_AUTH_TOKEN=your-token \\
  penguincloud/squawk-dns-client:${VERSION} forward -v

# Debian/Ubuntu
wget https://github.com/\${GITHUB_REPOSITORY}/releases/download/v${VERSION}-client/squawk-dns-client_${VERSION}_amd64.deb
sudo dpkg -i squawk-dns-client_${VERSION}_amd64.deb
\`\`\`
EOF
    else
        cat >> "$OUTPUT_FILE" << EOF
### DNS Server Features
- **Complete Solution**: DNS-over-HTTPS server with web console
- **Enterprise Security**: mTLS, MFA, SSO, brute force protection
- **High Performance**: Async processing, Redis caching, HTTP/3 support
- **Docker Images**: Development, production, testing, and Python client variants

### Quick Start
\`\`\`bash
# Development
docker run -p 8080:8080 -p 8000:8000 \\
  penguincloud/squawk-dns-server:${VERSION}

# Production
docker run -p 8080:8080 \\
  -e SQUAWK_ENV=production \\
  -e ENABLE_MTLS=true \\
  penguincloud/squawk-dns-server-prod:${VERSION}
\`\`\`
EOF
    fi

    echo "Successfully extracted $(wc -l < "$OUTPUT_FILE") lines to $OUTPUT_FILE"
else
    echo "Release notes file not found: $RELEASE_NOTES_FILE"
    echo "Using minimal release body..."

    cat >> "$OUTPUT_FILE" << EOF
High-performance DNS-over-HTTPS ${COMPONENT} with comprehensive security features.

## Features
- DNS-over-HTTPS support with HTTP/2 and HTTP/3
- mTLS authentication with automatic certificate generation
- Bearer token authentication
- Enterprise-grade security features
- Cross-platform support

For more information, visit the [GitHub repository](https://github.com/\${GITHUB_REPOSITORY}) or [documentation](https://docs.squawkdns.com).
EOF
fi

cat >> "$OUTPUT_FILE" << EOF

---

**Built from commit**: \${GITHUB_SHA:-$(git rev-parse HEAD 2>/dev/null || echo "unknown")}
**Release Date**: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
**Verify downloads**: Use SHA256SUMS file included in release assets

EOF

echo "Release body created: $OUTPUT_FILE ($(wc -l < "$OUTPUT_FILE") lines)"
