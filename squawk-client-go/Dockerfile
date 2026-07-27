# Multi-stage build for Squawk DNS Client (Go)
#
# Build stage
FROM golang:1.25-bookworm@sha256:ea341baa9bd5ba6784f6d7161ace70544349a6242d54d34a0fbfd2c4d51c9d58 AS builder

# Set working directory
WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application (static binary, no CGO)
ARG VERSION=docker
ARG BUILD_TIME
ARG GIT_COMMIT

RUN BUILD_TIME=$(date -u +%Y-%m-%d_%H:%M:%S) && \
    CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X 'main.version=${VERSION}' -X 'main.buildTime=${BUILD_TIME}' -X 'main.gitCommit=${GIT_COMMIT}'" \
    -o bin/squawk-dns-client \
    ./cmd/squawk-client

# Runtime stage
FROM debian:bookworm-slim@sha256:f06537653ac770703bc45b4b113475bd402f451e85223f0f2837acbf89ab020a

# Install runtime dependencies
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates tzdata && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -g 1001 squawk && \
    useradd -r -u 1001 -g squawk squawk

# Create directories
RUN mkdir -p /etc/squawk /var/log/squawk && \
    chown -R squawk:squawk /etc/squawk /var/log/squawk

# Copy binary from builder
COPY --from=builder /app/bin/squawk-dns-client /usr/local/bin/

# Set permissions
RUN chmod +x /usr/local/bin/squawk-dns-client

# Switch to non-root user
USER squawk

# Set working directory
WORKDIR /etc/squawk

# Health check (native binary, no curl)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD squawk-dns-client -d google.com -s https://dns.google/resolve || exit 1

# Default command
ENTRYPOINT ["squawk-dns-client"]
CMD ["--help"]

# Labels
LABEL org.opencontainers.image.title="Squawk DNS Client (Go)"
LABEL org.opencontainers.image.description="DNS-over-HTTPS client with mTLS support and local DNS forwarding"
LABEL org.opencontainers.image.vendor="PenguinTech Group"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/penguincloud/squawk"
