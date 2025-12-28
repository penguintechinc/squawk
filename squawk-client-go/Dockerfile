# Multi-stage build for Squawk DNS Client (Go)
# 
# Build stage
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
ARG VERSION=docker
ARG BUILD_TIME
ARG GIT_COMMIT

RUN BUILD_TIME=$(date -u +%Y-%m-%d_%H:%M:%S) && \
    CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X 'main.version=${VERSION}' -X 'main.buildTime=${BUILD_TIME}' -X 'main.gitCommit=${GIT_COMMIT}'" \
    -o bin/squawk-dns-client \
    ./cmd/squawk-dns-client

# Runtime stage
FROM alpine:3.18

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1001 squawk && \
    adduser -D -u 1001 -G squawk squawk

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

# Health check
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