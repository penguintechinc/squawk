# NTP/NTS Server Dockerfile (RFC 8915 Compliant)
# Production-grade NTS with real AEAD encryption and RFC 5705 TLS exporter
FROM python:3.13-slim-bookworm@sha256:061b6e52a07ab675f0e4a9428c5a8ee6bed996983427f4691f6bebf29c56d9dc

LABEL company="Penguin Tech Group LLC"
LABEL org.opencontainers.image.authors="info@penguintech.io"
LABEL license="GNU AGPL3"
LABEL description="Squawk NTP/NTS Server (RFC 8915) with AEAD Encryption"

# Build-time environment selector
ARG SQUAWK_ENV=production

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive \
    TZ=UTC \
    SQUAWK_ENV=${SQUAWK_ENV:-production}

# Install build dependencies and openssl development files (needed for pyOpenSSL)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libssl-dev \
    libffi-dev \
    pkg-config \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create app user (rootless)
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /bin/bash appuser

# Create directories
RUN mkdir -p /app /app/certs && \
    chown -R appuser:appuser /app

WORKDIR /app

# Copy requirements
COPY requirements*.txt ./

# Create virtual environment and install dependencies
RUN python3.13 -m venv /app/venv && \
    /app/venv/bin/pip install --upgrade pip wheel setuptools && \
    /app/venv/bin/pip install -r requirements.txt && \
    if [ "$SQUAWK_ENV" = "development" ] || [ "$SQUAWK_ENV" = "test" ]; then \
    /app/venv/bin/pip install pytest pytest-cov pytest-asyncio; \
    fi && \
    echo "✓ Python dependencies installed"

# Set venv as default
ENV PATH="/app/venv/bin:$PATH"

# Copy application code
COPY bins/ ./bins/

# Set permissions
RUN chown -R appuser:appuser /app && \
    chmod 755 /app/bins/server.py

# Switch to non-root user
USER appuser

# Health check (native Python, no curl)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /app/venv/bin/python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8082/health',timeout=5).status==200 else 1)" || exit 1

# Expose ports
# 8082: HTTP API (plain endpoints)
# 4460: NTS-KE TLS server
# 123/udp: NTP UDP server
EXPOSE 8082 4460 123/udp

# Launch server
CMD ["python3", "bins/server.py"]
