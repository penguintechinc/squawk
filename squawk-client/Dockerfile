# DNS Client Dockerfile with Python 3.13
FROM debian:bookworm-slim@sha256:f06537653ac770703bc45b4b113475bd402f451e85223f0f2837acbf89ab020a

LABEL company="Penguin Tech Group LLC"
LABEL org.opencontainers.image.authors="info@penguintech.group"
LABEL license="GNU AGPL3"
LABEL description="Squawk DNS Client - DNS-over-HTTPS Forwarder"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive \
    TZ=UTC

# Install Python 3.13 and basic build dependencies
RUN apt-get update && apt-get install -y \
    python3.13 \
    python3.13-dev \
    python3.13-venv \
    build-essential \
    gcc \
    libffi-dev \
    libssl-dev \
    curl \
    wget \
    ca-certificates \
    && ln -sf /usr/bin/python3.13 /usr/bin/python3 \
    && curl -sS https://bootstrap.pypa.io/get-pip.py | python3.13 \
    && rm -rf /var/lib/apt/lists/*

# Install client-specific dependencies
RUN apt-get update && apt-get install -y \
    dnsutils \
    net-tools \
    procps \
    systemd \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /bin/bash appuser

# Create directories
RUN mkdir -p /app/dns-client /app/data /app/logs /app/certs && \
    chown -R appuser:appuser /app

WORKDIR /app/dns-client

# Copy requirements file
COPY requirements.txt ./

# Create virtual environment and install Python dependencies
RUN python3.13 -m venv /app/venv && \
    /app/venv/bin/pip install --upgrade pip wheel setuptools && \
    /app/venv/bin/pip install -r requirements.txt && \
    /app/venv/bin/python -c "import sys; print(f'Python {sys.version}')" && \
    echo "✓ Python dependencies installed successfully"

# Make virtual environment the default
ENV PATH="/app/venv/bin:$PATH"

# Copy application code
COPY . /app/dns-client/

# Set permissions
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import dns.resolver; r = dns.resolver.Resolver(); r.nameservers = ['127.0.0.1']; r.query('health.check', 'A')" 2>/dev/null || exit 1

# Expose DNS ports
EXPOSE 53/udp 53/tcp

# Environment variables for configuration
ENV SQUAWK_SERVER_URL=https://dns.google/resolve \
    SQUAWK_AUTH_TOKEN="" \
    SQUAWK_DOMAIN="" \
    SQUAWK_RECORD_TYPE=A \
    LOG_LEVEL=INFO

# Default command - DNS forwarder mode
CMD ["sh", "-c", "python3 /app/dns-client/bins/client.py -s ${SQUAWK_SERVER_URL} -a ${SQUAWK_AUTH_TOKEN} -u -T -v"]