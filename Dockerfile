# Unified Multi-stage Dockerfile for Squawk DNS System
# Ubuntu 24.04 LTS with Python 3.13 - Standardized Build Environment
FROM debian:bookworm-slim@sha256:01f42367a0a94ad4bc17111776fd66e3500c1d87c15bbd6055b7371d39c124fb AS base

LABEL company="Penguin Tech Group LLC"
LABEL org.opencontainers.image.authors="info@penguintech.group"
LABEL license="GNU AGPL3"
LABEL description="Squawk DNS-over-HTTPS System - Unified Server and Client Build"

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
    gcc \
    g++ \
    libc6-dev \
    libffi-dev \
    libssl-dev \
    pkg-config \
    build-essential \
    curl \
    ca-certificates \
    && ln -sf /usr/bin/python3.13 /usr/bin/python3 \
    && curl -sS https://bootstrap.pypa.io/get-pip.py | python3.13 \
    && rm -rf /var/lib/apt/lists/*

# Install LDAP and XML dependencies
RUN apt-get update && apt-get install -y \
    libxml2-dev \
    libxslt1-dev \
    libldap-dev \
    libldap2-dev \
    libsasl2-dev \
    libldap-common \
    dnsutils \
    net-tools \
    procps \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Create directories
RUN mkdir -p /app/dns-server /app/dns-client /app/data /app/logs /app/certs && \
    chown -R appuser:appuser /app

WORKDIR /app

# DNS Server Stage
FROM base AS dns-server

# Copy requirements files
COPY dns-server/requirements*.txt /app/dns-server/

# Create virtual environment and install Python dependencies
RUN python3.13 -m venv /app/venv && \
    /app/venv/bin/pip install --upgrade pip wheel setuptools && \
    if [ -f /app/dns-server/requirements-base.txt ]; then \
        echo "Installing with fallback strategy..." && \
        (/app/venv/bin/pip install -r /app/dns-server/requirements.txt 2>/dev/null && echo "Full installation successful") || \
        (echo "WARNING: Enterprise features failed, using base requirements..." && \
         /app/venv/bin/pip install -r /app/dns-server/requirements-base.txt); \
    else \
        echo "Installing all requirements..." && \
        /app/venv/bin/pip install -r /app/dns-server/requirements.txt; \
    fi && \
    /app/venv/bin/python -c "import sys; print(f'Python {sys.version}')" && \
    echo "✓ DNS Server Python dependencies installed successfully"

# Make virtual environment the default
ENV PATH="/app/venv/bin:$PATH"

# Copy DNS server code
COPY dns-server/ /app/dns-server/
COPY docs/ /app/docs/

# Set permissions
RUN chown -R appuser:appuser /app

USER appuser

# Health check for DNS server
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f "http://localhost:8080/health" || exit 1

EXPOSE 8080 8000

# Default command
CMD ["python3", "/app/dns-server/bins/server.py", "-p", "8080", "-n"]

# DNS Client Stage
FROM base AS dns-client

# Create requirements files for client
RUN echo "dnspython>=2.4.2" > /app/dns-client/requirements.txt && \
    echo "requests>=2.31.0" >> /app/dns-client/requirements.txt && \
    echo "PyYAML>=6.0.1" >> /app/dns-client/requirements.txt

RUN echo "pytest>=7.4.3" > /app/dns-client/requirements-dev.txt && \
    echo "pytest-cov>=4.1.0" >> /app/dns-client/requirements-dev.txt && \
    echo "pytest-mock>=3.12.0" >> /app/dns-client/requirements-dev.txt

# Create virtual environment and install Python dependencies for client
RUN python3.13 -m venv /app/client-venv && \
    /app/client-venv/bin/pip install --upgrade pip wheel setuptools && \
    /app/client-venv/bin/pip install -r /app/dns-client/requirements.txt && \
    /app/client-venv/bin/python -c "import sys; print(f'Python {sys.version}')" && \
    echo "✓ DNS Client Python dependencies installed successfully"

# Make client virtual environment the default
ENV PATH="/app/client-venv/bin:$PATH"

# Copy DNS client code
COPY dns-client/ /app/dns-client/
COPY docs/ /app/docs/

# Set permissions
RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 53/udp 53/tcp

# Default command
CMD ["python3", "/app/dns-client/bins/client.py", "-u", "-T"]

# Testing Stage
FROM dns-server AS testing

USER root

# Install development dependencies in the existing virtual environment
RUN /app/venv/bin/pip install -r /app/dns-server/requirements-dev.txt

# Install additional testing tools
RUN /app/venv/bin/pip install \
    safety==2.3.5 \
    bandit==1.7.5 \
    pytest-xdist==3.3.1

# Copy test files
COPY dns-server/tests/ /app/dns-server/tests/
COPY dns-client/tests/ /app/dns-client/tests/

# Create test data directory
RUN mkdir -p /app/test-data && chown -R appuser:appuser /app

USER appuser

# Default command for testing
CMD ["pytest", "/app/dns-server/tests/", "/app/dns-client/tests/", "-v", "--cov=/app"]

# Production Stage
FROM dns-server AS production

USER root

# Install production monitoring tools in the existing virtual environment
RUN /app/venv/bin/pip install \
    prometheus-client==0.18.0 \
    structlog==23.1.0

# Set production environment variables
ENV PYTHONPATH=/app \
    SQUAWK_ENV=production \
    SQUAWK_LOG_LEVEL=INFO

USER appuser

# Production health check
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=5 \
    CMD curl -f "http://localhost:${SQUAWK_PORT:-8080}/health" || exit 1

# Production command
CMD ["python3", "/app/dns-server/bins/server.py", \
     "-p", "${SQUAWK_PORT:-8080}", \
     "-n"]
