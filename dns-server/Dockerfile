# DNS Server Dockerfile with Python 3.13
FROM debian:bookworm-slim@sha256:4724b8cc51e33e398f0e2e15e18d5ec2851ff0c2280647e1310bc1642182655d

LABEL company="Penguin Tech Group LLC"
LABEL org.opencontainers.image.authors="info@penguintech.io"
LABEL license="GNU AGPL3"
LABEL description="Squawk DNS-over-HTTPS Server with Enterprise Features"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive \
    TZ=UTC \
    SQUAWK_ENV=${SQUAWK_ENV:-production}

# Install Python 3.13 and basic build dependencies
RUN apt-get update && apt-get install -y \
    python3.13 \
    python3.13-dev \
    python3.13-venv \
    build-essential \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    pkg-config \
    curl \
    wget \
    ca-certificates \
    git && \
    curl -sS https://bootstrap.pypa.io/get-pip.py | python3.13 

# Install LDAP, XML and enterprise dependencies
RUN apt-get update && apt-get install -y \
    libxml2-dev \
    libxslt1-dev \
    libldap-dev \
    ldap-utils \
    libldap2-dev \
    libsasl2-dev \
    libldap-common \
    libxmlsec1-dev \
    libxmlsec1-openssl \
    dnsutils \
    net-tools \
    procps \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /bin/bash appuser

# Create directories
RUN mkdir -p /app/dns-server /app/data /app/logs /app/certs /app/web && \
    chown -R appuser:appuser /app

WORKDIR /app/dns-server

# Copy requirements files
COPY requirements*.txt ./

# Create virtual environment and install Python dependencies
RUN python3.13 -m venv /app/venv && \
    /app/venv/bin/pip install --upgrade pip wheel setuptools && \
    /app/venv/bin/pip install -r requirements.txt && \
    if [ "$SQUAWK_ENV" = "development" ] || [ "$SQUAWK_ENV" = "test" ] || [ -f requirements-dev.txt ]; then \
    echo "Installing development dependencies..." && \
    /app/venv/bin/pip install -r requirements-dev.txt 2>/dev/null || \
    echo "No dev requirements found or installation failed - continuing with production setup"; \
    fi && \
    /app/venv/bin/python -c "import sys; print(f'Python {sys.version}')" && \
    echo "✓ Python dependencies installed successfully"

# Make virtual environment the default
ENV PATH="/app/venv/bin:$PATH"


# Copy application code
COPY . /app/dns-server/

# Copy web console
COPY web/ /app/web/

# Set permissions
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f "http://localhost:${PORT:-8080}/health" || exit 1

# Expose ports
EXPOSE 8080 8000

# Smart command selection based on environment
CMD if [ "$SQUAWK_ENV" = "test" ]; then \
    echo "Running tests..." && \
    python3 -m pytest tests/ -v; \
    else \
    echo "Starting DNS server..." && \
    python3 /app/dns-server/bins/server_premium_integrated.py -p ${PORT:-8080} -n; \
    fi