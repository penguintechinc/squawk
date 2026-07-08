# DNS Server Dockerfile with Python 3.13
FROM python:3.13-slim-bookworm@sha256:061b6e52a07ab675f0e4a9428c5a8ee6bed996983427f4691f6bebf29c56d9dc

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

# Install build dependencies and LDAP/XML enterprise libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    pkg-config \
    curl \
    wget \
    ca-certificates \
    git \
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

# Health check (native Python, no curl)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /app/venv/bin/python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8080/health',timeout=5).status==200 else 1)"

# Expose ports
EXPOSE 8080 8000

# Launch Quart app via hypercorn
CMD ["sh", "-c", "PYTHONPATH=/app/dns-server /app/venv/bin/python -m app.main"]
