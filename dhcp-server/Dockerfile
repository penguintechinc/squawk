# DHCP-over-HTTPS Server - Production Dockerfile
# Base: Debian 12 (bookworm), Python 3.13

FROM python:3.13-slim-bookworm@sha256:fcbd8dfc2605ba7c2eca646846c5e892b2931e41f6227985154a596f26ab8ed7

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Install minimal system dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for application
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Create application directory
WORKDIR /app

# Copy requirements and install dependencies as root
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app ./app
COPY bins ./bins

# Create empty __init__.py for packages
RUN touch app/__init__.py bins/__init__.py

# Switch to non-root user
USER appuser

# Environment variables with defaults
ENV DHCP_PORT=8081 \
    DATABASE_URL=sqlite:///dhcp.db \
    JWT_SECRET_KEY= \
    DHCP_POOL_SUBNET=192.168.1.0/24 \
    DHCP_POOL_START=192.168.1.100 \
    DHCP_POOL_END=192.168.1.200 \
    DHCP_GATEWAY=192.168.1.1 \
    DHCP_DNS_SERVERS=8.8.8.8,8.8.4.4 \
    DHCP_LEASE_TIME=86400 \
    LOG_LEVEL=INFO \
    POSTHOG_KEY= \
    POSTHOG_HOST=https://license.penguintech.io

# Expose DHCP server port
EXPOSE 8081

# Health check using native Python (no curl required)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8081/health').read()" || exit 1

# Run the DHCP server
CMD ["python3", "bins/server.py"]
