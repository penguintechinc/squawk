# DHCP-over-HTTPS Server Dockerfile
# Based on Ubuntu 24.04 LTS with Python 3.13 from deadsnakes PPA

FROM ubuntu:24.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies and Python 3.13
RUN apt-get update && apt-get install -y \
    software-properties-common \
    curl \
    ca-certificates \
    && add-apt-repository ppa:deadsnakes/ppa \
    && apt-get update \
    && apt-get install -y \
    python3.13 \
    python3.13-venv \
    python3.13-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Create virtual environment
RUN python3.13 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY bins/ ./bins/
COPY managers/ ./managers/

# Create empty __init__.py files for Python packages
RUN touch bins/__init__.py managers/__init__.py

# Environment variables with defaults
ENV DHCP_PORT=8081
ENV AUTH_REQUIRED=true
ENV SHARED_AUTH_URL=http://localhost:8080
ENV DHCP_POOL_SUBNET=192.168.1.0/24
ENV DHCP_POOL_START=192.168.1.100
ENV DHCP_POOL_END=192.168.1.200
ENV DHCP_GATEWAY=192.168.1.1
ENV DHCP_DNS_SERVERS=8.8.8.8,8.8.4.4
ENV DHCP_LEASE_TIME=86400

# Expose DHCP server port
EXPOSE 8081

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8081/health || exit 1

# Run the server
CMD ["python", "bins/server.py"]
