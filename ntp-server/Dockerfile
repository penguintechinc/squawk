# NTP/NTS Server Dockerfile
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
    libffi-dev \
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
ENV NTP_PORT=8082
ENV NTS_KE_PORT=4460
ENV AUTH_REQUIRED=true
ENV SHARED_AUTH_URL=http://localhost:8080
ENV UPSTREAM_NTP=pool.ntp.org

# Expose NTP server ports
EXPOSE 8082
EXPOSE 4460

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8082/health || exit 1

# Run the server
CMD ["python", "bins/server.py"]
