FROM debian:bookworm-slim@sha256:f06537653ac770703bc45b4b113475bd402f451e85223f0f2837acbf89ab020a AS base

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3.13 python3.13-venv python3.13-dev \
    build-essential libpq-dev && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Stage 2: Copy supercronic binary (fixed to v0.2.47, digest pending registry access)
# TODO WAVE-6: Pin digest — requires ghcr.io registry access to resolve:
#   docker pull ghcr.io/aptible/supercronic:0.2.47 && \
#   docker inspect ghcr.io/aptible/supercronic:0.2.47 | grep Digest | head -1
# Replace 'latest' with @sha256:<digest> once digest is available
FROM ghcr.io/aptible/supercronic:0.2.47 AS supercronic
# Binary is at /usr/local/bin/supercronic in the supercronic image

FROM base AS backend
WORKDIR /app

# Copy requirements
COPY requirements.txt /app/

# Create virtual environment and install dependencies
RUN python3.13 -m venv /app/venv && \
    /app/venv/bin/pip install --upgrade pip && \
    /app/venv/bin/pip install -r requirements.txt

# Set PATH to use venv
ENV PATH="/app/venv/bin:$PATH"

# Copy application code
COPY . /app/

# Copy crontab for supercronic scheduler
COPY crontab /app/crontab

# Copy supercronic binary from builder stage
COPY --from=supercronic /usr/local/bin/supercronic /usr/local/bin/supercronic

# Create databases directory for PyDAL
RUN mkdir -p /app/databases

# Create non-root user and set ownership
RUN useradd --create-home --shell /bin/bash appuser && \
    chown -R appuser:appuser /app

USER appuser

# Expose ports
EXPOSE 5000 50051

# Default: run gunicorn (for normal manager service)
# Override with: docker run ... supercronic /app/crontab (for scheduler)
CMD ["/app/venv/bin/gunicorn", "--workers=4", "--worker-class=gthread", "--threads=2", \
     "--bind=0.0.0.0:5000", "--timeout=120", "wsgi:app"]
