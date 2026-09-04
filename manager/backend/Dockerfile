# python3.13 is not installable via apt on plain debian:bookworm-slim —
# it's absent from both the main and bookworm-backports repos (verified:
# `apt-cache madison python3.13` returns nothing from either). The previous
# `debian:bookworm-slim` + `apt-get install python3.13` base broke every
# build of this Dockerfile. python:3.13-slim-bookworm (same digest
# dns-server already uses successfully) provides it natively.
FROM python:3.13-slim-bookworm@sha256:061b6e52a07ab675f0e4a9428c5a8ee6bed996983427f4691f6bebf29c56d9dc AS base

# Install system dependencies
# xmlsec1: pysaml2's SAML assertion signature verification shells out to
# this binary (saml2.sigver.CryptoBackendXmlSec1) -- without it,
# Saml2Client/Saml2Config raise SigverError before ever comparing a
# signature, i.e. SAML SSO silently fails closed instead of actually
# verifying anything.
RUN apt-get update && apt-get install -y \
    build-essential libpq-dev ca-certificates curl xmlsec1 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

FROM base AS backend
WORKDIR /app

# supercronic ships as a GitHub release binary, not a container image —
# ghcr.io/aptible/supercronic does not exist under any tag (confirmed via
# `docker pull`, which returns "denied" for :0.2.47, :v0.2.47, and :latest
# alike — this is the upstream project's actual distribution mechanism, not
# a missing/private image). The previous FROM ghcr.io/aptible/supercronic
# multi-stage reference broke every build of this Dockerfile.
# TODO WAVE-6: pin to a specific release + verify its published sha256 checksum.
RUN curl -fsSL -o /usr/local/bin/supercronic \
    https://github.com/aptible/supercronic/releases/download/v0.2.34/supercronic-linux-amd64 && \
    chmod +x /usr/local/bin/supercronic

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
