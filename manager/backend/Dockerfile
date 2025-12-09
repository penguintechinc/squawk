FROM ubuntu:24.04 AS base

# Install system dependencies
RUN apt-get update && apt-get install -y software-properties-common curl && \
    add-apt-repository ppa:deadsnakes/ppa && \
    apt-get update && apt-get install -y \
    python3.13 python3.13-venv python3.13-dev \
    build-essential libpq-dev && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

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

# Create databases directory for PyDAL
RUN mkdir -p /app/databases

# Expose ports
EXPOSE 5000 50051

# Run the application
CMD ["/app/venv/bin/gunicorn", "--workers=4", "--worker-class=gthread", "--threads=2", \
     "--bind=0.0.0.0:5000", "--timeout=120", "wsgi:app"]
