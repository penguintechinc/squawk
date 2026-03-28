#!/bin/bash

# Squawk DNS Server with Web Console Startup Script

echo "Starting Squawk DNS Server with Web Console..."

# Set paths
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
WEB_DIR="$SCRIPT_DIR/web"
VENV_DIR="$SCRIPT_DIR/venv"

# Check if virtual environment exists
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

# Activate virtual environment
source "$VENV_DIR/bin/activate"

# Install/update dependencies
echo "Checking dependencies..."
pip install -q --upgrade pip
pip install -q py4web pydal dnspython requests pyyaml

# Start py4web in background
echo "Starting py4web console on port 8000..."
cd "$WEB_DIR"
py4web run apps --host 0.0.0.0 --port 8000 &
PY4WEB_PID=$!

# Give py4web time to start
sleep 2

# Start DNS server with new auth system
echo "Starting DNS server on port 8080 with new authentication system..."
cd "$SCRIPT_DIR"
python3 bins/server.py -p 8080 -n &
DNS_PID=$!

echo ""
echo "==============================================" 
echo "Squawk DNS Server with Web Console is running!"
echo "=============================================="
echo ""
echo "DNS Server: http://localhost:8080"
echo "Web Console: http://localhost:8000/dns_console"
echo ""
echo "To stop the services, press Ctrl+C"
echo ""

# Wait for interrupt
trap "echo 'Stopping services...'; kill $PY4WEB_PID $DNS_PID; exit" INT TERM
wait