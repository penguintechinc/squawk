"""
DNS Server Configuration
Loads configuration from environment variables.
"""
import os

# Manager connection
MANAGER_URL = os.getenv('MANAGER_URL', 'http://localhost:5000')
JOIN_KEY = os.getenv('JOIN_KEY')

# JWT authentication (MUST match manager's JWT_SECRET_KEY for token verification)
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')

# DNS server settings
DNS_PORT = int(os.getenv('DNS_PORT', 8080))
GRPC_PORT = int(os.getenv('GRPC_PORT', 50052))

# Cache settings
CACHE_URL = os.getenv('CACHE_URL', 'redis://localhost:6379')
CACHE_TTL = int(os.getenv('CACHE_TTL', 86400))  # 24 hours

# Sync intervals
SYNC_INTERVAL = int(os.getenv('SYNC_INTERVAL', 300))  # 5 minutes
HEARTBEAT_INTERVAL = int(os.getenv('HEARTBEAT_INTERVAL', 30))  # 30 seconds

# Storage
CACHE_DIR = os.getenv('CACHE_DIR', '/app/cache')

# Logging
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
