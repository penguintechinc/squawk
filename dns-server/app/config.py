"""
DNS Server Configuration
Loads configuration from environment variables.
"""
import os
from typing import Optional


def _load_key_from_env_or_file(env_var: str, env_var_file: str) -> Optional[str]:
    """Load a key from env var or file path specified in env var."""
    key = os.getenv(env_var)
    if key:
        return key

    key_file = os.getenv(env_var_file)
    if key_file and os.path.isfile(key_file):
        with open(key_file, 'r') as f:
            return f.read().strip()

    return None


# Manager connection
MANAGER_URL = os.getenv('MANAGER_URL', 'http://localhost:5000')
JOIN_KEY = os.getenv('JOIN_KEY')

# JWT authentication (asymmetric: ES256 default, RS256 fallback; verify user tokens only)
JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'ES256')
JWT_ISSUER = os.getenv('JWT_ISSUER', 'squawk-manager')
JWT_AUDIENCE = os.getenv('JWT_AUDIENCE', 'squawk')
JWT_PUBLIC_KEY = _load_key_from_env_or_file('JWT_PUBLIC_KEY', 'JWT_PUBLIC_KEY_FILE')
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')  # Legacy; for server tokens only

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

# HTTP/3 (QUIC) settings
HTTP3_ENABLED = os.getenv('HTTP3_ENABLED', 'false').lower() == 'true'
QUIC_BIND = os.getenv('QUIC_BIND', '0.0.0.0:8443')
TLS_CERT_FILE = os.getenv('TLS_CERT_FILE')  # Optional; CertManager fallback
TLS_KEY_FILE = os.getenv('TLS_KEY_FILE')    # Optional; CertManager fallback
