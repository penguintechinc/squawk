"""
DNS Server Configuration
Loads configuration from environment variables.
"""
import os
from typing import Optional, Dict


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


def _load_multiple_keys_from_directory(dir_path: Optional[str]) -> Dict[str, str]:
    """Load multiple PEM keys from a directory (for key rotation overlap).

    Args:
        dir_path: Directory containing .pem files

    Returns:
        Dict mapping kid -> PEM public key. Empty dict if dir not found/empty.
    """
    keys: Dict[str, str] = {}
    if not dir_path or not os.path.isdir(dir_path):
        return keys

    try:
        from app.utils.crypto import compute_kid_from_public_pem

        for filename in os.listdir(dir_path):
            if filename.endswith('.pem'):
                filepath = os.path.join(dir_path, filename)
                if os.path.isfile(filepath):
                    with open(filepath, 'r') as f:
                        pem_content = f.read().strip()
                        if pem_content:
                            try:
                                kid = compute_kid_from_public_pem(pem_content)
                                keys[kid] = pem_content
                            except Exception:
                                pass
    except Exception:
        pass

    return keys


# Manager connection
MANAGER_URL = os.getenv('MANAGER_URL', 'http://localhost:5000')
JOIN_KEY = os.getenv('JOIN_KEY')

# JWT authentication (asymmetric: ES256 default, RS256 fallback; verify user tokens only)
JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'ES256')
JWT_ISSUER = os.getenv('JWT_ISSUER', 'squawk-manager')
JWT_AUDIENCE = os.getenv('JWT_AUDIENCE', 'squawk')

# Single public key (backward compat) or multi-key directory for rotation
JWT_PUBLIC_KEY = _load_key_from_env_or_file('JWT_PUBLIC_KEY', 'JWT_PUBLIC_KEY_FILE')
JWT_PUBLIC_KEYS = _load_multiple_keys_from_directory(
    os.getenv('JWT_PUBLIC_KEYS_DIR')
)

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

# Rate limiting
SQUAWK_RATE_LIMIT_ENABLED = os.getenv('SQUAWK_RATE_LIMIT_ENABLED', 'false').lower() == 'true'
SQUAWK_RATE_LIMIT_RPS = float(os.getenv('SQUAWK_RATE_LIMIT_RPS', 50))
SQUAWK_RATE_LIMIT_BURST = float(os.getenv('SQUAWK_RATE_LIMIT_BURST', 100))
SQUAWK_RATE_LIMIT_BACKEND = os.getenv('SQUAWK_RATE_LIMIT_BACKEND', 'memory')  # 'memory' or 'valkey'
