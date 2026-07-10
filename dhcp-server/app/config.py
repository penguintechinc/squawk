"""
DHCP Server Configuration
Loads configuration from environment variables.
"""

import os
import sys
import logging
from typing import Optional

logger = logging.getLogger(__name__)


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


# Database connection (required for persistence)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///dhcp.db")

# DHCP Pool configuration
DHCP_PORT = int(os.getenv("DHCP_PORT", "8081"))
POOL_SUBNET = os.getenv("DHCP_POOL_SUBNET", "192.168.1.0/24")
POOL_START = os.getenv("DHCP_POOL_START", "192.168.1.100")
POOL_END = os.getenv("DHCP_POOL_END", "192.168.1.200")
GATEWAY = os.getenv("DHCP_GATEWAY", "192.168.1.1")
DNS_SERVERS = os.getenv("DHCP_DNS_SERVERS", "8.8.8.8,8.8.4.4").split(",")
LEASE_TIME = int(os.getenv("DHCP_LEASE_TIME", "86400"))  # seconds

# JWT authentication (asymmetric: ES256 default, RS256 fallback; verify user tokens only)
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "ES256")
JWT_ISSUER = os.getenv("JWT_ISSUER", "squawk-manager")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "squawk")
JWT_PUBLIC_KEY = _load_key_from_env_or_file("JWT_PUBLIC_KEY", "JWT_PUBLIC_KEY_FILE")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")  # Legacy; for server tokens only

# PostHog feature flag configuration
POSTHOG_KEY = os.getenv("POSTHOG_KEY", "")
POSTHOG_HOST = os.getenv("POSTHOG_HOST", "https://license.penguintech.io")

# Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")


def validate_config() -> None:
    """Validate critical configuration at startup. Fail closed if JWT_PUBLIC_KEY missing."""
    if not JWT_PUBLIC_KEY:
        logger.error("JWT_PUBLIC_KEY not configured; starting with 500 error on protected endpoints")
        # We'll return 500 on startup requests if this is missing

    logger.info(f"DHCP Server config: port={DHCP_PORT}, pool={POOL_START}-{POOL_END}, db={DATABASE_URL}")
