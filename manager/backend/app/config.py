"""
Configuration for Squawk DNS Manager.
"""

import os
from datetime import timedelta
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


class Config:
    """Base configuration."""

    # Flask
    DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'
    SECRET_KEY = os.getenv('SECRET_KEY')

    # JWT (asymmetric: ES256 default, RS256 fallback)
    JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'ES256')
    JWT_ISSUER = os.getenv('JWT_ISSUER', 'squawk-manager')
    JWT_AUDIENCE = os.getenv('JWT_AUDIENCE', 'squawk')
    JWT_PRIVATE_KEY = _load_key_from_env_or_file('JWT_PRIVATE_KEY', 'JWT_PRIVATE_KEY_FILE')
    JWT_PUBLIC_KEY = _load_key_from_env_or_file('JWT_PUBLIC_KEY', 'JWT_PUBLIC_KEY_FILE')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', SECRET_KEY)  # Legacy; for server tokens only
    TENANT_ID = os.getenv('TENANT_ID', 'default')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)

    # SPIFFE/mTLS service-to-service identity (preferred over per-server JWTs).
    # The service mesh / gateway terminates mTLS and forwards the verified peer
    # SPIFFE ID in the XFCC header. When present, it supersedes the legacy
    # static-secret server JWT.
    #
    # SECURITY: XFCC is a client-supplied header. It is trustworthy ONLY when a
    # mesh sidecar injects it AND strips any inbound copy, and the manager is
    # not directly reachable by clients. Because trusting it otherwise is an
    # auth-bypass (a caller could forge a server identity), it is OPT-IN and
    # defaults OFF — enable it only in a deployment that meets those conditions.
    SPIFFE_ENABLED = os.getenv('SPIFFE_ENABLED', 'false').lower() == 'true'
    SPIFFE_TRUST_DOMAIN = os.getenv('SPIFFE_TRUST_DOMAIN', 'penguintech.io')
    SPIFFE_XFCC_HEADER = os.getenv('SPIFFE_XFCC_HEADER', 'X-Forwarded-Client-Cert')

    # Database
    DB_URL = os.getenv('DB_URL', 'sqlite://storage.db')

    # Redis/Valkey for caching and rate limiting
    REDIS_URL = os.getenv('REDIS_URL', os.getenv('VALKEY_URL', 'redis://localhost:6379'))
    CACHE_TYPE = 'RedisCache'
    CACHE_DEFAULT_TIMEOUT = int(os.getenv('CACHE_TTL', 300))

    # Rate limiting
    RATELIMIT_ENABLED = os.getenv('RATELIMIT_ENABLED', 'true').lower() == 'true'
    RATELIMIT_STORAGE_URL = REDIS_URL
    RATELIMIT_DEFAULT = os.getenv('RATE_LIMIT_DEFAULT', '100/hour')

    # Trusted reverse-proxy hop count for Werkzeug's ProxyFix. Only the
    # client IP forwarded by exactly this many trusted hops is honored;
    # everything beyond it (including client-supplied X-Forwarded-For
    # entries) is ignored. Must match the actual number of proxies
    # (ingress/gateway) in front of this service, or the rate limiter can be
    # bypassed by a spoofed header.
    TRUSTED_PROXY_HOP_COUNT = int(os.getenv('TRUSTED_PROXY_HOP_COUNT', 1))

    # Account lockout / exponential backoff after repeated failed logins.
    LOGIN_LOCKOUT_THRESHOLD = int(os.getenv('LOGIN_LOCKOUT_THRESHOLD', 5))
    LOGIN_LOCKOUT_BASE_SECONDS = int(os.getenv('LOGIN_LOCKOUT_BASE_SECONDS', 30))
    LOGIN_LOCKOUT_MAX_SECONDS = int(os.getenv('LOGIN_LOCKOUT_MAX_SECONDS', 3600))

    # Server
    MAX_WORKERS = int(os.getenv('MAX_WORKERS', 4))
    MAX_CONCURRENT_REQUESTS = int(os.getenv('MAX_CONCURRENT_REQUESTS', 1000))

    # Features
    ENABLE_MTLS = os.getenv('ENABLE_MTLS', 'false').lower() == 'true'

    # License server
    USE_LICENSE_SERVER = os.getenv('USE_LICENSE_SERVER', 'false').lower() == 'true'
    LICENSE_SERVER_URL = os.getenv('LICENSE_SERVER_URL', 'https://license.squawkdns.com')
    LICENSE_KEY = os.getenv('PENGUINTECH_LICENSE_KEY')

    # PostHog feature flags
    POSTHOG_API_KEY = os.getenv('POSTHOG_API_KEY')
    POSTHOG_HOST = os.getenv('POSTHOG_HOST')
    POSTHOG_PROJECT_KEY = os.getenv('POSTHOG_PROJECT_KEY')

    # gRPC
    GRPC_PORT = int(os.getenv('GRPC_PORT', 50051))


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    # Development-only ephemeral secrets (never use in production)
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-ephemeral-secret-key-only')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', SECRET_KEY)

    def __init__(self) -> None:
        """Generate ephemeral ES256 keypair if not configured."""
        super().__init__()
        # If no keys configured, generate an ephemeral ES256 keypair in-memory
        if not self.JWT_PRIVATE_KEY or not self.JWT_PUBLIC_KEY:
            from app.utils.crypto import generate_ephemeral_es256_keypair
            self.JWT_PRIVATE_KEY, self.JWT_PUBLIC_KEY = (
                generate_ephemeral_es256_keypair()
            )


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False

    # Minimum SECRET_KEY length. SECRET_KEY is fed through HKDF-SHA256 to
    # derive the Fernet key used for MFA/SSO secret encryption (see
    # app/services/mfa_service.py), so a weak value directly weakens that
    # encryption key -- 32 bytes matches the derived AES-128 Fernet key size.
    MIN_SECRET_KEY_LENGTH = 32

    def __init__(self) -> None:
        """Validate required secrets are set at initialization."""
        super().__init__()
        if not self.SECRET_KEY:
            raise RuntimeError(
                'SECRET_KEY environment variable is required in production. '
                'Set a strong random value and never commit it.'
            )
        if len(self.SECRET_KEY) < self.MIN_SECRET_KEY_LENGTH:
            raise RuntimeError(
                f'SECRET_KEY must be at least {self.MIN_SECRET_KEY_LENGTH} bytes '
                'in production (it keys MFA/SSO encryption via HKDF). '
                'Generate with: python3 -c "import secrets; print(secrets.token_urlsafe(32))"'
            )
        if not self.JWT_PRIVATE_KEY:
            raise RuntimeError(
                'JWT_PRIVATE_KEY or JWT_PRIVATE_KEY_FILE must be set in production. '
                'Generate with: scripts/gen-jwt-keys.sh'
            )
        if not self.JWT_PUBLIC_KEY:
            raise RuntimeError(
                'JWT_PUBLIC_KEY or JWT_PUBLIC_KEY_FILE must be set in production. '
                'Generate with: scripts/gen-jwt-keys.sh'
            )


class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    DB_URL = 'sqlite:///:memory:'
    RATELIMIT_STORAGE_URL = None  # Use MemoryStorage for tests
    # Testing-only ephemeral secrets (never use in production)
    SECRET_KEY = 'test-ephemeral-secret-key-only'
    JWT_SECRET_KEY = 'test-ephemeral-jwt-key-only'

    def __init__(self) -> None:
        """Generate ephemeral ES256 keypair for testing."""
        super().__init__()
        # Always generate a fresh ES256 keypair for tests
        from app.utils.crypto import generate_ephemeral_es256_keypair
        self.JWT_PRIVATE_KEY, self.JWT_PUBLIC_KEY = (
            generate_ephemeral_es256_keypair()
        )


# Config dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': ProductionConfig
}
