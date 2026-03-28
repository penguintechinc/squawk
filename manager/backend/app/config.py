"""
Configuration for Squawk DNS Manager.
"""

import os
from datetime import timedelta


class Config:
    """Base configuration."""

    # Flask
    DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')

    # JWT
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', SECRET_KEY)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)

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

    # Server
    MAX_WORKERS = int(os.getenv('MAX_WORKERS', 4))
    MAX_CONCURRENT_REQUESTS = int(os.getenv('MAX_CONCURRENT_REQUESTS', 1000))

    # Features
    ENABLE_MTLS = os.getenv('ENABLE_MTLS', 'false').lower() == 'true'

    # License server
    USE_LICENSE_SERVER = os.getenv('USE_LICENSE_SERVER', 'false').lower() == 'true'
    LICENSE_SERVER_URL = os.getenv('LICENSE_SERVER_URL', 'https://license.squawkdns.com')
    LICENSE_KEY = os.getenv('PENGUINTECH_LICENSE_KEY')

    # gRPC
    GRPC_PORT = int(os.getenv('GRPC_PORT', 50051))


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False


class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    DB_URL = 'sqlite:///:memory:'
    RATELIMIT_STORAGE_URL = None  # Use MemoryStorage for tests


# Config dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
