"""Tests for manager/backend app/config.py — Configuration classes."""
import os
import sys
from datetime import timedelta

import pytest

# Ensure app package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def test_config_base_class():
    """Config class should define base configuration."""
    from app.config import Config

    # Check that Config class has these attributes
    assert hasattr(Config, 'DEBUG')
    assert hasattr(Config, 'SECRET_KEY')
    assert hasattr(Config, 'DB_URL')
    assert hasattr(Config, 'REDIS_URL')
    assert hasattr(Config, 'CACHE_TYPE')
    assert Config.CACHE_TYPE == 'RedisCache'
    assert Config.CACHE_DEFAULT_TIMEOUT == 300
    assert Config.RATELIMIT_ENABLED is True
    assert Config.MAX_WORKERS == 4
    assert Config.MAX_CONCURRENT_REQUESTS == 1000


def test_config_jwt_settings():
    """JWT configuration should be set."""
    from app.config import Config

    assert Config.JWT_SECRET_KEY == Config.SECRET_KEY  # defaults to SECRET_KEY
    assert Config.JWT_ACCESS_TOKEN_EXPIRES == timedelta(minutes=15)
    assert Config.JWT_REFRESH_TOKEN_EXPIRES == timedelta(days=7)


def test_config_mtls_disabled_by_default():
    """mTLS should be disabled by default."""
    from app.config import Config

    assert Config.ENABLE_MTLS is False


def test_config_license_server():
    """License server configuration should be present."""
    from app.config import Config

    assert Config.USE_LICENSE_SERVER is False
    assert 'license' in Config.LICENSE_SERVER_URL.lower()
    assert Config.LICENSE_KEY is None


def test_config_grpc_port():
    """gRPC port should be configured."""
    from app.config import Config

    assert Config.GRPC_PORT == 50051


def test_development_config():
    """DevelopmentConfig should enable debug mode."""
    from app.config import DevelopmentConfig

    assert hasattr(DevelopmentConfig, 'DEBUG')
    assert DevelopmentConfig.DEBUG is True


def test_production_config():
    """ProductionConfig should disable debug mode."""
    from app.config import ProductionConfig

    assert hasattr(ProductionConfig, 'DEBUG')
    assert ProductionConfig.DEBUG is False


def test_testing_config():
    """TestingConfig should enable testing mode."""
    from app.config import TestingConfig

    assert TestingConfig.TESTING is True
    assert TestingConfig.DB_URL == 'sqlite:///:memory:'
    assert TestingConfig.RATELIMIT_STORAGE_URL is None  # Use MemoryStorage


def test_config_dict():
    """config dictionary should map names to config classes."""
    from app.config import config, DevelopmentConfig, ProductionConfig, TestingConfig

    assert config['development'] == DevelopmentConfig
    assert config['production'] == ProductionConfig
    assert config['testing'] == TestingConfig
    assert config['default'] == DevelopmentConfig


def test_config_inheritance():
    """Development and Production configs should inherit from base Config."""
    from app.config import Config, DevelopmentConfig, ProductionConfig, TestingConfig

    assert issubclass(DevelopmentConfig, Config)
    assert issubclass(ProductionConfig, Config)
    assert issubclass(TestingConfig, Config)
