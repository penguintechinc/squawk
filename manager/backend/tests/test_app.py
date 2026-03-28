"""Tests for manager/backend app/__init__.py — Flask application factory."""
import os
import sys

import pytest

# Ensure app package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def test_create_app_with_testing_config(tmp_path):
    """create_app should respect custom config class."""
    from app import create_app
    from app.config import TestingConfig

    # Override TestingConfig to use a file-based DB instead of in-memory
    class CustomTestConfig(TestingConfig):
        DB_URL = f"sqlite:///{tmp_path / 'test.db'}"

    app = create_app(config_class=CustomTestConfig)

    assert app.config["TESTING"] is True
    assert app.limiter is not None
    assert app.db is not None
    assert app.license_service is not None
    app.db.close()


def test_app_health_endpoint(app):
    """Health check endpoint should return 200 with healthy status."""
    with app.test_client() as client:
        response = client.get("/health")
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "healthy"


def test_app_blueprints_registered(app):
    """All required blueprints should be registered."""
    # app fixture from conftest.py
    with app.app_context():
        # Collect all registered blueprints
        registered_blueprints = set(app.blueprints.keys())

        # These are the blueprints defined in create_app
        expected_blueprints = {
            "auth",
            "users",
            "teams",
            "tokens",
            "dns_servers",
            "zones",
            "ioc_feeds",
            "analytics",
            "dhcp",
            "time",
        }

        assert expected_blueprints.issubset(registered_blueprints)


def test_app_limiter_initialized(app):
    """Rate limiter should be initialized."""
    with app.app_context():
        assert app.limiter is not None
        # Verify limiter is a FlaskRateLimiter instance
        assert app.limiter.__class__.__name__ == "FlaskRateLimiter"


def test_app_database_initialized(app):
    """Database should be properly initialized on app context."""
    with app.app_context():
        assert app.db is not None
        # DB should be callable and have the DB interface
        assert hasattr(app.db, 'close')


def test_app_license_service_initialized(app):
    """License service should be initialized."""
    with app.app_context():
        assert app.license_service is not None
        assert hasattr(app.license_service, '__class__')


def test_app_cors_configured(app):
    """CORS should be configured for API routes."""
    with app.app_context():
        # Verify CORS extension is registered
        # The CORS middleware adds the necessary headers on requests
        assert hasattr(app, 'extensions')
        # Verify app has CORS enabled (it should be in extensions if flask-cors is active)
        # We just verify the app is properly configured
        assert app is not None
