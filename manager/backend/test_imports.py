#!/usr/bin/env python3
"""
Test script to verify all imports work correctly.
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

def test_imports():
    """Test that all modules can be imported."""
    print("Testing imports...")

    try:
        # Core app
        from app import create_app
        print("✓ app.create_app")

        from app.config import Config
        print("✓ app.config.Config")

        from app.db import init_db
        print("✓ app.db.init_db")

        # Models
        from app.models.auth import define_auth_tables
        print("✓ app.models.auth")

        from app.models.team import define_team_tables
        print("✓ app.models.team")

        from app.models.dns_server import define_dns_server_tables
        print("✓ app.models.dns_server")

        from app.models.dns import define_dns_tables
        print("✓ app.models.dns")

        from app.models.config import define_config_tables
        print("✓ app.models.config")

        # Services
        from app.services.auth_service import AuthService
        print("✓ app.services.auth_service")

        from app.services.join_key_service import JoinKeyService
        print("✓ app.services.join_key_service")

        from app.services.config_service import ConfigService
        print("✓ app.services.config_service")

        from app.services.license_service import LicenseService
        print("✓ app.services.license_service")

        # Middleware
        from app.middleware.auth import token_required
        print("✓ app.middleware.auth")

        from app.middleware.rbac import requires_role
        print("✓ app.middleware.rbac")

        # Utils
        from app.utils.validators import validate_email
        print("✓ app.utils.validators")

        from app.utils.decorators import requires_enterprise_license
        print("✓ app.utils.decorators")

        # Blueprints
        from app.blueprints.auth import auth_bp
        print("✓ app.blueprints.auth")

        from app.blueprints.users import users_bp
        print("✓ app.blueprints.users")

        from app.blueprints.teams import teams_bp
        print("✓ app.blueprints.teams")

        from app.blueprints.dns_servers import dns_servers_bp
        print("✓ app.blueprints.dns_servers")

        from app.blueprints.zones import zones_bp
        print("✓ app.blueprints.zones")

        from app.blueprints.ioc_feeds import ioc_feeds_bp
        print("✓ app.blueprints.ioc_feeds")

        from app.blueprints.analytics import analytics_bp
        print("✓ app.blueprints.analytics")

        from app.blueprints.tokens import tokens_bp
        print("✓ app.blueprints.tokens")

        print("\n✅ All imports successful!")
        return True

    except ImportError as e:
        print(f"\n❌ Import error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_app_creation():
    """Test creating Flask app."""
    print("\nTesting app creation...")

    try:
        from app import create_app
        app = create_app()
        print(f"✓ Flask app created: {app.name}")
        print(f"✓ Debug mode: {app.debug}")
        print(f"✓ Blueprints registered: {len(app.blueprints)}")
        print("\n✅ App creation successful!")
        return True

    except Exception as e:
        print(f"\n❌ App creation error: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    print("=" * 60)
    print("Squawk DNS Manager - Import Test")
    print("=" * 60)
    print()

    success = True

    if not test_imports():
        success = False

    if not test_app_creation():
        success = False

    print()
    print("=" * 60)
    if success:
        print("✅ ALL TESTS PASSED")
        sys.exit(0)
    else:
        print("❌ SOME TESTS FAILED")
        sys.exit(1)
