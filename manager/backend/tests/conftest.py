"""
Test fixtures for manager/backend.

Provides a penguin-dal DB backed by file-based SQLite with
the full schema pre-created from app/schema.py.
Includes ES256 JWT keypair fixtures for asymmetric token signing/verification.
"""

import os
import sys
from unittest.mock import MagicMock

import pytest
import jwt
from sqlalchemy import create_engine, text

# Ensure app package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Mock penguin_limiter which is not yet published
sys.modules['penguin_limiter'] = MagicMock()
sys.modules['penguin_limiter.storage'] = MagicMock()
sys.modules['penguin_limiter.storage.redis_store'] = MagicMock()


@pytest.fixture(scope="session")
def db_engine(tmp_path_factory):
    """Create a session-scoped SQLite engine with full schema."""
    from app.schema import metadata

    db_file = tmp_path_factory.mktemp("db") / "test_manager.db"
    engine = create_engine(f"sqlite:///{db_file}")
    metadata.create_all(engine)
    yield engine, str(db_file)
    metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture(scope="session")
def db(db_engine):
    """penguin-dal DB instance for tests."""
    from penguin_dal import DB

    _, db_path = db_engine
    test_db = DB(f"sqlite:///{db_path}")
    yield test_db
    test_db.close()


@pytest.fixture(scope="session")
def app(db_engine, jwt_keypair):
    """Flask app configured for testing."""
    from app import create_app
    from app.config import TestingConfig

    _, db_path = db_engine

    class _TestConfig(TestingConfig):
        DB_URL = f"sqlite:///{db_path}"
        TESTING = True
        WTF_CSRF_ENABLED = False

    flask_app = create_app(config_class=_TestConfig)

    # Ensure JWT keys are set (since __init__ is not called by from_object)
    flask_app.config['JWT_PRIVATE_KEY'] = jwt_keypair['private']
    flask_app.config['JWT_PUBLIC_KEY'] = jwt_keypair['public']

    with flask_app.app_context():
        yield flask_app


@pytest.fixture
def client(app):
    """Flask test client."""
    return app.test_client()


@pytest.fixture(autouse=True)
def clean_tables(db):
    """Wipe all rows between tests."""
    yield
    from app.schema import metadata

    with db.engine.connect() as conn:
        conn.execute(text("PRAGMA foreign_keys = OFF"))
        for table in reversed(metadata.sorted_tables):
            conn.execute(table.delete())
        conn.execute(text("PRAGMA foreign_keys = ON"))
        conn.commit()


@pytest.fixture(scope="session")
def jwt_keypair():
    """Generate an ephemeral ES256 keypair for testing (shared helper)."""
    from app.utils.crypto import generate_ephemeral_es256_keypair

    private_pem, public_pem = generate_ephemeral_es256_keypair()
    return {
        'private': private_pem,
        'public': public_pem
    }


@pytest.fixture
def jwt_token_factory(jwt_keypair):
    """Factory to create valid ES256 JWT tokens for testing."""
    def _make_token(user_id: int = 1, username: str = "testuser",
                    global_role: str = "Viewer", team_roles: dict = None,
                    token_type: str = "access", tenant: str = "default",
                    issuer: str = "squawk-manager", audience: str = "squawk",
                    expired: bool = False) -> str:
        """Create a valid JWT token with ES256 signature."""
        from datetime import datetime, timedelta

        now = datetime.utcnow()
        if expired:
            exp = now - timedelta(hours=1)
        else:
            exp = now + timedelta(hours=1)

        from app.services.scopes import scope_string

        payload = {
            'sub': str(user_id),
            'iss': issuer,
            'aud': audience,
            'tenant': tenant,
            'user_id': user_id,
            'username': username,
            'scope': scope_string(global_role, team_roles),
            'global_role': global_role,
            'team_roles': team_roles or {},
            'type': token_type,
            'exp': exp,
            'iat': now
        }
        return jwt.encode(payload, jwt_keypair['private'], algorithm='ES256')

    return _make_token


@pytest.fixture
def jwt_invalid_token_factory():
    """Factory to create invalid JWT tokens (HS256, missing claims, etc)."""
    def _make_hs256_token(user_id: int = 1) -> str:
        """Create an HS256-signed token (should be REJECTED)."""
        from datetime import datetime, timedelta
        payload = {
            'user_id': user_id,
            'type': 'access',
            'exp': datetime.utcnow() + timedelta(hours=1),
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, 'shared-secret', algorithm='HS256')

    def _make_missing_tenant_token(jwt_keypair, user_id: int = 1) -> str:
        """Create an ES256 token missing the tenant claim."""
        from datetime import datetime, timedelta
        payload = {
            'sub': str(user_id),
            'iss': 'squawk-manager',
            'aud': 'squawk',
            # Intentionally missing 'tenant'
            'user_id': user_id,
            'type': 'access',
            'exp': datetime.utcnow() + timedelta(hours=1),
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, jwt_keypair['private'], algorithm='ES256')

    def _make_wrong_aud_token(jwt_keypair, user_id: int = 1) -> str:
        """Create an ES256 token with wrong audience."""
        from datetime import datetime, timedelta
        payload = {
            'sub': str(user_id),
            'iss': 'squawk-manager',
            'aud': 'wrong-audience',  # Should be 'squawk'
            'tenant': 'default',
            'user_id': user_id,
            'type': 'access',
            'exp': datetime.utcnow() + timedelta(hours=1),
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, jwt_keypair['private'], algorithm='ES256')

    def _make_wrong_iss_token(jwt_keypair, user_id: int = 1) -> str:
        """Create an ES256 token with wrong issuer."""
        from datetime import datetime, timedelta
        payload = {
            'sub': str(user_id),
            'iss': 'wrong-issuer',  # Should be 'squawk-manager'
            'aud': 'squawk',
            'tenant': 'default',
            'user_id': user_id,
            'type': 'access',
            'exp': datetime.utcnow() + timedelta(hours=1),
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, jwt_keypair['private'], algorithm='ES256')

    return {
        'hs256': _make_hs256_token,
        'missing_tenant': _make_missing_tenant_token,
        'wrong_aud': _make_wrong_aud_token,
        'wrong_iss': _make_wrong_iss_token
    }
