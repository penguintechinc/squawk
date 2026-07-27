"""
Minimal test configuration for working features only
Includes ES256 JWT keypair fixtures for asymmetric token verification.
"""

import pytest
import asyncio
import os
import sys
import tempfile
from unittest.mock import Mock, patch
from sqlalchemy import create_engine
from collections.abc import Generator
from typing import Any
from sqlalchemy.engine import Engine
from penguin_dal import DB
import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta

# Resolve the shared SQLAlchemy schema. In the repo the canonical authority is
# manager/backend/app/schema.py; inside the dns-server container image that tree
# is NOT present (the image ships dns-server/ only), so fall back to an empty
# MetaData — these dns-server unit tests exercise app/services logic and do not
# depend on manager-owned tables.
manager_app_path = os.path.join(
    os.path.dirname(__file__), "..", "..", "manager", "backend", "app"
)
if manager_app_path not in sys.path:
    sys.path.insert(0, manager_app_path)

try:
    from schema import metadata as _schema_metadata
except ImportError:
    from sqlalchemy import MetaData
    _schema_metadata = MetaData()

# Generate ephemeral ES256 keypair for testing (module-level, before any app.* import)
# This must happen BEFORE JWT_PUBLIC_KEY env var is set, so tests can verify tokens correctly.
_test_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
_test_private_pem = _test_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8')
_test_public_key = _test_private_key.public_key()
_test_public_pem = _test_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')
_test_keypair = {
    'private': _test_private_pem,
    'public': _test_public_pem
}

# Create a temp cache directory for this test session (must happen BEFORE any app.* import,
# since app.config.CACHE_DIR is read at module import time by ManagerClient.__init__)
_test_cache_dir = tempfile.mkdtemp(prefix="squawk_test_cache_")
os.environ["CACHE_DIR"] = _test_cache_dir

# Set JWT_PUBLIC_KEY for app.config (must happen BEFORE any app.* import)
os.environ["JWT_PUBLIC_KEY"] = _test_public_pem

# Create a temp SQLite file for this test session
_fd, _test_db_tmp = tempfile.mkstemp(suffix=".db", prefix="squawk_test_")
os.close(_fd)
os.environ["DATABASE_URI"] = f"sqlite:///{_test_db_tmp}"

# Create schema so penguin-dal can reflect tables (no-op if metadata is empty)
_engine = create_engine(f"sqlite:///{_test_db_tmp}")
_schema_metadata.create_all(_engine)
_engine.dispose()


@pytest.fixture(scope="session")
def event_loop() -> Generator[Any, None, None]:
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def db_engine() -> Generator[Engine, None, None]:
    """SQLAlchemy engine for test database (session-scoped)."""
    engine = create_engine(os.environ["DATABASE_URI"])
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def db(db_engine: Engine) -> Generator[DB, None, None]:
    """penguin-dal DB instance connected to test SQLite database."""
    test_db = DB(os.environ["DATABASE_URI"])
    yield test_db
    test_db.close()


@pytest.fixture(autouse=True)
def clean_db_tables(db: DB) -> Generator[None, None, None]:
    """Truncate all tables before each test for isolation."""
    yield
    from sqlalchemy import text

    with db.engine.connect() as conn:
        conn.execute(text("PRAGMA foreign_keys = OFF"))
        for table in reversed(_schema_metadata.sorted_tables):
            conn.execute(table.delete())
        conn.execute(text("PRAGMA foreign_keys = ON"))
        conn.commit()


@pytest.fixture
def mock_dns_resolver() -> Generator[Any, None, None]:
    """Mock DNS resolver for testing"""
    with patch("dns.resolver.Resolver") as mock_resolver:
        mock_answer = Mock()
        mock_answer.to_text.return_value = "93.184.216.34"

        mock_resolver_instance = Mock()
        mock_resolver_instance.resolve.return_value = [mock_answer]
        mock_resolver.return_value = mock_resolver_instance

        yield mock_resolver_instance


@pytest.fixture
def invalid_domains() -> list[str]:
    """List of invalid domain names for testing"""
    return [
        "",  # Empty domain
        "invalid..domain",  # Double dots
        "domain-",  # Trailing hyphen
        "-domain",  # Leading hyphen
        "very-long-domain-name-that-exceeds-the-maximum-length-limit-of-sixty-three-characters.com",
        "domain with spaces",  # Spaces
        "domain@invalid",  # Invalid characters
        "domain\x00.com",  # Null character
        "javascript:alert(1)",  # XSS attempt
    ]


@pytest.fixture
def valid_domains() -> list[str]:
    """List of valid domain names for testing"""
    return [
        "example.com",
        "subdomain.example.com",
        "test-domain.co.uk",
        "a.b.c.example.org",
        "123.example.com",
        "localhost",
        "*.example.com",  # Wildcard
    ]


@pytest.fixture(scope="session")
def jwt_keypair():
    """Return the ephemeral ES256 keypair generated at module level for testing.

    The keypair is generated before any app.* import so that JWT_PUBLIC_KEY env var
    can be set correctly for app.config verification.
    """
    return _test_keypair


@pytest.fixture
def jwt_token_factory(jwt_keypair):
    """Factory to create valid ES256 JWT tokens for testing."""
    def _make_token(user_id: int = 1, username: str = "testuser",
                    global_role: str = "Viewer", team_roles: dict = None,
                    token_type: str = "access", tenant: str = "default",
                    issuer: str = "squawk-manager", audience: str = "squawk",
                    expired: bool = False) -> str:
        """Create a valid JWT token with ES256 signature."""
        now = datetime.utcnow()
        if expired:
            exp = now - timedelta(hours=1)
        else:
            exp = now + timedelta(hours=1)

        payload = {
            'sub': str(user_id),
            'iss': issuer,
            'aud': audience,
            'tenant': tenant,
            'user_id': user_id,
            'username': username,
            'global_role': global_role,
            'team_roles': team_roles or {},
            'type': token_type,
            'exp': exp,
            'iat': now
        }
        return jwt.encode(payload, jwt_keypair['private'], algorithm='ES256')

    return _make_token


@pytest.fixture
def app_with_rate_limiting():
    """Create a test app with rate limiting enabled."""
    from app.main import app, rate_limiter
    from app.services.rate_limiter import InMemoryBackend

    # Enable rate limiting for tests
    rate_limiter.enabled = True
    rate_limiter.rps = 2.0
    rate_limiter.burst = 3.0

    # Reinitialize backend with new burst value (fixture changes don't propagate to already-initialized backend)
    rate_limiter.backend = InMemoryBackend(rps=rate_limiter.rps, burst=rate_limiter.burst)

    return app


def pytest_unconfigure(config: Any) -> None:
    """Clean up test database and cache directory."""
    global _test_db_tmp, _test_cache_dir
    if _test_db_tmp and os.path.exists(_test_db_tmp):
        os.unlink(_test_db_tmp)
    if _test_cache_dir and os.path.exists(_test_cache_dir):
        import shutil
        shutil.rmtree(_test_cache_dir, ignore_errors=True)
