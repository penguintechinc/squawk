"""
Minimal test configuration for working features only
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


def pytest_unconfigure(config: Any) -> None:
    """Clean up test database."""
    global _test_db_tmp
    if _test_db_tmp and os.path.exists(_test_db_tmp):
        os.unlink(_test_db_tmp)
