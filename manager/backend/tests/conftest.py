"""
Test fixtures for manager/backend.

Provides a penguin-dal DB backed by file-based SQLite with
the full schema pre-created from app/schema.py.
"""

import os
import sys

import pytest
from sqlalchemy import create_engine, text

# Ensure app package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


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
def app(db_engine):
    """Flask app configured for testing."""
    from app import create_app
    from app.config import TestingConfig

    _, db_path = db_engine

    class _TestConfig(TestingConfig):
        DB_URL = f"sqlite:///{db_path}"
        TESTING = True
        WTF_CSRF_ENABLED = False

    flask_app = create_app(config_class=_TestConfig)
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
