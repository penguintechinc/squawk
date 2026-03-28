"""Test fixtures for flask_app tests."""
import os
import sys
import tempfile
import pytest
from sqlalchemy import create_engine


def pytest_configure(config):
    """Set up test database before any test imports database.py."""
    # Create a temp SQLite file for this test session
    tmp = tempfile.mktemp(suffix=".db", prefix="squawk_test_")
    os.environ["DATABASE_URI"] = f"sqlite:///{tmp}"

    # Create schema so penguin-dal can reflect tables
    # Import here to ensure flask_app is on path first
    flask_app_path = os.path.join(os.path.dirname(__file__), "..")
    if flask_app_path not in sys.path:
        sys.path.insert(0, flask_app_path)

    from schema import metadata
    engine = create_engine(f"sqlite:///{tmp}")
    metadata.create_all(engine)
    engine.dispose()
    # Store path for cleanup
    config._test_db_path = tmp


def pytest_unconfigure(config):
    """Clean up test database."""
    db_path = getattr(config, "_test_db_path", None)
    if db_path and os.path.exists(db_path):
        os.unlink(db_path)


@pytest.fixture(autouse=True)
def clean_db_tables():
    """Truncate all tables before each test for isolation."""
    yield
    from schema import metadata
    from sqlalchemy import text
    # Import db to get engine
    from database import db

    with db.engine.connect() as conn:
        # Disable FK checks for SQLite truncation
        conn.execute(text("PRAGMA foreign_keys = OFF"))
        for table in reversed(metadata.sorted_tables):
            conn.execute(table.delete())
        conn.execute(text("PRAGMA foreign_keys = ON"))
        conn.commit()
