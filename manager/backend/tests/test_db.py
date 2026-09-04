"""Tests for manager/backend app/db.py — Database initialization."""
import os
import sys

import pytest

# Ensure app package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def test_init_db_returns_db_instance(tmp_path):
    """init_db should return a penguin-dal DB instance."""
    from app.db import init_db
    from penguin_dal import DB
    from unittest.mock import MagicMock

    db_file = tmp_path / "test_init.db"

    # Create a mock Flask app with config
    mock_app = MagicMock()
    mock_app.config = {"DB_URL": f"sqlite:///{db_file}"}

    db = init_db(mock_app)

    assert isinstance(db, DB)
    assert db is not None
    db.close()


def test_init_db_uses_configured_url(tmp_path):
    """init_db should use the DB_URL from app.config."""
    from app.db import init_db
    from unittest.mock import MagicMock

    db_file = tmp_path / "test_configured.db"
    db_url = f"sqlite:///{db_file}"

    mock_app = MagicMock()
    mock_app.config = {"DB_URL": db_url}

    db = init_db(mock_app)

    # Verify it was initialized with the right URL
    # penguin-dal DB should connect to the specified database
    assert db is not None
    assert hasattr(db, 'close')
    db.close()


def test_init_db_pool_size(tmp_path):
    """init_db should set connection pool_size to 10."""
    from app.db import init_db
    from unittest.mock import MagicMock, patch

    db_file = tmp_path / "test_pool.db"

    mock_app = MagicMock()
    mock_app.config = {"DB_URL": f"sqlite:///{db_file}"}

    # Patch penguin_dal.DB to verify pool_size argument
    with patch("app.db.DB") as mock_db_class:
        init_db(mock_app)

        # Verify DB was instantiated with pool_size=10
        mock_db_class.assert_called_once()
        call_args = mock_db_class.call_args
        assert call_args[0][0] == f"sqlite:///{db_file}"
        assert call_args[1]["pool_size"] == 10


def test_init_db_with_app_fixture(app):
    """init_db should work with Flask app fixture from conftest."""
    # app fixture from conftest.py is already initialized
    assert app.db is not None
    assert hasattr(app.db, 'close')
