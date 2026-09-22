"""Tests for manager/backend app/utils/db_url.py — DB_URL scheme coercion."""
import os
import sys

# Ensure app package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.utils.db_url import to_sqlalchemy_url  # noqa: E402


def test_postgres_pydal_style_coerced():
    """PyDAL-style postgres:// becomes postgresql:// for SQLAlchemy."""
    assert (
        to_sqlalchemy_url("postgres://user:pass@host:5432/db")
        == "postgresql://user:pass@host:5432/db"
    )


def test_postgresql_already_correct_unchanged():
    """Already-SQLAlchemy postgresql:// passes through unchanged."""
    url = "postgresql://user:pass@host:5432/db"
    assert to_sqlalchemy_url(url) == url


def test_sqlite_pydal_style_relative_coerced():
    """PyDAL-style 2-slash sqlite:// becomes 3-slash sqlite:/// (relative)."""
    assert to_sqlalchemy_url("sqlite://storage.db") == "sqlite:///storage.db"


def test_sqlite_already_relative_unchanged():
    """Already-SQLAlchemy 3-slash relative sqlite URL passes through unchanged."""
    assert to_sqlalchemy_url("sqlite:///storage.db") == "sqlite:///storage.db"


def test_sqlite_already_absolute_unchanged():
    """Already-SQLAlchemy 4-slash absolute sqlite URL passes through unchanged."""
    url = "sqlite:////tmp/foo/test.db"
    assert to_sqlalchemy_url(url) == url


def test_sqlite_memory_aliases_normalized():
    """PyDAL-style in-memory aliases resolve to SQLAlchemy's bare in-memory URI."""
    assert to_sqlalchemy_url("sqlite:memory:") == "sqlite://"
    assert to_sqlalchemy_url("sqlite://:memory:") == "sqlite://"


def test_mysql_unaffected():
    """mysql:// is identical in both conventions -- left untouched."""
    url = "mysql://user:pass@host:3306/db"
    assert to_sqlalchemy_url(url) == url
