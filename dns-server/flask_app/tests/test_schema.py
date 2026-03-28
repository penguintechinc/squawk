"""Tests for schema.py — SQLAlchemy table definitions."""
from sqlalchemy import create_engine, inspect


def test_schema_creates_all_tables():
    """Schema must define all 14 tables and create them in SQLite."""
    from flask_app.schema import metadata

    engine = create_engine("sqlite:///:memory:")
    metadata.create_all(engine)
    insp = inspect(engine)
    tables = set(insp.get_table_names())

    assert "auth_user" in tables
    assert "dns_query_log" in tables
    assert "ioc_feed" in tables
    assert "ioc_entry" in tables
    assert "whois_cache" in tables
    assert "client_config" in tables
    assert "internal_domain" in tables
    assert "internal_domain_group" in tables
    assert "internal_domain_user" in tables
    assert "dns_group" in tables
    assert "dns_zone" in tables
    assert "dns_record" in tables
    assert "dns_permission" in tables
    assert "blocked_query" in tables
    assert len(tables) == 14
    engine.dispose()
