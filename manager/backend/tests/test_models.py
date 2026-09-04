"""Tests for manager/backend app/models/* — Data model definitions."""
import os
import sys

from sqlalchemy import inspect

# Ensure app package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _get_table_names(db):
    """Get list of table names from database using SQLAlchemy 2.0+ API."""
    insp = inspect(db.engine)
    return insp.get_table_names()


def test_auth_tables_exist(db):
    """auth_user table should be created and have expected fields."""
    tables = _get_table_names(db)
    assert 'auth_user' in tables

    # Verify table structure
    insp = inspect(db.engine)
    cols = insp.get_columns('auth_user')
    # get_columns returns dicts with 'name' key in SQLAlchemy 2.0+
    columns = [col['name'] if isinstance(col, dict) else col.name for col in cols]

    expected_cols = ['id', 'username', 'email', 'password_hash', 'global_role', 'active', 'created_at', 'updated_at']
    for col in expected_cols:
        assert col in columns, f"Missing column: {col}"


def test_config_tables_exist(db):
    """ioc_feed and token tables should be created."""
    tables = _get_table_names(db)
    assert 'ioc_feed' in tables
    assert 'token' in tables

    insp = inspect(db.engine)

    # Check ioc_feed columns
    ioc_cols = [col['name'] if isinstance(col, dict) else col.name for col in insp.get_columns('ioc_feed')]
    assert 'name' in ioc_cols
    assert 'url' in ioc_cols
    assert 'feed_type' in ioc_cols
    assert 'active' in ioc_cols

    # Check token columns. Plaintext `token` is intentionally not a column
    # (hashed at rest, see [[fix-token-hash-at-rest]]) -- assert the hash
    # column instead.
    token_cols = [col['name'] if isinstance(col, dict) else col.name for col in insp.get_columns('token')]
    assert 'token_hash' in token_cols
    assert 'token' not in token_cols


def test_dns_tables_exist(db):
    """dns_zone and dns_record tables should be created."""
    tables = _get_table_names(db)
    assert 'dns_zone' in tables
    assert 'dns_record' in tables

    insp = inspect(db.engine)

    # Check dns_zone columns
    zone_cols = [col['name'] if isinstance(col, dict) else col.name for col in insp.get_columns('dns_zone')]
    assert 'name' in zone_cols
    assert 'team_id' in zone_cols
    assert 'visibility' in zone_cols

    # Check dns_record columns
    record_cols = [col['name'] if isinstance(col, dict) else col.name for col in insp.get_columns('dns_record')]
    assert 'zone_id' in record_cols
    assert 'name' in record_cols
    assert 'type' in record_cols


def test_dhcp_tables_exist(db):
    """DHCP-related tables should be created."""
    tables = _get_table_names(db)
    assert 'dhcp_pool' in tables
    assert 'dhcp_server' in tables
    assert 'dhcp_lease' in tables


def test_time_tables_exist(db):
    """Time-related tables should be created."""
    tables = _get_table_names(db)
    assert 'time_server' in tables
    assert 'time_sync_log' in tables


def test_team_tables_exist(db):
    """Team and team_member tables should be created."""
    tables = _get_table_names(db)
    assert 'team' in tables
    assert 'team_member' in tables
