"""
Tests for Flask database schema

Note: models.py is now documentation-only. This file tests schema.py
which defines all SQLAlchemy tables that penguin-dal uses for reflection.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestSchemaMetadata:
    """Test SQLAlchemy schema metadata"""

    def test_schema_metadata_has_all_tables(self):
        """Test that schema.metadata defines all required tables"""
        from schema import metadata

        expected_tables = [
            'auth_user', 'dns_query_log', 'ioc_feed', 'ioc_entry',
            'whois_cache', 'client_config', 'internal_domain',
            'internal_domain_group', 'internal_domain_user'
        ]

        table_names = [t.name for t in metadata.sorted_tables]
        for table in expected_tables:
            assert table in table_names, f"Table {table} not found in schema"

    def test_auth_user_table_structure(self):
        """Test auth_user table has correct columns"""
        from schema import auth_user

        column_names = [c.name for c in auth_user.columns]
        assert 'id' in column_names
        assert 'email' in column_names
        assert 'password' in column_names
        assert 'first_name' in column_names
        assert 'last_name' in column_names
        assert 'is_active' in column_names
        assert 'is_admin' in column_names
        assert 'created_on' in column_names
        assert 'modified_on' in column_names

    def test_dns_query_log_table_structure(self):
        """Test dns_query_log table has correct columns"""
        from schema import dns_query_log

        column_names = [c.name for c in dns_query_log.columns]
        assert 'id' in column_names
        assert 'timestamp' in column_names
        assert 'client_ip' in column_names
        assert 'domain' in column_names
        assert 'record_type' in column_names
        assert 'response_status' in column_names
        assert 'cache_hit' in column_names
        assert 'processing_time_ms' in column_names
        assert 'user_id' in column_names

    def test_ioc_feed_table_structure(self):
        """Test ioc_feed table has correct columns"""
        from schema import ioc_feed

        column_names = [c.name for c in ioc_feed.columns]
        assert 'id' in column_names
        assert 'name' in column_names
        assert 'url' in column_names
        assert 'feed_type' in column_names
        assert 'is_active' in column_names
        assert 'last_updated' in column_names
        assert 'update_frequency_hours' in column_names

    def test_ioc_entry_table_structure(self):
        """Test ioc_entry table has correct columns"""
        from schema import ioc_entry

        column_names = [c.name for c in ioc_entry.columns]
        assert 'id' in column_names
        assert 'feed_id' in column_names
        assert 'indicator' in column_names
        assert 'indicator_type' in column_names
        assert 'threat_level' in column_names
        assert 'description' in column_names
        assert 'first_seen' in column_names
        assert 'last_seen' in column_names

    def test_whois_cache_table_structure(self):
        """Test whois_cache table has correct columns"""
        from schema import whois_cache

        column_names = [c.name for c in whois_cache.columns]
        assert 'id' in column_names
        assert 'domain' in column_names
        assert 'whois_data' in column_names
        assert 'cached_at' in column_names
        assert 'expires_at' in column_names

    def test_client_config_table_structure(self):
        """Test client_config table has correct columns"""
        from schema import client_config

        column_names = [c.name for c in client_config.columns]
        assert 'id' in column_names
        assert 'client_id' in column_names
        assert 'config_data' in column_names
        assert 'created_at' in column_names
        assert 'updated_at' in column_names
        assert 'user_id' in column_names

    def test_internal_domain_table_structure(self):
        """Test internal_domain table has correct columns"""
        from schema import internal_domain

        column_names = [c.name for c in internal_domain.columns]
        assert 'id' in column_names
        assert 'name' in column_names
        assert 'ip_address' in column_names
        assert 'description' in column_names
        assert 'access_type' in column_names
        assert 'is_active' in column_names
        assert 'created_on' in column_names
        assert 'modified_on' in column_names
        assert 'created_by' in column_names

    def test_internal_domain_group_table_structure(self):
        """Test internal_domain_group table has correct columns"""
        from schema import internal_domain_group

        column_names = [c.name for c in internal_domain_group.columns]
        assert 'id' in column_names
        assert 'domain_id' in column_names
        assert 'group_name' in column_names
        assert 'created_on' in column_names

    def test_internal_domain_user_table_structure(self):
        """Test internal_domain_user table has correct columns"""
        from schema import internal_domain_user

        column_names = [c.name for c in internal_domain_user.columns]
        assert 'id' in column_names
        assert 'domain_id' in column_names
        assert 'user_id' in column_names
        assert 'created_on' in column_names

    def test_schema_column_constraints(self):
        """Test that column constraints are properly defined"""
        from schema import auth_user, internal_domain

        # auth_user.email should be unique and not null
        email_col = auth_user.c.email
        assert email_col.unique is True
        assert email_col.nullable is False

        # internal_domain.name should be unique and not null
        name_col = internal_domain.c.name
        assert name_col.unique is True
        assert name_col.nullable is False

    def test_foreign_key_relationships(self):
        """Test that foreign keys are properly defined"""
        from schema import dns_query_log, ioc_entry, internal_domain_group, internal_domain_user

        # dns_query_log.user_id should reference auth_user.id
        user_id_fk = dns_query_log.c.user_id.foreign_keys
        assert len(user_id_fk) > 0

        # ioc_entry.feed_id should reference ioc_feed.id
        feed_id_fk = ioc_entry.c.feed_id.foreign_keys
        assert len(feed_id_fk) > 0

        # internal_domain_group.domain_id should reference internal_domain.id
        domain_id_fk = internal_domain_group.c.domain_id.foreign_keys
        assert len(domain_id_fk) > 0
