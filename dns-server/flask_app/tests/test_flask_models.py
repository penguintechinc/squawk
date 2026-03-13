"""
Tests for Flask database models
"""
import pytest
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestDefineTablesFunction:
    """Test the define_tables function in models.py"""

    def test_define_tables_returns_db(self):
        """Test that define_tables returns the db object"""
        from pydal import DAL
        from models import define_tables

        # Create a fresh in-memory db
        test_db = DAL('sqlite:memory', folder='/tmp', migrate=False)
        result = define_tables(test_db)
        assert result is test_db

    def test_define_tables_creates_auth_user(self):
        """Test auth_user table is created with correct fields"""
        from pydal import DAL
        from models import define_tables

        test_db = DAL('sqlite:memory', folder='/tmp', migrate=False)
        define_tables(test_db)

        assert 'auth_user' in test_db.tables
        field_names = [f.name for f in test_db.auth_user]
        assert 'email' in field_names
        assert 'password' in field_names
        assert 'first_name' in field_names
        assert 'last_name' in field_names
        assert 'is_active' in field_names
        assert 'is_admin' in field_names
        assert 'created_on' in field_names
        assert 'modified_on' in field_names

    def test_define_tables_creates_dns_query_log(self):
        """Test dns_query_log table is created"""
        from pydal import DAL
        from models import define_tables

        test_db = DAL('sqlite:memory', folder='/tmp', migrate=False)
        define_tables(test_db)

        assert 'dns_query_log' in test_db.tables
        field_names = [f.name for f in test_db.dns_query_log]
        assert 'timestamp' in field_names
        assert 'client_ip' in field_names
        assert 'domain' in field_names
        assert 'record_type' in field_names
        assert 'response_status' in field_names
        assert 'cache_hit' in field_names
        assert 'processing_time_ms' in field_names

    def test_define_tables_creates_ioc_feed(self):
        """Test ioc_feed table is created"""
        from pydal import DAL
        from models import define_tables

        test_db = DAL('sqlite:memory', folder='/tmp', migrate=False)
        define_tables(test_db)

        assert 'ioc_feed' in test_db.tables
        field_names = [f.name for f in test_db.ioc_feed]
        assert 'name' in field_names
        assert 'url' in field_names
        assert 'feed_type' in field_names
        assert 'is_active' in field_names
        assert 'last_updated' in field_names
        assert 'update_frequency_hours' in field_names

    def test_define_tables_creates_ioc_entry(self):
        """Test ioc_entry table is created"""
        from pydal import DAL
        from models import define_tables

        test_db = DAL('sqlite:memory', folder='/tmp', migrate=False)
        define_tables(test_db)

        assert 'ioc_entry' in test_db.tables
        field_names = [f.name for f in test_db.ioc_entry]
        assert 'feed_id' in field_names
        assert 'indicator' in field_names
        assert 'indicator_type' in field_names
        assert 'threat_level' in field_names

    def test_define_tables_creates_whois_cache(self):
        """Test whois_cache table is created"""
        from pydal import DAL
        from models import define_tables

        test_db = DAL('sqlite:memory', folder='/tmp', migrate=False)
        define_tables(test_db)

        assert 'whois_cache' in test_db.tables
        field_names = [f.name for f in test_db.whois_cache]
        assert 'domain' in field_names
        assert 'whois_data' in field_names
        assert 'cached_at' in field_names
        assert 'expires_at' in field_names

    def test_define_tables_creates_internal_domain(self):
        """Test internal_domain table is created"""
        from pydal import DAL
        from models import define_tables

        test_db = DAL('sqlite:memory', folder='/tmp', migrate=False)
        define_tables(test_db)

        assert 'internal_domain' in test_db.tables
        field_names = [f.name for f in test_db.internal_domain]
        assert 'name' in field_names
        assert 'ip_address' in field_names
        assert 'access_type' in field_names
        assert 'is_active' in field_names

    def test_define_tables_creates_internal_domain_group(self):
        """Test internal_domain_group table is created"""
        from pydal import DAL
        from models import define_tables

        test_db = DAL('sqlite:memory', folder='/tmp', migrate=False)
        define_tables(test_db)

        assert 'internal_domain_group' in test_db.tables

    def test_define_tables_creates_internal_domain_user(self):
        """Test internal_domain_user table is created"""
        from pydal import DAL
        from models import define_tables

        test_db = DAL('sqlite:memory', folder='/tmp', migrate=False)
        define_tables(test_db)

        assert 'internal_domain_user' in test_db.tables

    def test_define_tables_creates_client_config(self):
        """Test client_config table is created"""
        from pydal import DAL
        from models import define_tables

        test_db = DAL('sqlite:memory', folder='/tmp', migrate=False)
        define_tables(test_db)

        assert 'client_config' in test_db.tables

    def test_auth_user_default_values(self):
        """Test auth_user table has correct default values"""
        from pydal import DAL
        from models import define_tables
        from werkzeug.security import generate_password_hash

        test_db = DAL('sqlite:memory', folder='/tmp', migrate=False)
        define_tables(test_db)

        user_id = test_db.auth_user.insert(
            email='defaults@test.com',
            password=generate_password_hash('test123')
        )
        test_db.commit()

        user = test_db(test_db.auth_user.id == user_id).select().first()
        assert user.is_active is True   # default
        assert user.is_admin is False   # default

    def test_auth_user_email_is_stored(self):
        """Test that email is stored correctly in auth_user."""
        from pydal import DAL
        from models import define_tables
        from werkzeug.security import generate_password_hash

        test_db = DAL('sqlite:memory', folder='/tmp', migrate=False)
        define_tables(test_db)

        uid = test_db.auth_user.insert(
            email='store@test.com',
            password=generate_password_hash('x')
        )
        test_db.commit()
        user = test_db(test_db.auth_user.id == uid).select().first()
        assert user.email == 'store@test.com'

    def test_dns_query_log_default_record_type(self):
        """Test that dns_query_log default record_type is 'A'."""
        from pydal import DAL
        from models import define_tables

        test_db = DAL('sqlite:memory', folder='/tmp', migrate=False)
        define_tables(test_db)

        lid = test_db.dns_query_log.insert(domain='test.com')
        test_db.commit()
        log = test_db(test_db.dns_query_log.id == lid).select().first()
        assert log.record_type == 'A'

    def test_dns_query_log_cache_hit_defaults_false(self):
        """Test that cache_hit defaults to False in dns_query_log."""
        from pydal import DAL
        from models import define_tables

        test_db = DAL('sqlite:memory', folder='/tmp', migrate=False)
        define_tables(test_db)

        lid = test_db.dns_query_log.insert(domain='nocache.com')
        test_db.commit()
        log = test_db(test_db.dns_query_log.id == lid).select().first()
        assert log.cache_hit is False

    def test_ioc_feed_default_is_active(self):
        """Test that ioc_feed is_active defaults to True."""
        from pydal import DAL
        from models import define_tables

        test_db = DAL('sqlite:memory', folder='/tmp', migrate=False)
        define_tables(test_db)

        fid = test_db.ioc_feed.insert(name='DefaultFeed', url='https://example.com/f')
        test_db.commit()
        feed = test_db(test_db.ioc_feed.id == fid).select().first()
        assert feed.is_active is True

    def test_ioc_feed_default_update_frequency(self):
        """Test that ioc_feed update_frequency_hours defaults to 24."""
        from pydal import DAL
        from models import define_tables

        test_db = DAL('sqlite:memory', folder='/tmp', migrate=False)
        define_tables(test_db)

        fid = test_db.ioc_feed.insert(name='FreqFeed', url='https://example.com/freq')
        test_db.commit()
        feed = test_db(test_db.ioc_feed.id == fid).select().first()
        assert feed.update_frequency_hours == 24

    def test_internal_domain_default_access_type(self):
        """Test that internal_domain access_type defaults to 'all'."""
        from pydal import DAL
        from models import define_tables

        test_db = DAL('sqlite:memory', folder='/tmp', migrate=False)
        define_tables(test_db)

        did = test_db.internal_domain.insert(
            name='default.local',
            ip_address='10.0.0.1'
        )
        test_db.commit()
        domain = test_db(test_db.internal_domain.id == did).select().first()
        assert domain.access_type == 'all'

    def test_internal_domain_default_is_active(self):
        """Test that internal_domain is_active defaults to True."""
        from pydal import DAL
        from models import define_tables

        test_db = DAL('sqlite:memory', folder='/tmp', migrate=False)
        define_tables(test_db)

        did = test_db.internal_domain.insert(
            name='active.local',
            ip_address='10.0.0.2'
        )
        test_db.commit()
        domain = test_db(test_db.internal_domain.id == did).select().first()
        assert domain.is_active is True

    def test_all_tables_created_in_one_call(self):
        """Test that a single call to define_tables creates all expected tables."""
        from pydal import DAL
        from models import define_tables

        test_db = DAL('sqlite:memory', folder='/tmp', migrate=False)
        define_tables(test_db)

        expected = {
            'auth_user', 'dns_query_log', 'ioc_feed', 'ioc_entry',
            'whois_cache', 'client_config', 'internal_domain',
            'internal_domain_group', 'internal_domain_user'
        }
        for table_name in expected:
            assert table_name in test_db.tables, f"Missing table: {table_name}"

    def test_define_tables_idempotent(self):
        """
        Calling define_tables twice on the same DAL raises no error
        because PyDAL will reuse the already-defined table.
        """
        from pydal import DAL
        from models import define_tables

        test_db = DAL('sqlite:memory', folder='/tmp', migrate=False)
        define_tables(test_db)
        # Second call should not raise
        try:
            define_tables(test_db)
        except Exception as e:
            pytest.fail(f"define_tables raised on second call: {e}")

    def test_client_config_fields(self):
        """Test client_config table has expected fields."""
        from pydal import DAL
        from models import define_tables

        test_db = DAL('sqlite:memory', folder='/tmp', migrate=False)
        define_tables(test_db)

        field_names = [f.name for f in test_db.client_config]
        assert 'client_id' in field_names
        assert 'config_data' in field_names
        assert 'created_at' in field_names
        assert 'updated_at' in field_names

    def test_internal_domain_group_fields(self):
        """Test internal_domain_group table has expected fields."""
        from pydal import DAL
        from models import define_tables

        test_db = DAL('sqlite:memory', folder='/tmp', migrate=False)
        define_tables(test_db)

        field_names = [f.name for f in test_db.internal_domain_group]
        assert 'domain_id' in field_names
        assert 'group_name' in field_names
        assert 'created_on' in field_names

    def test_internal_domain_user_fields(self):
        """Test internal_domain_user table has expected fields."""
        from pydal import DAL
        from models import define_tables

        test_db = DAL('sqlite:memory', folder='/tmp', migrate=False)
        define_tables(test_db)

        field_names = [f.name for f in test_db.internal_domain_user]
        assert 'domain_id' in field_names
        assert 'user_id' in field_names
        assert 'created_on' in field_names
