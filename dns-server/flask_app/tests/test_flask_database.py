"""
Tests for Flask database initialization
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestDatabaseInit:
    """Test database initialization and connection"""

    def test_db_is_dal_instance(self):
        """Test that db is a PyDAL DAL instance"""
        from pydal import DAL
        from database import db
        assert isinstance(db, DAL)

    def test_db_has_required_tables(self):
        """Test that required tables are defined"""
        from database import db
        expected_tables = [
            'auth_user', 'dns_query_log', 'ioc_feed', 'ioc_entry',
            'whois_cache', 'client_config', 'internal_domain',
            'internal_domain_group', 'internal_domain_user'
        ]
        for table in expected_tables:
            assert table in db.tables, f"Table {table} not found in db"

    def test_db_connection_is_reusable(self):
        """Test that the db connection can be used for queries"""
        from database import db
        # Should be able to execute a simple query
        count = db(db.auth_user).count()
        assert isinstance(count, int)

    def test_db_auth_user_fields(self):
        """Test auth_user table has required fields"""
        from database import db
        table = db.auth_user
        field_names = [f.name for f in table]
        assert 'email' in field_names
        assert 'password' in field_names
        assert 'is_admin' in field_names
        assert 'is_active' in field_names

    def test_db_dns_query_log_fields(self):
        """Test dns_query_log table has required fields"""
        from database import db
        table = db.dns_query_log
        field_names = [f.name for f in table]
        assert 'domain' in field_names
        assert 'timestamp' in field_names
        assert 'cache_hit' in field_names

    def test_db_ioc_feed_fields(self):
        """Test ioc_feed table has required fields"""
        from database import db
        table = db.ioc_feed
        field_names = [f.name for f in table]
        assert 'name' in field_names
        assert 'url' in field_names
        assert 'is_active' in field_names

    def test_db_insert_and_query(self):
        """Test that db can insert and retrieve records"""
        from database import db
        from werkzeug.security import generate_password_hash

        # Insert a test record
        user_id = db.auth_user.insert(
            email='dbtest@example.com',
            password=generate_password_hash('test123'),
            first_name='DB',
            last_name='Test',
            is_active=True,
            is_admin=False
        )
        db.commit()
        assert user_id is not None

        # Query it back
        user = db(db.auth_user.id == user_id).select().first()
        assert user is not None
        assert user.email == 'dbtest@example.com'

        # Cleanup
        db(db.auth_user.id == user_id).delete()
        db.commit()

    def test_db_update_record(self):
        """Test that db can update records"""
        from database import db
        from werkzeug.security import generate_password_hash

        user_id = db.auth_user.insert(
            email='update_test@example.com',
            password=generate_password_hash('test123'),
            first_name='Update',
            last_name='Test',
            is_active=True,
            is_admin=False
        )
        db.commit()

        db(db.auth_user.id == user_id).update(first_name='Updated')
        db.commit()

        user = db(db.auth_user.id == user_id).select().first()
        assert user.first_name == 'Updated'

        db(db.auth_user.id == user_id).delete()
        db.commit()

    def test_db_delete_record(self):
        """Test that db can delete records"""
        from database import db
        from werkzeug.security import generate_password_hash

        user_id = db.auth_user.insert(
            email='delete_test@example.com',
            password=generate_password_hash('test123'),
            is_active=True, is_admin=False
        )
        db.commit()

        db(db.auth_user.id == user_id).delete()
        db.commit()

        user = db(db.auth_user.id == user_id).select().first()
        assert user is None

    def test_db_count_returns_integer(self):
        """Test that count() returns an integer."""
        from database import db
        result = db(db.dns_query_log).count()
        assert isinstance(result, int)
        assert result >= 0

    def test_db_select_returns_rows_object(self):
        """Test that select() returns an iterable Rows object."""
        from database import db
        rows = db(db.ioc_feed).select()
        # Should be iterable
        count = 0
        for _ in rows:
            count += 1
        assert isinstance(count, int)

    def test_db_query_nonexistent_returns_none(self):
        """Test that querying a non-existent id returns None via .first()."""
        from database import db
        result = db(db.auth_user.id == 999999999).select().first()
        assert result is None

    def test_db_rollback_on_error(self):
        """Test that rollback leaves db in consistent state."""
        from database import db
        try:
            # Attempt to insert without required field to force an error path
            db.auth_user.insert(email=None, password='x')
            db.commit()
        except Exception:
            db.rollback()

        # DB should still be queryable after rollback
        count = db(db.auth_user).count()
        assert isinstance(count, int)

    def test_db_ioc_entry_fields(self):
        """Test ioc_entry table has required fields"""
        from database import db
        table = db.ioc_entry
        field_names = [f.name for f in table]
        assert 'feed_id' in field_names
        assert 'indicator' in field_names
        assert 'indicator_type' in field_names
        assert 'threat_level' in field_names

    def test_db_whois_cache_fields(self):
        """Test whois_cache table has required fields"""
        from database import db
        table = db.whois_cache
        field_names = [f.name for f in table]
        assert 'domain' in field_names
        assert 'whois_data' in field_names
        assert 'cached_at' in field_names
        assert 'expires_at' in field_names

    def test_db_internal_domain_fields(self):
        """Test internal_domain table has required fields"""
        from database import db
        table = db.internal_domain
        field_names = [f.name for f in table]
        assert 'name' in field_names
        assert 'ip_address' in field_names
        assert 'access_type' in field_names
        assert 'is_active' in field_names
