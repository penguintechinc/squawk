"""
Test suite for Flask Dashboard Blueprint - JSON API Only
Tests /api/v1/dashboard/*, /api/v1/domains, /api/v1/users, etc.
"""

import pytest
import sys
import os
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from werkzeug.security import generate_password_hash
from app import app
from database import db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    """Create test client with test config."""
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret-key'
    app.config['JWT_SECRET_KEY'] = 'test-jwt-secret'
    app.config['WTF_CSRF_ENABLED'] = False
    with app.test_client() as c:
        with app.app_context():
            yield c


def _cleanup_dash_users():
    for email in ('dash_admin@example.com', 'dash_viewer@example.com'):
        db(db.auth_user.email == email).delete()
    db.commit()


@pytest.fixture
def auth_client(client):
    """
    Authenticated test client (admin user).
    Returns (client, access_token).
    """
    _cleanup_dash_users()
    db.auth_user.insert(
        email='dash_admin@example.com',
        password=generate_password_hash('adminpass'),
        first_name='Dash',
        last_name='Admin',
        is_active=True,
        is_admin=True
    )
    db.commit()

    resp = client.post('/api/v1/auth/login',
                       json={'email': 'dash_admin@example.com', 'password': 'adminpass'})
    token = resp.get_json()['access_token']
    yield client, token

    _cleanup_dash_users()


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

class TestDashboardHelpers:
    """Tests for helper functions duplicated in dashboard blueprint."""

    def test_is_json_safe_none(self):
        from blueprints.dashboard import _is_json_safe
        assert _is_json_safe(None) is True

    def test_is_json_safe_str(self):
        from blueprints.dashboard import _is_json_safe
        assert _is_json_safe('hello') is True

    def test_is_json_safe_int(self):
        from blueprints.dashboard import _is_json_safe
        assert _is_json_safe(1) is True

    def test_is_json_safe_float(self):
        from blueprints.dashboard import _is_json_safe
        assert _is_json_safe(1.5) is True

    def test_is_json_safe_bool(self):
        from blueprints.dashboard import _is_json_safe
        assert _is_json_safe(True) is True

    def test_is_json_safe_list(self):
        from blueprints.dashboard import _is_json_safe
        assert _is_json_safe([1, 2]) is True

    def test_is_json_safe_plain_dict(self):
        from blueprints.dashboard import _is_json_safe
        assert _is_json_safe({'a': 1}) is True

    def test_is_json_safe_datetime(self):
        from blueprints.dashboard import _is_json_safe
        assert _is_json_safe(datetime.utcnow()) is True

    def test_is_json_safe_pydal_subclass_not_safe(self):
        from blueprints.dashboard import _is_json_safe

        class FakeLazySet(dict):
            pass

        assert _is_json_safe(FakeLazySet()) is False

    def test_serialize_row_none(self):
        from blueprints.dashboard import serialize_row
        assert serialize_row(None) is None

    def test_serialize_rows_empty(self):
        from blueprints.dashboard import serialize_rows
        assert serialize_rows([]) == []

    def test_get_current_user_no_auth_returns_none_via_endpoint(self, client):
        """Without auth, dashboard endpoints return 401 (get_current_user = None)."""
        response = client.get('/api/v1/dashboard/stats')
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# Tests: GET /api/v1/dashboard/stats
# ---------------------------------------------------------------------------

class TestDashboardStats:
    """Tests for GET /api/v1/dashboard/stats"""

    def test_requires_auth(self, client):
        response = client.get('/api/v1/dashboard/stats')
        assert response.status_code == 401

    def test_authenticated_returns_200(self, auth_client):
        c, token = auth_client
        response = c.get('/api/v1/dashboard/stats',
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200

    def test_response_structure(self, auth_client):
        c, token = auth_client
        response = c.get('/api/v1/dashboard/stats',
                         headers={'Authorization': f'Bearer {token}'})
        data = response.get_json()
        assert 'total_queries_24h' in data
        assert 'cache_hit_rate' in data
        assert 'active_ioc_feeds' in data
        assert 'total_ioc_entries' in data
        assert 'internal_domains' in data
        assert 'recent_queries' in data


# ---------------------------------------------------------------------------
# Tests: GET /api/v1/domains
# ---------------------------------------------------------------------------

class TestGetDomains:
    """Tests for GET /api/v1/domains"""

    def test_requires_auth(self, client):
        response = client.get('/api/v1/domains')
        assert response.status_code == 401

    def test_returns_domains_list(self, auth_client):
        c, token = auth_client
        response = c.get('/api/v1/domains',
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.get_json()
        assert 'domains' in data
        assert isinstance(data['domains'], list)

    def test_filter_all(self, auth_client):
        c, token = auth_client
        response = c.get('/api/v1/domains?filter=all',
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200

    def test_filter_active(self, auth_client):
        c, token = auth_client
        db.internal_domain.insert(
            name='active.test.local',
            ip_address='10.0.0.1',
            is_active=True,
            access_type='all',
            created_on=datetime.utcnow(),
            modified_on=datetime.utcnow()
        )
        db.commit()

        response = c.get('/api/v1/domains?filter=active',
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.get_json()
        # All returned domains must have is_active=True
        for d in data['domains']:
            assert d['is_active'] is True

        db(db.internal_domain.name == 'active.test.local').delete()
        db.commit()

    def test_filter_inactive(self, auth_client):
        c, token = auth_client
        db.internal_domain.insert(
            name='inactive.test.local',
            ip_address='10.0.0.2',
            is_active=False,
            access_type='all',
            created_on=datetime.utcnow(),
            modified_on=datetime.utcnow()
        )
        db.commit()

        response = c.get('/api/v1/domains?filter=inactive',
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.get_json()
        for d in data['domains']:
            assert d['is_active'] is False

        db(db.internal_domain.name == 'inactive.test.local').delete()
        db.commit()

    def test_filter_groups(self, auth_client):
        c, token = auth_client
        response = c.get('/api/v1/domains?filter=groups',
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200

    def test_domain_includes_access_groups(self, auth_client):
        c, token = auth_client
        db(db.internal_domain.name == 'grouptest.local').delete()
        db.commit()

        did = db.internal_domain.insert(
            name='grouptest.local',
            ip_address='10.1.1.1',
            is_active=True,
            access_type='groups',
            created_on=datetime.utcnow(),
            modified_on=datetime.utcnow()
        )
        db.internal_domain_group.insert(
            domain_id=did,
            group_name='engineering',
            created_on=datetime.utcnow()
        )
        db.commit()

        response = c.get('/api/v1/domains',
                         headers={'Authorization': f'Bearer {token}'})
        data = response.get_json()
        found = [d for d in data['domains'] if d.get('name') == 'grouptest.local']
        assert len(found) == 1
        assert 'engineering' in found[0]['access_groups']

        db(db.internal_domain_group.domain_id == did).delete()
        db(db.internal_domain.id == did).delete()
        db.commit()


# ---------------------------------------------------------------------------
# Tests: GET /api/v1/users
# ---------------------------------------------------------------------------

class TestGetUsers:
    """Tests for GET /api/v1/users"""

    def test_requires_auth(self, client):
        response = client.get('/api/v1/users')
        assert response.status_code == 401

    def test_returns_users_list(self, auth_client):
        c, token = auth_client
        response = c.get('/api/v1/users',
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.get_json()
        assert 'users' in data
        assert isinstance(data['users'], list)

    def test_passwords_not_in_response(self, auth_client):
        c, token = auth_client
        response = c.get('/api/v1/users',
                         headers={'Authorization': f'Bearer {token}'})
        for user in response.get_json()['users']:
            assert 'password' not in user


# ---------------------------------------------------------------------------
# Tests: GET /api/v1/groups
# ---------------------------------------------------------------------------

class TestGetGroups:
    """Tests for GET /api/v1/groups"""

    def test_requires_auth(self, client):
        response = client.get('/api/v1/groups')
        assert response.status_code == 401

    def test_returns_groups_list(self, auth_client):
        c, token = auth_client
        response = c.get('/api/v1/groups',
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.get_json()
        assert 'groups' in data
        assert isinstance(data['groups'], list)


# ---------------------------------------------------------------------------
# Tests: GET /api/v1/zones
# ---------------------------------------------------------------------------

class TestGetZones:
    """Tests for GET /api/v1/zones"""

    def test_requires_auth(self, client):
        response = client.get('/api/v1/zones')
        assert response.status_code == 401

    def test_returns_zones_list(self, auth_client):
        c, token = auth_client
        response = c.get('/api/v1/zones',
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.get_json()
        assert 'zones' in data
        assert isinstance(data['zones'], list)


# ---------------------------------------------------------------------------
# Tests: GET /api/v1/records
# ---------------------------------------------------------------------------

class TestGetRecords:
    """Tests for GET /api/v1/records"""

    def test_requires_auth(self, client):
        response = client.get('/api/v1/records')
        assert response.status_code == 401

    def test_returns_records_and_zones(self, auth_client):
        c, token = auth_client
        response = c.get('/api/v1/records',
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.get_json()
        assert 'records' in data
        assert 'zones' in data


# ---------------------------------------------------------------------------
# Tests: GET /api/v1/permissions
# ---------------------------------------------------------------------------

class TestGetPermissions:
    """Tests for GET /api/v1/permissions"""

    def test_requires_auth(self, client):
        response = client.get('/api/v1/permissions')
        assert response.status_code == 401

    def test_returns_permissions_and_groups(self, auth_client):
        c, token = auth_client
        response = c.get('/api/v1/permissions',
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.get_json()
        assert 'permissions' in data
        assert 'groups' in data


# ---------------------------------------------------------------------------
# Tests: GET /api/v1/blocked
# ---------------------------------------------------------------------------

class TestGetBlocked:
    """Tests for GET /api/v1/blocked"""

    def test_requires_auth(self, client):
        response = client.get('/api/v1/blocked')
        assert response.status_code == 401

    def test_returns_blocked_queries(self, auth_client):
        c, token = auth_client
        response = c.get('/api/v1/blocked',
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.get_json()
        assert 'blocked_queries' in data
        assert isinstance(data['blocked_queries'], list)


# ---------------------------------------------------------------------------
# Tests: GET /api/v1/threats
# ---------------------------------------------------------------------------

class TestGetThreats:
    """Tests for GET /api/v1/threats"""

    def test_requires_auth(self, client):
        response = client.get('/api/v1/threats')
        assert response.status_code == 401

    def test_returns_feeds_and_entries(self, auth_client):
        c, token = auth_client
        response = c.get('/api/v1/threats',
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.get_json()
        assert 'feeds' in data
        assert 'recent_entries' in data


# ---------------------------------------------------------------------------
# Tests: GET /api/v1/logs
# ---------------------------------------------------------------------------

class TestGetLogs:
    """Tests for GET /api/v1/logs"""

    def test_requires_auth(self, client):
        response = client.get('/api/v1/logs')
        assert response.status_code == 401

    def test_returns_paginated_logs(self, auth_client):
        c, token = auth_client
        response = c.get('/api/v1/logs',
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.get_json()
        assert 'logs' in data
        assert 'page' in data
        assert 'per_page' in data
        assert 'total' in data
        assert 'total_pages' in data

    def test_page_param(self, auth_client):
        c, token = auth_client
        response = c.get('/api/v1/logs?page=2&per_page=5',
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.get_json()
        assert data['page'] == 2
        assert data['per_page'] == 5


# ---------------------------------------------------------------------------
# Tests: GET /api/v1/config
# ---------------------------------------------------------------------------

class TestGetConfig:
    """Tests for GET /api/v1/config"""

    def test_requires_auth(self, client):
        response = client.get('/api/v1/config')
        assert response.status_code == 401

    def test_returns_config(self, auth_client):
        c, token = auth_client
        response = c.get('/api/v1/config',
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        assert response.get_json() is not None


# ---------------------------------------------------------------------------
# Tests: GET /api/v1/cache
# ---------------------------------------------------------------------------

class TestGetCache:
    """Tests for GET /api/v1/cache"""

    def test_requires_auth(self, client):
        response = client.get('/api/v1/cache')
        assert response.status_code == 401

    def test_returns_cache_info(self, auth_client):
        c, token = auth_client
        response = c.get('/api/v1/cache',
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        assert response.get_json() is not None


# ---------------------------------------------------------------------------
# Tests: GET /api/v1/search/groups and /api/v1/search/users
# ---------------------------------------------------------------------------

class TestSearchEndpoints:
    """Tests for GET /api/v1/search/groups and /api/v1/search/users"""

    def test_search_groups_requires_auth(self, client):
        response = client.get('/api/v1/search/groups?q=test')
        assert response.status_code == 401

    def test_search_groups_returns_list(self, auth_client):
        c, token = auth_client
        response = c.get('/api/v1/search/groups?q=',
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.get_json()
        assert 'groups' in data
        assert isinstance(data['groups'], list)

    def test_search_users_requires_auth(self, client):
        response = client.get('/api/v1/search/users?q=test')
        assert response.status_code == 401

    def test_search_users_returns_list(self, auth_client):
        c, token = auth_client
        response = c.get('/api/v1/search/users?q=dash',
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.get_json()
        assert 'users' in data
        assert isinstance(data['users'], list)

    def test_search_users_result_structure(self, auth_client):
        c, token = auth_client
        response = c.get('/api/v1/search/users?q=dash',
                         headers={'Authorization': f'Bearer {token}'})
        for user in response.get_json()['users']:
            assert 'email' in user
            assert 'display' in user

    def test_search_users_finds_match(self, auth_client):
        c, token = auth_client
        response = c.get('/api/v1/search/users?q=dash_admin',
                         headers={'Authorization': f'Bearer {token}'})
        emails = [u['email'] for u in response.get_json()['users']]
        assert 'dash_admin@example.com' in emails


# ---------------------------------------------------------------------------
# Tests: POST /api/v1/domains
# ---------------------------------------------------------------------------

class TestCreateDomain:
    """Tests for POST /api/v1/domains"""

    def test_requires_auth(self, client):
        response = client.post('/api/v1/domains',
                               json={'domain_name': 'x.local', 'ip_address': '1.2.3.4'})
        assert response.status_code == 401

    def test_missing_domain_name_returns_400(self, auth_client):
        c, token = auth_client
        response = c.post('/api/v1/domains',
                          json={'ip_address': '1.2.3.4'},
                          headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 400

    def test_missing_ip_address_returns_400(self, auth_client):
        c, token = auth_client
        response = c.post('/api/v1/domains',
                          json={'domain_name': 'nip.local'},
                          headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 400

    def test_create_domain_success(self, auth_client):
        c, token = auth_client
        db(db.internal_domain.name == 'new.test.local').delete()
        db.commit()

        response = c.post('/api/v1/domains',
                          json={'domain_name': 'new.test.local', 'ip_address': '192.168.1.1'},
                          headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 201
        data = response.get_json()
        assert 'domain_id' in data

        db(db.internal_domain.name == 'new.test.local').delete()
        db.commit()

    def test_duplicate_domain_returns_409(self, auth_client):
        c, token = auth_client
        db(db.internal_domain.name == 'dup.test.local').delete()
        db.commit()

        c.post('/api/v1/domains',
               json={'domain_name': 'dup.test.local', 'ip_address': '10.0.0.1'},
               headers={'Authorization': f'Bearer {token}'})
        response = c.post('/api/v1/domains',
                          json={'domain_name': 'dup.test.local', 'ip_address': '10.0.0.2'},
                          headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 409

        db(db.internal_domain.name == 'dup.test.local').delete()
        db.commit()

    def test_create_domain_with_access_type_groups(self, auth_client):
        c, token = auth_client
        db(db.internal_domain.name == 'grp.test.local').delete()
        db.commit()

        response = c.post('/api/v1/domains',
                          json={
                              'domain_name': 'grp.test.local',
                              'ip_address': '10.0.0.10',
                              'access_type': 'groups',
                              'access_groups': 'devs, ops'
                          },
                          headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 201

        db(db.internal_domain_group.domain_id ==
           db(db.internal_domain.name == 'grp.test.local').select().first().id).delete()
        db(db.internal_domain.name == 'grp.test.local').delete()
        db.commit()

    def test_create_domain_with_access_type_users(self, auth_client):
        c, token = auth_client
        db(db.internal_domain.name == 'usr.test.local').delete()
        db.commit()

        response = c.post('/api/v1/domains',
                          json={
                              'domain_name': 'usr.test.local',
                              'ip_address': '10.0.0.20',
                              'access_type': 'users',
                              'access_users': 'dash_admin@example.com'
                          },
                          headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 201

        did = response.get_json()['domain_id']
        db(db.internal_domain_user.domain_id == did).delete()
        db(db.internal_domain.id == did).delete()
        db.commit()


# ---------------------------------------------------------------------------
# Tests: POST /api/v1/users
# ---------------------------------------------------------------------------

class TestCreateUser:
    """Tests for POST /api/v1/users"""

    def test_requires_auth(self, client):
        response = client.post('/api/v1/users',
                               json={'email': 'x@y.com', 'password': 'pass'})
        assert response.status_code == 401

    def test_missing_email_returns_400(self, auth_client):
        c, token = auth_client
        response = c.post('/api/v1/users',
                          json={'password': 'pass'},
                          headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 400

    def test_missing_password_returns_400(self, auth_client):
        c, token = auth_client
        response = c.post('/api/v1/users',
                          json={'email': 'nopw@example.com'},
                          headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 400

    def test_create_user_success(self, auth_client):
        c, token = auth_client
        db(db.auth_user.email == 'created@example.com').delete()
        db.commit()

        response = c.post('/api/v1/users',
                          json={'email': 'created@example.com', 'password': 'pass123'},
                          headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 201
        data = response.get_json()
        assert 'user_id' in data

        db(db.auth_user.email == 'created@example.com').delete()
        db.commit()

    def test_duplicate_user_returns_409(self, auth_client):
        c, token = auth_client
        db(db.auth_user.email == 'dupuser@example.com').delete()
        db.commit()

        c.post('/api/v1/users',
               json={'email': 'dupuser@example.com', 'password': 'pass'},
               headers={'Authorization': f'Bearer {token}'})
        response = c.post('/api/v1/users',
                          json={'email': 'dupuser@example.com', 'password': 'pass2'},
                          headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 409

        db(db.auth_user.email == 'dupuser@example.com').delete()
        db.commit()


# ---------------------------------------------------------------------------
# Tests: POST /api/v1/groups
# ---------------------------------------------------------------------------

class TestCreateGroup:
    """Tests for POST /api/v1/groups"""

    def test_requires_auth(self, client):
        response = client.post('/api/v1/groups',
                               json={'name': 'g', 'group_type': 't'})
        assert response.status_code == 401

    def test_missing_name_returns_400(self, auth_client):
        c, token = auth_client
        response = c.post('/api/v1/groups',
                          json={'group_type': 'static'},
                          headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 400

    def test_missing_group_type_returns_400(self, auth_client):
        c, token = auth_client
        response = c.post('/api/v1/groups',
                          json={'name': 'noname'},
                          headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 400

    def test_create_group_success(self, auth_client):
        c, token = auth_client
        # Ensure dns_group table exists (created on first POST)
        response = c.post('/api/v1/groups',
                          json={'name': 'TestGroup', 'group_type': 'static'},
                          headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 201
        data = response.get_json()
        assert 'group_id' in data

        if 'dns_group' in db.tables:
            db(db.dns_group.name == 'TestGroup').delete()
            db.commit()

    def test_duplicate_group_returns_409(self, auth_client):
        c, token = auth_client
        c.post('/api/v1/groups',
               json={'name': 'DupGroup', 'group_type': 'static'},
               headers={'Authorization': f'Bearer {token}'})
        response = c.post('/api/v1/groups',
                          json={'name': 'DupGroup', 'group_type': 'dynamic'},
                          headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 409

        if 'dns_group' in db.tables:
            db(db.dns_group.name == 'DupGroup').delete()
            db.commit()


# ---------------------------------------------------------------------------
# Tests: POST /api/v1/zones
# ---------------------------------------------------------------------------

class TestCreateZone:
    """Tests for POST /api/v1/zones"""

    def test_requires_auth(self, client):
        response = client.post('/api/v1/zones', json={'zone_name': 'example.local'})
        assert response.status_code == 401

    def test_missing_zone_name_returns_400(self, auth_client):
        c, token = auth_client
        response = c.post('/api/v1/zones',
                          json={'visibility': 'PUBLIC'},
                          headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 400

    def test_create_zone_success(self, auth_client):
        c, token = auth_client
        response = c.post('/api/v1/zones',
                          json={'zone_name': 'test.local', 'visibility': 'PRIVATE'},
                          headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 201
        data = response.get_json()
        assert 'zone_id' in data

        if 'dns_zone' in db.tables:
            db(db.dns_zone.name == 'test.local').delete()
            db.commit()


# ---------------------------------------------------------------------------
# Tests: POST /api/v1/records
# ---------------------------------------------------------------------------

class TestCreateRecord:
    """Tests for POST /api/v1/records"""

    def test_requires_auth(self, client):
        response = client.post('/api/v1/records',
                               json={'zone': 'x', 'record_name': 'y',
                                     'record_type': 'A', 'record_value': '1.2.3.4'})
        assert response.status_code == 401

    def test_missing_zone_returns_400(self, auth_client):
        c, token = auth_client
        response = c.post('/api/v1/records',
                          json={'record_name': 'host', 'record_type': 'A',
                                'record_value': '1.2.3.4'},
                          headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 400

    def test_missing_record_name_returns_400(self, auth_client):
        c, token = auth_client
        response = c.post('/api/v1/records',
                          json={'zone': 'x.local', 'record_type': 'A',
                                'record_value': '1.2.3.4'},
                          headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 400

    def test_missing_record_type_returns_400(self, auth_client):
        c, token = auth_client
        response = c.post('/api/v1/records',
                          json={'zone': 'x.local', 'record_name': 'host',
                                'record_value': '1.2.3.4'},
                          headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 400

    def test_missing_record_value_returns_400(self, auth_client):
        c, token = auth_client
        response = c.post('/api/v1/records',
                          json={'zone': 'x.local', 'record_name': 'host',
                                'record_type': 'A'},
                          headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 400

    def test_create_record_success(self, auth_client):
        c, token = auth_client
        response = c.post('/api/v1/records',
                          json={'zone': 'test.local', 'record_name': 'host',
                                'record_type': 'A', 'record_value': '192.168.1.50'},
                          headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 201
        data = response.get_json()
        assert 'record_id' in data

        if 'dns_record' in db.tables:
            db(db.dns_record.id == data['record_id']).delete()
            db.commit()


# ---------------------------------------------------------------------------
# Tests: POST /api/v1/permissions
# ---------------------------------------------------------------------------

class TestCreatePermission:
    """Tests for POST /api/v1/permissions"""

    def test_requires_auth(self, client):
        response = client.post('/api/v1/permissions',
                               json={'group': 'g', 'zone_pattern': '*.local'})
        assert response.status_code == 401

    def test_missing_group_returns_400(self, auth_client):
        c, token = auth_client
        response = c.post('/api/v1/permissions',
                          json={'zone_pattern': '*.local'},
                          headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 400

    def test_missing_zone_pattern_returns_400(self, auth_client):
        c, token = auth_client
        response = c.post('/api/v1/permissions',
                          json={'group': 'devs'},
                          headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 400

    def test_create_permission_success(self, auth_client):
        c, token = auth_client
        response = c.post('/api/v1/permissions',
                          json={'group': 'devs', 'zone_pattern': '*.dev.local',
                                'access_level': 'READ'},
                          headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 201
        data = response.get_json()
        assert 'permission_id' in data

        if 'dns_permission' in db.tables:
            db(db.dns_permission.id == data['permission_id']).delete()
            db.commit()


# ---------------------------------------------------------------------------
# Tests: POST /api/v1/feeds/update
# ---------------------------------------------------------------------------

class TestFeedsUpdate:
    """Tests for POST /api/v1/feeds/update"""

    def test_requires_auth(self, client):
        response = client.post('/api/v1/feeds/update')
        assert response.status_code == 401

    def test_update_feeds_success(self, auth_client):
        c, token = auth_client
        response = c.post('/api/v1/feeds/update',
                          headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.get_json()
        assert 'updated_count' in data

    def test_update_feeds_updates_active_feeds(self, auth_client):
        c, token = auth_client
        fid = db.ioc_feed.insert(
            name='Update Test Feed',
            url='https://example.com/update.txt',
            is_active=True
        )
        db.commit()

        response = c.post('/api/v1/feeds/update',
                          headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        assert response.get_json()['updated_count'] >= 1

        db(db.ioc_feed.id == fid).delete()
        db.commit()


# ---------------------------------------------------------------------------
# Tests: POST /api/v1/blocked/clear
# ---------------------------------------------------------------------------

class TestBlockedClear:
    """Tests for POST /api/v1/blocked/clear"""

    def test_requires_auth(self, client):
        response = client.post('/api/v1/blocked/clear')
        assert response.status_code == 401

    def test_clear_blocked_success(self, auth_client):
        c, token = auth_client
        response = c.post('/api/v1/blocked/clear',
                          headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert 'deleted_count' in data


# ---------------------------------------------------------------------------
# Tests: POST /api/v1/logs/clear
# ---------------------------------------------------------------------------

class TestLogsClear:
    """Tests for POST /api/v1/logs/clear"""

    def test_requires_auth(self, client):
        response = client.post('/api/v1/logs/clear')
        assert response.status_code == 401

    def test_clear_logs_success(self, auth_client):
        c, token = auth_client
        # Insert a log entry to ensure there is something to delete
        db.dns_query_log.insert(domain='todelete.com')
        db.commit()

        response = c.post('/api/v1/logs/clear',
                          headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert 'deleted_count' in data

    def test_logs_cleared_from_db(self, auth_client):
        c, token = auth_client
        db.dns_query_log.insert(domain='clearedlog.com')
        db.commit()

        c.post('/api/v1/logs/clear',
               headers={'Authorization': f'Bearer {token}'})
        count = db(db.dns_query_log).count()
        assert count == 0
