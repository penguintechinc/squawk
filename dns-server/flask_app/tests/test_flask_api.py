"""
Test suite for Flask API Blueprint - JSON API Only
Tests /api/v1/queries, /api/v1/ioc/feeds, /api/v1/whois, /api/v1/stats endpoints.
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


def _cleanup_test_users():
    """Remove test users created by fixtures."""
    for email in ('api_admin@example.com', 'api_viewer@example.com'):
        db(db.auth_user.email == email).delete()
    db.commit()


@pytest.fixture
def admin_client(client):
    """
    Authenticated client logged in as an admin user.
    Returns (client, access_token).
    """
    _cleanup_test_users()
    db.auth_user.insert(
        email='api_admin@example.com',
        password=generate_password_hash('adminpass'),
        first_name='API',
        last_name='Admin',
        is_active=True,
        is_admin=True
    )
    db.commit()

    resp = client.post('/api/v1/auth/login',
                       json={'email': 'api_admin@example.com', 'password': 'adminpass'})
    token = resp.get_json()['access_token']
    yield client, token

    _cleanup_test_users()


@pytest.fixture
def viewer_client(client):
    """
    Authenticated client logged in as a non-admin user.
    Returns (client, access_token).
    """
    _cleanup_test_users()
    db.auth_user.insert(
        email='api_viewer@example.com',
        password=generate_password_hash('viewerpass'),
        first_name='API',
        last_name='Viewer',
        is_active=True,
        is_admin=False
    )
    db.commit()

    resp = client.post('/api/v1/auth/login',
                       json={'email': 'api_viewer@example.com', 'password': 'viewerpass'})
    token = resp.get_json()['access_token']
    yield client, token

    _cleanup_test_users()


# ---------------------------------------------------------------------------
# Helper: _is_json_safe
# ---------------------------------------------------------------------------

class TestIsJsonSafe:
    """Tests for the _is_json_safe helper function in blueprints/api.py"""

    def test_none_is_safe(self):
        from blueprints.api import _is_json_safe
        assert _is_json_safe(None) is True

    def test_string_is_safe(self):
        from blueprints.api import _is_json_safe
        assert _is_json_safe('hello') is True

    def test_int_is_safe(self):
        from blueprints.api import _is_json_safe
        assert _is_json_safe(42) is True

    def test_float_is_safe(self):
        from blueprints.api import _is_json_safe
        assert _is_json_safe(3.14) is True

    def test_bool_is_safe(self):
        from blueprints.api import _is_json_safe
        assert _is_json_safe(True) is True
        assert _is_json_safe(False) is True

    def test_plain_list_is_safe(self):
        from blueprints.api import _is_json_safe
        assert _is_json_safe([1, 2, 3]) is True

    def test_plain_dict_is_safe(self):
        from blueprints.api import _is_json_safe
        assert _is_json_safe({'key': 'value'}) is True

    def test_datetime_is_safe(self):
        from blueprints.api import _is_json_safe
        assert _is_json_safe(datetime.utcnow()) is True

    def test_date_is_safe(self):
        from blueprints.api import _is_json_safe
        import datetime as dt
        assert _is_json_safe(dt.date.today()) is True

    def test_unknown_object_is_not_safe(self):
        from blueprints.api import _is_json_safe

        class WeirdObj:
            pass

        assert _is_json_safe(WeirdObj()) is False

    def test_pydal_subclass_dict_is_not_safe(self):
        """PyDAL internal types that subclass dict should NOT be safe."""
        from blueprints.api import _is_json_safe

        class FakeRecordUpdater(dict):
            pass

        assert _is_json_safe(FakeRecordUpdater()) is False


# ---------------------------------------------------------------------------
# Helper: serialize_row / serialize_rows
# ---------------------------------------------------------------------------

class TestSerializeHelpers:
    """Tests for serialize_row and serialize_rows helper functions."""

    def test_serialize_row_none(self):
        from blueprints.api import serialize_row
        assert serialize_row(None) is None

    def test_serialize_row_simple(self):
        from blueprints.api import serialize_row
        # Use a real PyDAL row to verify filtering
        db(db.auth_user.email == 'serialize_test@example.com').delete()
        db.commit()
        uid = db.auth_user.insert(
            email='serialize_test@example.com',
            password=generate_password_hash('x'),
            is_active=True,
            is_admin=False
        )
        db.commit()
        row = db(db.auth_user.id == uid).select().first()
        result = serialize_row(row)
        assert isinstance(result, dict)
        assert result['email'] == 'serialize_test@example.com'
        db(db.auth_user.id == uid).delete()
        db.commit()

    def test_serialize_rows_empty(self):
        from blueprints.api import serialize_rows
        result = serialize_rows([])
        assert result == []

    def test_serialize_rows_returns_list_of_dicts(self):
        from blueprints.api import serialize_rows
        db(db.auth_user.email == 'sr_test@example.com').delete()
        db.commit()
        uid = db.auth_user.insert(
            email='sr_test@example.com',
            password=generate_password_hash('x'),
            is_active=True,
            is_admin=False
        )
        db.commit()
        rows = db(db.auth_user.id == uid).select()
        result = serialize_rows(rows)
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], dict)
        db(db.auth_user.id == uid).delete()
        db.commit()


# ---------------------------------------------------------------------------
# Helper: get_current_user
# ---------------------------------------------------------------------------

class TestGetCurrentUser:
    """Tests for get_current_user helper in blueprints/api.py"""

    def test_no_auth_returns_none(self, client):
        """Without any auth, get_current_user returns None (validated via API 401)."""
        response = client.get('/api/v1/queries')
        assert response.status_code == 401

    def test_jwt_auth_returns_user(self, admin_client):
        """With a valid JWT, endpoints return 200 (user was resolved)."""
        c, token = admin_client
        response = c.get('/api/v1/queries',
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200

    def test_session_auth_returns_user(self, admin_client):
        """After session login, endpoints return 200 (user was resolved from session)."""
        c, _ = admin_client
        # Session cookie was set when admin_client fixture logged in
        response = c.get('/api/v1/queries')
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# Tests: GET /api/v1/queries
# ---------------------------------------------------------------------------

class TestQueriesEndpoint:
    """Tests for GET /api/v1/queries"""

    def test_requires_auth(self, client):
        """Unauthenticated request returns 401."""
        response = client.get('/api/v1/queries')
        assert response.status_code == 401

    def test_authenticated_returns_200(self, admin_client):
        """Authenticated request returns 200 with queries list."""
        c, token = admin_client
        response = c.get('/api/v1/queries',
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.get_json()
        assert 'queries' in data
        assert 'total' in data
        assert isinstance(data['queries'], list)

    def test_limit_param(self, admin_client):
        """limit query param is accepted."""
        c, token = admin_client
        response = c.get('/api/v1/queries?limit=5',
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.get_json()
        assert len(data['queries']) <= 5

    def test_offset_param(self, admin_client):
        """offset query param is accepted."""
        c, token = admin_client
        response = c.get('/api/v1/queries?limit=10&offset=0',
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200

    def test_returns_data_with_log_entry(self, admin_client):
        """Query logs inserted into db appear in the response."""
        c, token = admin_client
        db(db.dns_query_log.domain == 'apitest.example.com').delete()
        db.commit()
        db.dns_query_log.insert(
            timestamp=datetime.utcnow(),
            client_ip='10.0.0.1',
            domain='apitest.example.com',
            record_type='A',
            response_status=0,
            cache_hit=False,
            processing_time_ms=5.0
        )
        db.commit()

        response = c.get('/api/v1/queries',
                         headers={'Authorization': f'Bearer {token}'})
        data = response.get_json()
        domains = [q.get('domain') for q in data['queries']]
        assert 'apitest.example.com' in domains

        db(db.dns_query_log.domain == 'apitest.example.com').delete()
        db.commit()


# ---------------------------------------------------------------------------
# Tests: /api/v1/ioc/feeds
# ---------------------------------------------------------------------------

class TestIocFeedsEndpoint:
    """Tests for GET/POST /api/v1/ioc/feeds"""

    def test_get_requires_auth(self, client):
        """GET without auth returns 401."""
        response = client.get('/api/v1/ioc/feeds')
        assert response.status_code == 401

    def test_get_returns_feeds_list(self, admin_client):
        """GET returns a list of feeds."""
        c, token = admin_client
        response = c.get('/api/v1/ioc/feeds',
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.get_json()
        assert 'feeds' in data
        assert isinstance(data['feeds'], list)

    def test_post_requires_admin(self, viewer_client):
        """Non-admin POST returns 403."""
        c, token = viewer_client
        response = c.post('/api/v1/ioc/feeds',
                          json={'name': 'Test', 'url': 'https://example.com/feed'},
                          headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 403

    def test_post_requires_auth(self, client):
        """POST without auth returns 401."""
        response = client.post('/api/v1/ioc/feeds',
                               json={'name': 'Test', 'url': 'https://example.com/feed'})
        assert response.status_code == 401

    def test_post_admin_creates_feed(self, admin_client):
        """Admin POST with valid data creates feed and returns 201."""
        c, token = admin_client
        feed_data = {
            'name': 'Test IOC Feed',
            'url': 'https://example.com/ioc.txt',
            'feed_type': 'domain',
            'is_active': True
        }
        response = c.post('/api/v1/ioc/feeds',
                          json=feed_data,
                          headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 201
        data = response.get_json()
        assert 'id' in data
        assert data['status'] == 'created'

        # Cleanup
        db(db.ioc_feed.id == data['id']).delete()
        db.commit()

    def test_post_creates_feed_in_db(self, admin_client):
        """Feed created via POST is persisted in the database."""
        c, token = admin_client
        response = c.post('/api/v1/ioc/feeds',
                          json={'name': 'Persist Feed', 'url': 'https://example.com/p.txt'},
                          headers={'Authorization': f'Bearer {token}'})
        feed_id = response.get_json()['id']
        feed = db(db.ioc_feed.id == feed_id).select().first()
        assert feed is not None
        assert feed.name == 'Persist Feed'
        db(db.ioc_feed.id == feed_id).delete()
        db.commit()


# ---------------------------------------------------------------------------
# Tests: /api/v1/ioc/feeds/<id>
# ---------------------------------------------------------------------------

class TestIocFeedDetailEndpoint:
    """Tests for GET/PUT/DELETE /api/v1/ioc/feeds/<id>"""

    def _create_feed(self, name='Detail Feed'):
        fid = db.ioc_feed.insert(
            name=name,
            url='https://example.com/detail.txt',
            feed_type='domain',
            is_active=True
        )
        db.commit()
        return fid

    def test_get_requires_auth(self, client):
        """GET without auth returns 401."""
        fid = self._create_feed('AuthTest Feed')
        response = client.get(f'/api/v1/ioc/feeds/{fid}')
        assert response.status_code == 401
        db(db.ioc_feed.id == fid).delete()
        db.commit()

    def test_get_existing_feed(self, admin_client):
        """GET existing feed returns 200 with feed data."""
        c, token = admin_client
        fid = self._create_feed('Get Test Feed')
        response = c.get(f'/api/v1/ioc/feeds/{fid}',
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.get_json()
        assert data['name'] == 'Get Test Feed'
        db(db.ioc_feed.id == fid).delete()
        db.commit()

    def test_get_nonexistent_feed_returns_404(self, admin_client):
        """GET non-existent feed id returns 404."""
        c, token = admin_client
        response = c.get('/api/v1/ioc/feeds/999999',
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 404

    def test_put_requires_admin(self, viewer_client):
        """PUT by non-admin returns 403."""
        c, token = viewer_client
        fid = self._create_feed('Viewer Put Feed')
        response = c.put(f'/api/v1/ioc/feeds/{fid}',
                         json={'name': 'Changed'},
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 403
        db(db.ioc_feed.id == fid).delete()
        db.commit()

    def test_put_admin_updates_feed(self, admin_client):
        """Admin PUT updates the feed and returns 200."""
        c, token = admin_client
        fid = self._create_feed('Update Me Feed')
        response = c.put(f'/api/v1/ioc/feeds/{fid}',
                         json={'name': 'Updated Feed Name'},
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        assert response.get_json()['status'] == 'updated'
        db(db.ioc_feed.id == fid).delete()
        db.commit()

    def test_delete_requires_admin(self, viewer_client):
        """DELETE by non-admin returns 403."""
        c, token = viewer_client
        fid = self._create_feed('Viewer Delete Feed')
        response = c.delete(f'/api/v1/ioc/feeds/{fid}',
                            headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 403
        db(db.ioc_feed.id == fid).delete()
        db.commit()

    def test_delete_requires_auth(self, client):
        """DELETE without auth returns 401."""
        fid = self._create_feed('Unauth Delete Feed')
        response = client.delete(f'/api/v1/ioc/feeds/{fid}')
        assert response.status_code == 401
        db(db.ioc_feed.id == fid).delete()
        db.commit()

    def test_delete_admin_removes_feed(self, admin_client):
        """Admin DELETE removes the feed and returns 200."""
        c, token = admin_client
        fid = self._create_feed('Delete Me Feed')
        response = c.delete(f'/api/v1/ioc/feeds/{fid}',
                            headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        assert response.get_json()['status'] == 'deleted'
        # Confirm removed from db
        assert db(db.ioc_feed.id == fid).select().first() is None

    def test_delete_nonexistent_returns_404(self, admin_client):
        """DELETE non-existent feed returns 404."""
        c, token = admin_client
        response = c.delete('/api/v1/ioc/feeds/999999',
                            headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# Tests: GET /api/v1/whois/<domain>
# ---------------------------------------------------------------------------

class TestWhoisEndpoint:
    """Tests for GET /api/v1/whois/<domain>"""

    def test_requires_auth(self, client):
        """WHOIS without auth returns 401."""
        response = client.get('/api/v1/whois/example.com')
        assert response.status_code == 401

    def test_whois_not_cached(self, admin_client):
        """WHOIS for domain not in cache returns data with cached=False."""
        c, token = admin_client
        # Ensure no cached entry
        db(db.whois_cache.domain == 'notcached.example.com').delete()
        db.commit()

        response = c.get('/api/v1/whois/notcached.example.com',
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.get_json()
        assert data['domain'] == 'notcached.example.com'
        assert data['cached'] is False

    def test_whois_cached_entry(self, admin_client):
        """WHOIS for domain with valid cached entry returns cached=True."""
        c, token = admin_client
        domain = 'cached.example.com'
        db(db.whois_cache.domain == domain).delete()
        db.commit()

        # Insert a fresh cache entry (expires in the future)
        future = datetime.utcnow() + timedelta(hours=24)
        db.whois_cache.insert(
            domain=domain,
            whois_data={'registrar': 'Test Registrar'},
            cached_at=datetime.utcnow(),
            expires_at=future
        )
        db.commit()

        response = c.get(f'/api/v1/whois/{domain}',
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.get_json()
        assert data['domain'] == domain
        assert data['cached'] is True

        db(db.whois_cache.domain == domain).delete()
        db.commit()

    def test_whois_expired_cache_not_used(self, admin_client):
        """WHOIS for domain with expired cache returns cached=False."""
        c, token = admin_client
        domain = 'expired.example.com'
        db(db.whois_cache.domain == domain).delete()
        db.commit()

        # Insert expired cache entry
        past = datetime.utcnow() - timedelta(hours=1)
        db.whois_cache.insert(
            domain=domain,
            whois_data={'registrar': 'Old Registrar'},
            cached_at=datetime.utcnow() - timedelta(hours=25),
            expires_at=past
        )
        db.commit()

        response = c.get(f'/api/v1/whois/{domain}',
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.get_json()
        assert data['cached'] is False

        db(db.whois_cache.domain == domain).delete()
        db.commit()

    def test_whois_response_structure(self, admin_client):
        """WHOIS response includes domain and data keys."""
        c, token = admin_client
        response = c.get('/api/v1/whois/example.com',
                         headers={'Authorization': f'Bearer {token}'})
        data = response.get_json()
        assert 'domain' in data
        assert 'data' in data
        assert 'cached' in data


# ---------------------------------------------------------------------------
# Tests: GET /api/v1/stats/summary
# ---------------------------------------------------------------------------

class TestStatsSummaryEndpoint:
    """Tests for GET /api/v1/stats/summary"""

    def test_requires_auth(self, client):
        """Stats summary without auth returns 401."""
        response = client.get('/api/v1/stats/summary')
        assert response.status_code == 401

    def test_authenticated_returns_200(self, admin_client):
        """Authenticated request returns 200 with stats."""
        c, token = admin_client
        response = c.get('/api/v1/stats/summary',
                         headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200

    def test_response_structure(self, admin_client):
        """Stats summary response has all expected keys."""
        c, token = admin_client
        response = c.get('/api/v1/stats/summary',
                         headers={'Authorization': f'Bearer {token}'})
        data = response.get_json()
        assert 'total_queries_24h' in data
        assert 'cache_hits_24h' in data
        assert 'cache_hit_rate' in data
        assert 'active_feeds' in data
        assert 'total_ioc_entries' in data

    def test_cache_hit_rate_is_zero_when_no_queries(self, admin_client):
        """Cache hit rate is 0 when there are no queries."""
        c, token = admin_client
        db(db.dns_query_log.id > 0).delete()
        db.commit()

        response = c.get('/api/v1/stats/summary',
                         headers={'Authorization': f'Bearer {token}'})
        data = response.get_json()
        assert data['cache_hit_rate'] == 0

    def test_stats_reflect_inserted_data(self, admin_client):
        """Stats reflect actual data in the database."""
        c, token = admin_client
        db(db.dns_query_log.id > 0).delete()
        db.commit()

        now = datetime.utcnow()
        for i in range(4):
            db.dns_query_log.insert(
                timestamp=now - timedelta(minutes=i * 10),
                domain=f'stattest{i}.com',
                cache_hit=(i < 2)  # 2 cache hits
            )
        db.commit()

        response = c.get('/api/v1/stats/summary',
                         headers={'Authorization': f'Bearer {token}'})
        data = response.get_json()
        assert data['total_queries_24h'] == 4
        assert data['cache_hits_24h'] == 2

        db(db.dns_query_log.id > 0).delete()
        db.commit()
