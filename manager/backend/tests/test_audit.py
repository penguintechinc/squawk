"""Tests for audit logging and audit events API.

Tests audit_events table schema, endpoint scope enforcement, and filter coverage.
"""

from datetime import datetime, timedelta
import pytest

from app.services.scopes import expand_scopes


@pytest.fixture
def admin_token(app):
    """JWT token for SystemAdmin role."""
    from app.services.auth_service import AuthService

    with app.app_context():
        db = app.db
        user = db.auth_user.insert(
            username='admin',
            email='admin@example.com',
            password_hash='hashed',
            global_role='SystemAdmin'
        )
        db.commit()
        return AuthService.create_access_token(
            user_id=user,
            username='admin',
            global_role='SystemAdmin',
            team_roles={}
        )


@pytest.fixture
def viewer_token(app):
    """JWT token for Viewer role."""
    from app.services.auth_service import AuthService

    with app.app_context():
        db = app.db
        user = db.auth_user.insert(
            username='viewer',
            email='viewer@example.com',
            password_hash='hashed',
            global_role='Viewer'
        )
        db.commit()
        return AuthService.create_access_token(
            user_id=user,
            username='viewer',
            global_role='Viewer',
            team_roles={}
        )


@pytest.fixture
def orgadmin_token(app):
    """JWT token for OrgAdmin role."""
    from app.services.auth_service import AuthService

    with app.app_context():
        db = app.db
        user = db.auth_user.insert(
            username='orgadmin',
            email='orgadmin@example.com',
            password_hash='hashed',
            global_role='OrgAdmin'
        )
        db.commit()
        return AuthService.create_access_token(
            user_id=user,
            username='orgadmin',
            global_role='OrgAdmin',
            team_roles={}
        )


class TestAuditEventsAPI:
    """Test GET /api/v1/audit-events endpoint."""

    def test_endpoint_requires_auth(self, app):
        """GET /api/v1/audit-events requires authentication."""
        with app.test_client() as client:
            response = client.get('/api/v1/audit-events')
            assert response.status_code == 401

    def test_endpoint_requires_audit_read_scope_systemadmin_only(self, app, viewer_token, orgadmin_token, admin_token):
        """GET /api/v1/audit-events requires audit:read (SystemAdmin only)."""
        with app.test_client() as client:
            # Viewer: 403
            response = client.get(
                '/api/v1/audit-events',
                headers={'Authorization': f'Bearer {viewer_token}'}
            )
            assert response.status_code == 403

            # OrgAdmin: 403
            response = client.get(
                '/api/v1/audit-events',
                headers={'Authorization': f'Bearer {orgadmin_token}'}
            )
            assert response.status_code == 403

            # SystemAdmin: 200
            response = client.get(
                '/api/v1/audit-events',
                headers={'Authorization': f'Bearer {admin_token}'}
            )
            assert response.status_code == 200

    def test_endpoint_returns_empty_on_no_events(self, app, admin_token):
        """GET /api/v1/audit-events returns empty list when no events."""
        with app.test_client() as client:
            response = client.get(
                '/api/v1/audit-events',
                headers={'Authorization': f'Bearer {admin_token}'}
            )
            assert response.status_code == 200
            data = response.get_json()
            assert data['events'] == []
            assert data['total'] == 0

    def test_endpoint_filter_by_action(self, app, admin_token):
        """GET /api/v1/audit-events?action=X filters by action."""
        db = app.db
        with app.app_context():
            now = datetime.utcnow()
            db.audit_event.insert(action='user_created', outcome='success', status_code=201, created_at=now)
            db.audit_event.insert(action='user_deleted', outcome='success', status_code=200, created_at=now)
            db.commit()

        with app.test_client() as client:
            response = client.get(
                '/api/v1/audit-events?action=user_created',
                headers={'Authorization': f'Bearer {admin_token}'}
            )
            assert response.status_code == 200
            data = response.get_json()
            assert data['total'] == 1
            assert data['events'][0]['action'] == 'user_created'

    def test_endpoint_filter_by_actor_id(self, app, admin_token):
        """GET /api/v1/audit-events?actor_id=X filters by actor."""
        db = app.db
        with app.app_context():
            now = datetime.utcnow()
            db.audit_event.insert(actor_id=1, action='user_created', outcome='success', status_code=201, created_at=now)
            db.audit_event.insert(actor_id=2, action='user_created', outcome='success', status_code=201, created_at=now)
            db.commit()

        with app.test_client() as client:
            response = client.get(
                '/api/v1/audit-events?actor_id=1',
                headers={'Authorization': f'Bearer {admin_token}'}
            )
            assert response.status_code == 200
            data = response.get_json()
            assert data['total'] == 1
            assert data['events'][0]['actor_id'] == 1

    def test_endpoint_filter_by_resource_type(self, app, admin_token):
        """GET /api/v1/audit-events?resource_type=X filters by resource type."""
        db = app.db
        with app.app_context():
            now = datetime.utcnow()
            db.audit_event.insert(resource_type='user', action='created', outcome='success', status_code=201, created_at=now)
            db.audit_event.insert(resource_type='token', action='created', outcome='success', status_code=201, created_at=now)
            db.commit()

        with app.test_client() as client:
            response = client.get(
                '/api/v1/audit-events?resource_type=user',
                headers={'Authorization': f'Bearer {admin_token}'}
            )
            assert response.status_code == 200
            data = response.get_json()
            assert data['total'] == 1
            assert data['events'][0]['resource_type'] == 'user'

    def test_endpoint_filter_by_resource_id(self, app, admin_token):
        """GET /api/v1/audit-events?resource_id=X filters by resource ID."""
        db = app.db
        with app.app_context():
            now = datetime.utcnow()
            db.audit_event.insert(resource_id=1, action='deleted', outcome='success', status_code=200, created_at=now)
            db.audit_event.insert(resource_id=2, action='deleted', outcome='success', status_code=200, created_at=now)
            db.commit()

        with app.test_client() as client:
            response = client.get(
                '/api/v1/audit-events?resource_id=1',
                headers={'Authorization': f'Bearer {admin_token}'}
            )
            assert response.status_code == 200
            data = response.get_json()
            assert data['total'] == 1
            assert data['events'][0]['resource_id'] == 1

    def test_endpoint_filter_by_outcome(self, app, admin_token):
        """GET /api/v1/audit-events?outcome=X filters by outcome."""
        db = app.db
        with app.app_context():
            now = datetime.utcnow()
            db.audit_event.insert(action='test', outcome='success', status_code=200, created_at=now)
            db.audit_event.insert(action='test', outcome='failure', status_code=400, created_at=now)
            db.commit()

        with app.test_client() as client:
            response = client.get(
                '/api/v1/audit-events?outcome=success',
                headers={'Authorization': f'Bearer {admin_token}'}
            )
            assert response.status_code == 200
            data = response.get_json()
            assert data['total'] == 1
            assert data['events'][0]['outcome'] == 'success'

    def test_endpoint_filter_by_outcome_invalid(self, app, admin_token):
        """GET /api/v1/audit-events?outcome=invalid returns 400."""
        with app.test_client() as client:
            response = client.get(
                '/api/v1/audit-events?outcome=invalid',
                headers={'Authorization': f'Bearer {admin_token}'}
            )
            assert response.status_code == 400
            data = response.get_json()
            assert 'error' in data

    def test_endpoint_filter_by_since(self, app, admin_token):
        """GET /api/v1/audit-events?since=ISO_DATE filters by created_at >= since."""
        db = app.db
        with app.app_context():
            now = datetime.utcnow()
            earlier = now - timedelta(hours=1)
            db.audit_event.insert(action='old', outcome='success', status_code=200, created_at=earlier)
            db.audit_event.insert(action='new', outcome='success', status_code=200, created_at=now)
            db.commit()

        with app.test_client() as client:
            since_str = (now - timedelta(minutes=30)).isoformat()
            response = client.get(
                f'/api/v1/audit-events?since={since_str}',
                headers={'Authorization': f'Bearer {admin_token}'}
            )
            assert response.status_code == 200
            data = response.get_json()
            assert data['total'] == 1
            assert data['events'][0]['action'] == 'new'

    def test_endpoint_filter_by_since_invalid(self, app, admin_token):
        """GET /api/v1/audit-events?since=invalid returns 400."""
        with app.test_client() as client:
            response = client.get(
                '/api/v1/audit-events?since=not-a-date',
                headers={'Authorization': f'Bearer {admin_token}'}
            )
            assert response.status_code == 400

    def test_endpoint_filter_by_until(self, app, admin_token):
        """GET /api/v1/audit-events?until=ISO_DATE filters by created_at <= until."""
        db = app.db
        with app.app_context():
            now = datetime.utcnow()
            later = now + timedelta(hours=1)
            db.audit_event.insert(action='now', outcome='success', status_code=200, created_at=now)
            db.audit_event.insert(action='future', outcome='success', status_code=200, created_at=later)
            db.commit()

        with app.test_client() as client:
            until_str = (now + timedelta(minutes=30)).isoformat()
            response = client.get(
                f'/api/v1/audit-events?until={until_str}',
                headers={'Authorization': f'Bearer {admin_token}'}
            )
            assert response.status_code == 200
            data = response.get_json()
            assert data['total'] == 1
            assert data['events'][0]['action'] == 'now'

    def test_endpoint_filter_by_until_invalid(self, app, admin_token):
        """GET /api/v1/audit-events?until=invalid returns 400."""
        with app.test_client() as client:
            response = client.get(
                '/api/v1/audit-events?until=not-a-date',
                headers={'Authorization': f'Bearer {admin_token}'}
            )
            assert response.status_code == 400

    def test_endpoint_pagination_limit_default(self, app, admin_token):
        """GET /api/v1/audit-events uses default limit of 50."""
        db = app.db
        with app.app_context():
            now = datetime.utcnow()
            for i in range(75):
                db.audit_event.insert(action=f'test_{i}', outcome='success', status_code=200, created_at=now)
            db.commit()

        with app.test_client() as client:
            response = client.get(
                '/api/v1/audit-events',
                headers={'Authorization': f'Bearer {admin_token}'}
            )
            assert response.status_code == 200
            data = response.get_json()
            assert len(data['events']) == 50
            assert data['limit'] == 50
            assert data['total'] == 75

    def test_endpoint_pagination_custom_limit(self, app, admin_token):
        """GET /api/v1/audit-events?limit=N respects custom limit."""
        db = app.db
        with app.app_context():
            now = datetime.utcnow()
            for i in range(100):
                db.audit_event.insert(action=f'test_{i}', outcome='success', status_code=200, created_at=now)
            db.commit()

        with app.test_client() as client:
            response = client.get(
                '/api/v1/audit-events?limit=25',
                headers={'Authorization': f'Bearer {admin_token}'}
            )
            assert response.status_code == 200
            data = response.get_json()
            assert len(data['events']) == 25
            assert data['limit'] == 25

    def test_endpoint_pagination_limit_too_large(self, app, admin_token):
        """GET /api/v1/audit-events?limit=501 returns 400."""
        with app.test_client() as client:
            response = client.get(
                '/api/v1/audit-events?limit=501',
                headers={'Authorization': f'Bearer {admin_token}'}
            )
            assert response.status_code == 400

    def test_endpoint_pagination_limit_too_small(self, app, admin_token):
        """GET /api/v1/audit-events?limit=0 returns 400."""
        with app.test_client() as client:
            response = client.get(
                '/api/v1/audit-events?limit=0',
                headers={'Authorization': f'Bearer {admin_token}'}
            )
            assert response.status_code == 400

    def test_endpoint_pagination_offset_negative(self, app, admin_token):
        """GET /api/v1/audit-events?offset=-1 returns 400."""
        with app.test_client() as client:
            response = client.get(
                '/api/v1/audit-events?offset=-1',
                headers={'Authorization': f'Bearer {admin_token}'}
            )
            assert response.status_code == 400

    def test_endpoint_combined_filters(self, app, admin_token):
        """GET /api/v1/audit-events with multiple filters."""
        db = app.db
        with app.app_context():
            now = datetime.utcnow()
            db.audit_event.insert(actor_id=1, resource_type='user', action='created', outcome='success', status_code=201, created_at=now)
            db.audit_event.insert(actor_id=1, resource_type='token', action='created', outcome='success', status_code=201, created_at=now)
            db.audit_event.insert(actor_id=2, resource_type='user', action='created', outcome='success', status_code=201, created_at=now)
            db.commit()

        with app.test_client() as client:
            response = client.get(
                '/api/v1/audit-events?actor_id=1&resource_type=user',
                headers={'Authorization': f'Bearer {admin_token}'}
            )
            assert response.status_code == 200
            data = response.get_json()
            assert data['total'] == 1
            assert data['events'][0]['actor_id'] == 1
            assert data['events'][0]['resource_type'] == 'user'

    def test_endpoint_response_format(self, app, admin_token):
        """GET /api/v1/audit-events response includes all required fields."""
        db = app.db
        with app.app_context():
            now = datetime.utcnow()
            db.audit_event.insert(
                actor_id=1,
                action='test_action',
                resource_type='test_resource',
                resource_id=42,
                outcome='success',
                status_code=200,
                request_id='req-123',
                source_ip='192.168.1.1',
                created_at=now
            )
            db.commit()

        with app.test_client() as client:
            response = client.get(
                '/api/v1/audit-events',
                headers={'Authorization': f'Bearer {admin_token}'}
            )
            assert response.status_code == 200
            data = response.get_json()
            assert 'events' in data
            assert 'total' in data
            assert 'limit' in data
            assert 'offset' in data

            event = data['events'][0]
            assert 'id' in event
            assert 'created_at' in event
            assert 'actor_id' in event
            assert 'tenant' in event
            assert 'action' in event
            assert 'resource_type' in event
            assert 'resource_id' in event
            assert 'outcome' in event
            assert 'status_code' in event
            assert 'request_id' in event
            assert 'source_ip' in event

    def test_endpoint_filter_by_tenant(self, app, admin_token):
        """GET /api/v1/audit-events?tenant=X filters by tenant."""
        db = app.db
        with app.app_context():
            now = datetime.utcnow()
            db.audit_event.insert(tenant='default', action='created', outcome='success', status_code=201, created_at=now)
            db.audit_event.insert(tenant='acme', action='created', outcome='success', status_code=201, created_at=now)
            db.commit()

        with app.test_client() as client:
            response = client.get(
                '/api/v1/audit-events?tenant=default',
                headers={'Authorization': f'Bearer {admin_token}'}
            )
            assert response.status_code == 200
            data = response.get_json()
            assert data['total'] == 1
            assert data['events'][0]['tenant'] == 'default'

    def test_endpoint_filter_by_tenant_combined(self, app, admin_token):
        """GET /api/v1/audit-events?tenant=X&action=Y filters by both tenant and action."""
        db = app.db
        with app.app_context():
            now = datetime.utcnow()
            db.audit_event.insert(tenant='default', action='created', outcome='success', status_code=201, created_at=now)
            db.audit_event.insert(tenant='default', action='deleted', outcome='success', status_code=200, created_at=now)
            db.audit_event.insert(tenant='acme', action='created', outcome='success', status_code=201, created_at=now)
            db.commit()

        with app.test_client() as client:
            response = client.get(
                '/api/v1/audit-events?tenant=default&action=created',
                headers={'Authorization': f'Bearer {admin_token}'}
            )
            assert response.status_code == 200
            data = response.get_json()
            assert data['total'] == 1
            assert data['events'][0]['tenant'] == 'default'
            assert data['events'][0]['action'] == 'created'
