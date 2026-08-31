"""Regression tests for client-config API authorization.

Prior to the fix, every client-config route was gated only by
@token_required + a PostHog flag — no scope/ownership check — so any
authenticated caller (including a plain Viewer) could roll a deployment
domain's JWT (returned in the response body) or write configs. These tests
verify config:write/config:admin scope enforcement. `monkeypatch` (not a
direct app.posthog mutation) is used so the flag override never leaks into
other test modules sharing the session-scoped `app` fixture.
"""

import pytest

from app.services.auth_service import AuthService


@pytest.fixture(autouse=True)
def _enable_client_config_flag(app, monkeypatch):
    """Force the squawkdns.client-config PostHog flag on for this module."""
    monkeypatch.setattr(app.posthog, 'feature_enabled', lambda *a, **kw: True)


@pytest.fixture
def viewer_token(app):
    with app.app_context():
        db = app.db
        user = db.auth_user.insert(
            username='cc-viewer', email='cc-viewer@example.com',
            password_hash='hashed', global_role='Viewer',
        )
        db.commit()
        return AuthService.create_access_token(
            user_id=user, username='cc-viewer', global_role='Viewer', team_roles={},
        )


@pytest.fixture
def orgadmin_token(app):
    """Holds config:write but not config:admin."""
    with app.app_context():
        db = app.db
        user = db.auth_user.insert(
            username='cc-orgadmin', email='cc-orgadmin@example.com',
            password_hash='hashed', global_role='OrgAdmin',
        )
        db.commit()
        return AuthService.create_access_token(
            user_id=user, username='cc-orgadmin', global_role='OrgAdmin', team_roles={},
        )


@pytest.fixture
def sysadmin_token(app):
    """Holds config:admin."""
    with app.app_context():
        db = app.db
        user = db.auth_user.insert(
            username='cc-sysadmin', email='cc-sysadmin@example.com',
            password_hash='hashed', global_role='SystemAdmin',
        )
        db.commit()
        return AuthService.create_access_token(
            user_id=user, username='cc-sysadmin', global_role='SystemAdmin', team_roles={},
        )


@pytest.fixture
def deployment_domain(app):
    with app.app_context():
        db = app.db
        domain_id = db.deployment_domain.insert(
            name='rollover-test-domain',
            jwt_token='placeholder-jwt',
            jwt_expires=__import__('datetime').datetime.now(),
            active=True,
        )
        db.commit()
        return domain_id


class TestJwtRolloverRequiresConfigAdmin:
    """Regression: a non-config-scoped (and non-config:admin) token cannot roll a domain JWT."""

    def test_viewer_cannot_rollover_domain_jwt(self, app, viewer_token, deployment_domain):
        with app.test_client() as client:
            response = client.post(
                f'/api/v1/client-config/domains/{deployment_domain}/jwt-rollover',
                headers={'Authorization': f'Bearer {viewer_token}'},
            )
            assert response.status_code == 403

    def test_orgadmin_config_write_cannot_rollover_domain_jwt(self, app, orgadmin_token, deployment_domain):
        """config:write is not enough — rollover requires config:admin."""
        with app.test_client() as client:
            response = client.post(
                f'/api/v1/client-config/domains/{deployment_domain}/jwt-rollover',
                headers={'Authorization': f'Bearer {orgadmin_token}'},
            )
            assert response.status_code == 403

    def test_sysadmin_can_rollover_domain_jwt(self, app, sysadmin_token, deployment_domain):
        with app.test_client() as client:
            response = client.post(
                f'/api/v1/client-config/domains/{deployment_domain}/jwt-rollover',
                headers={'Authorization': f'Bearer {sysadmin_token}'},
            )
            assert response.status_code == 200


class TestCreateDomainRequiresConfigWrite:
    def test_viewer_cannot_create_domain(self, app, viewer_token):
        with app.test_client() as client:
            response = client.post(
                '/api/v1/client-config/domains',
                json={'name': 'viewer-created-domain'},
                headers={'Authorization': f'Bearer {viewer_token}'},
            )
            assert response.status_code == 403

    def test_orgadmin_can_create_domain(self, app, orgadmin_token):
        with app.test_client() as client:
            response = client.post(
                '/api/v1/client-config/domains',
                json={'name': 'orgadmin-created-domain'},
                headers={'Authorization': f'Bearer {orgadmin_token}'},
            )
            assert response.status_code == 201


class TestActorAttributionFromAuthenticatedIdentity:
    """X-User-ID header must never be trusted for audit attribution."""

    def test_created_by_ignores_spoofed_header(self, app, orgadmin_token, deployment_domain):
        with app.test_client() as client:
            response = client.post(
                f'/api/v1/client-config/domains/{deployment_domain}/configs',
                json={
                    'name': 'attribution-test-config',
                    'config_data': {
                        'server_url': 'https://dns.example.com',
                        'dns_port': 53,
                        'cache_enabled': True,
                    },
                },
                headers={
                    'Authorization': f'Bearer {orgadmin_token}',
                    'X-User-ID': 'someone-else-entirely',
                },
            )
            assert response.status_code == 201

        with app.app_context():
            db = app.db
            config = db(db.client_config.name == 'attribution-test-config').select().first()
            assert config is not None
            assert config.created_by != 'someone-else-entirely'
