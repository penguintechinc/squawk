"""Regression tests: user create/update must not allow privilege escalation.

Prior to the fix, both endpoints required only users:write yet accepted an
arbitrary global_role including SystemAdmin — a UserManager (users:write,
no users:admin) could mint or promote a SystemAdmin account. Only users:admin
(SystemAdmin) may grant a role other than the caller's own or Viewer.
"""

import pytest

from app.services.auth_service import AuthService


@pytest.fixture
def usermanager_token(app):
    """JWT for a UserManager (users:write only, no users:admin)."""
    with app.app_context():
        db = app.db
        user = db.auth_user.insert(
            username='usermgr', email='usermgr@example.com',
            password_hash='hashed', global_role='UserManager',
        )
        db.commit()
        return AuthService.create_access_token(
            user_id=user, username='usermgr', global_role='UserManager', team_roles={},
        )


@pytest.fixture
def sysadmin_token(app):
    """JWT for a SystemAdmin (holds users:admin)."""
    with app.app_context():
        db = app.db
        user = db.auth_user.insert(
            username='sysadmin2', email='sysadmin2@example.com',
            password_hash='hashed', global_role='SystemAdmin',
        )
        db.commit()
        return AuthService.create_access_token(
            user_id=user, username='sysadmin2', global_role='SystemAdmin', team_roles={},
        )


class TestCreateUserPrivilegeEscalation:
    def test_usermanager_cannot_create_systemadmin(self, app, usermanager_token):
        with app.test_client() as client:
            response = client.post(
                '/api/v1/users',
                json={
                    'username': 'evil-admin',
                    'email': 'evil-admin@example.com',
                    'password': 'correcthorsebatterystaple1',
                    'global_role': 'SystemAdmin',
                },
                headers={'Authorization': f'Bearer {usermanager_token}'},
            )
            assert response.status_code == 403

    def test_usermanager_cannot_create_orgadmin(self, app, usermanager_token):
        """Lateral escalation: OrgAdmin holds different privileged scopes too."""
        with app.test_client() as client:
            response = client.post(
                '/api/v1/users',
                json={
                    'username': 'lateral-admin',
                    'email': 'lateral-admin@example.com',
                    'password': 'correcthorsebatterystaple1',
                    'global_role': 'OrgAdmin',
                },
                headers={'Authorization': f'Bearer {usermanager_token}'},
            )
            assert response.status_code == 403

    def test_usermanager_can_create_viewer(self, app, usermanager_token):
        with app.test_client() as client:
            response = client.post(
                '/api/v1/users',
                json={
                    'username': 'new-viewer',
                    'email': 'new-viewer@example.com',
                    'password': 'correcthorsebatterystaple1',
                    'global_role': 'Viewer',
                },
                headers={'Authorization': f'Bearer {usermanager_token}'},
            )
            assert response.status_code == 201

    def test_sysadmin_can_create_systemadmin(self, app, sysadmin_token):
        with app.test_client() as client:
            response = client.post(
                '/api/v1/users',
                json={
                    'username': 'legit-admin',
                    'email': 'legit-admin@example.com',
                    'password': 'correcthorsebatterystaple1',
                    'global_role': 'SystemAdmin',
                },
                headers={'Authorization': f'Bearer {sysadmin_token}'},
            )
            assert response.status_code == 201


class TestUpdateUserPrivilegeEscalation:
    def test_usermanager_cannot_promote_user_to_systemadmin(self, app, usermanager_token):
        with app.app_context():
            db = app.db
            target = db.auth_user.insert(
                username='target-user', email='target-user@example.com',
                password_hash='hashed', global_role='Viewer',
            )
            db.commit()

        with app.test_client() as client:
            response = client.put(
                f'/api/v1/users/{target}',
                json={'global_role': 'SystemAdmin'},
                headers={'Authorization': f'Bearer {usermanager_token}'},
            )
            assert response.status_code == 403

        with app.app_context():
            db = app.db
            assert db.auth_user[target].global_role == 'Viewer'
