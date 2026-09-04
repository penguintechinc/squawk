"""Regression tests: SCIM tokens must not act on users outside their scope.

Prior to the fix, any valid SCIM bearer token could enumerate, DELETE,
PATCH active=false, or PUT-rewrite ANY user in `auth_user` — including
locally-created SystemAdmins — because the SCIM handlers never filtered by
provisioning origin (external_id) and hardcoded a single 'default' tenant.

Without adding tenant infrastructure (out of scope — no tenant column
exists on auth_user), `_scim_manageable_user()` uses `external_id IS NOT
NULL` (set exclusively by the SCIM create flow) as the strongest available
proxy for "this token's provisioning scope", and unconditionally excludes
SystemAdmin regardless of provisioning origin to block SCIM-driven
lockout/takeover. This is a narrower guarantee than real per-tenant
isolation between multiple SCIM tokens — see the PR notes for what remains
open if/when a tenant column is added.
"""

import pytest

from app.services.scim_service import SCIMTokenService


@pytest.fixture
def scim_token(app):
    plaintext, _ = SCIMTokenService.create_token('access-control-test-token', 'default')
    SCIMTokenService.store_token(plaintext, 'access-control-test-token', 'default')
    return plaintext


@pytest.fixture
def scim_header(scim_token):
    return {'Authorization': f'Bearer {scim_token}'}


@pytest.fixture
def locally_created_systemadmin(app):
    """A SystemAdmin created outside SCIM (external_id is NULL)."""
    with app.app_context():
        db = app.db
        user_id = db.auth_user.insert(
            username='local-sysadmin', email='local-sysadmin@example.com',
            password_hash='hashed', global_role='SystemAdmin', active=True,
        )
        db.commit()
        return user_id


@pytest.fixture
def locally_created_viewer(app):
    """A regular Viewer created outside SCIM (external_id is NULL)."""
    with app.app_context():
        db = app.db
        user_id = db.auth_user.insert(
            username='local-viewer', email='local-viewer@example.com',
            password_hash='hashed', global_role='Viewer', active=True,
        )
        db.commit()
        return user_id


class TestScimCannotTouchOutOfScopeUsers:
    def test_scim_delete_cannot_deactivate_local_systemadmin(
        self, client, app, scim_header, locally_created_systemadmin
    ):
        resp = client.delete(f'/scim/v2/Users/{locally_created_systemadmin}', headers=scim_header)
        assert resp.status_code == 404

        with app.app_context():
            db = app.db
            assert db.auth_user[locally_created_systemadmin].active is True

    def test_scim_patch_cannot_deactivate_local_systemadmin(
        self, client, app, scim_header, locally_created_systemadmin
    ):
        resp = client.patch(
            f'/scim/v2/Users/{locally_created_systemadmin}',
            headers=scim_header,
            json={'Operations': [{'op': 'replace', 'path': 'active', 'value': False}]},
        )
        assert resp.status_code == 404

        with app.app_context():
            db = app.db
            assert db.auth_user[locally_created_systemadmin].active is True

    def test_scim_cannot_deactivate_locally_created_non_scim_user(
        self, client, app, scim_header, locally_created_viewer
    ):
        """Even a non-privileged locally-created user is out of SCIM's scope
        (no external_id) — the token must not be able to enumerate/act on it."""
        resp = client.delete(f'/scim/v2/Users/{locally_created_viewer}', headers=scim_header)
        assert resp.status_code == 404

        with app.app_context():
            db = app.db
            assert db.auth_user[locally_created_viewer].active is True

    def test_scim_get_cannot_read_local_systemadmin(
        self, client, scim_header, locally_created_systemadmin
    ):
        resp = client.get(f'/scim/v2/Users/{locally_created_systemadmin}', headers=scim_header)
        assert resp.status_code == 404

    def test_scim_list_excludes_locally_created_users(self, client, scim_header, locally_created_viewer):
        resp = client.get('/scim/v2/Users', headers=scim_header)
        assert resp.status_code == 200
        usernames = [r['userName'] for r in resp.get_json()['Resources']]
        assert 'local-viewer' not in usernames


class TestScimCanManageItsOwnProvisionedUsers:
    """Positive control: SCIM-provisioned users remain fully manageable."""

    def test_scim_can_deactivate_user_it_provisioned(self, client, scim_header):
        create_resp = client.post(
            '/scim/v2/Users', headers=scim_header,
            json={'userName': 'scim-owned-user', 'externalId': 'ext-owned-1', 'active': True},
        )
        assert create_resp.status_code == 201
        user_id = create_resp.get_json()['id']

        resp = client.delete(f'/scim/v2/Users/{user_id}', headers=scim_header)
        assert resp.status_code == 204
