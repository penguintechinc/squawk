"""Regression tests for DNS zone write access control.

Prior to the fix, `check_zone_access()` returned True for any public zone
and gated both reads AND writes — a Viewer (read-only role) could tamper
with or delete records in any public zone, and `create_zone` had no scope
check at all. These tests verify:

- Mutations require a zones:write/zones:admin scope (Viewer denied outright)
- `create_zone` requires zones:write and rejects an unowned team_id
- Zones with no team (org-wide/public) remain writable to any zones:write
  holder; zones:admin is required for delete (mirrors dhcp/time convention)
"""

import pytest

from app.services.auth_service import AuthService


@pytest.fixture
def viewer_token(app):
    """JWT for a Viewer (read-only; no zones:write/zones:admin)."""
    with app.app_context():
        db = app.db
        user = db.auth_user.insert(
            username='viewer', email='viewer@zonetest.example',
            password_hash='hashed', global_role='Viewer',
        )
        db.commit()
        return AuthService.create_access_token(
            user_id=user, username='viewer', global_role='Viewer', team_roles={},
        )


@pytest.fixture
def orgadmin_token(app):
    """JWT for an OrgAdmin (holds zones:write, not zones:admin)."""
    with app.app_context():
        db = app.db
        user = db.auth_user.insert(
            username='orgadmin', email='orgadmin@zonetest.example',
            password_hash='hashed', global_role='OrgAdmin',
        )
        db.commit()
        return AuthService.create_access_token(
            user_id=user, username='orgadmin', global_role='OrgAdmin', team_roles={},
        )


@pytest.fixture
def sysadmin_token(app):
    """JWT for a SystemAdmin (holds zones:write and zones:admin)."""
    with app.app_context():
        db = app.db
        user = db.auth_user.insert(
            username='sysadmin', email='sysadmin@zonetest.example',
            password_hash='hashed', global_role='SystemAdmin',
        )
        db.commit()
        return AuthService.create_access_token(
            user_id=user, username='sysadmin', global_role='SystemAdmin', team_roles={},
        )


@pytest.fixture
def public_zone(app):
    """A public, org-wide (team_id=None) DNS zone."""
    with app.app_context():
        db = app.db
        zone_id = db.dns_zone.insert(name='public.example.com', visibility='public')
        db.commit()
        return zone_id


class TestZoneMutationsRequireWriteScope:
    """Regression: a Viewer must not be able to mutate a public zone."""

    def test_viewer_cannot_update_public_zone(self, app, viewer_token, public_zone):
        with app.test_client() as client:
            response = client.put(
                f'/api/v1/zones/{public_zone}',
                json={'description': 'pwned by viewer'},
                headers={'Authorization': f'Bearer {viewer_token}'},
            )
            assert response.status_code == 403

    def test_viewer_cannot_delete_public_zone(self, app, viewer_token, public_zone):
        with app.test_client() as client:
            response = client.delete(
                f'/api/v1/zones/{public_zone}',
                headers={'Authorization': f'Bearer {viewer_token}'},
            )
            assert response.status_code == 403

    def test_viewer_cannot_create_dns_record_in_public_zone(self, app, viewer_token, public_zone):
        with app.test_client() as client:
            response = client.post(
                f'/api/v1/zones/{public_zone}/records',
                json={'name': 'evil.public.example.com', 'type': 'A', 'value': '6.6.6.6'},
                headers={'Authorization': f'Bearer {viewer_token}'},
            )
            assert response.status_code == 403

    def test_viewer_cannot_create_zone(self, app, viewer_token):
        with app.test_client() as client:
            response = client.post(
                '/api/v1/zones',
                json={'name': 'newzone.example.com', 'visibility': 'public'},
                headers={'Authorization': f'Bearer {viewer_token}'},
            )
            assert response.status_code == 403


class TestZoneWriteScopePositiveControl:
    """OrgAdmin (zones:write) can mutate an org-wide zone; delete needs zones:admin.

    regression: gh-dal-api-fix — the installed penguin-dal build has no
    Row.update_record()/TableProxy.__delitem__, so these routes previously
    500'd for every authorized caller (see app/blueprints/zones.py, fixed to
    the `db(db.dns_zone.id == ...).update()/.delete()` QuerySet idiom).
    These assertions now verify the mutation actually persisted, not just
    that authz let the caller through.
    """

    def test_orgadmin_can_update_public_zone(self, app, orgadmin_token, public_zone):
        with app.test_client() as client:
            response = client.put(
                f'/api/v1/zones/{public_zone}',
                json={'description': 'updated by orgadmin'},
                headers={'Authorization': f'Bearer {orgadmin_token}'},
            )
            assert response.status_code == 200
            assert response.get_json()['description'] == 'updated by orgadmin'

        with app.app_context():
            db = app.db
            zone = db.dns_zone[public_zone]
            assert zone.description == 'updated by orgadmin'

    def test_orgadmin_cannot_delete_public_zone(self, app, orgadmin_token, public_zone):
        """Delete requires zones:admin (SystemAdmin only), mirrors dhcp:admin/time:admin."""
        with app.test_client() as client:
            response = client.delete(
                f'/api/v1/zones/{public_zone}',
                headers={'Authorization': f'Bearer {orgadmin_token}'},
            )
            assert response.status_code == 403

    def test_sysadmin_can_delete_public_zone(self, app, sysadmin_token, public_zone):
        with app.test_client() as client:
            response = client.delete(
                f'/api/v1/zones/{public_zone}',
                headers={'Authorization': f'Bearer {sysadmin_token}'},
            )
            assert response.status_code == 200

        with app.app_context():
            db = app.db
            assert db.dns_zone[public_zone] is None


class TestCreateZoneTeamOwnership:
    """create_zone must not let a caller associate a zone with an unowned team."""

    def test_cannot_create_zone_for_team_not_a_member_of(self, app, orgadmin_token):
        with app.test_client() as client:
            response = client.post(
                '/api/v1/zones',
                json={
                    'name': 'notmine.example.com',
                    'visibility': 'internal',
                    'team_id': 9999,
                },
                headers={'Authorization': f'Bearer {orgadmin_token}'},
            )
            assert response.status_code == 403

    def test_can_create_zone_with_no_team(self, app, orgadmin_token):
        with app.test_client() as client:
            response = client.post(
                '/api/v1/zones',
                json={'name': 'orgwide.example.com', 'visibility': 'public'},
                headers={'Authorization': f'Bearer {orgadmin_token}'},
            )
            assert response.status_code == 201
