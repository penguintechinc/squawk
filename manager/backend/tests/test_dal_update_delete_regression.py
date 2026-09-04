"""Regression tests: penguin-dal has no Row.update_record() / TableProxy
__delitem__, so every PUT/DELETE route that called `row.update_record(...)`
or `del db.<table>[id]` 500'd for every caller (two independent audits
confirmed this against installed penguin-dal 0.1.0-0.4.1). Fixed to the
supported QuerySet idiom: `db(db.<table>.id == <id>).update(**fields)` /
`db(db.<table>.id == <id>).delete()`.

These tests exercise each affected route end-to-end and assert the mutation
actually PERSISTED (re-fetch the row and check the field changed / the row
is gone) -- a bare 200 would not have caught this bug, since the response
body for several routes never echoed the fields the old .update_record()
call was silently failing to set.

Coverage not already exercised (with real persistence assertions) by
test_zone_access_control.py (zone update/delete) and
test_dhcp_time_access_control.py (dhcp pool / time server update/delete):
dns_record update+delete, user update+deactivate, team rename + member
role update + team delete, token delete, ioc_feed update+delete, sso
provider update, dns_server delete.
"""

from unittest.mock import Mock

import pytest

from app.services.auth_service import AuthService


@pytest.fixture
def sysadmin_token(app):
    """JWT for a SystemAdmin -- holds every scope exercised below."""
    with app.app_context():
        db = app.db
        user = db.auth_user.insert(
            username='dal-fix-sysadmin', email='dal-fix-sysadmin@example.com',
            password_hash='hashed', global_role='SystemAdmin',
        )
        db.commit()
        return AuthService.create_access_token(
            user_id=user, username='dal-fix-sysadmin', global_role='SystemAdmin',
            team_roles={},
        )


@pytest.fixture(autouse=True)
def _enterprise_license(app, monkeypatch):
    """SSO provider routes require Enterprise tier."""
    monkeypatch.setattr(app.license_service, 'is_enterprise', lambda: True)


@pytest.fixture
def ioc_flag_enabled(app):
    """Mock PostHog so ioc_feeds PUT/DELETE routes clear the flag gate."""
    original = app.posthog
    app.posthog = Mock(feature_enabled=lambda *a, **k: True)
    yield
    app.posthog = original


class TestDnsRecordUpdateDelete:
    """regression: dal-api-fix -- zones.py update_dns_record/delete_dns_record
    called `record.update_record(...)` / `del db.dns_record[id]`."""

    @pytest.fixture
    def zone_and_record(self, app):
        with app.app_context():
            db = app.db
            zone_id = db.dns_zone.insert(name='dal-fix-record.example.com', visibility='public')
            record_id = db.dns_record.insert(
                zone_id=zone_id, name='www', type='A', value='10.0.0.1', ttl=300,
            )
            db.commit()
            return zone_id, record_id

    def test_update_dns_record_persists(self, app, sysadmin_token, zone_and_record):
        zone_id, record_id = zone_and_record
        with app.test_client() as client:
            response = client.put(
                f'/api/v1/zones/{zone_id}/records/{record_id}',
                json={'value': '10.0.0.99', 'ttl': 600},
                headers={'Authorization': f'Bearer {sysadmin_token}'},
            )
            assert response.status_code == 200
            body = response.get_json()
            assert body['value'] == '10.0.0.99'
            assert body['ttl'] == 600

        with app.app_context():
            db = app.db
            record = db.dns_record[record_id]
            assert record.value == '10.0.0.99'
            assert record.ttl == 600

    def test_delete_dns_record_persists(self, app, sysadmin_token, zone_and_record):
        zone_id, record_id = zone_and_record
        with app.test_client() as client:
            response = client.delete(
                f'/api/v1/zones/{zone_id}/records/{record_id}',
                headers={'Authorization': f'Bearer {sysadmin_token}'},
            )
            assert response.status_code == 200

        with app.app_context():
            db = app.db
            assert db.dns_record[record_id] is None


class TestUserUpdateDeactivate:
    """regression: dal-api-fix -- users.py update_user/delete_user (soft
    delete) called `user.update_record(...)`."""

    @pytest.fixture
    def target_user(self, app):
        with app.app_context():
            db = app.db
            user_id = db.auth_user.insert(
                username='dal-fix-target', email='dal-fix-target@example.com',
                password_hash='hashed', global_role='Viewer', active=True,
            )
            db.commit()
            return user_id

    def test_update_user_persists(self, app, sysadmin_token, target_user):
        with app.test_client() as client:
            response = client.put(
                f'/api/v1/users/{target_user}',
                json={'email': 'dal-fix-target-new@example.com'},
                headers={'Authorization': f'Bearer {sysadmin_token}'},
            )
            assert response.status_code == 200
            assert response.get_json()['email'] == 'dal-fix-target-new@example.com'

        with app.app_context():
            db = app.db
            user = db.auth_user[target_user]
            assert user.email == 'dal-fix-target-new@example.com'

    def test_delete_user_soft_deactivates(self, app, sysadmin_token, target_user):
        with app.test_client() as client:
            response = client.delete(
                f'/api/v1/users/{target_user}',
                headers={'Authorization': f'Bearer {sysadmin_token}'},
            )
            assert response.status_code == 200

        with app.app_context():
            db = app.db
            user = db.auth_user[target_user]
            assert user is not None
            assert user.active is False


class TestTeamRenameMemberRoleDelete:
    """regression: dal-api-fix -- teams.py update_team (name/description),
    update_team_member_role, and delete_team called `team.update_record(...)`
    / `membership.update_record(...)` / `del db.team[id]`."""

    @pytest.fixture
    def team_with_member(self, app):
        with app.app_context():
            db = app.db
            team_id = db.team.insert(name='dal-fix-team', description='original')
            member_id = db.auth_user.insert(
                username='dal-fix-member', email='dal-fix-member@example.com',
                password_hash='hashed', global_role='Viewer',
            )
            db.team_member.insert(team_id=team_id, user_id=member_id, role='TeamMember')
            db.commit()
            return team_id, member_id

    def test_rename_team_persists(self, app, sysadmin_token, team_with_member):
        team_id, _ = team_with_member
        with app.test_client() as client:
            response = client.put(
                f'/api/v1/teams/{team_id}',
                json={'name': 'dal-fix-team-renamed', 'description': 'updated'},
                headers={'Authorization': f'Bearer {sysadmin_token}'},
            )
            assert response.status_code == 200
            assert response.get_json()['name'] == 'dal-fix-team-renamed'

        with app.app_context():
            db = app.db
            team = db.team[team_id]
            assert team.name == 'dal-fix-team-renamed'
            assert team.description == 'updated'

    def test_update_member_role_persists(self, app, sysadmin_token, team_with_member):
        team_id, member_id = team_with_member
        with app.test_client() as client:
            response = client.put(
                f'/api/v1/teams/{team_id}/members/{member_id}',
                json={'role': 'TeamAdmin'},
                headers={'Authorization': f'Bearer {sysadmin_token}'},
            )
            assert response.status_code == 200

        with app.app_context():
            db = app.db
            membership = db(
                (db.team_member.team_id == team_id) & (db.team_member.user_id == member_id)
            ).select().first()
            assert membership.role == 'TeamAdmin'

    def test_delete_team_persists(self, app, sysadmin_token, team_with_member):
        team_id, _ = team_with_member
        with app.test_client() as client:
            response = client.delete(
                f'/api/v1/teams/{team_id}',
                headers={'Authorization': f'Bearer {sysadmin_token}'},
            )
            assert response.status_code == 200

        with app.app_context():
            db = app.db
            assert db.team[team_id] is None


class TestTokenDelete:
    """regression: dal-api-fix -- tokens.py delete_token called
    `del db.token[token_id]`."""

    @pytest.fixture
    def team_less_token(self, app):
        """Team-less (global) token: _can_manage_token default-denies to
        SystemAdmin only, so the sysadmin_token fixture must be the caller."""
        with app.app_context():
            db = app.db
            token_id = db.token.insert(
                token_hash='a' * 64, name='dal-fix-token', active=True,
            )
            db.commit()
            return token_id

    def test_delete_token_persists(self, app, sysadmin_token, team_less_token):
        with app.test_client() as client:
            response = client.delete(
                f'/api/v1/tokens/{team_less_token}',
                headers={'Authorization': f'Bearer {sysadmin_token}'},
            )
            assert response.status_code == 200

        with app.app_context():
            db = app.db
            assert db.token[team_less_token] is None


class TestIocFeedUpdateDelete:
    """regression: dal-api-fix -- ioc_feeds.py update_ioc_feed and
    delete_ioc_feed called `feed.update_record(...)` / `del db.ioc_feed[id]`."""

    @pytest.fixture
    def ioc_feed(self, app):
        with app.app_context():
            db = app.db
            feed_id = db.ioc_feed.insert(
                name='dal-fix-feed', url='https://example.com/feed.csv',
                feed_type='url', active=True,
            )
            db.commit()
            return feed_id

    def test_update_ioc_feed_persists(
        self, app, sysadmin_token, ioc_flag_enabled, ioc_feed
    ):
        with app.test_client() as client:
            response = client.put(
                f'/api/v1/ioc-feeds/{ioc_feed}',
                json={'active': False, 'update_interval': 12},
                headers={'Authorization': f'Bearer {sysadmin_token}'},
            )
            assert response.status_code == 200
            body = response.get_json()
            assert body['active'] is False
            assert body['update_interval'] == 12

        with app.app_context():
            db = app.db
            feed = db.ioc_feed[ioc_feed]
            assert feed.active is False
            assert feed.update_interval == 12

    def test_delete_ioc_feed_persists(
        self, app, sysadmin_token, ioc_flag_enabled, ioc_feed
    ):
        with app.test_client() as client:
            response = client.delete(
                f'/api/v1/ioc-feeds/{ioc_feed}',
                headers={'Authorization': f'Bearer {sysadmin_token}'},
            )
            assert response.status_code == 200

        with app.app_context():
            db = app.db
            assert db.ioc_feed[ioc_feed] is None


class TestSsoProviderUpdate:
    """regression: dal-api-fix -- sso_admin.py update_sso_provider called
    `provider.update_record(**update_fields)`."""

    @pytest.fixture
    def sso_provider(self, app):
        with app.app_context():
            db = app.db
            provider_id = db.sso_providers.insert(
                name='dal-fix-okta', display_name='Okta (dal-fix)',
                issuer='https://okta.example.com', client_id='client-id',
                client_secret='encrypted-secret',
                authorization_endpoint='https://okta.example.com/authorize',
                token_endpoint='https://okta.example.com/token',
                jwks_url='https://okta.example.com/jwks', enabled=False,
            )
            db.commit()
            return provider_id

    def test_update_sso_provider_persists(self, app, sysadmin_token, sso_provider):
        with app.test_client() as client:
            response = client.patch(
                f'/api/v1/admin/sso/providers/{sso_provider}',
                json={'display_name': 'Okta Production', 'enabled': True},
                headers={'Authorization': f'Bearer {sysadmin_token}'},
            )
            assert response.status_code == 200
            assert response.get_json()['enabled'] is True

        with app.app_context():
            db = app.db
            provider = db.sso_providers[sso_provider]
            assert provider.display_name == 'Okta Production'
            assert provider.enabled is True


class TestDnsServerDelete:
    """regression: dal-api-fix -- dns_servers.py delete_dns_server called
    `del db.dns_server[server_id]`."""

    @pytest.fixture
    def dns_server(self, app):
        with app.app_context():
            db = app.db
            server_id = db.dns_server.insert(
                name='dal-fix-server', join_key_hash='b' * 64, jwt_secret='encrypted',
            )
            db.commit()
            return server_id

    def test_delete_dns_server_persists(self, app, sysadmin_token, dns_server):
        with app.test_client() as client:
            response = client.delete(
                f'/api/v1/dns-servers/{dns_server}',
                headers={'Authorization': f'Bearer {sysadmin_token}'},
            )
            assert response.status_code == 200

        with app.app_context():
            db = app.db
            assert db.dns_server[dns_server] is None
