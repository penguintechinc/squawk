"""Regression tests for DHCP/time BOLA fixes.

Prior to the fix, `update_dhcp_pool`/`delete_dhcp_pool`/`release_lease`/
`create_reservation`/`delete_reservation` (and the time-server equivalents)
checked only a global scope and skipped the `_can_access_pool`/
`_can_access_server` object/team check the GET handlers already applied —
any dhcp:write/time:write holder could mutate any team's pool/server.

NOTE on role model: today only SystemAdmin/OrgAdmin hold dhcp:write/
time:write, and `_can_access_pool`/`_can_access_server` treat both as
org-wide (pre-existing behavior, unchanged here) — so a real "team-scoped
operator" role does not exist yet. These tests construct a token with a
non-admin global_role but dhcp:write/time:write scope (the shape a future
team-scoped role would have) to directly exercise the object-level guard
added to the mutation routes. This also incidentally regression-tests the
`user['id']` / `globalRole` -> `user['user_id']` / `global_role` key-name
fix required to make that guard usable at all (previously KeyError'd for
every non-admin caller).
"""

from __future__ import annotations

import time as _time

import jwt
import pytest


def _team_scoped_token(app, jwt_keypair, user_id: int, scopes: str) -> str:
    """A token holding the given scopes but NOT global_role SystemAdmin/OrgAdmin.

    Exercises the object-level team check independent of the global_role
    short-circuit in _can_access_pool/_can_access_server.
    """
    now = int(_time.time())
    payload = {
        'sub': str(user_id),
        'iss': 'squawk-manager',
        'aud': 'squawk',
        'tenant': 'default',
        'user_id': user_id,
        'username': f'team-operator-{user_id}',
        'scope': scopes,
        'global_role': 'TeamOperator',  # deliberately not SystemAdmin/OrgAdmin
        'team_roles': {},
        'type': 'access',
        'exp': now + 3600,
        'iat': now,
    }
    return jwt.encode(payload, jwt_keypair['private'], algorithm='ES256')


@pytest.fixture
def team_a_and_b(app):
    """Two teams; a distinct user is a member of team A only."""
    with app.app_context():
        db = app.db
        team_a = db.team.insert(name='team-a-dhcp-test')
        team_b = db.team.insert(name='team-b-dhcp-test')
        user = db.auth_user.insert(
            username='team-a-op', email='team-a-op@example.com',
            password_hash='hashed', global_role='Viewer',
        )
        db.team_member.insert(team_id=team_a, user_id=user, role='TeamMember')
        db.commit()
        return {'team_a': team_a, 'team_b': team_b, 'user_id': user}


class TestDhcpPoolCrossTeamIsolation:
    def test_team_a_token_cannot_delete_team_b_pool(self, app, jwt_keypair, team_a_and_b):
        with app.app_context():
            db = app.db
            pool_id = db.dhcp_pool.insert(
                name='team-b-pool', network='10.20.0.0/24',
                range_start='10.20.0.10', range_end='10.20.0.200',
                team_id=team_a_and_b['team_b'],
            )
            db.commit()

        # delete_dhcp_pool requires dhcp:admin (not just dhcp:write) — grant
        # it here so the request reaches the object-level team check being
        # tested, rather than getting denied one layer earlier on scope.
        token = _team_scoped_token(
            app, jwt_keypair, team_a_and_b['user_id'], 'dhcp:admin dhcp:read'
        )
        with app.test_client() as client:
            response = client.delete(
                f'/api/v1/dhcp/pools/{pool_id}',
                headers={'Authorization': f'Bearer {token}'},
            )
            assert response.status_code == 403

    def test_team_a_token_can_delete_team_a_pool(self, app, jwt_keypair, team_a_and_b):
        with app.app_context():
            db = app.db
            pool_id = db.dhcp_pool.insert(
                name='team-a-pool', network='10.30.0.0/24',
                range_start='10.30.0.10', range_end='10.30.0.200',
                team_id=team_a_and_b['team_a'],
            )
            db.commit()

        token = _team_scoped_token(
            app, jwt_keypair, team_a_and_b['user_id'], 'dhcp:admin dhcp:read'
        )
        # NOTE: `del db.dhcp_pool[...]` raises in this environment — the
        # installed penguin-dal build's TableProxy has no __delitem__ (a
        # pre-existing, unrelated DAL/app mismatch affecting every DELETE
        # route in this codebase; see PR notes). With TESTING=True, Flask
        # re-raises rather than returning 500, so reaching this specific
        # exception (instead of a clean 403 JSON body) is itself proof the
        # authz gate let the same-team caller through.
        with app.test_client() as client, pytest.raises(TypeError, match='item deletion'):
            client.delete(
                f'/api/v1/dhcp/pools/{pool_id}',
                headers={'Authorization': f'Bearer {token}'},
            )


class TestTimeServerCrossTeamIsolation:
    def test_team_a_token_cannot_repoint_team_b_ntp_server(self, app, jwt_keypair, team_a_and_b):
        with app.app_context():
            db = app.db
            server_id = db.time_server.insert(
                name='team-b-ntp', server_url='ntp://10.0.0.1', protocol='ntp',
                team_id=team_a_and_b['team_b'],
            )
            db.commit()

        token = _team_scoped_token(
            app, jwt_keypair, team_a_and_b['user_id'], 'time:write time:read'
        )
        with app.test_client() as client:
            response = client.put(
                f'/api/v1/time/servers/{server_id}',
                json={'serverUrl': 'ntp://attacker.example'},
                headers={'Authorization': f'Bearer {token}'},
            )
            assert response.status_code == 403

        with app.app_context():
            db = app.db
            server = db.time_server[server_id]
            assert server.server_url == 'ntp://10.0.0.1'

    def test_team_a_token_can_repoint_team_a_ntp_server(self, app, jwt_keypair, team_a_and_b):
        with app.app_context():
            db = app.db
            server_id = db.time_server.insert(
                name='team-a-ntp', server_url='ntp://10.0.0.2', protocol='ntp',
                team_id=team_a_and_b['team_a'],
            )
            db.commit()

        token = _team_scoped_token(
            app, jwt_keypair, team_a_and_b['user_id'], 'time:write time:read'
        )
        # NOTE: `server.update_record(...)` raises in this environment — the
        # installed penguin-dal build's Row has no update_record() (a
        # pre-existing, unrelated DAL/app mismatch affecting every PUT route
        # in this codebase; see PR notes). With TESTING=True, Flask
        # re-raises rather than returning 500, so reaching this specific
        # exception (instead of a clean 403 JSON body) is itself proof the
        # authz gate let the same-team caller through.
        with app.test_client() as client, pytest.raises(AttributeError, match='update_record'):
            client.put(
                f'/api/v1/time/servers/{server_id}',
                json={'serverUrl': 'ntp://10.0.0.99'},
                headers={'Authorization': f'Bearer {token}'},
            )
