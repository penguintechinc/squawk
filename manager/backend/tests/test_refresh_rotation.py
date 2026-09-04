"""Tests for refresh-token rotation and revocation.

Refresh tokens are single-use: /auth/refresh revokes the presented token and
issues a new pair; reuse of a rotated or logged-out token fails. Legacy
jti-less refresh tokens are rejected (they cannot be revoked).
"""

from __future__ import annotations

from datetime import datetime, timedelta

import jwt
import pytest

from app.services.auth_service import AuthService


@pytest.fixture
def user_id(app):
    """Insert an active test user and return its id."""
    user = app.db.auth_user.insert(
        username='rotate-user',
        email='rotate@example.com',
        password_hash='x',
        global_role='Viewer',
        active=True,
    )
    app.db.commit()
    return user


def test_refresh_token_carries_jti(app, jwt_keypair, user_id):
    token = AuthService.create_refresh_token(user_id)
    payload = jwt.decode(
        token, jwt_keypair['public'], algorithms=['ES256'],
        audience='squawk', issuer='squawk-manager',
    )
    assert payload['type'] == 'refresh'
    assert payload.get('jti')  # non-empty unique id


def test_refresh_rotates_and_blocks_reuse(app, user_id):
    original = AuthService.create_refresh_token(user_id)

    first = AuthService.refresh_access_token(original)
    assert first is not None
    assert first['access_token'] and first['refresh_token']
    assert first['refresh_token'] != original

    # The presented token was revoked by rotation — reuse must fail.
    assert AuthService.refresh_access_token(original) is None

    # The rotated (new) token still works.
    second = AuthService.refresh_access_token(first['refresh_token'])
    assert second is not None


def test_logout_revocation_blocks_refresh(app, user_id):
    token = AuthService.create_refresh_token(user_id)
    assert AuthService.revoke_refresh_token(token, reason='logout') is True
    assert AuthService.refresh_access_token(token) is None


def test_legacy_jtiless_refresh_token_rejected(app, jwt_keypair, user_id):
    """Refresh tokens minted before rotation (no jti) cannot be rotated."""
    now = datetime.utcnow()
    legacy = jwt.encode(
        {
            'sub': str(user_id), 'iss': 'squawk-manager', 'aud': 'squawk',
            'tenant': 'default', 'user_id': user_id, 'type': 'refresh',
            'exp': now + timedelta(days=7), 'iat': now,
        },
        jwt_keypair['private'], algorithm='ES256',
    )
    assert AuthService.refresh_access_token(legacy) is None


def test_access_token_not_accepted_for_refresh(app, user_id):
    access = AuthService.create_access_token(user_id, 'rotate-user', 'Viewer')
    assert AuthService.refresh_access_token(access) is None


def test_inactive_user_cannot_refresh(app, user_id):
    token = AuthService.create_refresh_token(user_id)
    app.db(app.db.auth_user.id == user_id).update(active=False)
    app.db.commit()
    assert AuthService.refresh_access_token(token) is None


def test_expired_denylist_rows_are_purged(app, user_id):
    """Rows for already-expired tokens are purged on the next revocation."""
    db = app.db
    db.revoked_token.insert(
        jti='stale-jti', user_id=user_id, reason='rotated',
        expires_at=datetime.utcnow() - timedelta(days=1),
    )
    db.commit()

    token = AuthService.create_refresh_token(user_id)
    AuthService.revoke_refresh_token(token, reason='logout')

    assert db(db.revoked_token.jti == 'stale-jti').count() == 0


def test_refresh_endpoint_rotation_flow(app, client, user_id):
    original = AuthService.create_refresh_token(user_id)

    resp = client.post('/api/v1/auth/refresh', json={'refreshToken': original})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body['accessToken'] and body['refreshToken']

    # Reuse of the original (rotated) token → 401.
    resp2 = client.post('/api/v1/auth/refresh', json={'refreshToken': original})
    assert resp2.status_code == 401

    # The rotated token works.
    resp3 = client.post(
        '/api/v1/auth/refresh', json={'refreshToken': body['refreshToken']}
    )
    assert resp3.status_code == 200


def test_logout_endpoint_revokes_refresh_token(app, client, user_id, jwt_token_factory):
    refresh = AuthService.create_refresh_token(user_id)
    access = jwt_token_factory(user_id=user_id)

    resp = client.post(
        '/api/v1/auth/logout',
        json={'refreshToken': refresh},
        headers={'Authorization': f'Bearer {access}'},
    )
    assert resp.status_code == 200

    # The revoked refresh token can no longer mint access tokens.
    resp2 = client.post('/api/v1/auth/refresh', json={'refreshToken': refresh})
    assert resp2.status_code == 401
