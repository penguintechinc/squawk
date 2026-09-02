"""Tests for HttpOnly-cookie JWT auth (dns-webui XSS token-theft fix).

Covers the additive cookie flow set up in app/services/cookie_auth.py:
login/refresh/mfa-verify set HttpOnly access/refresh cookies plus a
JS-readable CSRF cookie; token_required accepts either an Authorization
header (existing bearer clients) or the cookie; state-changing
cookie-authenticated requests must present a matching X-CSRF-Token header
(double-submit); logout clears all three cookies and revokes the refresh
token regardless of which transport supplied it.
"""

from __future__ import annotations

from app.services.auth_service import AuthService
from app.services.cookie_auth import (
    ACCESS_COOKIE_NAME,
    CSRF_COOKIE_NAME,
    REFRESH_COOKIE_NAME,
)


def _make_user(db, username='cookie_user', password='CorrectHorse123!'):
    user_id = db.auth_user.insert(
        username=username,
        email=f'{username}@example.com',
        password_hash=AuthService.hash_password(password),
        global_role='Viewer',
        active=True,
        mfa_enabled=False,
    )
    db.commit()
    return user_id


def _set_cookie_headers(resp):
    """Return the raw Set-Cookie header values for the response."""
    return resp.headers.get_all('Set-Cookie')


def _find_cookie_header(resp, name):
    for header in _set_cookie_headers(resp):
        if header.startswith(f'{name}='):
            return header
    return None


class TestLoginSetsCookies:
    def test_login_sets_httponly_secure_samesite_cookies(self, app, db, client):
        with app.app_context():
            _make_user(db, username='alice_cookie')

        resp = client.post(
            '/api/v1/auth/login',
            json={'username': 'alice_cookie', 'password': 'CorrectHorse123!'},
        )
        assert resp.status_code == 200

        access_header = _find_cookie_header(resp, ACCESS_COOKIE_NAME)
        refresh_header = _find_cookie_header(resp, REFRESH_COOKIE_NAME)
        csrf_header = _find_cookie_header(resp, CSRF_COOKIE_NAME)

        assert access_header is not None
        assert 'HttpOnly' in access_header
        assert 'SameSite=Strict' in access_header
        assert 'Path=/' in access_header

        assert refresh_header is not None
        assert 'HttpOnly' in refresh_header
        assert 'Path=/api/v1/auth' in refresh_header

        # CSRF cookie must be readable by JS -- no HttpOnly attribute.
        assert csrf_header is not None
        assert 'HttpOnly' not in csrf_header

    def test_login_still_returns_tokens_in_json_body(self, app, db, client):
        """Bearer-token clients (manager/frontend, Go client) must be unaffected."""
        with app.app_context():
            _make_user(db, username='bob_cookie')

        resp = client.post(
            '/api/v1/auth/login',
            json={'username': 'bob_cookie', 'password': 'CorrectHorse123!'},
        )
        data = resp.get_json()
        assert 'accessToken' in data
        assert 'refreshToken' in data


class TestCookieAuthenticatesRequests:
    def test_protected_route_authenticates_via_cookie_only(self, app, db, client):
        """No Authorization header at all -- only the cookie jar from login."""
        with app.app_context():
            _make_user(db, username='carol_cookie')

        login_resp = client.post(
            '/api/v1/auth/login',
            json={'username': 'carol_cookie', 'password': 'CorrectHorse123!'},
        )
        assert login_resp.status_code == 200

        # client.get() with no Authorization header; the test client's
        # cookie jar resends the Set-Cookie values automatically.
        me_resp = client.get('/api/v1/auth/me')
        assert me_resp.status_code == 200
        assert me_resp.get_json()['username'] == 'carol_cookie'

    def test_bearer_header_still_works_unaffected(self, app, db, client):
        """Existing header-based clients keep working exactly as before."""
        with app.app_context():
            user_id = _make_user(db, username='dave_bearer')
            token = AuthService.create_access_token(user_id, 'dave_bearer', 'Viewer')

        resp = client.get(
            '/api/v1/auth/me', headers={'Authorization': f'Bearer {token}'}
        )
        assert resp.status_code == 200
        assert resp.get_json()['username'] == 'dave_bearer'

    def test_malformed_authorization_header_rejected(self, client):
        resp = client.get('/api/v1/auth/me', headers={'Authorization': 'NotBearer'})
        assert resp.status_code == 401

    def test_no_token_at_all_rejected(self, client):
        resp = client.get('/api/v1/auth/me')
        assert resp.status_code == 401


class TestCsrfProtectionOnCookiePath:
    def test_mutating_cookie_request_without_csrf_header_is_rejected(self, app, db, client):
        with app.app_context():
            _make_user(db, username='erin_csrf')

        login_resp = client.post(
            '/api/v1/auth/login',
            json={'username': 'erin_csrf', 'password': 'CorrectHorse123!'},
        )
        assert login_resp.status_code == 200

        # logout is a state-changing POST behind @token_required; the
        # cookie jar supplies the access_token cookie but no CSRF header.
        resp = client.post('/api/v1/auth/logout')
        assert resp.status_code == 403

    def test_mutating_cookie_request_with_correct_csrf_header_succeeds(self, app, db, client):
        with app.app_context():
            _make_user(db, username='frank_csrf')

        login_resp = client.post(
            '/api/v1/auth/login',
            json={'username': 'frank_csrf', 'password': 'CorrectHorse123!'},
        )
        csrf_token = login_resp.headers.get('Set-Cookie')
        # Pull the actual csrf_token value out of the client cookie jar.
        csrf_value = client.get_cookie(CSRF_COOKIE_NAME).value

        resp = client.post(
            '/api/v1/auth/logout', headers={'X-CSRF-Token': csrf_value}
        )
        assert resp.status_code == 200

    def test_mutating_cookie_request_with_wrong_csrf_header_is_rejected(self, app, db, client):
        with app.app_context():
            _make_user(db, username='grace_csrf')

        client.post(
            '/api/v1/auth/login',
            json={'username': 'grace_csrf', 'password': 'CorrectHorse123!'},
        )
        resp = client.post(
            '/api/v1/auth/logout', headers={'X-CSRF-Token': 'attacker-guessed-value'}
        )
        assert resp.status_code == 403

    def test_get_request_via_cookie_does_not_require_csrf(self, app, db, client):
        """GET is side-effect-free; no CSRF header should be required."""
        with app.app_context():
            _make_user(db, username='henry_csrf')

        client.post(
            '/api/v1/auth/login',
            json={'username': 'henry_csrf', 'password': 'CorrectHorse123!'},
        )
        resp = client.get('/api/v1/auth/me')
        assert resp.status_code == 200


class TestRefreshViaCookie:
    def test_refresh_with_no_body_uses_cookie_and_requires_csrf(self, app, db, client):
        with app.app_context():
            _make_user(db, username='iris_refresh')

        client.post(
            '/api/v1/auth/login',
            json={'username': 'iris_refresh', 'password': 'CorrectHorse123!'},
        )

        # Missing CSRF header -> rejected even though the refresh_token
        # cookie is present and valid.
        resp = client.post('/api/v1/auth/refresh', json={})
        assert resp.status_code == 403

        csrf_value = client.get_cookie(CSRF_COOKIE_NAME).value
        resp = client.post(
            '/api/v1/auth/refresh', json={}, headers={'X-CSRF-Token': csrf_value}
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'accessToken' in data and 'refreshToken' in data

        # Rotation also re-set the cookies.
        assert _find_cookie_header(resp, ACCESS_COOKIE_NAME) is not None
        assert _find_cookie_header(resp, REFRESH_COOKIE_NAME) is not None

    def test_refresh_body_token_still_works_for_bearer_clients(self, app, db, client):
        with app.app_context():
            user_id = _make_user(db, username='jack_refresh')
            refresh_token = AuthService.create_refresh_token(user_id)

        # Fresh client with no cookie jar state -- purely body-driven, as a
        # non-browser bearer client would do.
        resp = client.post(
            '/api/v1/auth/refresh', json={'refreshToken': refresh_token}
        )
        assert resp.status_code == 200
        assert 'accessToken' in resp.get_json()

    def test_refresh_missing_token_entirely_returns_400(self, client):
        resp = client.post('/api/v1/auth/refresh', json={})
        assert resp.status_code == 400


class TestLogoutClearsCookies:
    def test_logout_clears_all_three_cookies(self, app, db, client):
        with app.app_context():
            _make_user(db, username='karen_logout')

        client.post(
            '/api/v1/auth/login',
            json={'username': 'karen_logout', 'password': 'CorrectHorse123!'},
        )
        csrf_value = client.get_cookie(CSRF_COOKIE_NAME).value

        resp = client.post(
            '/api/v1/auth/logout', headers={'X-CSRF-Token': csrf_value}
        )
        assert resp.status_code == 200

        for name in (ACCESS_COOKIE_NAME, REFRESH_COOKIE_NAME, CSRF_COOKIE_NAME):
            header = _find_cookie_header(resp, name)
            assert header is not None
            # Expired cookies carry Max-Age=0 (or an epoch Expires date).
            assert 'Max-Age=0' in header

    def test_logout_revokes_cookie_sourced_refresh_token(self, app, db, client):
        with app.app_context():
            _make_user(db, username='larry_logout')

        login_resp = client.post(
            '/api/v1/auth/login',
            json={'username': 'larry_logout', 'password': 'CorrectHorse123!'},
        )
        refresh_token = login_resp.get_json()['refreshToken']
        csrf_value = client.get_cookie(CSRF_COOKIE_NAME).value

        client.post('/api/v1/auth/logout', headers={'X-CSRF-Token': csrf_value})

        # The refresh token that was in the (now-cleared) cookie must be
        # revoked server-side, not just forgotten client-side.
        with app.app_context():
            assert AuthService.refresh_access_token(refresh_token) is None


class TestMfaVerifySetsCookies:
    def test_mfa_verify_sets_cookies_on_success(self, app, db, client):
        import json as _json
        import pyotp
        from app.services.mfa_service import MFAService

        with app.app_context():
            secret = pyotp.random_base32()
            encrypted = MFAService.encrypt_secret(secret)
            _, hashed_codes = MFAService.generate_recovery_codes(count=8)
            db.auth_user.insert(
                username='mona_mfa',
                email='mona_mfa@example.com',
                password_hash=AuthService.hash_password('password123'),
                global_role='Viewer',
                active=True,
                mfa_enabled=True,
                mfa_secret=encrypted,
                mfa_recovery_codes=_json.dumps(hashed_codes),
            )
            db.commit()
            code = pyotp.TOTP(secret).now()

        login_resp = client.post(
            '/api/v1/auth/login',
            json={'username': 'mona_mfa', 'password': 'password123'},
        )
        pre_auth_token = login_resp.get_json()['pre_auth_token']

        resp = client.post(
            '/api/v1/auth/mfa-verify',
            json={'pre_auth_token': pre_auth_token, 'totp_code': code},
        )
        assert resp.status_code == 200
        assert _find_cookie_header(resp, ACCESS_COOKIE_NAME) is not None
        assert _find_cookie_header(resp, CSRF_COOKIE_NAME) is not None
