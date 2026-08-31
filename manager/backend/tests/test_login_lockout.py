"""Regression tests for account lockout / exponential backoff on repeated
failed logins, and MFA pre-auth token single-use consumption.

Prior implementation: `AuthService.authenticate_user` had no failure
tracking at all -- an attacker could throw unlimited password guesses at a
single username with no per-account defense (only a coarse, easily-varied
per-IP rate limit stood in the way). Similarly, `mfa_verify` allowed a
single pre-auth token to be presented repeatedly for the full 5-minute
validity window, permitting unlimited TOTP guesses per login.
"""

from datetime import datetime, timedelta

import pyotp

from app.services.auth_service import AuthService
from app.services.mfa_service import MFAService


def _make_user(db, username='lockout_test', password='CorrectHorse123!'):
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


class TestAccountLockout:
    """AuthService.authenticate_user lockout behavior."""

    def test_successful_login_does_not_lock(self, app, db):
        with app.app_context():
            _make_user(db, username='alice_lockout')
            result = AuthService.authenticate_user('alice_lockout', 'CorrectHorse123!')
            assert result is not None

    def test_failed_logins_below_threshold_not_locked(self, app, db):
        with app.app_context():
            _make_user(db, username='bob_lockout')
            threshold = app.config.get('LOGIN_LOCKOUT_THRESHOLD', 5)

            for _ in range(threshold - 1):
                assert AuthService.authenticate_user('bob_lockout', 'wrong') is None

            # Still below threshold: a correct password should succeed.
            assert AuthService.authenticate_user('bob_lockout', 'CorrectHorse123!') is not None

    def test_account_locked_after_threshold_failures(self, app, db):
        with app.app_context():
            _make_user(db, username='carol_lockout')
            threshold = app.config.get('LOGIN_LOCKOUT_THRESHOLD', 5)

            for _ in range(threshold):
                AuthService.authenticate_user('carol_lockout', 'wrong')

            # Even the CORRECT password is rejected while locked out.
            assert AuthService.authenticate_user('carol_lockout', 'CorrectHorse123!') is None

            user = db(db.auth_user.username == 'carol_lockout').select().first()
            assert user.locked_until is not None
            assert user.locked_until > datetime.utcnow()

    def test_lockout_backoff_increases_with_repeated_failures(self, app, db):
        with app.app_context():
            _make_user(db, username='dave_lockout')
            threshold = app.config.get('LOGIN_LOCKOUT_THRESHOLD', 5)

            for _ in range(threshold):
                AuthService.authenticate_user('dave_lockout', 'wrong')
            user = db(db.auth_user.username == 'dave_lockout').select().first()
            first_lock_duration = (user.locked_until - datetime.utcnow()).total_seconds()

            # Clear the lock to simulate the window expiring, then fail once
            # more -- the NEXT lock (failed_count now threshold+1) must be a
            # longer backoff than the first.
            db(db.auth_user.id == user.id).update(locked_until=None)
            db.commit()
            AuthService.authenticate_user('dave_lockout', 'wrong')
            user = db(db.auth_user.username == 'dave_lockout').select().first()
            second_lock_duration = (user.locked_until - datetime.utcnow()).total_seconds()

            assert second_lock_duration > first_lock_duration

    def test_lockout_expires_and_allows_retry(self, app, db):
        with app.app_context():
            user_id = _make_user(db, username='erin_lockout')
            threshold = app.config.get('LOGIN_LOCKOUT_THRESHOLD', 5)

            for _ in range(threshold):
                AuthService.authenticate_user('erin_lockout', 'wrong')

            # Simulate the lockout window having already elapsed.
            db(db.auth_user.id == user_id).update(
                locked_until=datetime.utcnow() - timedelta(seconds=1)
            )
            db.commit()

            assert AuthService.authenticate_user('erin_lockout', 'CorrectHorse123!') is not None

    def test_successful_login_resets_failure_count(self, app, db):
        with app.app_context():
            user_id = _make_user(db, username='frank_lockout')

            AuthService.authenticate_user('frank_lockout', 'wrong')
            AuthService.authenticate_user('frank_lockout', 'wrong')
            assert AuthService.authenticate_user('frank_lockout', 'CorrectHorse123!') is not None

            user = db.auth_user[user_id]
            assert (user.failed_login_count or 0) == 0
            assert user.locked_until is None

    def test_inactive_user_never_locks_or_leaks_state(self, app, db):
        """Inactive accounts still return None uniformly (no lockout
        bookkeeping performed) -- unchanged pre-existing behavior."""
        with app.app_context():
            user_id = db.auth_user.insert(
                username='inactive_lockout',
                email='inactive_lockout@example.com',
                password_hash=AuthService.hash_password('CorrectHorse123!'),
                global_role='Viewer',
                active=False,
            )
            db.commit()
            assert AuthService.authenticate_user('inactive_lockout', 'CorrectHorse123!') is None


class TestMFAPreAuthTokenSingleUse:
    """Pre-auth token jti single-use consumption."""

    def test_pre_auth_token_has_jti(self, app):
        with app.app_context():
            token = MFAService.create_pre_auth_token(user_id=1)
            payload = MFAService.decode_pre_auth_token(token)
            assert payload['jti']

    def test_second_verify_attempt_with_same_token_rejected(self, client, app, db):
        with app.app_context():
            secret = pyotp.random_base32()
            encrypted = MFAService.encrypt_secret(secret)
            totp = pyotp.TOTP(secret)
            code = totp.now()

            db.auth_user.insert(
                username='mfa_single_use',
                email='mfa_single_use@example.com',
                password_hash=AuthService.hash_password('CorrectHorse123!'),
                global_role='Viewer',
                active=True,
                mfa_enabled=True,
                mfa_secret=encrypted,
            )
            db.commit()

            resp_login = client.post(
                '/api/v1/auth/login',
                json={'username': 'mfa_single_use', 'password': 'CorrectHorse123!'}
            )
            pre_auth_token = resp_login.get_json()['pre_auth_token']

            # First attempt: deliberately wrong code -- still consumes the jti.
            resp1 = client.post(
                '/api/v1/auth/mfa-verify',
                json={'pre_auth_token': pre_auth_token, 'totp_code': '000000'}
            )
            assert resp1.status_code == 401

        # Second attempt with the SAME token (even with the now-correct
        # code) must be rejected -- the token was burned by attempt #1.
        with app.app_context():
            resp2 = client.post(
                '/api/v1/auth/mfa-verify',
                json={'pre_auth_token': pre_auth_token, 'totp_code': code}
            )
            assert resp2.status_code == 401
            assert 'Invalid or expired pre-auth token' in resp2.get_json()['error']
