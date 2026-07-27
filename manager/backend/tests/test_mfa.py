"""
TOTP Multi-Factor Authentication Tests

Tests for TOTP enrollment, activation, verification, and disabling.
Covers happy path, error cases, replay protection, and recovery codes.
"""

import json
import pytest
import pyotp
from app.services.auth_service import AuthService
from app.services.mfa_service import MFAService


class TestMFAServiceUnit:
    """Unit tests for MFAService logic."""

    def test_generate_totp_secret(self):
        """Test TOTP secret generation."""
        mfa_secret = MFAService.generate_totp_secret('testuser')
        assert mfa_secret.secret
        assert len(mfa_secret.secret) == 32  # Base32-encoded
        assert 'otpauth://' in mfa_secret.provisioning_uri
        assert 'testuser' in mfa_secret.provisioning_uri
        # Issuer name may be URL-encoded
        assert 'Squawk%20DNS%20Manager' in mfa_secret.provisioning_uri or 'Squawk DNS Manager' in mfa_secret.provisioning_uri

    def test_verify_totp_valid_code(self):
        """Test TOTP code verification with valid code."""
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        code = totp.now()
        assert MFAService.verify_totp(secret, code, window=1) is True

    def test_verify_totp_invalid_code(self):
        """Test TOTP code verification with invalid code."""
        secret = pyotp.random_base32()
        assert MFAService.verify_totp(secret, '000000', window=1) is False

    def test_verify_totp_wrong_format(self):
        """Test TOTP code verification with wrong format."""
        secret = pyotp.random_base32()
        assert MFAService.verify_totp(secret, 'abcdef', window=1) is False
        assert MFAService.verify_totp(secret, '12345', window=1) is False
        assert MFAService.verify_totp(secret, '', window=1) is False

    def test_encrypt_decrypt_secret(self, app):
        """Test TOTP secret encryption and decryption."""
        with app.app_context():
            original_secret = 'JBSWY3DPEBLW64TMMQ======'
            encrypted = MFAService.encrypt_secret(original_secret)
            assert encrypted != original_secret
            decrypted = MFAService.decrypt_secret(encrypted)
            assert decrypted == original_secret

    def test_recovery_code_hashing(self):
        """Test recovery code hashing and verification."""
        code = 'ABC12345'
        hashed = MFAService.hash_recovery_code(code)
        assert hashed != code
        assert MFAService.verify_recovery_code(code, hashed) is True
        assert MFAService.verify_recovery_code('WRONG1234', hashed) is False

    def test_generate_recovery_codes(self):
        """Test recovery code generation."""
        plain, hashed = MFAService.generate_recovery_codes(count=8)
        assert len(plain) == 8
        assert len(hashed) == 8
        # Verify each code matches its hash
        for code, code_hash in zip(plain, hashed):
            assert MFAService.verify_recovery_code(code, code_hash) is True

    def test_create_pre_auth_token(self, app):
        """Test pre-auth token creation."""
        with app.app_context():
            token = MFAService.create_pre_auth_token(user_id=1)
            assert token
            payload = MFAService.decode_pre_auth_token(token)
            assert payload
            assert payload['user_id'] == 1
            assert payload['type'] == 'pre_auth'
            assert payload['scope'] == 'mfa:verify'
            assert payload['tenant'] == 'default'

    def test_decode_pre_auth_token_invalid(self, app):
        """Test pre-auth token validation with invalid token."""
        with app.app_context():
            assert MFAService.decode_pre_auth_token('invalid') is None

    def test_decode_pre_auth_token_wrong_type(self, app, jwt_token_factory):
        """Test pre-auth token validation with wrong type."""
        with app.app_context():
            # Create a normal access token (not pre_auth)
            token = jwt_token_factory(user_id=1, token_type='access')
            assert MFAService.decode_pre_auth_token(token) is None

    def test_totp_counter_tracking(self):
        """Test TOTP counter for replay detection."""
        secret = pyotp.random_base32()
        counter1 = MFAService.get_totp_counter(secret)
        assert isinstance(counter1, int)
        counter2 = MFAService.get_totp_counter(secret)
        # Counters should be the same within the same time window
        assert counter1 == counter2


class TestMFAEnrollment:
    """Test MFA enrollment flow."""

    def test_enroll_starts_mfa_flow(self, client, app, jwt_token_factory):
        """Test MFA enrollment returns provisioning URI."""
        with app.app_context():
            # Create user
            db = app.db
            user = db.auth_user.insert(
                username='alice',
                email='alice@example.com',
                password_hash=AuthService.hash_password('password123'),
                global_role='Viewer',
                active=True,
                mfa_enabled=False
            )

            token = jwt_token_factory(user_id=user, username='alice')
            resp = client.post(
                '/api/v1/mfa/enroll',
                headers={'Authorization': f'Bearer {token}'}
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert 'secret' in data
        assert 'provisioning_uri' in data
        assert 'otpauth://' in data['provisioning_uri']
        assert len(data['secret']) == 32

    def test_enroll_without_auth(self, client):
        """Test enrollment requires authentication."""
        resp = client.post('/api/v1/mfa/enroll')
        assert resp.status_code == 401

    def test_enroll_mfa_already_enabled(self, client, app, jwt_token_factory):
        """Test enrollment fails if MFA already enabled."""
        with app.app_context():
            db = app.db
            user = db.auth_user.insert(
                username='bob',
                email='bob@example.com',
                password_hash=AuthService.hash_password('password123'),
                global_role='Viewer',
                active=True,
                mfa_enabled=True,
                mfa_secret='encrypted_secret'
            )

            token = jwt_token_factory(user_id=user, username='bob')
            resp = client.post(
                '/api/v1/mfa/enroll',
                headers={'Authorization': f'Bearer {token}'}
            )

        assert resp.status_code == 409
        assert 'already enabled' in resp.get_json()['error']


class TestMFAActivation:
    """Test MFA activation flow."""

    def test_activate_mfa_happy_path(self, client, app, jwt_token_factory):
        """Test MFA activation with valid TOTP code."""
        with app.app_context():
            db = app.db
            user = db.auth_user.insert(
                username='charlie',
                email='charlie@example.com',
                password_hash=AuthService.hash_password('password123'),
                global_role='Viewer',
                active=True,
                mfa_enabled=False
            )

            # Generate a fresh secret
            secret = pyotp.random_base32()
            totp = pyotp.TOTP(secret)
            code = totp.now()

            token = jwt_token_factory(user_id=user, username='charlie')
            resp = client.post(
                '/api/v1/mfa/activate',
                json={'secret': secret, 'totp_code': code},
                headers={'Authorization': f'Bearer {token}'}
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert data['message'] == 'MFA activated successfully'
        assert 'recovery_codes' in data
        assert len(data['recovery_codes']) == 8

        # Verify user record updated
        with app.app_context():
            updated_user = db(db.auth_user.id == user).select().first()
            assert updated_user.get('mfa_enabled') is True
            assert updated_user.get('mfa_secret') is not None

    def test_activate_invalid_totp_code(self, client, app, jwt_token_factory):
        """Test activation fails with invalid TOTP code."""
        with app.app_context():
            db = app.db
            user = db.auth_user.insert(
                username='diana',
                email='diana@example.com',
                password_hash=AuthService.hash_password('password123'),
                global_role='Viewer',
                active=True,
                mfa_enabled=False
            )

            secret = pyotp.random_base32()
            token = jwt_token_factory(user_id=user, username='diana')
            resp = client.post(
                '/api/v1/mfa/activate',
                json={'secret': secret, 'totp_code': '000000'},
                headers={'Authorization': f'Bearer {token}'}
            )

        assert resp.status_code == 401
        assert 'Invalid TOTP code' in resp.get_json()['error']

    def test_activate_already_enabled(self, client, app, jwt_token_factory):
        """Test activation fails if MFA already enabled."""
        with app.app_context():
            db = app.db
            user = db.auth_user.insert(
                username='eve',
                email='eve@example.com',
                password_hash=AuthService.hash_password('password123'),
                global_role='Viewer',
                active=True,
                mfa_enabled=True,
                mfa_secret='encrypted_secret'
            )

            secret = pyotp.random_base32()
            token = jwt_token_factory(user_id=user, username='eve')
            resp = client.post(
                '/api/v1/mfa/activate',
                json={'secret': secret, 'totp_code': '123456'},
                headers={'Authorization': f'Bearer {token}'}
            )

        assert resp.status_code == 409


class TestMFAVerification:
    """Test MFA verification during login."""

    def test_login_with_mfa_returns_pre_auth_token(self, client, app):
        """Test login returns pre-auth token when MFA enabled."""
        with app.app_context():
            db = app.db
            secret = pyotp.random_base32()
            encrypted = MFAService.encrypt_secret(secret)
            _, hashed_codes = MFAService.generate_recovery_codes(count=8)

            user = db.auth_user.insert(
                username='frank',
                email='frank@example.com',
                password_hash=AuthService.hash_password('password123'),
                global_role='Viewer',
                active=True,
                mfa_enabled=True,
                mfa_secret=encrypted,
                mfa_recovery_codes=json.dumps(hashed_codes)
            )

            resp = client.post(
                '/api/v1/auth/login',
                json={'username': 'frank', 'password': 'password123'}
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert data['mfa_required'] is True
        assert 'pre_auth_token' in data
        assert 'accessToken' not in data

    def test_mfa_verify_with_totp_happy_path(self, client, app, jwt_token_factory):
        """Test MFA verification with valid TOTP code."""
        with app.app_context():
            db = app.db
            secret = pyotp.random_base32()
            encrypted = MFAService.encrypt_secret(secret)
            totp = pyotp.TOTP(secret)
            code = totp.now()
            _, hashed_codes = MFAService.generate_recovery_codes(count=8)

            user = db.auth_user.insert(
                username='grace',
                email='grace@example.com',
                password_hash=AuthService.hash_password('password123'),
                global_role='Viewer',
                active=True,
                mfa_enabled=True,
                mfa_secret=encrypted,
                mfa_recovery_codes=json.dumps(hashed_codes)
            )

            # Get pre-auth token
            resp_login = client.post(
                '/api/v1/auth/login',
                json={'username': 'grace', 'password': 'password123'}
            )
            pre_auth_token = resp_login.get_json()['pre_auth_token']

            # Verify MFA
            resp = client.post(
                '/api/v1/auth/mfa-verify',
                json={'pre_auth_token': pre_auth_token, 'totp_code': code}
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert 'accessToken' in data
        assert 'refreshToken' in data
        assert data['user']['username'] == 'grace'

    def test_mfa_verify_with_recovery_code(self, client, app):
        """Test MFA verification with recovery code."""
        with app.app_context():
            db = app.db
            secret = pyotp.random_base32()
            encrypted = MFAService.encrypt_secret(secret)
            plain_codes, hashed_codes = MFAService.generate_recovery_codes(count=8)
            recovery_code = plain_codes[0]

            user = db.auth_user.insert(
                username='henry',
                email='henry@example.com',
                password_hash=AuthService.hash_password('password123'),
                global_role='Viewer',
                active=True,
                mfa_enabled=True,
                mfa_secret=encrypted,
                mfa_recovery_codes=json.dumps(hashed_codes)
            )

            # Get pre-auth token
            resp_login = client.post(
                '/api/v1/auth/login',
                json={'username': 'henry', 'password': 'password123'}
            )
            pre_auth_token = resp_login.get_json()['pre_auth_token']

            # Verify with recovery code
            resp = client.post(
                '/api/v1/auth/mfa-verify',
                json={'pre_auth_token': pre_auth_token, 'recovery_code': recovery_code}
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert 'accessToken' in data

    def test_mfa_verify_invalid_code(self, client, app):
        """Test MFA verification fails with invalid code."""
        with app.app_context():
            db = app.db
            secret = pyotp.random_base32()
            encrypted = MFAService.encrypt_secret(secret)
            _, hashed_codes = MFAService.generate_recovery_codes(count=8)

            user = db.auth_user.insert(
                username='iris',
                email='iris@example.com',
                password_hash=AuthService.hash_password('password123'),
                global_role='Viewer',
                active=True,
                mfa_enabled=True,
                mfa_secret=encrypted,
                mfa_recovery_codes=json.dumps(hashed_codes)
            )

            resp_login = client.post(
                '/api/v1/auth/login',
                json={'username': 'iris', 'password': 'password123'}
            )
            pre_auth_token = resp_login.get_json()['pre_auth_token']

            # Try invalid code
            resp = client.post(
                '/api/v1/auth/mfa-verify',
                json={'pre_auth_token': pre_auth_token, 'totp_code': '000000'}
            )

        assert resp.status_code == 401
        assert 'Invalid TOTP code' in resp.get_json()['error']

    def test_mfa_verify_recovery_code_single_use(self, client, app):
        """Test recovery code is consumed after single use."""
        with app.app_context():
            db = app.db
            secret = pyotp.random_base32()
            encrypted = MFAService.encrypt_secret(secret)
            plain_codes, hashed_codes = MFAService.generate_recovery_codes(count=8)
            recovery_code = plain_codes[0]

            user = db.auth_user.insert(
                username='jack',
                email='jack@example.com',
                password_hash=AuthService.hash_password('password123'),
                global_role='Viewer',
                active=True,
                mfa_enabled=True,
                mfa_secret=encrypted,
                mfa_recovery_codes=json.dumps(hashed_codes)
            )

            # First use succeeds
            resp_login1 = client.post(
                '/api/v1/auth/login',
                json={'username': 'jack', 'password': 'password123'}
            )
            pre_auth_token1 = resp_login1.get_json()['pre_auth_token']

            resp1 = client.post(
                '/api/v1/auth/mfa-verify',
                json={'pre_auth_token': pre_auth_token1, 'recovery_code': recovery_code}
            )
            assert resp1.status_code == 200

        # Second use fails (code consumed)
        with app.app_context():
            resp_login2 = client.post(
                '/api/v1/auth/login',
                json={'username': 'jack', 'password': 'password123'}
            )
            pre_auth_token2 = resp_login2.get_json()['pre_auth_token']

            resp2 = client.post(
                '/api/v1/auth/mfa-verify',
                json={'pre_auth_token': pre_auth_token2, 'recovery_code': recovery_code}
            )
            assert resp2.status_code == 401

    def test_mfa_verify_totp_replay_detection(self, client, app):
        """Test TOTP replay attack prevention."""
        with app.app_context():
            db = app.db
            secret = pyotp.random_base32()
            encrypted = MFAService.encrypt_secret(secret)
            totp = pyotp.TOTP(secret)
            code = totp.now()
            _, hashed_codes = MFAService.generate_recovery_codes(count=8)

            user = db.auth_user.insert(
                username='kevin',
                email='kevin@example.com',
                password_hash=AuthService.hash_password('password123'),
                global_role='Viewer',
                active=True,
                mfa_enabled=True,
                mfa_secret=encrypted,
                mfa_recovery_codes=json.dumps(hashed_codes)
            )

            # First use succeeds
            resp_login1 = client.post(
                '/api/v1/auth/login',
                json={'username': 'kevin', 'password': 'password123'}
            )
            pre_auth_token1 = resp_login1.get_json()['pre_auth_token']

            resp1 = client.post(
                '/api/v1/auth/mfa-verify',
                json={'pre_auth_token': pre_auth_token1, 'totp_code': code}
            )
            assert resp1.status_code == 200

        # Immediate reuse of same code should fail
        with app.app_context():
            resp_login2 = client.post(
                '/api/v1/auth/login',
                json={'username': 'kevin', 'password': 'password123'}
            )
            pre_auth_token2 = resp_login2.get_json()['pre_auth_token']

            resp2 = client.post(
                '/api/v1/auth/mfa-verify',
                json={'pre_auth_token': pre_auth_token2, 'totp_code': code}
            )
            # Should fail because counter hasn't advanced
            assert resp2.status_code == 401


class TestPreAuthTokenSecurity:
    """Test pre-auth token security and scope isolation."""

    def test_pre_auth_token_rejected_on_normal_endpoint(self, client, app):
        """Test that pre-auth tokens are rejected on normal endpoints."""
        with app.app_context():
            db = app.db
            user = db.auth_user.insert(
                username='security_test',
                email='sec@example.com',
                password_hash=AuthService.hash_password('password123'),
                global_role='Viewer',
                active=True,
                mfa_enabled=False
            )

            # Create a pre-auth token
            pre_auth_token = MFAService.create_pre_auth_token(user)

            # Try to use it on /api/v1/auth/me (requires normal access token)
            resp = client.get(
                '/api/v1/auth/me',
                headers={'Authorization': f'Bearer {pre_auth_token}'}
            )

        # Should be rejected (invalid token type)
        assert resp.status_code == 401
        assert 'Invalid token type' in resp.get_json()['error']

    def test_pre_auth_token_only_for_mfa_verify(self, client, app):
        """Test that pre-auth tokens only work on mfa-verify endpoint."""
        with app.app_context():
            db = app.db
            secret = pyotp.random_base32()
            encrypted = MFAService.encrypt_secret(secret)
            totp = pyotp.TOTP(secret)
            code = totp.now()
            _, hashed_codes = MFAService.generate_recovery_codes(count=8)

            user = db.auth_user.insert(
                username='pre_auth_test',
                email='pat@example.com',
                password_hash=AuthService.hash_password('password123'),
                global_role='Viewer',
                active=True,
                mfa_enabled=True,
                mfa_secret=encrypted,
                mfa_recovery_codes=json.dumps(hashed_codes)
            )

            # Get pre-auth token via login
            resp_login = client.post(
                '/api/v1/auth/login',
                json={'username': 'pre_auth_test', 'password': 'password123'}
            )
            pre_auth_token = resp_login.get_json()['pre_auth_token']

            # Use it on mfa-verify (should work)
            resp_mfa = client.post(
                '/api/v1/auth/mfa-verify',
                json={'pre_auth_token': pre_auth_token, 'totp_code': code}
            )
            assert resp_mfa.status_code == 200

            # Create another pre-auth token and try on different endpoint
            pre_auth_token2 = MFAService.create_pre_auth_token(user)
            resp_me = client.get(
                '/api/v1/auth/me',
                headers={'Authorization': f'Bearer {pre_auth_token2}'}
            )
            # Should fail on /auth/me (invalid token type)
            assert resp_me.status_code == 401
            assert 'Invalid token type' in resp_me.get_json()['error']


class TestMFADisable:
    """Test MFA disabling."""

    def test_disable_mfa_with_password_and_totp(self, client, app, jwt_token_factory):
        """Test MFA disable with password and TOTP code."""
        with app.app_context():
            db = app.db
            secret = pyotp.random_base32()
            encrypted = MFAService.encrypt_secret(secret)
            totp = pyotp.TOTP(secret)
            code = totp.now()
            _, hashed_codes = MFAService.generate_recovery_codes(count=8)

            user = db.auth_user.insert(
                username='liam',
                email='liam@example.com',
                password_hash=AuthService.hash_password('password123'),
                global_role='Viewer',
                active=True,
                mfa_enabled=True,
                mfa_secret=encrypted,
                mfa_recovery_codes=json.dumps(hashed_codes)
            )

            token = jwt_token_factory(user_id=user, username='liam')
            resp = client.post(
                '/api/v1/mfa/disable',
                json={'password': 'password123', 'totp_code': code},
                headers={'Authorization': f'Bearer {token}'}
            )

        assert resp.status_code == 200
        assert 'MFA disabled' in resp.get_json()['message']

        # Verify user record updated
        with app.app_context():
            updated_user = db.auth_user[user]
            assert updated_user.mfa_enabled is False
            assert updated_user.mfa_secret is None

    def test_disable_mfa_with_password_and_recovery_code(self, client, app, jwt_token_factory):
        """Test MFA disable with password and recovery code."""
        with app.app_context():
            db = app.db
            secret = pyotp.random_base32()
            encrypted = MFAService.encrypt_secret(secret)
            plain_codes, hashed_codes = MFAService.generate_recovery_codes(count=8)
            recovery_code = plain_codes[0]

            user = db.auth_user.insert(
                username='mia',
                email='mia@example.com',
                password_hash=AuthService.hash_password('password123'),
                global_role='Viewer',
                active=True,
                mfa_enabled=True,
                mfa_secret=encrypted,
                mfa_recovery_codes=json.dumps(hashed_codes)
            )

            token = jwt_token_factory(user_id=user, username='mia')
            resp = client.post(
                '/api/v1/mfa/disable',
                json={'password': 'password123', 'recovery_code': recovery_code},
                headers={'Authorization': f'Bearer {token}'}
            )

        assert resp.status_code == 200

    def test_disable_mfa_wrong_password(self, client, app, jwt_token_factory):
        """Test disable fails with wrong password."""
        with app.app_context():
            db = app.db
            secret = pyotp.random_base32()
            encrypted = MFAService.encrypt_secret(secret)
            _, hashed_codes = MFAService.generate_recovery_codes(count=8)

            user = db.auth_user.insert(
                username='noah',
                email='noah@example.com',
                password_hash=AuthService.hash_password('password123'),
                global_role='Viewer',
                active=True,
                mfa_enabled=True,
                mfa_secret=encrypted,
                mfa_recovery_codes=json.dumps(hashed_codes)
            )

            token = jwt_token_factory(user_id=user, username='noah')
            resp = client.post(
                '/api/v1/mfa/disable',
                json={'password': 'wrongpassword', 'totp_code': '123456'},
                headers={'Authorization': f'Bearer {token}'}
            )

        assert resp.status_code == 401

    def test_disable_mfa_not_enabled(self, client, app, jwt_token_factory):
        """Test disable fails if MFA not enabled."""
        with app.app_context():
            db = app.db
            user = db.auth_user.insert(
                username='olivia',
                email='olivia@example.com',
                password_hash=AuthService.hash_password('password123'),
                global_role='Viewer',
                active=True,
                mfa_enabled=False
            )

            token = jwt_token_factory(user_id=user, username='olivia')
            resp = client.post(
                '/api/v1/mfa/disable',
                json={'password': 'password123', 'totp_code': '123456'},
                headers={'Authorization': f'Bearer {token}'}
            )

        assert resp.status_code == 409
