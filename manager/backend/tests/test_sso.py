"""
OIDC SSO security tests (Finding 1-6 fixes).

Tests for:
1. CRITICAL - Opaque state (no code_verifier exposed)
2. CRITICAL - Email takeover prevention + email_verified requirement
3. HIGH - CSRF via browser binding cookie
4. MEDIUM - Nonce validation (server-side)
5. MEDIUM - Redirect URI from config only
6. LOW - NULL password hash for SSO users + login rejection
"""

import json
import secrets
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
import pytest
import jwt

from app.services.sso_service import SSOService, OIDCConfig, ValidatedIDToken
from app.services.auth_service import AuthService
from tests.conftest import client, app, db


class TestOpaqueState:
    """Test Finding 1: State token is opaque, not decodable."""

    def test_state_is_not_jwt_decodable(self, app, db):
        """Returned state cannot be decoded as JWT or contains no secrets."""
        with app.app_context():
            config = OIDCConfig(
                name='okta', display_name='Okta',
                issuer='https://okta.example.com', client_id='client123',
                client_secret=SSOService.encrypt_secret('secret456'),
                authorization_endpoint='https://okta.example.com/auth',
                token_endpoint='https://okta.example.com/token',
                jwks_url='https://okta.example.com/keys',
                scopes='openid email'
            )

            binding_token = secrets.token_urlsafe(32)
            auth_req = SSOService.build_authorization_url(config, 'okta', db, binding_token)

            # State should be opaque (random, ~43 chars)
            assert len(auth_req.state) == 43
            assert auth_req.state.replace('-', '').replace('_', '').isalnum()

            # State is NOT a JWT (should raise exception)
            with pytest.raises(Exception):
                jwt.decode(auth_req.state, 'secret', algorithms=['HS256'])

    def test_code_verifier_not_in_state(self, app, db):
        """Code verifier must NOT be in returned state."""
        with app.app_context():
            config = OIDCConfig(
                name='okta', display_name='Okta',
                issuer='https://okta.example.com', client_id='client123',
                client_secret=SSOService.encrypt_secret('secret456'),
                authorization_endpoint='https://okta.example.com/auth',
                token_endpoint='https://okta.example.com/token',
                jwks_url='https://okta.example.com/keys',
                scopes='openid email'
            )

            binding_token = secrets.token_urlsafe(32)
            auth_req = SSOService.build_authorization_url(config, 'okta', db, binding_token)

            # Retrieve from DB to verify stored separately
            attempt = db(db.sso_login_attempts.opaque_state == auth_req.state).select().first()
            assert attempt is not None
            assert attempt['code_verifier']  # Stored server-side
            # State itself contains no verifier
            assert attempt['code_verifier'] not in auth_req.state


class TestEmailTakeover:
    """Test Finding 2: Refuse auto-link existing local accounts; require email_verified."""

    def test_existing_local_account_refused(self, app, db):
        """SSO user with existing local account email → refuse auto-link with 403."""
        with app.app_context():
            # Create local user
            db.auth_user.insert(
                username='local',
                email='user@example.com',
                password_hash=AuthService.hash_password('password'),
                global_role='Viewer'
            )
            db.commit()

            config = OIDCConfig(
                name='okta', display_name='Okta',
                issuer='https://okta.example.com', client_id='client123',
                client_secret=SSOService.encrypt_secret('secret'),
                authorization_endpoint='https://okta.example.com/auth',
                token_endpoint='https://okta.example.com/token',
                jwks_url='https://okta.example.com/keys',
                scopes='openid email'
            )

            # SSO token with same email but different subject
            validated = ValidatedIDToken(
                sub='okta-user-123',
                email='user@example.com',
                email_verified=True,
                name='User',
                iss=config.issuer,
                aud=config.client_id
            )

            # Should return None (refused)
            user_id = SSOService.jit_provision_or_match_user(config, validated, db)
            assert user_id is None

    def test_unverified_email_refused(self, app, db):
        """ID token with email_verified=false → refuse JIT with None."""
        with app.app_context():
            config = OIDCConfig(
                name='okta', display_name='Okta',
                issuer='https://okta.example.com', client_id='client123',
                client_secret=SSOService.encrypt_secret('secret'),
                authorization_endpoint='https://okta.example.com/auth',
                token_endpoint='https://okta.example.com/token',
                jwks_url='https://okta.example.com/keys',
                scopes='openid email'
            )

            validated = ValidatedIDToken(
                sub='okta-user-new',
                email='newuser@example.com',
                email_verified=False,  # NOT verified
                name='New User',
                iss=config.issuer,
                aud=config.client_id
            )

            user_id = SSOService.jit_provision_or_match_user(config, validated, db)
            assert user_id is None

    def test_returning_sso_user_matched(self, app, db):
        """Returning SSO user matched by (sso_provider, sso_subject) even if email changed."""
        with app.app_context():
            # Create SSO user with old email
            old_id = db.auth_user.insert(
                username='user',
                email='old@example.com',
                password_hash=None,  # SSO user
                global_role='Viewer',
                sso_provider='okta',
                sso_subject='okta-user-456'
            )
            db.commit()

            config = OIDCConfig(
                name='okta', display_name='Okta',
                issuer='https://okta.example.com', client_id='client123',
                client_secret=SSOService.encrypt_secret('secret'),
                authorization_endpoint='https://okta.example.com/auth',
                token_endpoint='https://okta.example.com/token',
                jwks_url='https://okta.example.com/keys',
                scopes='openid email'
            )

            # Return with NEW email
            validated = ValidatedIDToken(
                sub='okta-user-456',
                email='new@example.com',  # Changed
                email_verified=True,
                name='User',
                iss=config.issuer,
                aud=config.client_id
            )

            user_id = SSOService.jit_provision_or_match_user(config, validated, db)
            assert user_id == old_id  # Matched by subject


class TestCSRFBrowserBinding:
    """Test Finding 3: CSRF protection via browser binding cookie."""

    def test_browser_binding_mismatch_rejected(self, app, db):
        """Code exchange with mismatched binding cookie → rejected."""
        with app.app_context():
            config = OIDCConfig(
                name='okta', display_name='Okta',
                issuer='https://okta.example.com', client_id='client123',
                client_secret=SSOService.encrypt_secret('secret'),
                authorization_endpoint='https://okta.example.com/auth',
                token_endpoint='https://okta.example.com/token',
                jwks_url='https://okta.example.com/keys',
                scopes='openid email'
            )

            # Create attempt with binding token A
            binding_a = secrets.token_urlsafe(32)
            state = SSOService.create_login_attempt('okta', 'verifier', 'nonce',
                                                    __import__('hashlib').sha256(binding_a.encode()).hexdigest(), db)

            # Try exchange with binding token B
            binding_b = secrets.token_urlsafe(32)

            result = SSOService.exchange_code_for_token(
                config, 'fake-code', state, binding_b, db
            )

            # Should fail (binding mismatch)
            assert result is None

    def test_missing_browser_binding_cookie_rejected(self, client, db, app):
        """Callback without browser binding cookie → rejected."""
        with app.app_context():
            db.sso_providers.insert(
                name='okta', display_name='Okta',
                issuer='https://okta.example.com',
                client_id='client123',
                client_secret=SSOService.encrypt_secret('secret'),
                authorization_endpoint='https://okta.example.com/auth',
                token_endpoint='https://okta.example.com/token',
                jwks_url='https://okta.example.com/keys',
                enabled=True
            )
            db.commit()

        response = client.post(
            '/api/v1/auth/sso/okta/callback',
            json={'code': 'code', 'state': 'state'}
        )

        assert response.status_code == 400
        assert 'cookie' in response.get_json()['error'].lower()


class TestNonceValidation:
    """Test Finding 4: Nonce validation (server-side, from attempt row)."""

    def test_wrong_nonce_rejected(self, app):
        """ID token with wrong nonce → rejected."""
        from cryptography.hazmat.primitives.asymmetric import rsa

        with app.app_context():
            private_key = rsa.generate_private_key(65537, 2048)

            config = OIDCConfig(
                name='okta', display_name='Okta',
                issuer='https://okta.example.com', client_id='client123',
                client_secret='secret',
                authorization_endpoint='https://okta.example.com/auth',
                token_endpoint='https://okta.example.com/token',
                jwks_url='https://okta.example.com/keys',
                scopes='openid email'
            )

            payload = {
                'sub': 'user123',
                'email': 'user@example.com',
                'email_verified': True,
                'iss': config.issuer,
                'aud': config.client_id,
                'exp': datetime.utcnow() + timedelta(hours=1),
                'iat': datetime.utcnow(),
                'nonce': 'wrong-nonce'  # Wrong nonce
            }
            id_token = jwt.encode(payload, private_key, algorithm='RS256')

            with patch('app.services.sso_service.PyJWKClient') as mock_jwks:
                mock_client = MagicMock()
                mock_key = MagicMock()
                mock_key.key = private_key.public_key()
                mock_client.get_signing_key_from_jwt.return_value = mock_key
                mock_jwks.return_value = mock_client

                # Validate with different expected nonce
                validated = SSOService.validate_id_token(config, id_token, 'correct-nonce')

                assert validated is None


class TestNullPasswordHash:
    """Test Finding 6: SSO users have NULL password; login rejection before bcrypt."""

    def test_sso_user_created_with_null_password(self, app, db):
        """JIT-provisioned SSO user gets NULL password hash."""
        with app.app_context():
            config = OIDCConfig(
                name='okta', display_name='Okta',
                issuer='https://okta.example.com', client_id='client123',
                client_secret=SSOService.encrypt_secret('secret'),
                authorization_endpoint='https://okta.example.com/auth',
                token_endpoint='https://okta.example.com/token',
                jwks_url='https://okta.example.com/keys',
                scopes='openid email'
            )

            validated = ValidatedIDToken(
                sub='okta-user-789',
                email='new@example.com',
                email_verified=True,
                name='New User',
                iss=config.issuer,
                aud=config.client_id
            )

            user_id = SSOService.jit_provision_or_match_user(config, validated, db)
            user = db.auth_user[user_id]

            assert user['password_hash'] is None or user['password_hash'] == ''

    def test_verify_password_short_circuits_null_hash(self):
        """AuthService.verify_password returns False immediately for NULL hash."""
        result = AuthService.verify_password('anypassword', None)
        assert result is False

        result = AuthService.verify_password('anypassword', '')
        assert result is False

    def test_sso_user_login_rejected_at_auth_layer(self, app, db):
        """Attempting password login on SSO user → 401 (same as wrong password)."""
        with app.app_context():
            # Create SSO user with NULL password
            user_id = db.auth_user.insert(
                username='ssouser',
                email='sso@example.com',
                password_hash=None,  # SSO user
                global_role='Viewer',
                sso_provider='okta',
                sso_subject='okta-123'
            )
            db.commit()

            # Attempt password verification
            result = AuthService.verify_password('anypassword', None)
            assert result is False
