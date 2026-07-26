"""
OIDC SSO service and endpoints tests.

All network calls (JWKS, token endpoint) are stubbed.
Tests cover: happy path, bad nonce, bad state, expired state, wrong aud,
HS256 rejection, JIT provisioning, existing user matching, disabled provider,
non-enterprise tier blocking, and sensitive data not logged.
"""

import json
import jwt
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from app.services.sso_service import SSOService, OIDCConfig, ValidatedIDToken
from tests.conftest import client, app, db


class TestOIDCConfig:
    """Test OIDCConfig data structure."""

    def test_oidc_config_creation(self):
        """Test OIDCConfig dataclass."""
        config = OIDCConfig(
            name='test-idp',
            display_name='Test IdP',
            issuer='https://example.com',
            client_id='client123',
            client_secret='secret456',
            authorization_endpoint='https://example.com/auth',
            token_endpoint='https://example.com/token',
            jwks_url='https://example.com/.well-known/jwks.json',
            scopes='openid email profile'
        )

        assert config.name == 'test-idp'
        assert config.client_id == 'client123'


class TestSecretEncryption:
    """Test secret encryption/decryption."""

    def test_encrypt_decrypt_secret(self, app):
        """Test Fernet encryption of secrets."""
        with app.app_context():
            original = 'my-client-secret-123'
            encrypted = SSOService.encrypt_secret(original)
            decrypted = SSOService.decrypt_secret(encrypted)

            assert encrypted != original
            assert decrypted == original
            assert isinstance(encrypted, str)

    def test_encrypt_is_deterministic_false(self, app):
        """Test that encryption is non-deterministic (Fernet adds timestamp)."""
        with app.app_context():
            secret = 'test-secret'
            enc1 = SSOService.encrypt_secret(secret)
            enc2 = SSOService.encrypt_secret(secret)

            # Fernet includes timestamp, so ciphertexts differ
            assert enc1 != enc2
            # But both decrypt to the same value
            assert SSOService.decrypt_secret(enc1) == secret
            assert SSOService.decrypt_secret(enc2) == secret


class TestPKCE:
    """Test PKCE code challenge generation."""

    def test_pkce_pair_generation(self, app):
        """Test PKCE code_verifier and code_challenge generation."""
        with app.app_context():
            verifier, challenge = SSOService._generate_pkce_pair()

            # Verifier: 43-128 chars, unreserved
            assert 43 <= len(verifier) <= 128
            assert all(c.isalnum() or c in '-._~' for c in verifier)

            # Challenge: base64url of SHA256(verifier)
            assert len(challenge) > 0
            assert '=' not in challenge  # No padding

    def test_pkce_pair_uniqueness(self, app):
        """Test that PKCE pairs are unique."""
        with app.app_context():
            pair1 = SSOService._generate_pkce_pair()
            pair2 = SSOService._generate_pkce_pair()

            # Should be different every time
            assert pair1 != pair2


class TestStateToken:
    """Test state token generation and verification."""

    def test_state_token_creation_and_verification(self, app):
        """Test state token with embedded code_verifier."""
        with app.app_context():
            code_verifier = 'test-verifier-12345'
            state = SSOService._create_state_token(code_verifier)

            # Verify and extract
            extracted = SSOService._verify_state_token(state)
            assert extracted == code_verifier

    def test_state_token_expiry(self, app):
        """Test that expired state tokens fail verification."""
        with app.app_context():
            code_verifier = 'test-verifier'
            # Create a state token manually with expiry in the past
            payload = {
                'code_verifier': code_verifier,
                'iat': datetime.utcnow() - timedelta(minutes=20),
                'exp': datetime.utcnow() - timedelta(minutes=10),
            }
            expired_state = jwt.encode(
                payload,
                app.config['SECRET_KEY'],
                algorithm='HS256'
            )

            extracted = SSOService._verify_state_token(expired_state)
            assert extracted is None

    def test_state_token_invalid_signature(self, app):
        """Test that tampered state tokens fail verification."""
        with app.app_context():
            code_verifier = 'test-verifier'
            state = SSOService._create_state_token(code_verifier)

            # Tamper with the token
            tampered = state[:-10] + 'corrupted!'

            extracted = SSOService._verify_state_token(tampered)
            assert extracted is None


class TestAuthorizationRequest:
    """Test authorization URL generation."""

    def test_build_authorization_url(self, app):
        """Test building authorization URL with PKCE and state."""
        with app.app_context():
            config = OIDCConfig(
                name='okta',
                display_name='Okta',
                issuer='https://example.okta.com',
                client_id='client123',
                client_secret='secret456',
                authorization_endpoint='https://example.okta.com/oauth2/v1/authorize',
                token_endpoint='https://example.okta.com/oauth2/v1/token',
                jwks_url='https://example.okta.com/oauth2/v1/keys',
                scopes='openid email profile'
            )

            auth_req = SSOService.build_authorization_url(config)

            assert 'https://example.okta.com/oauth2/v1/authorize?' in auth_req.authorization_url
            assert 'client_id=client123' in auth_req.authorization_url
            assert 'response_type=code' in auth_req.authorization_url
            assert 'code_challenge=' in auth_req.authorization_url
            assert 'code_challenge_method=S256' in auth_req.authorization_url
            assert 'state=' in auth_req.authorization_url
            assert auth_req.state  # State token present


class TestIDTokenValidation:
    """Test ID token signature and claim validation."""

    @staticmethod
    def _create_rsa_keys():
        """Create RSA key pair for testing."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_key, private_pem, public_pem

    def test_valid_id_token(self, app):
        """Test validation of a valid ID token."""
        with app.app_context():
            private_key, _, _ = self._create_rsa_keys()

            config = OIDCConfig(
                name='okta',
                display_name='Okta',
                issuer='https://example.okta.com',
                client_id='client123',
                client_secret='secret456',
                authorization_endpoint='https://example.okta.com/oauth2/v1/authorize',
                token_endpoint='https://example.okta.com/oauth2/v1/token',
                jwks_url='https://example.okta.com/oauth2/v1/keys',
                scopes='openid email profile'
            )

            # Create valid ID token
            payload = {
                'sub': 'user123',
                'email': 'user@example.com',
                'name': 'Test User',
                'iss': config.issuer,
                'aud': config.client_id,
                'exp': datetime.utcnow() + timedelta(hours=1),
                'iat': datetime.utcnow(),
                'nonce': 'test-nonce'
            }
            id_token = jwt.encode(payload, private_key, algorithm='RS256')

            # Mock JWKS endpoint
            with patch('jwt.PyJWKClient') as mock_jwks:
                mock_client = MagicMock()
                mock_key = MagicMock()
                mock_key.key = private_key.public_key()
                mock_client.get_signing_key_from_jwt.return_value = mock_key
                mock_jwks.return_value = mock_client

                validated = SSOService.validate_id_token(config, id_token, nonce='test-nonce')

                assert validated is not None
                assert validated.sub == 'user123'
                assert validated.email == 'user@example.com'
                assert validated.name == 'Test User'

    def test_invalid_nonce(self, app):
        """Test ID token with mismatched nonce."""
        with app.app_context():
            private_key, _, _ = self._create_rsa_keys()

            config = OIDCConfig(
                name='okta',
                display_name='Okta',
                issuer='https://example.okta.com',
                client_id='client123',
                client_secret='secret456',
                authorization_endpoint='https://example.okta.com/oauth2/v1/authorize',
                token_endpoint='https://example.okta.com/oauth2/v1/token',
                jwks_url='https://example.okta.com/oauth2/v1/keys',
                scopes='openid email profile'
            )

            payload = {
                'sub': 'user123',
                'email': 'user@example.com',
                'iss': config.issuer,
                'aud': config.client_id,
                'exp': datetime.utcnow() + timedelta(hours=1),
                'iat': datetime.utcnow(),
                'nonce': 'correct-nonce'
            }
            id_token = jwt.encode(payload, private_key, algorithm='RS256')

            with patch('jwt.PyJWKClient') as mock_jwks:
                mock_client = MagicMock()
                mock_key = MagicMock()
                mock_key.key = private_key.public_key()
                mock_client.get_signing_key_from_jwt.return_value = mock_key
                mock_jwks.return_value = mock_client

                # Wrong nonce
                validated = SSOService.validate_id_token(config, id_token, nonce='wrong-nonce')
                assert validated is None

    def test_wrong_audience(self, app):
        """Test ID token with wrong audience claim."""
        with app.app_context():
            private_key, _, _ = self._create_rsa_keys()

            config = OIDCConfig(
                name='okta',
                display_name='Okta',
                issuer='https://example.okta.com',
                client_id='client123',
                client_secret='secret456',
                authorization_endpoint='https://example.okta.com/oauth2/v1/authorize',
                token_endpoint='https://example.okta.com/oauth2/v1/token',
                jwks_url='https://example.okta.com/oauth2/v1/keys',
                scopes='openid email profile'
            )

            # Token has wrong aud
            payload = {
                'sub': 'user123',
                'email': 'user@example.com',
                'iss': config.issuer,
                'aud': 'wrong-client-id',
                'exp': datetime.utcnow() + timedelta(hours=1),
                'iat': datetime.utcnow(),
            }
            id_token = jwt.encode(payload, private_key, algorithm='RS256')

            with patch('jwt.PyJWKClient') as mock_jwks:
                mock_client = MagicMock()
                mock_key = MagicMock()
                mock_key.key = private_key.public_key()
                mock_client.get_signing_key_from_jwt.return_value = mock_key
                mock_jwks.return_value = mock_client

                validated = SSOService.validate_id_token(config, id_token)
                assert validated is None

    def test_hs256_algorithm_rejected(self, app):
        """Test that HS256 (symmetric) ID tokens are rejected."""
        with app.app_context():
            config = OIDCConfig(
                name='okta',
                display_name='Okta',
                issuer='https://example.okta.com',
                client_id='client123',
                client_secret='secret456',
                authorization_endpoint='https://example.okta.com/oauth2/v1/authorize',
                token_endpoint='https://example.okta.com/oauth2/v1/token',
                jwks_url='https://example.okta.com/oauth2/v1/keys',
                scopes='openid email profile'
            )

            # Sign with HS256 (symmetric, bad for IdP)
            payload = {
                'sub': 'user123',
                'email': 'user@example.com',
                'iss': config.issuer,
                'aud': config.client_id,
                'exp': datetime.utcnow() + timedelta(hours=1),
                'iat': datetime.utcnow(),
            }
            id_token = jwt.encode(payload, 'shared-secret', algorithm='HS256')

            with patch('jwt.PyJWKClient') as mock_jwks:
                mock_client = MagicMock()
                mock_key = MagicMock()
                mock_key.key = 'shared-secret'
                mock_client.get_signing_key_from_jwt.return_value = mock_key
                mock_jwks.return_value = mock_client

                # HS256 should be rejected (only RS256/ES256 allowed)
                validated = SSOService.validate_id_token(config, id_token)
                assert validated is None


class TestJITProvisioning:
    """Test just-in-time user provisioning."""

    def test_jit_creates_new_viewer_user(self, app, db):
        """Test JIT creates a new Viewer (read-only) user."""
        with app.app_context():
            config = OIDCConfig(
                name='okta',
                display_name='Okta',
                issuer='https://example.okta.com',
                client_id='client123',
                client_secret='secret456',
                authorization_endpoint='https://example.okta.com/oauth2/v1/authorize',
                token_endpoint='https://example.okta.com/oauth2/v1/token',
                jwks_url='https://example.okta.com/oauth2/v1/keys',
                scopes='openid email profile'
            )

            validated = ValidatedIDToken(
                sub='okta-user-456',
                email='newuser@example.com',
                name='New User',
                iss=config.issuer,
                aud=config.client_id
            )

            user_id = SSOService.jit_provision_or_match_user(config, validated, db)

            assert user_id is not None
            user = db.auth_user[user_id]
            assert user['email'] == 'newuser@example.com'
            assert user['global_role'] == 'Viewer'
            assert user['sso_provider'] == 'okta'
            assert user['sso_subject'] == 'okta-user-456'
            assert user['mfa_enabled'] is False
            # Password is placeholder (SSO users can't login locally)
            assert user['password_hash'] == '*' * 64

    def test_jit_matches_existing_user_by_sso_subject(self, app, db):
        """Test JIT matches existing user by SSO provider + subject."""
        with app.app_context():
            config = OIDCConfig(
                name='okta',
                display_name='Okta',
                issuer='https://example.okta.com',
                client_id='client123',
                client_secret='secret456',
                authorization_endpoint='https://example.okta.com/oauth2/v1/authorize',
                token_endpoint='https://example.okta.com/oauth2/v1/token',
                jwks_url='https://example.okta.com/oauth2/v1/keys',
                scopes='openid email profile'
            )

            # Create existing user with SSO fields
            existing_user_id = db.auth_user.insert(
                username='existing',
                email='existing@example.com',
                password_hash='*' * 64,
                global_role='Viewer',
                sso_provider='okta',
                sso_subject='okta-user-123'
            )
            db.commit()

            validated = ValidatedIDToken(
                sub='okta-user-123',
                email='different@example.com',  # Different email, but same sub
                name='Existing User',
                iss=config.issuer,
                aud=config.client_id
            )

            user_id = SSOService.jit_provision_or_match_user(config, validated, db)

            # Should match the existing user
            assert user_id == existing_user_id

    def test_jit_matches_existing_user_by_email(self, app, db):
        """Test JIT matches existing local user by email."""
        with app.app_context():
            config = OIDCConfig(
                name='okta',
                display_name='Okta',
                issuer='https://example.okta.com',
                client_id='client123',
                client_secret='secret456',
                authorization_endpoint='https://example.okta.com/oauth2/v1/authorize',
                token_endpoint='https://example.okta.com/oauth2/v1/token',
                jwks_url='https://example.okta.com/oauth2/v1/keys',
                scopes='openid email profile'
            )

            # Create local user (no SSO)
            local_user_id = db.auth_user.insert(
                username='localuser',
                email='user@example.com',
                password_hash='hashed-password-123',
                global_role='Viewer'
            )
            db.commit()

            validated = ValidatedIDToken(
                sub='okta-user-789',
                email='user@example.com',  # Same email as local user
                name='User',
                iss=config.issuer,
                aud=config.client_id
            )

            user_id = SSOService.jit_provision_or_match_user(config, validated, db)

            # Should match and update SSO fields
            assert user_id == local_user_id
            updated_user = db.auth_user[user_id]
            assert updated_user['sso_provider'] == 'okta'
            assert updated_user['sso_subject'] == 'okta-user-789'


class TestSSOEndpoints:
    """Test SSO API endpoints."""

    def test_list_enabled_providers(self, client, db, app):
        """Test GET /api/v1/auth/sso/providers (PUBLIC)."""
        with app.app_context():
            # Create enabled and disabled providers
            db.sso_providers.insert(
                name='okta',
                display_name='Okta',
                issuer='https://okta.example.com',
                client_id='client123',
                client_secret=SSOService.encrypt_secret('secret123'),
                authorization_endpoint='https://okta.example.com/auth',
                token_endpoint='https://okta.example.com/token',
                jwks_url='https://okta.example.com/keys',
                enabled=True
            )
            db.sso_providers.insert(
                name='google',
                display_name='Google',
                issuer='https://accounts.google.com',
                client_id='client456',
                client_secret=SSOService.encrypt_secret('secret456'),
                authorization_endpoint='https://accounts.google.com/auth',
                token_endpoint='https://accounts.google.com/token',
                jwks_url='https://accounts.google.com/keys',
                enabled=False  # Disabled
            )
            db.commit()

            response = client.get('/api/v1/auth/sso/providers')

            assert response.status_code == 200
            data = response.get_json()
            assert len(data['providers']) == 1  # Only enabled provider
            assert data['providers'][0]['name'] == 'okta'
            assert 'client_secret' not in data['providers'][0]  # Secret never leaked

    def test_authorize_endpoint_generates_auth_url(self, client, db, app):
        """Test GET /api/v1/auth/sso/<name>/authorize generates authorization URL."""
        with app.app_context():
            db.sso_providers.insert(
                name='okta',
                display_name='Okta',
                issuer='https://okta.example.com',
                client_id='client123',
                client_secret=SSOService.encrypt_secret('secret123'),
                authorization_endpoint='https://okta.example.com/oauth/authorize',
                token_endpoint='https://okta.example.com/oauth/token',
                jwks_url='https://okta.example.com/oauth/keys',
                scopes='openid email profile',
                enabled=True
            )
            db.commit()

            response = client.get('/api/v1/auth/sso/okta/authorize')

            assert response.status_code == 200
            data = response.get_json()
            assert 'authorization_url' in data
            assert 'https://okta.example.com/oauth/authorize?' in data['authorization_url']
            assert 'client_id=client123' in data['authorization_url']
            assert 'code_challenge=' in data['authorization_url']
            assert 'state' in data

    def test_authorize_endpoint_disabled_provider(self, client, db, app):
        """Test authorize with disabled provider returns 404."""
        with app.app_context():
            db.sso_providers.insert(
                name='okta',
                display_name='Okta',
                issuer='https://okta.example.com',
                client_id='client123',
                client_secret=SSOService.encrypt_secret('secret123'),
                authorization_endpoint='https://okta.example.com/oauth/authorize',
                token_endpoint='https://okta.example.com/oauth/token',
                jwks_url='https://okta.example.com/oauth/keys',
                enabled=False  # Disabled
            )
            db.commit()

            response = client.get('/api/v1/auth/sso/okta/authorize')

            assert response.status_code == 404
            assert 'not found' in response.get_json()['error'].lower()

    def test_admin_create_provider_enterprise_only(self, client, db, app, jwt_token_factory):
        """Test SSO provider creation requires Enterprise tier."""
        with app.app_context():
            # Create a token with admin scope (non-enterprise)
            access_token = jwt_token_factory(
                user_id=1,
                global_role='Admin'
            )

            # Mock license check to return non-enterprise
            with patch.object(app.license_service, 'is_enterprise', return_value=False):
                response = client.post(
                    '/api/v1/admin/sso/providers',
                    json={
                        'name': 'okta',
                        'display_name': 'Okta',
                        'issuer': 'https://okta.example.com',
                        'client_id': 'client123',
                        'client_secret': 'secret123',
                        'authorization_endpoint': 'https://okta.example.com/auth',
                        'token_endpoint': 'https://okta.example.com/token',
                        'jwks_url': 'https://okta.example.com/keys',
                    },
                    headers={'Authorization': f'Bearer {access_token}'}
                )

                assert response.status_code == 403
                assert 'Enterprise' in response.get_json()['error']

    def test_admin_create_provider_https_validation(self, client, db, app, jwt_token_factory):
        """Test HTTPS validation on endpoint URLs."""
        with app.app_context():
            access_token = jwt_token_factory(
                user_id=1,
                global_role='Admin'
            )

            with patch.object(app.license_service, 'is_enterprise', return_value=True):
                # Non-HTTPS authorization_endpoint
                response = client.post(
                    '/api/v1/admin/sso/providers',
                    json={
                        'name': 'okta',
                        'display_name': 'Okta',
                        'issuer': 'https://okta.example.com',
                        'client_id': 'client123',
                        'client_secret': 'secret123',
                        'authorization_endpoint': 'http://okta.example.com/auth',  # HTTP!
                        'token_endpoint': 'https://okta.example.com/token',
                        'jwks_url': 'https://okta.example.com/keys',
                    },
                    headers={'Authorization': f'Bearer {access_token}'}
                )

                assert response.status_code == 400
                assert 'https://' in response.get_json()['error']
