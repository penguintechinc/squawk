"""
JWT Authentication Tests

Tests for asymmetric JWT (ES256/RS256) authentication including:
- Token creation with mandatory claims (sub, iss, aud, tenant)
- Token verification with ES256 and RS256
- Rejection of HS256 tokens (algorithm confusion)
- Rejection of tokens missing required claims
- Rejection of tokens with wrong aud/iss
"""

import pytest
import jwt
from datetime import datetime, timedelta
from app.services.auth_service import AuthService


class TestTokenCreation:
    """Test JWT token creation with asymmetric signing."""

    def test_create_access_token_with_required_claims(self, app, jwt_keypair):
        """Test that access tokens include all required claims."""
        with app.app_context():
            # Create test user
            db = app.db
            user = db.auth_user.insert(
                username='testuser',
                email='test@example.com',
                password_hash='hashed_password',
                global_role='Viewer',
                active=True
            )

            # Create token
            token = AuthService.create_access_token(
                user_id=user,
                username='testuser',
                global_role='Viewer',
                team_roles={'team1': 'Member'}
            )

            # Decode with public key
            payload = jwt.decode(
                token,
                app.config['JWT_PUBLIC_KEY'],
                algorithms=['ES256', 'RS256'],
                audience='squawk',
                issuer='squawk-manager'
            )

            # Verify required claims
            assert payload['sub'] == str(user)
            assert payload['iss'] == 'squawk-manager'
            assert payload['aud'] == 'squawk'
            assert payload['tenant'] == 'default'
            assert payload['user_id'] == user
            assert payload['username'] == 'testuser'
            assert payload['global_role'] == 'Viewer'
            assert payload['type'] == 'access'
            assert 'exp' in payload
            assert 'iat' in payload

    def test_create_refresh_token_with_required_claims(self, app):
        """Test that refresh tokens include all required claims."""
        with app.app_context():
            token = AuthService.create_refresh_token(user_id=1)

            payload = jwt.decode(
                token,
                app.config['JWT_PUBLIC_KEY'],
                algorithms=['ES256', 'RS256'],
                audience='squawk',
                issuer='squawk-manager',
                options={'require': ['exp', 'iat', 'tenant']}
            )

            assert payload['sub'] == '1'
            assert payload['iss'] == 'squawk-manager'
            assert payload['aud'] == 'squawk'
            assert payload['tenant'] == 'default'
            assert payload['user_id'] == 1
            assert payload['type'] == 'refresh'

    def test_token_signed_with_private_key(self, app, jwt_keypair):
        """Verify token is signed with private key (not shared secret)."""
        with app.app_context():
            # Create token
            token = AuthService.create_access_token(
                user_id=1,
                username='testuser',
                global_role='Viewer'
            )

            # Should verify with public key (with aud/iss validation)
            payload = jwt.decode(
                token,
                jwt_keypair['public'],
                algorithms=['ES256', 'RS256'],
                audience='squawk',
                issuer='squawk-manager'
            )
            assert payload['user_id'] == 1

            # Should NOT verify with a different key
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend

            wrong_key = ec.generate_private_key(
                ec.SECP256R1(), default_backend()
            ).public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')

            with pytest.raises(jwt.InvalidSignatureError):
                jwt.decode(
                    token,
                    wrong_key,
                    algorithms=['ES256', 'RS256'],
                    audience='squawk',
                    issuer='squawk-manager'
                )


class TestTokenVerification:
    """Test JWT token verification (decode_token)."""

    def test_valid_token_accepted(self, app, jwt_token_factory):
        """Test that valid ES256 token is accepted."""
        with app.app_context():
            token = jwt_token_factory(user_id=1, username='testuser')
            payload = AuthService.decode_token(token)

            assert payload is not None
            assert payload['user_id'] == 1
            assert payload['username'] == 'testuser'
            assert payload['tenant'] == 'default'

    def test_expired_token_rejected(self, app, jwt_token_factory):
        """Test that expired token is rejected."""
        with app.app_context():
            token = jwt_token_factory(user_id=1, expired=True)
            payload = AuthService.decode_token(token)

            assert payload is None

    def test_token_with_wrong_audience_rejected(self, app, jwt_keypair):
        """Test that token with wrong aud claim is rejected."""
        with app.app_context():
            # Create token with wrong audience
            payload = {
                'sub': '1',
                'iss': 'squawk-manager',
                'aud': 'wrong-audience',  # Should be 'squawk'
                'tenant': 'default',
                'user_id': 1,
                'exp': datetime.utcnow() + timedelta(hours=1),
                'iat': datetime.utcnow()
            }
            token = jwt.encode(
                payload,
                jwt_keypair['private'],
                algorithm='ES256'
            )

            result = AuthService.decode_token(token)
            assert result is None

    def test_token_with_wrong_issuer_rejected(self, app, jwt_keypair):
        """Test that token with wrong iss claim is rejected."""
        with app.app_context():
            payload = {
                'sub': '1',
                'iss': 'wrong-issuer',  # Should be 'squawk-manager'
                'aud': 'squawk',
                'tenant': 'default',
                'user_id': 1,
                'exp': datetime.utcnow() + timedelta(hours=1),
                'iat': datetime.utcnow()
            }
            token = jwt.encode(
                payload,
                jwt_keypair['private'],
                algorithm='ES256'
            )

            result = AuthService.decode_token(token)
            assert result is None

    def test_token_missing_tenant_rejected(self, app, jwt_keypair):
        """Regression test: Token missing tenant claim is REJECTED (fail closed)."""
        with app.app_context():
            # Create token WITHOUT tenant claim
            payload = {
                'sub': '1',
                'iss': 'squawk-manager',
                'aud': 'squawk',
                'user_id': 1,
                'type': 'access',
                'exp': datetime.utcnow() + timedelta(hours=1),
                'iat': datetime.utcnow()
            }
            token = jwt.encode(
                payload,
                jwt_keypair['private'],
                algorithm='ES256'
            )

            result = AuthService.decode_token(token)
            assert result is None

    def test_token_with_empty_tenant_rejected(self, app, jwt_keypair):
        """Regression test: Token with empty tenant claim is REJECTED (fail closed)."""
        with app.app_context():
            # Create token with empty tenant
            payload = {
                'sub': '1',
                'iss': 'squawk-manager',
                'aud': 'squawk',
                'tenant': '',  # Empty is not allowed
                'user_id': 1,
                'type': 'access',
                'exp': datetime.utcnow() + timedelta(hours=1),
                'iat': datetime.utcnow()
            }
            token = jwt.encode(
                payload,
                jwt_keypair['private'],
                algorithm='ES256'
            )

            result = AuthService.decode_token(token)
            assert result is None


class TestAlgorithmConfusionPrevention:
    """Regression tests: prevent algorithm confusion attacks."""

    def test_hs256_token_rejected(self, app, jwt_invalid_token_factory):
        """Regression test: HS256-signed token is REJECTED (never accept HS256)."""
        with app.app_context():
            # Create HS256 token (should be rejected)
            hs256_token = jwt_invalid_token_factory['hs256'](user_id=1)

            result = AuthService.decode_token(hs256_token)
            assert result is None, "HS256 tokens must be rejected to prevent algorithm confusion"

    def test_rs256_token_accepted_when_configured(self, app, jwt_keypair):
        """Test that RS256 token is accepted (fallback algorithm support)."""
        with app.app_context():
            # Generate RS256 keypair
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend

            rs256_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )

            # Configure app with RS256 public key
            rs256_public_pem = rs256_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')

            app.config['JWT_PUBLIC_KEY'] = rs256_public_pem

            # Create RS256 token
            rs256_private_pem = rs256_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')

            payload = {
                'sub': '1',
                'iss': 'squawk-manager',
                'aud': 'squawk',
                'tenant': 'default',
                'user_id': 1,
                'type': 'access',
                'exp': datetime.utcnow() + timedelta(hours=1),
                'iat': datetime.utcnow()
            }

            rs256_token = jwt.encode(
                payload,
                rs256_private_pem,
                algorithm='RS256'
            )

            # Verify RS256 token works
            result = AuthService.decode_token(rs256_token)
            assert result is not None
            assert result['user_id'] == 1


class TestServerTokenVerification:
    """Test that server tokens (HS256) still work with server-specific secret."""

    def test_server_token_with_custom_secret(self, app):
        """Test that server tokens use custom secret (backwards compatible)."""
        with app.app_context():
            server_secret = 'server-specific-secret-key'

            # Create server token using HS256
            payload = {
                'server_id': 1,
                'type': 'server',
                'exp': datetime.utcnow() + timedelta(hours=24),
                'iat': datetime.utcnow()
            }
            token = jwt.encode(payload, server_secret, algorithm='HS256')

            # Verify with custom secret (server path)
            result = AuthService.decode_token(token, secret_key=server_secret)
            assert result is not None
            assert result['server_id'] == 1
            assert result['type'] == 'server'

    def test_server_token_fails_without_correct_secret(self, app):
        """Test that server token fails with wrong secret."""
        with app.app_context():
            server_secret = 'server-specific-secret-key'
            wrong_secret = 'wrong-secret'

            payload = {
                'server_id': 1,
                'type': 'server',
                'exp': datetime.utcnow() + timedelta(hours=24),
                'iat': datetime.utcnow()
            }
            token = jwt.encode(payload, server_secret, algorithm='HS256')

            # Should fail with wrong secret
            result = AuthService.decode_token(token, secret_key=wrong_secret)
            assert result is None
