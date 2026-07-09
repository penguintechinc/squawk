"""
Tests for JWT authentication and authorization.
Covers token validation, scope checking, and error responses.
"""
import pytest
import jwt
import os
from datetime import datetime, timedelta

# Ensure JWT_SECRET_KEY is set before importing app modules
os.environ.setdefault('JWT_SECRET_KEY', 'test-jwt-secret-key-do-not-use-in-production')


class TestTokenExtraction:
    """Test JWT token extraction from Authorization header."""

    def test_extract_valid_bearer_token(self):
        """Test extracting token from valid Bearer header."""
        from app.auth import extract_token

        header = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
        token = extract_token(header)

        assert token == 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'

    def test_extract_returns_none_for_empty_header(self):
        """Test extracting token from empty header returns None."""
        from app.auth import extract_token

        token = extract_token('')

        assert token is None

    def test_extract_returns_none_for_missing_bearer_prefix(self):
        """Test extracting token without Bearer prefix returns None."""
        from app.auth import extract_token

        header = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
        token = extract_token(header)

        assert token is None

    def test_extract_returns_none_for_basic_auth(self):
        """Test extracting token from Basic auth returns None."""
        from app.auth import extract_token

        header = 'Basic dXNlcjpwYXNz'
        token = extract_token(header)

        assert token is None


class TestTokenVerification:
    """Test JWT signature and expiration verification."""

    def test_verify_valid_token(self, test_token_read):
        """Test verifying a valid JWT token."""
        from app.auth import verify_token

        is_valid, payload = verify_token(test_token_read)

        assert is_valid is True
        assert payload is not None
        assert payload['sub'] == 'test-user-id'
        assert payload['scope'] == 'dhcp:read'

    def test_verify_expired_token(self, jwt_secret_key, test_token_expired):
        """Test verifying an expired JWT token."""
        from app.auth import verify_token

        is_valid, payload = verify_token(test_token_expired)

        assert is_valid is False
        assert payload is None

    def test_verify_invalid_signature(self, jwt_secret_key):
        """Test verifying token with wrong secret key."""
        from app.auth import verify_token
        import jwt

        # Create a token with a different secret
        payload = {
            'sub': 'test-user-id',
            'iss': 'test-issuer',
            'aud': 'test-audience',
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(hours=1),
            'scope': 'dhcp:read',
            'tenant': 'test-tenant',
            'teams': ['test-team'],
            'roles': ['viewer']
        }
        token_with_wrong_secret = jwt.encode(payload, 'wrong-secret-key', algorithm='HS256')

        # Try to verify with the correct secret (should fail)
        is_valid, payload_result = verify_token(token_with_wrong_secret)

        assert is_valid is False
        assert payload_result is None

    def test_verify_empty_token(self, jwt_secret_key):
        """Test verifying empty token."""
        from app.auth import verify_token

        is_valid, payload = verify_token('')

        assert is_valid is False
        assert payload is None

    def test_verify_malformed_token(self, jwt_secret_key):
        """Test verifying malformed token."""
        from app.auth import verify_token

        is_valid, payload = verify_token('not.a.valid.jwt')

        assert is_valid is False
        assert payload is None


class TestScopeChecking:
    """Test JWT scope validation."""

    def test_check_scope_valid(self, jwt_secret_key, test_token_read):
        """Test checking valid scope in token."""
        from app.auth import verify_token, check_scope

        _, payload = verify_token(test_token_read)
        has_scope = check_scope(payload, 'dhcp:read')

        assert has_scope is True

    def test_check_scope_invalid(self, jwt_secret_key, test_token_read):
        """Test checking invalid scope in token."""
        from app.auth import verify_token, check_scope

        _, payload = verify_token(test_token_read)
        has_scope = check_scope(payload, 'dhcp:admin')

        assert has_scope is False

    def test_check_scope_admin(self, jwt_secret_key, test_token_admin):
        """Test checking admin scope in token."""
        from app.auth import verify_token, check_scope

        _, payload = verify_token(test_token_admin)
        has_scope = check_scope(payload, 'dhcp:admin')

        assert has_scope is True

    def test_check_scope_multiple(self, jwt_secret_key):
        """Test checking scope when token has multiple scopes."""
        from app.auth import check_scope

        payload = {'scope': 'dhcp:read dhcp:admin other:write'}
        has_read = check_scope(payload, 'dhcp:read')
        has_admin = check_scope(payload, 'dhcp:admin')
        has_write = check_scope(payload, 'other:write')
        has_delete = check_scope(payload, 'other:delete')

        assert has_read is True
        assert has_admin is True
        assert has_write is True
        assert has_delete is False

    def test_check_scope_empty(self):
        """Test checking scope in token with no scope."""
        from app.auth import check_scope

        payload = {}
        has_scope = check_scope(payload, 'dhcp:read')

        assert has_scope is False


class TestFullAuthCheck:
    """Test complete auth check flow."""

    def test_auth_success_with_valid_token(self, jwt_secret_key, test_token_read):
        """Test full auth check succeeds with valid token and scope."""
        from app.auth import check_auth

        header = f'Bearer {test_token_read}'
        status_code, payload = check_auth(header, 'dhcp:read')

        assert status_code == 200
        assert payload is not None
        assert payload['scope'] == 'dhcp:read'

    def test_auth_403_without_header(self):
        """Test full auth check returns 403 without Authorization header."""
        from app.auth import check_auth

        status_code, payload = check_auth('', 'dhcp:read')

        assert status_code == 403
        assert payload is None

    def test_auth_401_with_invalid_token(self, jwt_secret_key):
        """Test full auth check returns 401 with invalid token."""
        from app.auth import check_auth

        header = 'Bearer invalid.token.here'
        status_code, payload = check_auth(header, 'dhcp:read')

        assert status_code == 401
        assert payload is None

    def test_auth_401_with_expired_token(self, test_token_expired):
        """Test full auth check returns 401 with expired token."""
        from app.auth import check_auth

        header = f'Bearer {test_token_expired}'
        status_code, payload = check_auth(header, 'dhcp:read')

        assert status_code == 401
        assert payload is None

    def test_auth_403_with_wrong_scope(self, test_token_read):
        """Test full auth check returns 403 with wrong scope."""
        from app.auth import check_auth

        header = f'Bearer {test_token_read}'
        status_code, payload = check_auth(header, 'dhcp:admin')

        assert status_code == 403
        assert payload is None

    def test_auth_success_with_admin_scope(self, test_token_admin):
        """Test full auth check succeeds for admin scope."""
        from app.auth import check_auth

        header = f'Bearer {test_token_admin}'
        status_code, payload = check_auth(header, 'dhcp:admin')

        assert status_code == 200
        assert payload is not None
        assert payload['scope'] == 'dhcp:admin'


class TestAuthConfigMissing:
    """Test auth behavior when JWT_SECRET_KEY is not configured or invalid."""

    def test_verify_token_with_empty_token(self):
        """Test verify_token returns (False, None) with empty token."""
        from app.auth import verify_token

        is_valid, payload = verify_token('')

        assert is_valid is False
        assert payload is None

    def test_check_auth_with_invalid_token(self):
        """Test check_auth rejects invalid tokens."""
        from app.auth import check_auth

        header = 'Bearer invalid.malformed.token'
        status_code, payload = check_auth(header, 'dhcp:read')

        # Should fail at token verification stage (401)
        assert status_code == 401
        assert payload is None
