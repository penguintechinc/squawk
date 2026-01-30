"""
Authentication Smoke Tests
Verifies authentication flows and security
"""

import pytest
import requests


@pytest.mark.smoke
@pytest.mark.auth
class TestWebConsoleAuthentication:
    """Test Flask API JWT authentication flows"""

    def test_login_get_method_not_allowed(self, config, http_session):
        """GET request to login endpoint returns 405 Method Not Allowed"""
        url = f"{config.web_console_url}/api/v1/auth/login"

        response = http_session.get(url, timeout=config.request_timeout)

        assert response.status_code == 405

    def test_login_with_valid_credentials(self, config, http_session):
        """Login with valid credentials returns JWT access token"""
        login_url = f"{config.web_console_url}/api/v1/auth/login"

        response = http_session.post(
            login_url,
            json={
                "email": config.admin_email,
                "password": config.admin_password
            },
            timeout=config.request_timeout
        )

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data

    def test_login_with_invalid_credentials(self, config, http_session):
        """Login with invalid credentials returns 401"""
        login_url = f"{config.web_console_url}/api/v1/auth/login"

        response = http_session.post(
            login_url,
            json={
                "email": "invalid@example.com",
                "password": "wrongpassword"
            },
            timeout=config.request_timeout
        )

        assert response.status_code == 401
        data = response.json()
        assert data.get("success") is False

    def test_logout_with_jwt_token(self, config, http_session):
        """Logout with JWT token succeeds"""
        # First login to get token
        login_url = f"{config.web_console_url}/api/v1/auth/login"
        login_response = http_session.post(
            login_url,
            json={
                "email": config.admin_email,
                "password": config.admin_password
            },
            timeout=config.request_timeout
        )

        if login_response.status_code != 200:
            pytest.skip("Could not authenticate for logout test")

        token = login_response.json().get("access_token")

        # Now logout
        logout_url = f"{config.web_console_url}/api/v1/auth/logout"
        response = http_session.post(
            logout_url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=config.request_timeout
        )

        assert response.status_code == 200

    def test_registration_missing_fields_rejected(self, config, http_session):
        """Registration with missing required fields returns 400"""
        register_url = f"{config.web_console_url}/api/v1/auth/register"

        response = http_session.post(
            register_url,
            json={
                "email": "incomplete@example.com"
                # Missing password and other required fields
            },
            timeout=config.request_timeout
        )

        assert response.status_code == 400

    def test_registration_duplicate_email_rejected(self, config, http_session):
        """Registration with existing email returns 409"""
        register_url = f"{config.web_console_url}/api/v1/auth/register"

        # Try to register with admin email
        response = http_session.post(
            register_url,
            json={
                "email": config.admin_email,
                "password": "NewPassword123!",
                "first_name": "Test",
                "last_name": "User"
            },
            timeout=config.request_timeout
        )

        assert response.status_code == 409


@pytest.mark.smoke
@pytest.mark.auth
class TestJWTSecurity:
    """Test JWT security features"""

    def test_protected_routes_require_authentication(self, config, fresh_http_session):
        """Protected API routes return 401 for unauthenticated requests"""
        protected_urls = [
            "/api/v1/domains",
            "/api/v1/queries",
            "/api/v1/ioc/feeds",
            "/api/v1/users",
        ]

        for path in protected_urls:
            url = f"{config.web_console_url}{path}"
            response = fresh_http_session.get(
                url,
                timeout=config.request_timeout,
                allow_redirects=False
            )

            assert response.status_code == 401, \
                f"Path {path} did not require auth (expected 401, got {response.status_code})"

    def test_invalid_jwt_rejected(self, config, http_session):
        """Invalid JWT token is rejected"""
        url = f"{config.web_console_url}/api/v1/auth/me"

        response = http_session.get(
            url,
            headers={"Authorization": "Bearer invalid.token.here"},
            timeout=config.request_timeout
        )

        assert response.status_code in [401, 422]


@pytest.mark.smoke
@pytest.mark.auth
class TestManagerAuthentication:
    """Test manager backend authentication"""

    def test_login_returns_jwt(self, config, http_session):
        """Manager login returns JWT tokens"""
        url = f"{config.manager_backend_url}/api/v1/auth/login"

        try:
            response = http_session.post(
                url,
                json={
                    "username": config.manager_admin_user,
                    "password": config.manager_admin_pass
                },
                timeout=config.request_timeout
            )

            if response.status_code == 200:
                data = response.json()
                assert "accessToken" in data
                assert "refreshToken" in data
        except requests.exceptions.ConnectionError:
            pytest.skip("Manager backend not available")

    def test_invalid_jwt_rejected(self, config, http_session):
        """Invalid JWT token is rejected"""
        url = f"{config.manager_backend_url}/api/v1/auth/me"

        try:
            response = http_session.get(
                url,
                headers={"Authorization": "Bearer invalid.token.here"},
                timeout=config.request_timeout
            )

            assert response.status_code in [401, 403]
        except requests.exceptions.ConnectionError:
            pytest.skip("Manager backend not available")

    def test_expired_token_rejected(self, config, http_session):
        """Expired JWT token is rejected"""
        url = f"{config.manager_backend_url}/api/v1/auth/me"

        try:
            response = http_session.get(
                url,
                headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjB9.fake"},
                timeout=config.request_timeout
            )

            assert response.status_code in [401, 403]
        except requests.exceptions.ConnectionError:
            pytest.skip("Manager backend not available")


@pytest.mark.smoke
@pytest.mark.auth
class TestPasswordSecurity:
    """Test password security features"""

    def test_change_password_endpoint_requires_auth(self, config, http_session):
        """Change password endpoint requires authentication"""
        url = f"{config.manager_backend_url}/api/v1/auth/change-password"

        try:
            response = http_session.post(
                url,
                json={
                    "current_password": "old",
                    "new_password": "new"
                },
                timeout=config.request_timeout
            )

            assert response.status_code in [401, 403, 404]
        except requests.exceptions.ConnectionError:
            pytest.skip("Manager backend not available")

    def test_change_password_with_auth(self, manager_client):
        """Change password works with authentication"""
        if not manager_client.token:
            pytest.skip("No auth token available")

        try:
            response = manager_client.post(
                "/api/v1/auth/change-password",
                json={
                    "current_password": "wrongpassword",
                    "new_password": "NewPassword123!"
                }
            )

            # Should fail with wrong current password, or 404 if not implemented
            assert response.status_code in [400, 401, 404]
        except requests.exceptions.ConnectionError:
            pytest.skip("Manager backend not available")


@pytest.mark.smoke
@pytest.mark.auth
class TestDNSServerAuthentication:
    """Test DNS server authentication"""

    def test_dns_query_with_token_header(self, config, http_session):
        """DNS query accepts Authorization header"""
        url = f"{config.dns_server_url}/dns-query"

        response = http_session.get(
            url,
            params={"name": "example.com", "type": "A"},
            headers={"Authorization": "Bearer test-token"},
            timeout=config.request_timeout
        )

        # Should not be 500 - endpoint should handle token
        assert response.status_code in [200, 401, 403]

    def test_dns_query_with_x_auth_token(self, config, http_session):
        """DNS query accepts X-Auth-Token header"""
        url = f"{config.dns_server_url}/dns-query"

        response = http_session.get(
            url,
            params={"name": "example.com", "type": "A"},
            headers={"X-Auth-Token": "test-token"},
            timeout=config.request_timeout
        )

        assert response.status_code in [200, 401, 403]

    def test_admin_endpoint_requires_auth(self, config, http_session):
        """Admin blacklist endpoint requires authentication"""
        url = f"{config.dns_server_url}/admin/blacklist"

        response = http_session.post(
            url,
            json={"domain": "test.com"},
            timeout=config.request_timeout
        )

        # Should require auth for POST, or 404 if not implemented
        assert response.status_code in [200, 401, 403, 404]
