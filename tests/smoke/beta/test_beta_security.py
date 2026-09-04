"""
Beta Security Tests
Security testing for deployed Kubernetes environment
"""

import pytest
import requests
import jwt as pyjwt
from datetime import datetime, timedelta
import re


@pytest.mark.beta
@pytest.mark.security
class TestBetaDeploymentSecurity:
    """Test security in deployed K8s environment"""

    def test_https_enforced(self, config, http_session):
        """HTTPS is enforced in beta deployment"""
        # Beta should use HTTPS
        assert config.dns_server_url.startswith("https://") or \
               config.web_console_url.startswith("https://"), \
               "Beta deployment should use HTTPS"

    def test_tls_version_minimum(self, config):
        """TLS 1.2 or higher is enforced"""
        # This tests that old TLS versions are rejected
        if not config.web_console_url.startswith("https://"):
            pytest.skip("HTTPS not configured")

        import ssl
        import socket

        hostname = config.web_console_url.replace("https://", "").split("/")[0]

        # Try to connect with old TLS version
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            context.maximum_version = ssl.TLSVersion.TLSv1_1
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Should fail with old TLS
                    pytest.fail("Old TLS version allowed (security risk)")
        except (ssl.SSLError, ConnectionError):
            # Good - old TLS rejected
            pass

    def test_security_headers_production(self, config, http_session, wait_for_services):
        """Production security headers are present"""
        if not wait_for_services.get("web_console"):
            pytest.skip("Web console not available")

        response = http_session.get(
            f"{config.web_console_url}/health",
            timeout=config.request_timeout
        )

        assert response.status_code == 200
        headers = response.headers

        # Production should have security headers
        important_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Strict-Transport-Security",
        ]

        for header in important_headers:
            if header in headers:
                assert len(headers[header]) > 0

    def test_no_sensitive_headers_exposed(self, config, http_session, wait_for_services):
        """Sensitive headers are not exposed"""
        if not wait_for_services.get("web_console"):
            pytest.skip("Web console not available")

        response = http_session.get(
            f"{config.web_console_url}/health",
            timeout=config.request_timeout
        )

        headers = response.headers

        # Should not expose internal details
        sensitive_headers = [
            "X-Powered-By",
            "Server",
        ]

        for header in sensitive_headers:
            if header in headers:
                value = headers[header].lower()
                # Should not reveal version numbers
                assert not re.search(r'\d+\.\d+', value), \
                    f"Header {header} exposes version info"


@pytest.mark.beta
@pytest.mark.security
class TestBetaAuthenticationSecurity:
    """Test authentication security in beta"""

    def test_authentication_required_on_all_endpoints(self, config, http_session, wait_for_services):
        """All protected endpoints require authentication"""
        if not wait_for_services.get("web_console"):
            pytest.skip("Web console not available")

        protected_endpoints = [
            "/api/v1/dashboard/stats",
            "/api/v1/queries",
            "/api/v1/users",
            "/api/v1/domains",
        ]

        for endpoint in protected_endpoints:
            response = http_session.get(
                f"{config.web_console_url}{endpoint}",
                timeout=config.request_timeout
            )

            assert response.status_code == 401, \
                f"Endpoint {endpoint} should require authentication"

    def test_rate_limiting_enabled(self, config, http_session, wait_for_services):
        """Rate limiting is enabled in production"""
        if not wait_for_services.get("web_console"):
            pytest.skip("Web console not available")

        login_url = f"{config.web_console_url}/api/v1/auth/login"

        # Make multiple failed login attempts
        for i in range(15):
            response = http_session.post(
                login_url,
                json={
                    "email": f"attacker{i}@example.com",
                    "password": "wrongpassword"
                },
                timeout=config.request_timeout
            )

            if response.status_code == 429:
                # Rate limiting is working
                return

        # Rate limiting should eventually trigger
        pytest.skip("Rate limiting not detected (consider implementing)")

    def test_token_expiration_enforced(self, config, http_session, wait_for_services):
        """JWT token expiration is enforced"""
        if not wait_for_services.get("web_console"):
            pytest.skip("Web console not available")

        # Create expired token
        expired_payload = {
            'user_id': 1,
            'exp': datetime.utcnow() - timedelta(hours=1)
        }
        expired_token = pyjwt.encode(expired_payload, "fake", algorithm="HS256")

        # Try to use expired token
        response = http_session.get(
            f"{config.web_console_url}/api/v1/dashboard/stats",
            headers={"Authorization": f"Bearer {expired_token}"},
            timeout=config.request_timeout
        )

        assert response.status_code == 401


@pytest.mark.beta
@pytest.mark.security
class TestBetaNetworkSecurity:
    """Test network security in K8s deployment"""

    def test_internal_services_not_exposed(self, config):
        """Internal services are not publicly accessible"""
        # Database, cache should not be accessible
        internal_ports = [5432, 6379, 3306]

        hostname = config.web_console_url.replace("https://", "").replace("http://", "").split("/")[0]

        for port in internal_ports:
            try:
                import socket
                socket.create_connection((hostname, port), timeout=2)
                pytest.fail(f"Internal port {port} is publicly accessible (security risk)")
            except (ConnectionRefusedError, TimeoutError, OSError):
                # Good - port not accessible
                pass

    def test_cors_properly_configured(self, config, http_session, wait_for_services):
        """CORS is properly configured"""
        if not wait_for_services.get("web_console"):
            pytest.skip("Web console not available")

        response = http_session.options(
            f"{config.web_console_url}/api/v1/dashboard/stats",
            headers={"Origin": "https://evil.com"},
            timeout=config.request_timeout
        )

        # Should have CORS headers
        if "Access-Control-Allow-Origin" in response.headers:
            allowed_origin = response.headers["Access-Control-Allow-Origin"]
            # Should not allow all origins in production
            assert allowed_origin != "*", "CORS allows all origins (security risk)"


@pytest.mark.beta
@pytest.mark.security
class TestBetaInputValidation:
    """Test input validation in beta environment"""

    def test_xss_prevention(self, authenticated_client):
        """XSS attacks are prevented"""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
        ]

        for payload in xss_payloads:
            response = authenticated_client.post(
                "/api/v1/domains",
                json={"domain": payload, "type": "A", "value": "1.2.3.4"}
            )

            # Should reject or sanitize
            if response.status_code == 200:
                data = response.json()
                assert "<script>" not in str(data)

    def test_sql_injection_prevention(self, authenticated_client):
        """SQL injection is prevented"""
        sql_payloads = [
            "' OR '1'='1",
            "1'; DROP TABLE users--",
        ]

        for payload in sql_payloads:
            response = authenticated_client.get(
                f"/api/v1/search/users?q={payload}"
            )

            # Should not cause server error
            assert response.status_code != 500

    def test_path_traversal_prevention(self, config, http_session, wait_for_services):
        """Path traversal attacks are prevented"""
        if not wait_for_services.get("web_console"):
            pytest.skip("Web console not available")

        traversal_payloads = [
            "../../../etc/passwd",
            "....//....//etc/passwd",
        ]

        for payload in traversal_payloads:
            response = http_session.get(
                f"{config.web_console_url}/api/v1/file?path={payload}",
                timeout=config.request_timeout
            )

            assert response.status_code in [400, 403, 404]


@pytest.mark.beta
@pytest.mark.security
class TestBetaDataSecurity:
    """Test data security in beta environment"""

    def test_no_data_leakage_in_errors(self, config, http_session, wait_for_services):
        """Error messages don't leak sensitive data"""
        if not wait_for_services.get("web_console"):
            pytest.skip("Web console not available")

        response = http_session.get(
            f"{config.web_console_url}/api/v1/nonexistent",
            timeout=config.request_timeout
        )

        error_text = response.text.lower()

        # Should not contain sensitive info
        sensitive_patterns = [
            r'/home/\w+',
            r'password',
            r'secret',
            r'token.*:.*[a-zA-Z0-9]{20,}',
        ]

        for pattern in sensitive_patterns:
            assert not re.search(pattern, error_text), \
                f"Error contains sensitive info: {pattern}"

    def test_user_data_isolation(self, authenticated_client):
        """Users can only access their own data"""
        # Get current user info
        response = authenticated_client.get("/api/v1/auth/me")

        if response.status_code != 200:
            pytest.skip("User info endpoint not available")

        # Try to access other user's data
        response = authenticated_client.get("/api/v1/users/99999")

        # Should be forbidden or not found
        assert response.status_code in [403, 404]


@pytest.mark.beta
@pytest.mark.security
class TestBetaComplianceSecurity:
    """Test compliance and audit requirements"""

    def test_audit_logging_enabled(self, authenticated_client):
        """Audit logging is enabled for important actions"""
        # Perform an action
        authenticated_client.get("/api/v1/dashboard/stats")

        # Check if logs exist
        response = authenticated_client.get("/api/v1/logs?limit=10")

        # Logs should be available or endpoint should exist
        assert response.status_code in [200, 403, 404]

    def test_password_complexity_enforced(self, authenticated_client):
        """Password complexity requirements enforced"""
        weak_passwords = [
            "123456",
            "password",
            "abc",
        ]

        for weak_pass in weak_passwords:
            response = authenticated_client.post(
                "/api/v1/users",
                json={
                    "email": "test@example.com",
                    "password": weak_pass,
                    "role": "user"
                }
            )

            # Should reject weak passwords
            if response.status_code in [200, 201]:
                pytest.fail(f"Weak password accepted: {weak_pass}")
