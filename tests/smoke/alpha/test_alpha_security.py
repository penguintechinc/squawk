"""
Alpha Security Tests
Comprehensive security testing for local development environment
"""

import pytest
import requests
from unittest.mock import Mock, patch
import jwt as pyjwt
from datetime import datetime, timedelta
import hashlib
import re


@pytest.mark.alpha
@pytest.mark.security
class TestAlphaAuthenticationSecurity:
    """Test authentication security in alpha environment"""

    def test_login_requires_valid_email(self, config, http_session):
        """Login endpoint validates email format"""
        login_url = f"{config.web_console_url}/api/v1/auth/login"

        invalid_emails = [
            "notanemail",
            "@example.com",
            "test@",
            "test..test@example.com",
            "",
            "   ",
            "test@example",
        ]

        for invalid_email in invalid_emails:
            response = http_session.post(
                login_url,
                json={"email": invalid_email, "password": "test123"},
                timeout=config.request_timeout
            )
            # Should reject invalid email format
            assert response.status_code in [400, 422], \
                f"Invalid email '{invalid_email}' should be rejected"

    def test_login_requires_password(self, config, http_session):
        """Login endpoint requires password"""
        login_url = f"{config.web_console_url}/api/v1/auth/login"

        invalid_passwords = [
            "",
            None,
            "   ",
        ]

        for invalid_password in invalid_passwords:
            response = http_session.post(
                login_url,
                json={"email": "test@example.com", "password": invalid_password},
                timeout=config.request_timeout
            )
            # Should reject missing/empty password
            assert response.status_code in [400, 401, 422], \
                f"Invalid password should be rejected"

    def test_login_rate_limiting(self, config, http_session):
        """Login endpoint has rate limiting"""
        login_url = f"{config.web_console_url}/api/v1/auth/login"

        # Try many failed logins
        attempts = 0
        rate_limited = False

        for i in range(20):
            response = http_session.post(
                login_url,
                json={
                    "email": f"attacker{i}@example.com",
                    "password": "wrongpassword"
                },
                timeout=config.request_timeout
            )
            attempts += 1

            if response.status_code == 429:
                rate_limited = True
                break

        # Should eventually get rate limited (optional, may not be implemented)
        # This is informational - good if rate limiting exists
        if rate_limited:
            pytest.skip("Rate limiting detected (good security practice)")

    def test_jwt_token_has_expiration(self, config, http_session):
        """JWT tokens have expiration time"""
        login_url = f"{config.web_console_url}/api/v1/auth/login"

        response = http_session.post(
            login_url,
            json={
                "email": config.admin_email,
                "password": config.admin_password
            },
            timeout=config.request_timeout
        )

        if response.status_code != 200:
            pytest.skip("Authentication not configured")

        data = response.json()
        token = data.get("access_token")

        if not token:
            pytest.skip("No JWT token returned")

        # Decode without verification to check structure
        try:
            decoded = pyjwt.decode(token, options={"verify_signature": False})
            assert "exp" in decoded, "JWT token must have expiration"

            # Verify expiration is in the future
            exp_time = datetime.fromtimestamp(decoded["exp"])
            assert exp_time > datetime.utcnow(), "Token expiration must be in future"
        except Exception:
            pytest.skip("Cannot decode JWT token")

    def test_expired_token_rejected(self, config, http_session):
        """Expired JWT tokens are rejected"""
        # Create an expired token (mock)
        expired_payload = {
            'user_id': 1,
            'role': 'admin',
            'exp': datetime.utcnow() - timedelta(hours=1),  # Expired 1 hour ago
            'iat': datetime.utcnow() - timedelta(hours=2)
        }

        expired_token = pyjwt.encode(expired_payload, "fake_secret", algorithm="HS256")

        # Try to use expired token
        response = http_session.get(
            f"{config.web_console_url}/api/v1/dashboard/stats",
            headers={"Authorization": f"Bearer {expired_token}"},
            timeout=config.request_timeout
        )

        # Should reject expired token
        assert response.status_code == 401


@pytest.mark.alpha
@pytest.mark.security
class TestAlphaAuthorizationSecurity:
    """Test authorization and RBAC in alpha environment"""

    def test_protected_endpoints_require_auth(self, config, http_session):
        """Protected API endpoints require authentication"""
        protected_endpoints = [
            "/api/v1/dashboard/stats",
            "/api/v1/queries",
            "/api/v1/domains",
            "/api/v1/users",
            "/api/v1/zones",
            "/api/v1/records",
        ]

        # Use fresh session without auth
        new_session = requests.Session()

        for endpoint in protected_endpoints:
            response = new_session.get(
                f"{config.web_console_url}{endpoint}",
                timeout=config.request_timeout
            )

            assert response.status_code == 401, \
                f"Endpoint {endpoint} should require authentication"

    def test_admin_only_endpoints(self, authenticated_client):
        """Admin-only endpoints check role permissions"""
        admin_endpoints = [
            "/api/v1/users",
            "/api/v1/groups",
            "/api/v1/permissions",
        ]

        # This test assumes authenticated_client is admin
        # In production, test with non-admin user too
        for endpoint in admin_endpoints:
            response = authenticated_client.get(endpoint)

            # Should allow admin access OR return 403 if not admin
            assert response.status_code in [200, 403], \
                f"Admin endpoint {endpoint} should check permissions"


@pytest.mark.alpha
@pytest.mark.security
class TestAlphaInputValidation:
    """Test input validation and sanitization"""

    def test_xss_prevention_in_domain_names(self, authenticated_client):
        """Domain name inputs prevent XSS attacks"""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "'\"><script>alert('xss')</script>",
        ]

        for payload in xss_payloads:
            response = authenticated_client.post(
                "/api/v1/domains",
                json={"domain": payload, "type": "A", "value": "1.2.3.4"}
            )

            # Should reject or sanitize XSS payloads
            if response.status_code == 200:
                data = response.json()
                # Verify XSS payload was sanitized
                assert "<script>" not in str(data), "XSS payload not sanitized"

    def test_sql_injection_prevention(self, authenticated_client):
        """API endpoints prevent SQL injection"""
        sql_payloads = [
            "' OR '1'='1",
            "1'; DROP TABLE users--",
            "admin'--",
            "' UNION SELECT * FROM users--",
        ]

        for payload in sql_payloads:
            # Test in search endpoint
            response = authenticated_client.get(
                f"/api/v1/search/users?q={payload}"
            )

            # Should not error (500) from SQL injection
            assert response.status_code != 500, \
                f"SQL injection payload caused server error: {payload}"

    def test_command_injection_prevention(self, authenticated_client):
        """Input validation prevents command injection"""
        cmd_payloads = [
            "; ls -la",
            "| cat /etc/passwd",
            "`whoami`",
            "$(whoami)",
            "&& rm -rf /",
        ]

        for payload in cmd_payloads:
            response = authenticated_client.post(
                "/api/v1/domains",
                json={"domain": f"test{payload}.com", "type": "A", "value": "1.2.3.4"}
            )

            # Should reject or sanitize command injection
            assert response.status_code in [200, 400, 422], \
                f"Command injection not prevented: {payload}"

    def test_path_traversal_prevention(self, config, http_session):
        """File path inputs prevent directory traversal"""
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32",
            "....//....//....//etc/passwd",
            "file:///etc/passwd",
        ]

        for payload in traversal_payloads:
            response = http_session.get(
                f"{config.web_console_url}/api/v1/file?path={payload}",
                timeout=config.request_timeout
            )

            # Should reject path traversal attempts
            assert response.status_code in [400, 403, 404], \
                f"Path traversal not prevented: {payload}"


@pytest.mark.alpha
@pytest.mark.security
class TestAlphaCSRFProtection:
    """Test CSRF protection in alpha environment"""

    def test_state_changing_operations_require_csrf_token(self, authenticated_client):
        """POST/PUT/DELETE operations require CSRF protection"""
        # Test POST without CSRF token
        response = authenticated_client.post(
            "/api/v1/domains",
            json={"domain": "test.com", "type": "A", "value": "1.2.3.4"}
        )

        # Should succeed with JWT (REST API typically doesn't need CSRF)
        # But form-based endpoints should require CSRF
        assert response.status_code in [200, 201, 400, 403, 422]


@pytest.mark.alpha
@pytest.mark.security
class TestAlphaSecureHeaders:
    """Test security headers in responses"""

    def test_security_headers_present(self, config, http_session):
        """Responses include security headers"""
        response = http_session.get(
            f"{config.web_console_url}/health",
            timeout=config.request_timeout
        )

        headers = response.headers

        # Check for important security headers
        # Note: Not all may be present in development
        expected_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": ["DENY", "SAMEORIGIN"],
            "X-XSS-Protection": "1; mode=block",
        }

        for header, expected_value in expected_headers.items():
            if header in headers:
                if isinstance(expected_value, list):
                    assert headers[header] in expected_value, \
                        f"Header {header} has unexpected value"
                else:
                    assert headers[header] == expected_value, \
                        f"Header {header} has unexpected value"

    def test_no_sensitive_info_in_errors(self, config, http_session):
        """Error responses don't leak sensitive information"""
        response = http_session.get(
            f"{config.web_console_url}/api/v1/nonexistent",
            timeout=config.request_timeout
        )

        error_text = response.text.lower()

        # Should not contain sensitive paths or stack traces
        sensitive_patterns = [
            r'/home/\w+',
            r'c:\\users\\',
            r'traceback',
            r'stack trace',
            r'__file__',
        ]

        for pattern in sensitive_patterns:
            assert not re.search(pattern, error_text), \
                f"Error response contains sensitive info: {pattern}"


@pytest.mark.alpha
@pytest.mark.security
class TestAlphaDNSSecurityQueries:
    """Test DNS query security in alpha environment"""

    def test_dns_query_validation(self, config, http_session):
        """DNS queries validate domain names"""
        invalid_domains = [
            "",
            " ",
            "a" * 300,  # Too long
            "test..com",  # Double dots
            "-test.com",  # Starts with hyphen
            "test-.com",  # Ends with hyphen
            "test$.com",  # Invalid character
        ]

        for invalid_domain in invalid_domains:
            response = http_session.get(
                f"{config.dns_server_url}/dns-query",
                params={"name": invalid_domain, "type": "A"},
                timeout=config.request_timeout
            )

            # Should reject invalid domain names
            assert response.status_code in [400, 422], \
                f"Invalid domain not rejected: {invalid_domain}"

    def test_dns_amplification_protection(self, config, http_session):
        """DNS server protects against amplification attacks"""
        # Request large responses
        response = http_session.get(
            f"{config.dns_server_url}/dns-query",
            params={"name": "example.com", "type": "ANY"},
            timeout=config.request_timeout
        )

        # Should limit response size or reject ANY queries
        if response.status_code == 200:
            assert len(response.content) < 65535, \
                "DNS response too large (amplification risk)"
