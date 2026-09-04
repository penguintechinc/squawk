"""
API Endpoint Smoke Tests
Verifies all API endpoints return proper JSON responses
"""

import pytest
import requests


@pytest.mark.smoke
@pytest.mark.api
class TestPublicEndpoints:
    """Test endpoints accessible without authentication"""

    def test_root_endpoint_returns_json(self, config, http_session):
        """Root endpoint returns JSON service identifier"""
        url = config.web_console_url

        response = http_session.get(
            url,
            timeout=config.request_timeout
        )

        assert response.status_code == 200
        data = response.json()
        assert "service" in data
        assert data["service"] == "squawk-dns-api"

    def test_login_endpoint_validates_input(self, config, http_session):
        """Login endpoint validates input (POST-only)"""
        url = f"{config.web_console_url}/api/v1/auth/login"

        # Empty body should return 400
        response = http_session.post(
            url,
            json={},
            timeout=config.request_timeout
        )

        assert response.status_code == 400
        data = response.json()
        assert "error" in data or "message" in data

    def test_register_endpoint_validates_input(self, config, http_session):
        """Register endpoint validates input (POST-only)"""
        url = f"{config.web_console_url}/api/v1/auth/register"

        # Empty body should return 400
        response = http_session.post(
            url,
            json={},
            timeout=config.request_timeout
        )

        assert response.status_code == 400
        data = response.json()
        assert "error" in data or "message" in data

    def test_health_endpoint_public(self, config, http_session):
        """Health endpoint is publicly accessible"""
        url = f"{config.web_console_url}/health"

        response = http_session.get(url, timeout=config.request_timeout)

        assert response.status_code == 200


@pytest.mark.smoke
@pytest.mark.api
@pytest.mark.auth
class TestAuthenticatedAPIEndpoints:
    """Test API endpoints that require authentication"""

    def test_dashboard_stats_endpoint(self, authenticated_client):
        """Dashboard stats endpoint returns JSON"""
        response = authenticated_client.get("/api/v1/dashboard/stats")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, dict)

    def test_queries_endpoint(self, authenticated_client):
        """Query log endpoint returns JSON"""
        response = authenticated_client.get("/api/v1/queries")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, (dict, list))

    def test_ioc_feeds_endpoint(self, authenticated_client):
        """IOC feeds endpoint returns JSON"""
        response = authenticated_client.get("/api/v1/ioc/feeds")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, (dict, list))

    def test_domains_endpoint(self, authenticated_client):
        """Internal domains endpoint returns JSON"""
        response = authenticated_client.get("/api/v1/domains")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, (dict, list))

    def test_users_endpoint(self, authenticated_client):
        """User management endpoint returns JSON"""
        response = authenticated_client.get("/api/v1/users")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, (dict, list))

    def test_groups_endpoint(self, authenticated_client):
        """Group management endpoint returns JSON"""
        response = authenticated_client.get("/api/v1/groups")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, (dict, list))

    def test_zones_endpoint(self, authenticated_client):
        """DNS zones endpoint returns JSON"""
        response = authenticated_client.get("/api/v1/zones")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, (dict, list))

    def test_records_endpoint(self, authenticated_client):
        """DNS records endpoint returns JSON"""
        response = authenticated_client.get("/api/v1/records")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, (dict, list))

    def test_permissions_endpoint(self, authenticated_client):
        """Permissions endpoint returns JSON"""
        response = authenticated_client.get("/api/v1/permissions")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, (dict, list))

    def test_blocked_endpoint(self, authenticated_client):
        """Blocked queries endpoint returns JSON"""
        response = authenticated_client.get("/api/v1/blocked")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, (dict, list))

    def test_threats_endpoint(self, authenticated_client):
        """Threat intelligence endpoint returns JSON"""
        response = authenticated_client.get("/api/v1/threats")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, (dict, list))

    def test_logs_endpoint(self, authenticated_client):
        """System logs endpoint returns JSON"""
        response = authenticated_client.get("/api/v1/logs")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, (dict, list))


@pytest.mark.smoke
@pytest.mark.api
@pytest.mark.auth
class TestAPIPagination:
    """Test pagination on API endpoints"""

    def test_queries_pagination_limit_offset(self, authenticated_client):
        """Query log pagination with limit/offset works"""
        # First page
        response1 = authenticated_client.get("/api/v1/queries?limit=10&offset=0")
        assert response1.status_code == 200
        data1 = response1.json()
        assert isinstance(data1, (dict, list))

        # Second page
        response2 = authenticated_client.get("/api/v1/queries?limit=10&offset=10")
        assert response2.status_code == 200
        data2 = response2.json()
        assert isinstance(data2, (dict, list))

    def test_logs_pagination_page_perpage(self, authenticated_client):
        """Logs pagination with page/per_page works"""
        # First page
        response1 = authenticated_client.get("/api/v1/logs?page=1&per_page=10")
        assert response1.status_code == 200
        data1 = response1.json()
        assert isinstance(data1, (dict, list))

        # Second page
        response2 = authenticated_client.get("/api/v1/logs?page=2&per_page=10")
        assert response2.status_code == 200
        data2 = response2.json()
        assert isinstance(data2, (dict, list))


@pytest.mark.smoke
@pytest.mark.api
class TestUnauthenticatedAPIAccess:
    """Test that protected API endpoints require authentication"""

    def test_api_endpoints_require_auth(self, config, fresh_http_session):
        """Protected API endpoints return 401 when unauthenticated"""
        protected_endpoints = [
            "/api/v1/domains",
            "/api/v1/users",
            "/api/v1/groups",
            "/api/v1/queries",
            "/api/v1/ioc/feeds",
            "/api/v1/zones",
            "/api/v1/records",
            "/api/v1/permissions",
            "/api/v1/blocked",
            "/api/v1/threats",
            "/api/v1/logs"
        ]

        for endpoint in protected_endpoints:
            url = f"{config.web_console_url}{endpoint}"
            response = fresh_http_session.get(
                url,
                timeout=config.request_timeout
            )

            assert response.status_code == 401, \
                f"Endpoint {endpoint} did not require auth (got {response.status_code})"
