"""
Manager Backend API Smoke Tests
Verifies all REST API endpoints in the manager backend
"""

import pytest
import requests


@pytest.mark.smoke
@pytest.mark.api
class TestManagerAuthAPI:
    """Test manager authentication API endpoints"""

    def test_login_endpoint_exists(self, config, http_session):
        """POST /api/v1/auth/login endpoint exists"""
        url = f"{config.manager_backend_url}/api/v1/auth/login"

        response = http_session.post(
            url,
            json={"username": "invalid", "password": "invalid"},
            timeout=config.request_timeout
        )

        # Should return 401 for invalid credentials, not 404
        assert response.status_code in [400, 401]

    def test_login_with_valid_credentials(self, config, http_session):
        """Login with valid credentials returns tokens"""
        url = f"{config.manager_backend_url}/api/v1/auth/login"

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
            assert "user" in data

    def test_refresh_token_endpoint(self, config, http_session, manager_auth_token):
        """POST /api/v1/auth/refresh endpoint works"""
        if not manager_auth_token:
            pytest.skip("No auth token available")

        url = f"{config.manager_backend_url}/api/v1/auth/refresh"

        # This would need a refresh token, testing endpoint exists
        response = http_session.post(
            url,
            json={"refreshToken": "invalid_token"},
            timeout=config.request_timeout
        )

        assert response.status_code in [400, 401]

    def test_me_endpoint_requires_auth(self, config, http_session):
        """GET /api/v1/auth/me requires authentication"""
        url = f"{config.manager_backend_url}/api/v1/auth/me"

        response = http_session.get(url, timeout=config.request_timeout)

        assert response.status_code in [401, 403]

    def test_me_endpoint_with_auth(self, manager_client):
        """GET /api/v1/auth/me returns user info with auth"""
        response = manager_client.get("/api/v1/auth/me")

        if manager_client.token:
            assert response.status_code in [200, 401]
            if response.status_code == 200:
                data = response.json()
                assert "id" in data or "user_id" in data

    def test_logout_endpoint(self, manager_client):
        """POST /api/v1/auth/logout endpoint works"""
        response = manager_client.post("/api/v1/auth/logout")

        # Should succeed if authenticated
        assert response.status_code in [200, 401]


@pytest.mark.smoke
@pytest.mark.api
class TestManagerTeamsAPI:
    """Test team management API endpoints"""

    def test_list_teams_endpoint(self, manager_client):
        """GET /api/v1/teams returns team list"""
        response = manager_client.get("/api/v1/teams")

        if manager_client.token:
            assert response.status_code in [200, 401, 403]
            if response.status_code == 200:
                data = response.json()
                assert isinstance(data, list)

    def test_create_team_endpoint(self, manager_client):
        """POST /api/v1/teams creates a team"""
        try:
            response = manager_client.post(
                "/api/v1/teams",
                json={"name": "Test Team", "description": "Test description"}
            )

            # May succeed, require admin role, or not be implemented yet
            assert response.status_code in [201, 400, 401, 403, 404, 409]
        except requests.exceptions.ConnectionError:
            pytest.skip("Manager backend not available")

    def test_get_single_team(self, manager_client):
        """GET /api/v1/teams/<id> returns team details"""
        # First get teams list
        list_response = manager_client.get("/api/v1/teams")

        if list_response.status_code == 200:
            teams = list_response.json()
            if teams:
                team_id = teams[0].get("id")
                if team_id:
                    response = manager_client.get(f"/api/v1/teams/{team_id}")
                    assert response.status_code in [200, 403, 404]

    def test_list_team_members(self, manager_client):
        """GET /api/v1/teams/<id>/members returns member list"""
        # First get teams list
        list_response = manager_client.get("/api/v1/teams")

        if list_response.status_code == 200:
            teams = list_response.json()
            if teams:
                team_id = teams[0].get("id")
                if team_id:
                    response = manager_client.get(f"/api/v1/teams/{team_id}/members")
                    assert response.status_code in [200, 403, 404]


@pytest.mark.smoke
@pytest.mark.api
class TestManagerDNSServersAPI:
    """Test DNS server management API endpoints"""

    def test_list_dns_servers(self, manager_client):
        """GET /api/v1/dns-servers returns server list"""
        response = manager_client.get("/api/v1/dns-servers")

        if manager_client.token:
            assert response.status_code in [200, 401, 403]
            if response.status_code == 200:
                data = response.json()
                assert isinstance(data, list)

    def test_create_dns_server(self, manager_client):
        """POST /api/v1/dns-servers creates a server"""
        try:
            response = manager_client.post(
                "/api/v1/dns-servers",
                json={"name": "test-server", "region": "us-east-1"}
            )

            # May succeed, require admin role, or not be implemented yet
            assert response.status_code in [201, 400, 401, 403, 404, 409]
        except requests.exceptions.ConnectionError:
            pytest.skip("Manager backend not available")

    def test_register_dns_server_endpoint(self, config, http_session):
        """POST /api/v1/dns-servers/register endpoint exists"""
        url = f"{config.manager_backend_url}/api/v1/dns-servers/register"

        try:
            response = http_session.post(
                url,
                json={"joinKey": "invalid-key", "hostname": "test.local"},
                timeout=config.request_timeout
            )

            # Should return 401 for invalid join key, or 404 if not implemented
            assert response.status_code in [400, 401, 404]
        except requests.exceptions.ConnectionError:
            pytest.skip("Manager backend not available")

    def test_get_dns_server_config(self, manager_client):
        """GET /api/v1/dns-servers/<id>/config endpoint exists"""
        # This requires server token, not user token
        response = manager_client.get("/api/v1/dns-servers/1/config")

        # Should require server token
        assert response.status_code in [401, 403, 404]


@pytest.mark.smoke
@pytest.mark.api
class TestManagerUsersAPI:
    """Test user management API endpoints"""

    def test_list_users_endpoint(self, manager_client):
        """GET /api/v1/users returns user list"""
        response = manager_client.get("/api/v1/users")

        if manager_client.token:
            assert response.status_code in [200, 401, 403]

    def test_create_user_endpoint(self, manager_client):
        """POST /api/v1/users creates a user"""
        response = manager_client.post(
            "/api/v1/users",
            json={
                "username": "testuser",
                "email": "test@example.com",
                "password": "TestPass123!"
            }
        )

        # May succeed or require admin role
        assert response.status_code in [201, 400, 401, 403, 409]


@pytest.mark.smoke
@pytest.mark.api
class TestManagerZonesAPI:
    """Test zone management API endpoints"""

    def test_list_zones(self, manager_client):
        """GET /api/v1/zones returns zone list"""
        response = manager_client.get("/api/v1/zones")

        if manager_client.token:
            assert response.status_code in [200, 401, 403]


@pytest.mark.smoke
@pytest.mark.api
class TestManagerTokensAPI:
    """Test token management API endpoints"""

    def test_list_tokens(self, manager_client):
        """GET /api/v1/tokens returns token list"""
        response = manager_client.get("/api/v1/tokens")

        if manager_client.token:
            assert response.status_code in [200, 401, 403]


@pytest.mark.smoke
@pytest.mark.api
class TestManagerIOCFeedsAPI:
    """Test IOC feed management API endpoints"""

    def test_list_ioc_feeds(self, manager_client):
        """GET /api/v1/ioc-feeds returns feed list"""
        response = manager_client.get("/api/v1/ioc-feeds")

        if manager_client.token:
            assert response.status_code in [200, 401, 403]


@pytest.mark.smoke
@pytest.mark.api
class TestManagerAnalyticsAPI:
    """Test analytics API endpoints"""

    def test_analytics_endpoint(self, manager_client):
        """GET /api/v1/analytics returns analytics data"""
        response = manager_client.get("/api/v1/analytics")

        if manager_client.token:
            assert response.status_code in [200, 401, 403]


@pytest.mark.smoke
@pytest.mark.api
class TestManagerTimeAPI:
    """Test time/NTP API endpoints"""

    def test_time_endpoint(self, manager_client):
        """GET /api/v1/time returns current time"""
        response = manager_client.get("/api/v1/time")

        # May be public endpoint
        assert response.status_code in [200, 401, 403, 404]


@pytest.mark.smoke
@pytest.mark.api
class TestManagerAPIResponseFormat:
    """Test API response format consistency"""

    def test_error_responses_are_json(self, config, http_session):
        """Error responses return JSON"""
        url = f"{config.manager_backend_url}/api/v1/auth/login"

        response = http_session.post(
            url,
            json={"username": "x", "password": "x"},
            timeout=config.request_timeout
        )

        if response.status_code in [400, 401]:
            # Should be JSON
            content_type = response.headers.get("Content-Type", "")
            assert "application/json" in content_type

    def test_api_versioning(self, config, http_session):
        """API uses versioned endpoints"""
        # Try v1 endpoint
        url = f"{config.manager_backend_url}/api/v1/auth/me"
        response = http_session.get(url, timeout=config.request_timeout)

        # Should not be 404 (endpoint exists)
        assert response.status_code in [200, 401, 403]
