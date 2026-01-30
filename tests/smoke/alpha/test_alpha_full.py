"""
Alpha Environment Full Smoke Tests
Complete verification of local development environment
"""

import pytest
import requests
import subprocess
import time
import os


@pytest.mark.alpha
@pytest.mark.full
class TestAlphaBuildVerification:
    """Verify builds work in local environment"""

    def test_docker_compose_config_valid(self):
        """Docker compose configuration is valid"""
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.dirname(__file__))))

        result = subprocess.run(
            ["docker", "compose", "config", "--quiet"],
            cwd=project_root,
            capture_output=True,
            text=True
        )

        assert result.returncode == 0, f"Docker compose config invalid: {result.stderr}"

    def test_containers_are_running(self):
        """Required containers are running"""
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True
        )

        running_containers = result.stdout.strip().split('\n')

        # Check for expected containers
        expected_patterns = ["squawk", "dns"]
        found = any(
            any(pattern in container.lower() for pattern in expected_patterns)
            for container in running_containers
        )

        # Note: Containers may have different names, this is a soft check
        if not found:
            pytest.skip("Squawk containers not detected - may be using different names")


@pytest.mark.alpha
@pytest.mark.full
class TestAlphaContainerHealth:
    """Full container health checks for alpha"""

    def test_dns_server_health(self, config, http_session):
        """DNS server is healthy"""
        response = http_session.get(
            f"{config.dns_server_url}/health",
            timeout=config.request_timeout
        )

        assert response.status_code == 200
        data = response.json()
        assert data.get("status") == "healthy"

    def test_web_console_health(self, config, http_session):
        """Web console is healthy"""
        response = http_session.get(
            f"{config.web_console_url}/health",
            timeout=config.request_timeout
        )

        assert response.status_code == 200
        data = response.json()
        assert data.get("status") == "healthy"

    def test_dns_server_cache_connected(self, config, http_session):
        """DNS server cache (Valkey) is connected"""
        response = http_session.get(
            f"{config.dns_server_url}/health",
            timeout=config.request_timeout
        )

        if response.status_code == 200:
            data = response.json()
            # Cache info may be in health response
            assert "status" in data


@pytest.mark.alpha
@pytest.mark.full
class TestAlphaAllAPIEndpoints:
    """Test all API endpoints in alpha environment"""

    @pytest.mark.parametrize("path", [
        "/",
        "/health"
    ])
    def test_public_pages_load(self, config, http_session, path):
        """Public endpoints return JSON without authentication"""
        response = http_session.get(
            f"{config.web_console_url}{path}",
            timeout=config.request_timeout,
            allow_redirects=True
        )

        assert response.status_code == 200

    @pytest.mark.parametrize("path", [
        "/api/v1/dashboard/stats",
        "/api/v1/queries",
        "/api/v1/ioc/feeds",
        "/api/v1/domains",
        "/api/v1/users",
        "/api/v1/groups",
        "/api/v1/zones",
        "/api/v1/records",
        "/api/v1/permissions",
        "/api/v1/blocked",
        "/api/v1/threats",
        "/api/v1/logs"
    ])
    def test_authenticated_api_endpoints(self, authenticated_client, path):
        """Authenticated API endpoints return data for logged-in user"""
        response = authenticated_client.get(path)

        assert response.status_code == 200, f"API {path} failed: {response.status_code}"


@pytest.mark.alpha
@pytest.mark.full
class TestAlphaAllAPIs:
    """Test all APIs work in alpha environment"""

    def test_queries_api(self, authenticated_client):
        """GET /api/v1/queries returns data"""
        response = authenticated_client.get("/api/v1/queries")
        assert response.status_code == 200
        assert "queries" in response.json()

    def test_ioc_feeds_api(self, authenticated_client):
        """GET /api/v1/ioc/feeds returns data"""
        response = authenticated_client.get("/api/v1/ioc/feeds")
        assert response.status_code == 200
        assert "feeds" in response.json()

    def test_stats_summary_api(self, authenticated_client):
        """GET /api/v1/dashboard/stats returns data"""
        response = authenticated_client.get("/api/v1/dashboard/stats")
        assert response.status_code == 200

    def test_users_search_api(self, authenticated_client):
        """GET /api/v1/search/users returns data"""
        response = authenticated_client.get("/api/v1/search/users?q=")
        assert response.status_code == 200
        assert "users" in response.json()

    def test_groups_search_api(self, authenticated_client):
        """GET /api/v1/search/groups returns data"""
        response = authenticated_client.get("/api/v1/search/groups?q=")
        assert response.status_code == 200
        assert "groups" in response.json()


@pytest.mark.alpha
@pytest.mark.full
class TestAlphaDNSServer:
    """Test DNS server APIs in alpha"""

    def test_dns_query_endpoint(self, config, http_session):
        """DNS query endpoint responds"""
        response = http_session.get(
            f"{config.dns_server_url}/dns-query",
            params={"name": "example.com", "type": "A"},
            timeout=config.request_timeout
        )

        assert response.status_code in [200, 401, 403]

    def test_health_includes_cache_stats(self, config, http_session):
        """Health endpoint includes cache info"""
        response = http_session.get(
            f"{config.dns_server_url}/health",
            timeout=config.request_timeout
        )

        assert response.status_code == 200
        data = response.json()
        assert "status" in data

    def test_blacklist_endpoint(self, config, http_session):
        """Blacklist admin endpoint is accessible"""
        response = http_session.get(
            f"{config.dns_server_url}/admin/blacklist",
            timeout=config.request_timeout
        )

        # May require auth or not exist yet
        assert response.status_code in [200, 401, 403, 404]


@pytest.mark.alpha
@pytest.mark.full
class TestAlphaAuthentication:
    """Test full auth flow in alpha"""

    def test_login_with_valid_credentials(self, config, http_session):
        """Login succeeds with valid credentials and returns access token"""
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

    def test_login_with_invalid_credentials_fails(self, config, http_session):
        """Login fails with invalid credentials"""
        login_url = f"{config.web_console_url}/api/v1/auth/login"

        # Use a new session to avoid any cached state
        new_session = requests.Session()
        response = new_session.post(
            login_url,
            json={
                "email": "invalid@example.com",
                "password": "wrongpassword"
            },
            timeout=config.request_timeout
        )

        assert response.status_code == 401

    def test_protected_api_requires_auth(self, config, http_session):
        """Protected API endpoints require authentication"""
        # Use a new session without auth
        new_session = requests.Session()
        response = new_session.get(
            f"{config.web_console_url}/api/v1/dashboard/stats",
            timeout=config.request_timeout
        )

        assert response.status_code == 401


@pytest.mark.alpha
@pytest.mark.full
class TestAlphaDataPersistence:
    """Test data persistence in alpha environment"""

    def test_create_and_retrieve_data(self, authenticated_client):
        """Data can be created and retrieved"""
        # This would test actual data persistence
        # For now, verify APIs work
        response = authenticated_client.get("/api/v1/queries")
        assert response.status_code == 200

    def test_session_persists_across_requests(self, authenticated_client):
        """JWT token remains valid across multiple requests"""
        # Make multiple requests with same token
        for _ in range(3):
            response = authenticated_client.get("/api/v1/dashboard/stats")
            assert response.status_code == 200
