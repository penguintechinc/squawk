"""
Beta Environment Deployed Verification Tests
Verify services work correctly when deployed to K8s
"""

import pytest
import requests


@pytest.mark.beta
@pytest.mark.deployed
class TestBetaServiceHealth:
    """Verify deployed services are healthy"""

    def test_dns_server_health(self, config, http_session, wait_for_services):
        """DNS server is healthy in K8s"""
        if not wait_for_services.get("dns_server"):
            pytest.skip("DNS server not available in beta")

        response = http_session.get(
            f"{config.dns_server_url}/health",
            timeout=config.request_timeout
        )

        assert response.status_code == 200
        data = response.json()
        assert data.get("status") == "healthy"

    def test_web_console_health(self, config, http_session, wait_for_services):
        """Web console is healthy in K8s"""
        if not wait_for_services.get("web_console"):
            pytest.skip("Web console not available in beta")

        response = http_session.get(
            f"{config.web_console_url}/health",
            timeout=config.request_timeout
        )

        assert response.status_code == 200
        data = response.json()
        assert data.get("status") == "healthy"

    def test_https_working(self, config, http_session):
        """HTTPS is properly configured"""
        # Beta should be using HTTPS
        if config.dns_server_url.startswith("https://"):
            response = http_session.get(
                f"{config.dns_server_url}/health",
                timeout=config.request_timeout
            )
            assert response.status_code == 200


@pytest.mark.beta
@pytest.mark.deployed
class TestBetaCorePages:
    """Verify core pages work when deployed"""

    def test_login_page_loads(self, config, http_session, wait_for_services):
        """Login page loads in K8s deployment"""
        if not wait_for_services.get("web_console"):
            pytest.skip("Web console not available")

        response = http_session.get(
            f"{config.web_console_url}/auth/login",
            timeout=config.request_timeout
        )

        assert response.status_code == 200

    def test_dashboard_accessible_when_authenticated(self, authenticated_client, wait_for_services):
        """Dashboard loads for authenticated users"""
        response = authenticated_client.get("/dashboard/")

        assert response.status_code == 200

    @pytest.mark.parametrize("path", [
        "/dashboard/queries",
        "/dashboard/ioc",
        "/dashboard/domains",
        "/dashboard/users"
    ])
    def test_core_dashboard_pages(self, authenticated_client, path):
        """Core dashboard pages load"""
        response = authenticated_client.get(path)

        assert response.status_code == 200


@pytest.mark.beta
@pytest.mark.deployed
class TestBetaCoreAPIs:
    """Verify core APIs work when deployed"""

    def test_dns_query_endpoint(self, config, http_session, wait_for_services):
        """DNS query endpoint works in K8s"""
        if not wait_for_services.get("dns_server"):
            pytest.skip("DNS server not available")

        response = http_session.get(
            f"{config.dns_server_url}/dns-query",
            params={"name": "google.com", "type": "A"},
            timeout=config.request_timeout
        )

        # Should work or require auth (not 500/404)
        assert response.status_code in [200, 401, 403]

    def test_queries_api(self, authenticated_client):
        """Queries API works when deployed"""
        response = authenticated_client.get("/api/queries")

        assert response.status_code == 200

    def test_ioc_feeds_api(self, authenticated_client):
        """IOC feeds API works when deployed"""
        response = authenticated_client.get("/api/ioc/feeds")

        assert response.status_code == 200

    def test_stats_api(self, authenticated_client):
        """Stats API works when deployed"""
        response = authenticated_client.get("/api/stats/summary")

        assert response.status_code == 200


@pytest.mark.beta
@pytest.mark.deployed
class TestBetaAuthentication:
    """Verify authentication works when deployed"""

    def test_login_flow(self, config, http_session, wait_for_services):
        """Login flow works in K8s deployment"""
        if not wait_for_services.get("web_console"):
            pytest.skip("Web console not available")

        if not config.admin_password:
            pytest.skip("Beta admin password not configured")

        # Get login page
        login_url = f"{config.web_console_url}/auth/login"
        http_session.get(login_url, timeout=config.request_timeout)

        # Login
        response = http_session.post(
            login_url,
            data={
                "email": config.admin_email,
                "password": config.admin_password
            },
            timeout=config.request_timeout,
            allow_redirects=False
        )

        # Should redirect to dashboard
        assert response.status_code in [200, 302, 303]

    def test_protected_routes_require_auth(self, config, http_session, wait_for_services):
        """Protected routes require authentication in K8s"""
        if not wait_for_services.get("web_console"):
            pytest.skip("Web console not available")

        # Use fresh session without auth
        new_session = requests.Session()
        new_session.verify = config.verify_ssl

        response = new_session.get(
            f"{config.web_console_url}/dashboard/",
            timeout=config.request_timeout,
            allow_redirects=False
        )

        # Should redirect to login or return 401
        assert response.status_code in [302, 303, 401]


@pytest.mark.beta
@pytest.mark.deployed
@pytest.mark.k8s
class TestBetaK8sSpecific:
    """Kubernetes-specific deployment tests"""

    def test_service_responds_consistently(self, config, http_session, wait_for_services):
        """Service responds consistently (pod health)"""
        if not wait_for_services.get("dns_server"):
            pytest.skip("DNS server not available")

        # Multiple requests to verify pod stability
        successes = 0
        for _ in range(5):
            try:
                response = http_session.get(
                    f"{config.dns_server_url}/health",
                    timeout=config.request_timeout
                )
                if response.status_code == 200:
                    successes += 1
            except requests.exceptions.RequestException:
                pass

        # At least 80% should succeed
        assert successes >= 4, f"Only {successes}/5 requests succeeded"

    def test_ingress_routing_works(self, config, http_session, wait_for_services):
        """Ingress routes requests correctly"""
        if not wait_for_services.get("web_console"):
            pytest.skip("Web console not available")

        # Verify both services are routed correctly
        dns_response = http_session.get(
            f"{config.dns_server_url}/health",
            timeout=config.request_timeout
        )

        web_response = http_session.get(
            f"{config.web_console_url}/health",
            timeout=config.request_timeout
        )

        # Both should be accessible
        assert dns_response.status_code == 200 or not wait_for_services.get("dns_server")
        assert web_response.status_code == 200


@pytest.mark.beta
@pytest.mark.deployed
class TestBetaResponseTimes:
    """Verify response times are acceptable in deployed environment"""

    def test_health_response_time(self, config, http_session, wait_for_services):
        """Health endpoint responds within acceptable time"""
        if not wait_for_services.get("dns_server"):
            pytest.skip("DNS server not available")

        import time
        start = time.time()
        response = http_session.get(
            f"{config.dns_server_url}/health",
            timeout=config.request_timeout
        )
        elapsed = time.time() - start

        assert response.status_code == 200
        # Allow more latency for K8s (network hops)
        assert elapsed < 3.0, f"Response took {elapsed:.2f}s (max 3s)"

    def test_page_load_time(self, authenticated_client, wait_for_services):
        """Pages load within acceptable time"""
        import time
        start = time.time()
        response = authenticated_client.get("/dashboard/")
        elapsed = time.time() - start

        assert response.status_code == 200
        # Allow more latency for K8s
        assert elapsed < 5.0, f"Page load took {elapsed:.2f}s (max 5s)"
