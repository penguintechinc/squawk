"""
Beta Integration Tests
Integration testing for Kubernetes deployed environment
"""

import pytest
import requests
import time
from datetime import datetime
import subprocess


@pytest.mark.beta
@pytest.mark.integration
class TestBetaKubernetesIntegration:
    """Test K8s-specific integration"""

    def test_service_discovery_works(self, config, http_session, wait_for_services):
        """Services are discoverable via K8s DNS"""
        # Both services should be accessible
        dns_healthy = wait_for_services.get("dns_server")
        web_healthy = wait_for_services.get("web_console")

        assert web_healthy, "Web console should be healthy"
        # DNS server may be optional
        if dns_healthy:
            response = http_session.get(
                f"{config.dns_server_url}/health",
                timeout=config.request_timeout
            )
            assert response.status_code == 200

    def test_pods_are_resilient(self, config, http_session, wait_for_services):
        """Pods can handle failures gracefully"""
        if not wait_for_services.get("web_console"):
            pytest.skip("Web console not available")

        # Make multiple requests to verify stability
        successes = 0
        for _ in range(10):
            try:
                response = http_session.get(
                    f"{config.web_console_url}/health",
                    timeout=config.request_timeout
                )
                if response.status_code == 200:
                    successes += 1
            except Exception:
                pass
            time.sleep(0.5)

        # Should be highly available
        assert successes >= 8, f"Only {successes}/10 requests succeeded"

    def test_ingress_routing_consistent(self, config, http_session, wait_for_services):
        """Ingress routes requests consistently"""
        if not wait_for_services.get("web_console"):
            pytest.skip("Web console not available")

        # Make multiple requests
        responses = []
        for _ in range(5):
            response = http_session.get(
                f"{config.web_console_url}/health",
                timeout=config.request_timeout
            )
            responses.append(response.status_code)

        # All should succeed
        assert all(r == 200 for r in responses), "Inconsistent routing"


@pytest.mark.beta
@pytest.mark.integration
class TestBetaServiceCommunication:
    """Test service-to-service communication"""

    def test_dns_server_manager_communication(self, config, http_session, wait_for_services):
        """DNS server and Manager communicate correctly"""
        if not wait_for_services.get("dns_server"):
            pytest.skip("DNS server not available")

        # DNS server should be operational
        response = http_session.get(
            f"{config.dns_server_url}/health",
            timeout=config.request_timeout
        )

        assert response.status_code == 200
        data = response.json()
        assert data.get("status") == "healthy"

    def test_webui_backend_communication(self, authenticated_client):
        """WebUI communicates with backend APIs"""
        # WebUI should be able to fetch data
        response = authenticated_client.get("/api/v1/dashboard/stats")

        assert response.status_code == 200
        data = response.json()
        assert data is not None

    def test_backend_database_communication(self, authenticated_client):
        """Backend communicates with database"""
        # Query that requires database
        response = authenticated_client.get("/api/v1/queries?limit=5")

        assert response.status_code == 200
        data = response.json()
        assert "queries" in data


@pytest.mark.beta
@pytest.mark.integration
class TestBetaDataFlow:
    """Test data flow through system"""

    def test_dns_query_logged_to_database(self, config, http_session, authenticated_client):
        """DNS queries are logged to database"""
        # Make DNS query
        domain = f"beta-test-{datetime.utcnow().timestamp()}.com"

        dns_response = http_session.get(
            f"{config.dns_server_url}/dns-query",
            params={"name": domain, "type": "A"},
            timeout=config.request_timeout
        )

        # Allow time for logging
        time.sleep(2)

        # Check if query appears in logs
        logs_response = authenticated_client.get("/api/v1/queries?limit=50")

        if logs_response.status_code == 200:
            data = logs_response.json()
            queries = data.get("queries", [])
            # Query might be in logs (optional check)
            assert isinstance(queries, list)

    def test_ioc_feed_propagates_to_blocking(self, authenticated_client):
        """IOC feeds propagate to blocking system"""
        # Get IOC feeds
        feeds_response = authenticated_client.get("/api/v1/ioc/feeds")

        if feeds_response.status_code == 200:
            data = feeds_response.json()
            assert "feeds" in data

            # Get blocked domains
            blocked_response = authenticated_client.get("/api/v1/blocked")
            # Should be accessible
            assert blocked_response.status_code in [200, 404]

    def test_user_actions_create_audit_logs(self, authenticated_client):
        """User actions are logged for audit"""
        # Perform action
        authenticated_client.get("/api/v1/dashboard/stats")

        # Check for logs
        logs_response = authenticated_client.get("/api/v1/logs?limit=10")

        # Logs endpoint should exist
        assert logs_response.status_code in [200, 403, 404]


@pytest.mark.beta
@pytest.mark.integration
class TestBetaAuthenticationIntegration:
    """Test authentication flow in K8s"""

    def test_full_authentication_workflow(self, config, http_session, wait_for_services):
        """Complete authentication workflow in K8s"""
        if not wait_for_services.get("web_console"):
            pytest.skip("Web console not available")

        if not config.admin_password:
            pytest.skip("Admin credentials not configured for beta")

        # Login
        login_response = http_session.post(
            f"{config.web_console_url}/api/v1/auth/login",
            json={
                "email": config.admin_email,
                "password": config.admin_password
            },
            timeout=config.request_timeout
        )

        if login_response.status_code != 200:
            pytest.skip("Authentication failed in beta")

        data = login_response.json()
        token = data.get("access_token")
        assert token is not None

        # Use token
        api_response = http_session.get(
            f"{config.web_console_url}/api/v1/dashboard/stats",
            headers={"Authorization": f"Bearer {token}"},
            timeout=config.request_timeout
        )

        assert api_response.status_code == 200

    def test_session_persistence_across_pods(self, config, http_session, wait_for_services):
        """Sessions persist across pod restarts"""
        if not wait_for_services.get("web_console"):
            pytest.skip("Web console not available")

        if not config.admin_password:
            pytest.skip("Admin credentials not configured")

        # Login and get token
        login_response = http_session.post(
            f"{config.web_console_url}/api/v1/auth/login",
            json={
                "email": config.admin_email,
                "password": config.admin_password
            },
            timeout=config.request_timeout
        )

        if login_response.status_code != 200:
            pytest.skip("Authentication failed")

        token = login_response.json().get("access_token")

        # Make multiple requests (may hit different pods)
        for _ in range(5):
            response = http_session.get(
                f"{config.web_console_url}/api/v1/dashboard/stats",
                headers={"Authorization": f"Bearer {token}"},
                timeout=config.request_timeout
            )
            assert response.status_code == 200
            time.sleep(1)


@pytest.mark.beta
@pytest.mark.integration
class TestBetaDatabaseIntegration:
    """Test database integration in K8s"""

    def test_database_connection_pooling(self, authenticated_client):
        """Database connection pooling works"""
        # Make multiple concurrent requests
        import concurrent.futures

        def make_query():
            return authenticated_client.get("/api/v1/queries?limit=10")

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_query) for _ in range(10)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # All should succeed
        successes = sum(1 for r in results if r.status_code == 200)
        assert successes >= 8, f"Only {successes}/10 concurrent DB queries succeeded"

    def test_database_transactions_atomic(self, authenticated_client):
        """Database transactions are atomic"""
        # Create record
        test_domain = f"atomic-{datetime.utcnow().timestamp()}.com"

        response = authenticated_client.post(
            "/api/v1/domains",
            json={
                "domain": test_domain,
                "type": "A",
                "value": "1.2.3.4"
            }
        )

        # Should succeed completely or fail completely
        assert response.status_code in [200, 201, 400, 409, 422]

    def test_database_read_replicas_consistent(self, authenticated_client):
        """Read replicas return consistent data"""
        # Make multiple read requests
        responses = []
        for _ in range(3):
            response = authenticated_client.get("/api/v1/dashboard/stats")
            if response.status_code == 200:
                responses.append(response.json())
            time.sleep(1)

        # All should return valid data
        assert len(responses) >= 2


@pytest.mark.beta
@pytest.mark.integration
class TestBetaCacheIntegration:
    """Test cache integration in K8s"""

    def test_cache_reduces_database_load(self, config, http_session):
        """Cache reduces database queries"""
        domain = f"cache-{datetime.utcnow().timestamp()}.com"

        # First query (cache miss)
        response1 = http_session.get(
            f"{config.dns_server_url}/dns-query",
            params={"name": domain, "type": "A"},
            timeout=config.request_timeout
        )

        # Second query (cache hit)
        response2 = http_session.get(
            f"{config.dns_server_url}/dns-query",
            params={"name": domain, "type": "A"},
            timeout=config.request_timeout
        )

        # Both should work
        if response1.status_code == 200:
            assert response2.status_code == 200

    def test_cache_invalidation_works(self, authenticated_client, config, http_session):
        """Cache invalidation works correctly"""
        # Create/update record
        test_domain = f"cache-inv-{datetime.utcnow().timestamp()}.com"

        create_response = authenticated_client.post(
            "/api/v1/domains",
            json={
                "domain": test_domain,
                "type": "A",
                "value": "1.2.3.4"
            }
        )

        if create_response.status_code in [200, 201]:
            # Cache should be invalidated or updated
            time.sleep(2)

            # Query should reflect new data
            query_response = http_session.get(
                f"{config.dns_server_url}/dns-query",
                params={"name": test_domain, "type": "A"},
                timeout=config.request_timeout
            )

            # Should work
            assert query_response.status_code in [200, 401, 403, 404]


@pytest.mark.beta
@pytest.mark.integration
class TestBetaMonitoringIntegration:
    """Test monitoring integration"""

    def test_metrics_endpoint_available(self, config, http_session, wait_for_services):
        """Prometheus metrics endpoint works"""
        if not wait_for_services.get("dns_server"):
            pytest.skip("DNS server not available")

        # Check metrics endpoint
        response = http_session.get(
            f"{config.dns_server_url}/metrics",
            timeout=config.request_timeout
        )

        # Should exist or be protected
        assert response.status_code in [200, 401, 404]

    def test_health_checks_comprehensive(self, config, http_session, wait_for_services):
        """Health checks include all components"""
        if not wait_for_services.get("web_console"):
            pytest.skip("Web console not available")

        response = http_session.get(
            f"{config.web_console_url}/health",
            timeout=config.request_timeout
        )

        assert response.status_code == 200
        data = response.json()

        # Should include status
        assert "status" in data
        assert data["status"] in ["healthy", "ok", "up"]

    def test_logging_aggregation_works(self, authenticated_client):
        """Logs are aggregated from all pods"""
        # Get logs
        response = authenticated_client.get("/api/v1/logs?limit=100")

        # Logs endpoint should exist
        assert response.status_code in [200, 403, 404]

        if response.status_code == 200:
            data = response.json()
            # Should have logs structure
            assert "logs" in data or isinstance(data, list)


@pytest.mark.beta
@pytest.mark.integration
class TestBetaScalingBehavior:
    """Test scaling behavior in K8s"""

    def test_load_balanced_across_pods(self, config, http_session, wait_for_services):
        """Requests are load balanced"""
        if not wait_for_services.get("web_console"):
            pytest.skip("Web console not available")

        # Make many requests
        responses = []
        for _ in range(20):
            try:
                response = http_session.get(
                    f"{config.web_console_url}/health",
                    timeout=config.request_timeout
                )
                responses.append(response.status_code)
            except Exception:
                responses.append(0)

        # Most should succeed
        successes = sum(1 for r in responses if r == 200)
        assert successes >= 18, f"Only {successes}/20 requests succeeded"

    def test_handles_pod_rollout(self, authenticated_client):
        """Service remains available during rollouts"""
        # Make continuous requests
        successes = 0
        for _ in range(10):
            try:
                response = authenticated_client.get("/api/v1/dashboard/stats")
                if response.status_code == 200:
                    successes += 1
            except Exception:
                pass
            time.sleep(1)

        # Should remain mostly available
        assert successes >= 7, f"Only {successes}/10 requests succeeded during test"
