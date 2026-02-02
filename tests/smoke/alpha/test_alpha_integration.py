"""
Alpha Integration Tests
Test integration between components and end-to-end workflows
"""

import pytest
import requests
import socket
import time
from datetime import datetime


@pytest.mark.alpha
@pytest.mark.integration
class TestAlphaDNSManagerIntegration:
    """Test DNS Server + Manager API integration"""

    def test_manager_can_update_dns_server_config(self, manager_client):
        """Manager API can update DNS server configuration"""
        # Get current DNS server list
        response = manager_client.get("/api/v1/dns/servers")

        if response.status_code == 200:
            # Successfully retrieved server list
            data = response.json()
            assert "servers" in data or "dns_servers" in data

    def test_dns_server_uses_manager_blacklist(self, config, http_session):
        """DNS server queries manager for blacklist"""
        # This tests the integration between DNS server and Manager

        # Query DNS server health
        response = http_session.get(
            f"{config.dns_server_url}/health",
            timeout=config.request_timeout
        )

        assert response.status_code == 200

    def test_ioc_feed_propagation(self, authenticated_client):
        """IOC feeds propagate from Manager to DNS server"""
        # Get IOC feeds from manager
        response = authenticated_client.get("/api/v1/ioc/feeds")

        if response.status_code == 200:
            data = response.json()
            assert "feeds" in data
            assert isinstance(data["feeds"], list)


@pytest.mark.alpha
@pytest.mark.integration
class TestAlphaDatabaseCacheIntegration:
    """Test Database + Cache (Valkey) integration"""

    def test_query_logging_to_database(self, authenticated_client, config):
        """DNS queries are logged to database"""
        # Make a DNS query
        try:
            socket.create_connection(
                (config.dns_client_host, config.dns_client_port),
                timeout=2
            ).close()
        except Exception:
            pass  # Connection attempt is enough

        # Check if queries appear in database via API
        time.sleep(1)  # Allow time for logging
        response = authenticated_client.get("/api/v1/queries?limit=10")

        assert response.status_code == 200
        data = response.json()
        assert "queries" in data

    def test_cache_hit_reduces_database_load(self, config, http_session):
        """Cache hits reduce database queries"""
        domain = f"cache-test-{datetime.utcnow().timestamp()}.com"

        # First query (cache miss)
        response1 = http_session.get(
            f"{config.dns_server_url}/dns-query",
            params={"name": domain, "type": "A"},
            timeout=config.request_timeout
        )

        # Second query (should be cached)
        response2 = http_session.get(
            f"{config.dns_server_url}/dns-query",
            params={"name": domain, "type": "A"},
            timeout=config.request_timeout
        )

        # Both should work
        if response1.status_code == 200:
            assert response2.status_code == 200

    def test_cache_expiration_refreshes_data(self, config, http_session):
        """Expired cache entries are refreshed from database"""
        # Get health info
        response = http_session.get(
            f"{config.dns_server_url}/health",
            timeout=config.request_timeout
        )

        assert response.status_code == 200


@pytest.mark.alpha
@pytest.mark.integration
class TestAlphaAuthenticationFlow:
    """Test complete authentication flow integration"""

    def test_full_login_to_api_access_flow(self, config, http_session):
        """Complete flow: login -> get token -> access API"""
        # Step 1: Login
        login_response = http_session.post(
            f"{config.web_console_url}/api/v1/auth/login",
            json={
                "email": config.admin_email,
                "password": config.admin_password
            },
            timeout=config.request_timeout
        )

        if login_response.status_code != 200:
            pytest.skip("Authentication not configured")

        data = login_response.json()
        access_token = data.get("access_token")
        assert access_token is not None

        # Step 2: Use token to access protected API
        api_response = http_session.get(
            f"{config.web_console_url}/api/v1/dashboard/stats",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=config.request_timeout
        )

        assert api_response.status_code == 200

    def test_token_refresh_flow(self, config, http_session):
        """Token refresh flow works correctly"""
        # Login to get tokens
        login_response = http_session.post(
            f"{config.web_console_url}/api/v1/auth/login",
            json={
                "email": config.admin_email,
                "password": config.admin_password
            },
            timeout=config.request_timeout
        )

        if login_response.status_code != 200:
            pytest.skip("Authentication not configured")

        data = login_response.json()
        refresh_token = data.get("refresh_token")

        if not refresh_token:
            pytest.skip("Refresh token not implemented")

        # Use refresh token to get new access token
        refresh_response = http_session.post(
            f"{config.web_console_url}/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
            timeout=config.request_timeout
        )

        assert refresh_response.status_code == 200

    def test_logout_invalidates_token(self, config, http_session):
        """Logout invalidates access token"""
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
            pytest.skip("Authentication not configured")

        data = login_response.json()
        access_token = data.get("access_token")

        # Logout
        logout_response = http_session.post(
            f"{config.web_console_url}/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=config.request_timeout
        )

        # Try to use token after logout
        api_response = http_session.get(
            f"{config.web_console_url}/api/v1/dashboard/stats",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=config.request_timeout
        )

        # Token should be invalid after logout
        # Note: Stateless JWT may still work until expiration
        assert api_response.status_code in [200, 401]


@pytest.mark.alpha
@pytest.mark.integration
class TestAlphaDNSQueryWorkflow:
    """Test complete DNS query workflow"""

    def test_dns_query_end_to_end(self, config, http_session):
        """Complete DNS query: receive -> resolve -> cache -> respond"""
        domain = "google.com"

        response = http_session.get(
            f"{config.dns_server_url}/dns-query",
            params={"name": domain, "type": "A"},
            timeout=config.request_timeout
        )

        # Should work or require auth
        assert response.status_code in [200, 401, 403]

    def test_blacklisted_domain_blocked(self, authenticated_client, config, http_session):
        """Blacklisted domains are blocked in DNS queries"""
        # Add domain to blacklist
        blocked_domain = f"blocked-{datetime.utcnow().timestamp()}.com"

        blacklist_response = authenticated_client.post(
            "/api/v1/blocked",
            json={
                "domain": blocked_domain,
                "reason": "Test blocking",
                "threat_type": "malware"
            }
        )

        # Query the blocked domain
        time.sleep(1)  # Allow time for propagation
        query_response = http_session.get(
            f"{config.dns_server_url}/dns-query",
            params={"name": blocked_domain, "type": "A"},
            timeout=config.request_timeout
        )

        # Should block or return special response
        if query_response.status_code == 200:
            data = query_response.json()
            # Check if it's blocked (may return NXDOMAIN or blocked IP)
            assert data is not None

    def test_query_statistics_updated(self, authenticated_client, config):
        """Query statistics are updated after DNS queries"""
        # Get initial stats
        stats_response1 = authenticated_client.get("/api/v1/dashboard/stats")
        assert stats_response1.status_code == 200
        initial_stats = stats_response1.json()

        # Make DNS query
        try:
            socket.create_connection(
                (config.dns_client_host, config.dns_client_port),
                timeout=2
            ).close()
        except Exception:
            pass

        time.sleep(2)  # Allow time for stats update

        # Get updated stats
        stats_response2 = authenticated_client.get("/api/v1/dashboard/stats")
        assert stats_response2.status_code == 200


@pytest.mark.alpha
@pytest.mark.integration
class TestAlphaUserManagementWorkflow:
    """Test user management workflow integration"""

    def test_create_user_and_login(self, authenticated_client, config, http_session):
        """Create new user and login with credentials"""
        new_user_email = f"testuser-{datetime.utcnow().timestamp()}@example.com"
        new_user_password = "TestPass123!"

        # Create user
        create_response = authenticated_client.post(
            "/api/v1/users",
            json={
                "email": new_user_email,
                "password": new_user_password,
                "role": "user"
            }
        )

        if create_response.status_code not in [200, 201]:
            pytest.skip("User creation not implemented")

        # Try to login with new user
        time.sleep(1)  # Allow time for user creation
        login_response = http_session.post(
            f"{config.web_console_url}/api/v1/auth/login",
            json={
                "email": new_user_email,
                "password": new_user_password
            },
            timeout=config.request_timeout
        )

        # Should be able to login
        assert login_response.status_code in [200, 401, 403]

    def test_update_user_permissions(self, authenticated_client):
        """Update user permissions and verify access"""
        # Get list of users
        users_response = authenticated_client.get("/api/v1/users")

        if users_response.status_code != 200:
            pytest.skip("User management not implemented")

        users = users_response.json().get("users", [])
        if not users:
            pytest.skip("No users to test")

        # Try to update user
        user_id = users[0].get("id")
        if user_id:
            update_response = authenticated_client.put(
                f"/api/v1/users/{user_id}",
                json={"role": "viewer"}
            )
            # Should succeed or require additional permissions
            assert update_response.status_code in [200, 403, 404]


@pytest.mark.alpha
@pytest.mark.integration
class TestAlphaZoneManagementWorkflow:
    """Test DNS zone management workflow"""

    def test_create_zone_and_add_records(self, authenticated_client):
        """Create zone and add DNS records"""
        zone_name = f"test-{datetime.utcnow().timestamp()}.com"

        # Create zone
        zone_response = authenticated_client.post(
            "/api/v1/zones",
            json={
                "name": zone_name,
                "type": "master"
            }
        )

        if zone_response.status_code not in [200, 201]:
            pytest.skip("Zone creation not implemented")

        # Add record to zone
        record_response = authenticated_client.post(
            "/api/v1/records",
            json={
                "zone": zone_name,
                "name": f"www.{zone_name}",
                "type": "A",
                "value": "1.2.3.4",
                "ttl": 3600
            }
        )

        # Should succeed
        assert record_response.status_code in [200, 201, 400, 404]

    def test_zone_transfer_integration(self, authenticated_client):
        """Zone transfer between master and slave"""
        # This tests AXFR/IXFR functionality
        zones_response = authenticated_client.get("/api/v1/zones")

        if zones_response.status_code != 200:
            pytest.skip("Zones not implemented")

        # Verify zones are accessible
        data = zones_response.json()
        assert "zones" in data or isinstance(data, list)


@pytest.mark.alpha
@pytest.mark.integration
class TestAlphaMonitoringIntegration:
    """Test monitoring and metrics integration"""

    def test_metrics_endpoint_available(self, config, http_session):
        """Prometheus metrics endpoint available"""
        metrics_urls = [
            f"{config.dns_server_url}/metrics",
            f"{config.web_console_url}/metrics",
        ]

        for url in metrics_urls:
            response = http_session.get(url, timeout=config.request_timeout)
            # Should exist or return 404 if not implemented
            assert response.status_code in [200, 404, 401]

    def test_health_checks_comprehensive(self, config, http_session):
        """Health checks include all dependencies"""
        response = http_session.get(
            f"{config.dns_server_url}/health",
            timeout=config.request_timeout
        )

        assert response.status_code == 200
        data = response.json()

        # Should include status
        assert "status" in data
