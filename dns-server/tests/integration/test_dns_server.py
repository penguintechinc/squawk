"""
DNS Server Test Suite
Tests DNS query handling, caching, IOC blocking, and resilience.
"""

import pytest
import requests
import time

DNS_SERVER_URL = "http://localhost:8080"
MANAGER_URL = "http://localhost:5000"


class TestDNSServer:
    """Test suite for DNS Server."""

    @classmethod
    def setup_class(cls):
        """Setup: Register DNS server with Manager."""
        # Login to Manager
        try:
            login_response = requests.post(
                f"{MANAGER_URL}/api/v1/auth/login",
                json={"username": "admin", "password": "admin123"},
                timeout=5,
            )
            if login_response.status_code == 200:
                cls.admin_token = login_response.json()["accessToken"]

                # Create DNS server in Manager
                server_response = requests.post(
                    f"{MANAGER_URL}/api/v1/dns-servers",
                    headers={"Authorization": f"Bearer {cls.admin_token}"},
                    json={"name": "test-server", "region": "test"},
                    timeout=5,
                )
                if server_response.status_code == 201:
                    cls.join_key = server_response.json()["joinKey"]
                    cls.manager_available = True
                else:
                    cls.manager_available = False
            else:
                cls.manager_available = False

        except Exception as e:
            print(f"Manager not available: {e}")
            cls.manager_available = False

        # Wait for DNS server to start
        time.sleep(2)

    def test_health_check(self):
        """Test DNS server health endpoint."""
        response = requests.get(f"{DNS_SERVER_URL}/health", timeout=5)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "mode" in data
        assert "registered" in data

    def test_dns_query_public(self):
        """Test public DNS query (google.com)."""
        response = requests.get(
            f"{DNS_SERVER_URL}/dns/query",
            params={"name": "google.com", "type": "A"},
            timeout=10,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["Status"] == 0  # NOERROR
        assert "Question" in data
        assert "Answer" in data
        assert len(data["Answer"]) > 0

    def test_dns_query_with_token(self):
        """Test DNS query with authentication token."""
        if not self.manager_available:
            pytest.skip("Manager not available")

        # Create token in Manager
        token_response = requests.post(
            f"{MANAGER_URL}/api/v1/tokens",
            headers={"Authorization": f"Bearer {self.admin_token}"},
            json={"name": "test-token"},
            timeout=5,
        )

        if token_response.status_code == 201:
            token = token_response.json()["token"]

            # Query DNS with token
            response = requests.get(
                f"{DNS_SERVER_URL}/dns/query",
                params={"name": "example.com", "type": "A"},
                headers={"Authorization": f"Bearer {token}"},
                timeout=10,
            )

            assert response.status_code == 200
            data = response.json()
            assert "Status" in data

    def test_dns_query_private_zone_authorized(self):
        """Test private zone query with authorized token."""
        if not self.manager_available:
            pytest.skip("Manager not available")

        # Create private zone
        zone_response = requests.post(
            f"{MANAGER_URL}/api/v1/zones",
            headers={"Authorization": f"Bearer {self.admin_token}"},
            json={
                "name": f"internal-{int(time.time())}.company.com",
                "visibility": "internal",
            },
            timeout=5,
        )

        if zone_response.status_code == 201:
            zone = zone_response.json()
            zone_id = zone["id"]

            # Create record
            record_response = requests.post(
                f"{MANAGER_URL}/api/v1/zones/{zone_id}/records",
                headers={"Authorization": f"Bearer {self.admin_token}"},
                json={
                    "name": f"server.{zone['name']}",
                    "type": "A",
                    "value": "10.0.0.1",
                    "ttl": 300,
                },
                timeout=5,
            )

            # Wait for DNS server to sync
            time.sleep(6)

            # Create authorized token
            token_response = requests.post(
                f"{MANAGER_URL}/api/v1/tokens",
                headers={"Authorization": f"Bearer {self.admin_token}"},
                json={"name": "internal-token", "visibility": "internal"},
                timeout=5,
            )

            if token_response.status_code == 201:
                token = token_response.json()["token"]

                # Query with authorized token
                response = requests.get(
                    f"{DNS_SERVER_URL}/dns/query",
                    params={"name": f"server.{zone['name']}", "type": "A"},
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=10,
                )

                assert response.status_code == 200

    def test_dns_query_private_zone_unauthorized(self):
        """Test private zone query without authorization."""
        # Query internal domain without token
        response = requests.get(
            f"{DNS_SERVER_URL}/dns/query",
            params={"name": "server.internal.company.com", "type": "A"},
            timeout=10,
        )

        assert response.status_code == 200
        data = response.json()
        # Should return NXDOMAIN (3) for unauthorized access
        assert data["Status"] in [2, 3]

    def test_ioc_blocking(self):
        """Test IOC domain blocking."""
        if not self.manager_available:
            pytest.skip("Manager not available")

        # Add IOC entry
        ioc_response = requests.post(
            f"{MANAGER_URL}/api/v1/ioc-feeds",
            headers={"Authorization": f"Bearer {self.admin_token}"},
            json={"name": "test-ioc", "type": "domain", "value": "malicious-test.com"},
            timeout=5,
        )

        # Wait for sync
        time.sleep(6)

        # Query blocked domain
        response = requests.get(
            f"{DNS_SERVER_URL}/dns/query",
            params={"name": "malicious-test.com", "type": "A"},
            timeout=10,
        )

        assert response.status_code == 200
        data = response.json()
        # Should be blocked (NXDOMAIN)
        assert data["Status"] == 3

    def test_cache_hit(self):
        """Test cache hit on repeated query."""
        domain = f"cache-test-{int(time.time())}.example.com"

        # First query
        response1 = requests.get(
            f"{DNS_SERVER_URL}/dns/query",
            params={"name": domain, "type": "A"},
            timeout=10,
        )
        assert response1.status_code == 200

        # Second query (should hit cache)
        response2 = requests.get(
            f"{DNS_SERVER_URL}/dns/query",
            params={"name": domain, "type": "A"},
            timeout=10,
        )
        assert response2.status_code == 200

        # Responses should be consistent
        assert response1.json()["Status"] == response2.json()["Status"]

    def test_metrics_endpoint(self):
        """Test Prometheus metrics endpoint."""
        response = requests.get(f"{DNS_SERVER_URL}/metrics", timeout=5)
        assert response.status_code == 200
        text = response.text

        # Check for key metrics
        assert "dns_queries_total" in text
        assert "dns_cache_hits" in text
        assert "dns_cache_misses" in text

    def test_status_endpoint(self):
        """Test detailed status endpoint."""
        response = requests.get(f"{DNS_SERVER_URL}/status", timeout=5)
        assert response.status_code == 200
        data = response.json()

        assert "resilience" in data
        assert "metrics" in data
        assert "cache" in data
        assert "ioc" in data
        assert "routing" in data

        # Check resilience status
        assert "mode" in data["resilience"]
        assert data["resilience"]["mode"] in ["normal", "cached", "degraded"]

    def test_resilience_degraded_mode(self):
        """Test DNS server resilience when Manager is down."""
        # Even if Manager is down, DNS server should serve public queries
        response = requests.get(
            f"{DNS_SERVER_URL}/dns/query",
            params={"name": "google.com", "type": "A"},
            timeout=10,
        )

        # Should still work
        assert response.status_code == 200
        data = response.json()
        # Should either resolve or fail gracefully
        assert data["Status"] in [0, 2, 3]

    def test_multiple_record_types(self):
        """Test different DNS record types."""
        record_types = ["A", "AAAA", "MX", "TXT"]

        for record_type in record_types:
            response = requests.get(
                f"{DNS_SERVER_URL}/dns/query",
                params={"name": "google.com", "type": record_type},
                timeout=10,
            )

            assert response.status_code == 200
            data = response.json()
            assert "Status" in data
            assert "Question" in data


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
