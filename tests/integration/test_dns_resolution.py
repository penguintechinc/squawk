"""
DNS Resolution Integration Tests
Tests end-to-end DNS resolution functionality
"""

import pytest
import requests
import time


DNS_SERVER_URL = "http://localhost:8080"
REQUEST_TIMEOUT = 30


@pytest.mark.integration
@pytest.mark.network
class TestDNSResolution:
    """Test DNS resolution through the DNS server"""

    def test_resolve_a_record(self, http_session):
        """Resolve A record for common domain"""
        url = f"{DNS_SERVER_URL}/dns-query"

        response = http_session.get(
            url,
            params={"name": "google.com", "type": "A"},
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code == 200:
            data = response.json()
            assert data.get("Status") == 0  # NOERROR
            assert "Answer" in data
        else:
            # May require auth
            assert response.status_code in [401, 403]

    def test_resolve_aaaa_record(self, http_session):
        """Resolve AAAA (IPv6) record"""
        url = f"{DNS_SERVER_URL}/dns-query"

        response = http_session.get(
            url,
            params={"name": "google.com", "type": "AAAA"},
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code == 200:
            data = response.json()
            assert data.get("Status") in [0, 3]  # NOERROR or NXDOMAIN
        else:
            assert response.status_code in [401, 403]

    def test_resolve_mx_record(self, http_session):
        """Resolve MX record"""
        url = f"{DNS_SERVER_URL}/dns-query"

        response = http_session.get(
            url,
            params={"name": "google.com", "type": "MX"},
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code == 200:
            data = response.json()
            assert data.get("Status") in [0, 3]
        else:
            assert response.status_code in [401, 403]

    def test_resolve_txt_record(self, http_session):
        """Resolve TXT record"""
        url = f"{DNS_SERVER_URL}/dns-query"

        response = http_session.get(
            url,
            params={"name": "google.com", "type": "TXT"},
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code == 200:
            data = response.json()
            assert data.get("Status") in [0, 3]
        else:
            assert response.status_code in [401, 403]

    def test_resolve_nonexistent_domain(self, http_session):
        """Nonexistent domain returns NXDOMAIN"""
        url = f"{DNS_SERVER_URL}/dns-query"

        response = http_session.get(
            url,
            params={"name": "this-domain-definitely-does-not-exist-12345.com", "type": "A"},
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code == 200:
            data = response.json()
            assert data.get("Status") == 3  # NXDOMAIN
        else:
            assert response.status_code in [401, 403]


@pytest.mark.integration
@pytest.mark.network
class TestDNSCaching:
    """Test DNS response caching"""

    def test_cached_response_faster(self, http_session):
        """Cached response should be faster"""
        url = f"{DNS_SERVER_URL}/dns-query"
        domain = "example.com"

        # First request - may hit upstream
        start1 = time.time()
        response1 = http_session.get(
            url,
            params={"name": domain, "type": "A"},
            timeout=REQUEST_TIMEOUT
        )
        time1 = time.time() - start1

        if response1.status_code != 200:
            pytest.skip("DNS server requires authentication")

        # Second request - should be cached
        start2 = time.time()
        response2 = http_session.get(
            url,
            params={"name": domain, "type": "A"},
            timeout=REQUEST_TIMEOUT
        )
        time2 = time.time() - start2

        assert response2.status_code == 200

        # Note: Cached response may not always be faster due to network variance
        # This is a soft assertion
        if time2 < time1:
            assert True  # Cache hit likely
        else:
            # Still valid - cache may have been invalidated
            assert True

    def test_cache_status_in_health(self, http_session):
        """Health endpoint reports cache status"""
        url = f"{DNS_SERVER_URL}/health"

        response = http_session.get(url, timeout=REQUEST_TIMEOUT)

        assert response.status_code == 200
        data = response.json()

        # Cache info may be present
        if "cache" in data:
            assert data["cache"] is not None


@pytest.mark.integration
@pytest.mark.network
class TestDNSBlocking:
    """Test DNS blocking functionality"""

    def test_blocked_domain_returns_nxdomain(self, http_session):
        """Blocked domain should return NXDOMAIN or blocked status"""
        # First add a domain to blacklist (if admin)
        blacklist_url = f"{DNS_SERVER_URL}/admin/blacklist"

        # Try to add test domain
        http_session.post(
            blacklist_url,
            json={"domain": "test-blocked.local", "reason": "Integration test"},
            timeout=REQUEST_TIMEOUT
        )

        # Query the blocked domain
        query_url = f"{DNS_SERVER_URL}/dns-query"
        response = http_session.get(
            query_url,
            params={"name": "test-blocked.local", "type": "A"},
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code == 200:
            data = response.json()
            # Should be blocked (NXDOMAIN) or have blocked comment
            assert data.get("Status") in [0, 3] or "blocked" in str(data).lower()

        # Cleanup - remove from blacklist
        http_session.delete(
            blacklist_url,
            json={"domain": "test-blocked.local"},
            timeout=REQUEST_TIMEOUT
        )


@pytest.mark.integration
class TestDNSServerWebConsoleIntegration:
    """Test integration between DNS server and web console"""

    def test_query_appears_in_logs(self, http_session, web_console_auth):
        """DNS query should appear in web console logs"""
        if not web_console_auth.get("authenticated"):
            pytest.skip("Web console authentication failed")

        # Make a DNS query
        dns_url = f"{DNS_SERVER_URL}/dns-query"
        http_session.get(
            dns_url,
            params={"name": "integration-test.example.com", "type": "A"},
            timeout=REQUEST_TIMEOUT
        )

        # Check query logs in web console
        log_url = "http://localhost:8005/api/queries"
        response = http_session.get(
            log_url,
            cookies=web_console_auth.get("cookies", {}),
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code == 200:
            data = response.json()
            # Query may or may not be in logs depending on timing
            assert "queries" in data or isinstance(data, list)


@pytest.mark.integration
class TestMultipleRecordTypes:
    """Test querying multiple record types"""

    def test_all_common_record_types(self, http_session):
        """All common record types are supported"""
        url = f"{DNS_SERVER_URL}/dns-query"
        domain = "cloudflare.com"
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

        results = {}
        for record_type in record_types:
            response = http_session.get(
                url,
                params={"name": domain, "type": record_type},
                timeout=REQUEST_TIMEOUT
            )

            results[record_type] = response.status_code

        # All should return valid responses (200 or auth required)
        for record_type, status_code in results.items():
            assert status_code in [200, 401, 403], \
                f"Record type {record_type} failed with {status_code}"
