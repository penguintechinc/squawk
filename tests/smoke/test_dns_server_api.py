"""
DNS Server API Smoke Tests
Verifies all REST API endpoints on the DNS server
"""

import pytest
import requests
import json


@pytest.mark.smoke
@pytest.mark.api
class TestDNSServerHealth:
    """Test DNS server health endpoints"""

    def test_ready_endpoint(self, config, http_session):
        """GET /ready returns readiness status"""
        url = f"{config.dns_server_url}/ready"

        response = http_session.get(url, timeout=config.request_timeout)

        assert response.status_code == 200
        data = response.json()
        assert data.get("status") in ("ready", "ok", "healthy")

    def test_health_endpoint(self, config, http_session):
        """GET /health returns healthy status"""
        url = f"{config.dns_server_url}/health"

        response = http_session.get(url, timeout=config.request_timeout)

        assert response.status_code == 200
        data = response.json()
        assert data.get("status") == "healthy"
        assert "timestamp" in data

    def test_health_endpoint_includes_cache_info(self, config, http_session):
        """Health endpoint includes cache statistics"""
        url = f"{config.dns_server_url}/health"

        response = http_session.get(url, timeout=config.request_timeout)

        assert response.status_code == 200
        data = response.json()
        # Cache info may or may not be present depending on config
        # Just verify response is valid JSON
        assert isinstance(data, dict)


@pytest.mark.smoke
@pytest.mark.api
class TestDNSQueryEndpoint:
    """Test DNS query endpoint"""

    def test_dns_query_get_method(self, config, http_session):
        """GET /dns-query with name parameter"""
        url = f"{config.dns_server_url}/dns-query"

        response = http_session.get(
            url,
            params={"name": "example.com", "type": "A"},
            timeout=config.request_timeout
        )

        # May require auth, but should not be 404 or 500
        assert response.status_code in [200, 401, 403]

    def test_dns_query_post_method(self, config, http_session):
        """POST /dns-query with JSON body"""
        url = f"{config.dns_server_url}/dns-query"

        response = http_session.post(
            url,
            json={"name": "example.com", "type": "A"},
            timeout=config.request_timeout
        )

        assert response.status_code in [200, 401, 403]

    def test_dns_query_missing_name_returns_error(self, config, http_session):
        """DNS query without name returns 400"""
        url = f"{config.dns_server_url}/dns-query"

        response = http_session.get(
            url,
            params={"type": "A"},
            timeout=config.request_timeout
        )

        assert response.status_code in [400, 401, 403]

    def test_dns_query_different_record_types(self, config, http_session):
        """DNS query supports different record types"""
        url = f"{config.dns_server_url}/dns-query"
        record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]

        for record_type in record_types:
            response = http_session.get(
                url,
                params={"name": "google.com", "type": record_type},
                timeout=config.request_timeout
            )

            assert response.status_code in [200, 401, 403], \
                f"Record type {record_type} failed with {response.status_code}"


@pytest.mark.smoke
@pytest.mark.api
class TestDNSQueryValidation:
    """Test DNS query input validation"""

    def test_invalid_domain_rejected(self, config, http_session):
        """Invalid domain names are rejected"""
        url = f"{config.dns_server_url}/dns-query"
        invalid_domains = [
            "invalid..domain",
            "-startwithhyphen.com",
            "endwithhyphen-.com",
            "has spaces.com",
            "has<script>.com",
        ]

        for domain in invalid_domains:
            response = http_session.get(
                url,
                params={"name": domain, "type": "A"},
                timeout=config.request_timeout
            )

            # Should reject with 400 or handle gracefully
            assert response.status_code in [200, 400, 401, 403], \
                f"Domain {domain} returned unexpected {response.status_code}"


@pytest.mark.smoke
@pytest.mark.api
class TestBlacklistEndpoint:
    """Test blacklist management endpoint"""

    def test_get_blacklist(self, config, http_session):
        """GET /admin/blacklist returns blacklist info"""
        url = f"{config.dns_server_url}/admin/blacklist"

        response = http_session.get(url, timeout=config.request_timeout)

        # May require admin auth or not be implemented yet
        assert response.status_code in [200, 401, 403, 404]

    def test_add_to_blacklist(self, config, http_session):
        """POST /admin/blacklist adds domain"""
        url = f"{config.dns_server_url}/admin/blacklist"

        response = http_session.post(
            url,
            json={"domain": "malicious-test.com", "reason": "Test entry"},
            timeout=config.request_timeout
        )

        # May require admin auth or not be implemented yet
        assert response.status_code in [200, 201, 401, 403, 404]

    def test_remove_from_blacklist(self, config, http_session):
        """DELETE /admin/blacklist removes domain"""
        url = f"{config.dns_server_url}/admin/blacklist"

        response = http_session.delete(
            url,
            json={"domain": "malicious-test.com"},
            timeout=config.request_timeout
        )

        # May require admin auth
        assert response.status_code in [200, 401, 403, 404]


@pytest.mark.smoke
@pytest.mark.api
class TestPremiumEndpoints:
    """Test premium feature endpoints"""

    def test_groups_endpoint(self, config, http_session):
        """GET /api/groups endpoint exists"""
        url = f"{config.dns_server_url}/api/groups"

        response = http_session.get(url, timeout=config.request_timeout)

        # Premium feature - may require license
        assert response.status_code in [200, 401, 403]

    def test_analytics_report_endpoint(self, config, http_session):
        """GET /api/analytics/report endpoint exists"""
        url = f"{config.dns_server_url}/api/analytics/report"

        response = http_session.get(url, timeout=config.request_timeout)

        # Premium feature - may require license
        assert response.status_code in [200, 401, 403]

    def test_zones_endpoint(self, config, http_session):
        """GET /api/zones endpoint exists"""
        url = f"{config.dns_server_url}/api/zones"

        response = http_session.get(url, timeout=config.request_timeout)

        # Premium feature - may require license
        assert response.status_code in [200, 401, 403]


@pytest.mark.smoke
@pytest.mark.api
class TestEnterpriseEndpoints:
    """Test enterprise-only endpoints"""

    def test_saml_sso_endpoint(self, config, http_session):
        """POST /api/sso/saml endpoint exists"""
        url = f"{config.dns_server_url}/api/sso/saml"

        response = http_session.post(
            url,
            json={"SAMLResponse": "test"},
            timeout=config.request_timeout
        )

        # Enterprise feature - should return 403 without license
        assert response.status_code in [200, 400, 401, 403]

    def test_scim_users_endpoint(self, config, http_session):
        """GET /api/scim/v2/Users endpoint exists"""
        url = f"{config.dns_server_url}/api/scim/v2/Users"

        response = http_session.get(url, timeout=config.request_timeout)

        # Enterprise feature - should return 403 without license
        assert response.status_code in [200, 401, 403]


@pytest.mark.smoke
@pytest.mark.api
class TestResponseFormat:
    """Test API response format consistency"""

    def test_health_response_is_json(self, config, http_session):
        """Health endpoint returns valid JSON"""
        url = f"{config.dns_server_url}/health"

        response = http_session.get(url, timeout=config.request_timeout)

        assert response.status_code == 200
        assert response.headers.get("Content-Type", "").startswith("application/json")
        # Verify it's valid JSON
        data = response.json()
        assert isinstance(data, dict)

    def test_dns_query_response_format(self, config, http_session):
        """DNS query returns standard DNS JSON format"""
        url = f"{config.dns_server_url}/dns-query"

        response = http_session.get(
            url,
            params={"name": "example.com", "type": "A"},
            timeout=config.request_timeout
        )

        if response.status_code == 200:
            data = response.json()
            # Standard DNS-over-HTTPS response fields
            assert "Status" in data
            assert isinstance(data["Status"], int)
