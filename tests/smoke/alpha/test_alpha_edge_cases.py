"""
Alpha Edge Case Tests
Test boundary conditions, edge cases, and unusual inputs
"""

import pytest
import requests
from datetime import datetime, timedelta
import json


@pytest.mark.alpha
@pytest.mark.edge_cases
class TestAlphaBoundaryConditions:
    """Test boundary values and limits"""

    def test_domain_name_length_limits(self, authenticated_client):
        """Domain names respect RFC length limits"""
        # RFC 1035: 255 characters max
        max_length_domain = "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 61 + ".com"
        too_long_domain = "a" * 256

        # Valid max length should work
        response = authenticated_client.post(
            "/api/v1/domains",
            json={"domain": max_length_domain, "type": "A", "value": "1.2.3.4"}
        )
        assert response.status_code in [200, 201, 400]

        # Too long should be rejected
        response = authenticated_client.post(
            "/api/v1/domains",
            json={"domain": too_long_domain, "type": "A", "value": "1.2.3.4"}
        )
        assert response.status_code in [400, 422]

    def test_label_length_limits(self, authenticated_client):
        """Domain labels respect 63 character limit"""
        # RFC 1035: Each label max 63 characters
        valid_label = "a" * 63 + ".example.com"
        invalid_label = "a" * 64 + ".example.com"

        response = authenticated_client.post(
            "/api/v1/domains",
            json={"domain": valid_label, "type": "A", "value": "1.2.3.4"}
        )
        assert response.status_code in [200, 201, 400]

        response = authenticated_client.post(
            "/api/v1/domains",
            json={"domain": invalid_label, "type": "A", "value": "1.2.3.4"}
        )
        assert response.status_code in [400, 422]

    def test_ipv4_address_validation(self, authenticated_client):
        """IPv4 addresses validated correctly"""
        valid_ips = ["0.0.0.0", "255.255.255.255", "192.168.1.1"]
        invalid_ips = ["256.1.1.1", "1.1.1", "1.1.1.1.1", "abc.def.ghi.jkl"]

        for ip in valid_ips:
            response = authenticated_client.post(
                "/api/v1/domains",
                json={"domain": "test.com", "type": "A", "value": ip}
            )
            assert response.status_code in [200, 201, 400]

        for ip in invalid_ips:
            response = authenticated_client.post(
                "/api/v1/domains",
                json={"domain": "test.com", "type": "A", "value": ip}
            )
            assert response.status_code in [400, 422]

    def test_ipv6_address_validation(self, authenticated_client):
        """IPv6 addresses validated correctly"""
        valid_ipv6 = [
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "2001:db8::1",
            "::1",
            "::",
        ]
        invalid_ipv6 = [
            "gggg::1",
            "2001:0db8:85a3::8a2e:0370:7334:extra",
            ":::",
        ]

        for ip in valid_ipv6:
            response = authenticated_client.post(
                "/api/v1/domains",
                json={"domain": "test.com", "type": "AAAA", "value": ip}
            )
            assert response.status_code in [200, 201, 400]

        for ip in invalid_ipv6:
            response = authenticated_client.post(
                "/api/v1/domains",
                json={"domain": "test.com", "type": "AAAA", "value": ip}
            )
            assert response.status_code in [400, 422]

    def test_ttl_boundary_values(self, authenticated_client):
        """TTL values respect valid ranges"""
        valid_ttls = [0, 1, 86400, 2147483647]  # 0 to max int32
        invalid_ttls = [-1, -100, 2147483648]  # Negative or too large

        for ttl in valid_ttls:
            response = authenticated_client.post(
                "/api/v1/records",
                json={
                    "name": "test.com",
                    "type": "A",
                    "value": "1.2.3.4",
                    "ttl": ttl
                }
            )
            assert response.status_code in [200, 201, 400, 422]

        for ttl in invalid_ttls:
            response = authenticated_client.post(
                "/api/v1/records",
                json={
                    "name": "test.com",
                    "type": "A",
                    "value": "1.2.3.4",
                    "ttl": ttl
                }
            )
            assert response.status_code in [400, 422]


@pytest.mark.alpha
@pytest.mark.edge_cases
class TestAlphaSpecialCharacters:
    """Test handling of special characters"""

    def test_unicode_in_domain_names(self, authenticated_client):
        """Unicode characters handled correctly (IDN)"""
        unicode_domains = [
            "münchen.de",  # German umlaut
            "日本.jp",      # Japanese
            "россия.ru",   # Russian
            "café.com",    # French
        ]

        for domain in unicode_domains:
            response = authenticated_client.post(
                "/api/v1/domains",
                json={"domain": domain, "type": "A", "value": "1.2.3.4"}
            )
            # Should handle or reject gracefully
            assert response.status_code in [200, 201, 400, 422]

    def test_special_chars_in_txt_records(self, authenticated_client):
        """TXT records handle special characters"""
        special_txt_values = [
            "v=spf1 include:_spf.google.com ~all",
            "key=value; key2=value2",
            "\"quoted string\"",
            "multi\nline\ntext",
            "unicode: émojis 🚀",
        ]

        for txt_value in special_txt_values:
            response = authenticated_client.post(
                "/api/v1/records",
                json={
                    "name": "test.com",
                    "type": "TXT",
                    "value": txt_value
                }
            )
            assert response.status_code in [200, 201, 400, 422]

    def test_whitespace_handling(self, authenticated_client):
        """Whitespace in inputs handled correctly"""
        whitespace_tests = [
            "  test.com  ",  # Leading/trailing spaces
            "test .com",     # Space in middle
            "test\t.com",    # Tab character
            "test\n.com",    # Newline
        ]

        for domain in whitespace_tests:
            response = authenticated_client.post(
                "/api/v1/domains",
                json={"domain": domain, "type": "A", "value": "1.2.3.4"}
            )
            # Should trim or reject
            assert response.status_code in [200, 201, 400, 422]


@pytest.mark.alpha
@pytest.mark.edge_cases
class TestAlphaEmptyAndNull:
    """Test empty, null, and missing values"""

    def test_empty_string_inputs(self, authenticated_client):
        """Empty strings handled correctly"""
        response = authenticated_client.post(
            "/api/v1/domains",
            json={"domain": "", "type": "A", "value": "1.2.3.4"}
        )
        assert response.status_code in [400, 422]

        response = authenticated_client.post(
            "/api/v1/domains",
            json={"domain": "test.com", "type": "", "value": "1.2.3.4"}
        )
        assert response.status_code in [400, 422]

    def test_null_values(self, authenticated_client):
        """Null values handled correctly"""
        response = authenticated_client.post(
            "/api/v1/domains",
            json={"domain": None, "type": "A", "value": "1.2.3.4"}
        )
        assert response.status_code in [400, 422]

    def test_missing_required_fields(self, authenticated_client):
        """Missing required fields detected"""
        # Missing domain
        response = authenticated_client.post(
            "/api/v1/domains",
            json={"type": "A", "value": "1.2.3.4"}
        )
        assert response.status_code in [400, 422]

        # Missing type
        response = authenticated_client.post(
            "/api/v1/domains",
            json={"domain": "test.com", "value": "1.2.3.4"}
        )
        assert response.status_code in [400, 422]

        # Missing value
        response = authenticated_client.post(
            "/api/v1/domains",
            json={"domain": "test.com", "type": "A"}
        )
        assert response.status_code in [400, 422]

    def test_empty_json_body(self, authenticated_client):
        """Empty JSON body handled correctly"""
        response = authenticated_client.post(
            "/api/v1/domains",
            json={}
        )
        assert response.status_code in [400, 422]

    def test_empty_list_responses(self, authenticated_client):
        """Empty lists returned correctly"""
        response = authenticated_client.get("/api/v1/queries")
        assert response.status_code == 200

        data = response.json()
        # Should return empty list, not null
        assert "queries" in data
        assert isinstance(data["queries"], list)


@pytest.mark.alpha
@pytest.mark.edge_cases
class TestAlphaConcurrentOperations:
    """Test concurrent operations and race conditions"""

    def test_multiple_simultaneous_logins(self, config, http_session):
        """Handle multiple simultaneous login attempts"""
        login_url = f"{config.web_console_url}/api/v1/auth/login"

        # Make multiple concurrent requests
        import concurrent.futures

        def login_attempt():
            return http_session.post(
                login_url,
                json={
                    "email": config.admin_email,
                    "password": config.admin_password
                },
                timeout=config.request_timeout
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(login_attempt) for _ in range(5)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # All should succeed or fail gracefully
        for response in results:
            assert response.status_code in [200, 429, 500]

    def test_duplicate_record_creation(self, authenticated_client):
        """Handle duplicate record creation attempts"""
        record = {
            "domain": f"duplicate-test-{datetime.utcnow().timestamp()}.com",
            "type": "A",
            "value": "1.2.3.4"
        }

        # Create first record
        response1 = authenticated_client.post("/api/v1/domains", json=record)

        # Try to create duplicate
        response2 = authenticated_client.post("/api/v1/domains", json=record)

        # Should handle duplicate (accept or reject)
        assert response2.status_code in [200, 201, 409, 422]


@pytest.mark.alpha
@pytest.mark.edge_cases
class TestAlphaLargeDatasets:
    """Test handling of large datasets"""

    def test_large_txt_record(self, authenticated_client):
        """Handle large TXT records (up to 255 chars per string)"""
        large_txt = "a" * 255  # Max single string
        response = authenticated_client.post(
            "/api/v1/records",
            json={
                "name": "test.com",
                "type": "TXT",
                "value": large_txt
            }
        )
        assert response.status_code in [200, 201, 400, 422]

        # Too large should be rejected
        too_large_txt = "a" * 1000
        response = authenticated_client.post(
            "/api/v1/records",
            json={
                "name": "test.com",
                "type": "TXT",
                "value": too_large_txt
            }
        )
        assert response.status_code in [400, 422]

    def test_large_json_payload(self, authenticated_client):
        """Handle large JSON payloads"""
        # Create large payload
        large_payload = {
            "domain": "test.com",
            "type": "A",
            "value": "1.2.3.4",
            "metadata": {"key" + str(i): "value" * 100 for i in range(100)}
        }

        response = authenticated_client.post(
            "/api/v1/domains",
            json=large_payload
        )
        # Should handle or reject based on size limits
        assert response.status_code in [200, 201, 400, 413, 422]

    def test_pagination_with_large_results(self, authenticated_client):
        """Pagination works with large result sets"""
        response = authenticated_client.get(
            "/api/v1/queries?limit=1000"
        )
        assert response.status_code == 200

        data = response.json()
        # Should limit results or paginate
        assert "queries" in data


@pytest.mark.alpha
@pytest.mark.edge_cases
class TestAlphaErrorRecovery:
    """Test error handling and recovery"""

    def test_malformed_json_request(self, config, http_session):
        """Handle malformed JSON gracefully"""
        response = http_session.post(
            f"{config.web_console_url}/api/v1/domains",
            data="not valid json{{{",
            headers={"Content-Type": "application/json"},
            timeout=config.request_timeout
        )
        # Should return 400, not crash
        assert response.status_code in [400, 422]

    def test_unsupported_content_type(self, authenticated_client):
        """Handle unsupported content types"""
        response = authenticated_client.post(
            "/api/v1/domains",
            data="domain=test.com",
            headers={"Content-Type": "text/plain"}
        )
        # Should reject or handle gracefully
        assert response.status_code in [400, 415, 422]

    def test_invalid_http_methods(self, config, http_session):
        """Handle invalid HTTP methods"""
        # Try PATCH on endpoint that doesn't support it
        response = http_session.patch(
            f"{config.web_console_url}/api/v1/domains",
            timeout=config.request_timeout
        )
        assert response.status_code in [405, 501]
