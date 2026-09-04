"""
Container Health Check Smoke Tests
Verifies all service containers are running and healthy
"""

import pytest
import requests
import subprocess
import time


@pytest.mark.smoke
@pytest.mark.health
class TestContainerHealth:
    """Test container health endpoints"""

    def test_dns_server_health(self, config, http_session):
        """DNS server health endpoint returns healthy status"""
        url = f"{config.dns_server_url}/health"

        response = http_session.get(url, timeout=config.request_timeout)

        assert response.status_code == 200
        data = response.json()
        assert data.get("status") == "healthy"

    def test_web_console_health(self, config, http_session):
        """Web console health endpoint returns healthy status"""
        url = f"{config.web_console_url}/health"

        response = http_session.get(url, timeout=config.request_timeout)

        assert response.status_code == 200
        data = response.json()
        assert data.get("status") == "healthy"
        assert data.get("service") == "squawk-dns-api"

    def test_dns_server_responds_to_dns_query_endpoint(self, config, http_session):
        """DNS server /dns-query endpoint is accessible"""
        url = f"{config.dns_server_url}/dns-query"

        # GET request with name parameter
        response = http_session.get(
            url,
            params={"name": "example.com", "type": "A"},
            timeout=config.request_timeout
        )

        # Should return 200 or 401 (if auth required) - not 404 or 500
        assert response.status_code in [200, 401, 403]

    def test_web_console_root_accessible(self, config, http_session):
        """Web console root path is accessible"""
        url = config.web_console_url

        response = http_session.get(
            url,
            timeout=config.request_timeout,
            allow_redirects=False
        )

        # Should redirect to login or return 200
        assert response.status_code in [200, 302, 303]

    @pytest.mark.slow
    def test_all_services_start_within_timeout(self, config, http_session, wait_for_services):
        """All services should start within the configured timeout"""
        assert wait_for_services, "Not all services became healthy within timeout"


@pytest.mark.smoke
@pytest.mark.health
class TestContainerConnectivity:
    """Test inter-container connectivity"""

    def test_dns_server_cache_connectivity(self, config, http_session):
        """DNS server health shows cache is enabled"""
        url = f"{config.dns_server_url}/health"

        response = http_session.get(url, timeout=config.request_timeout)

        if response.status_code == 200:
            data = response.json()
            # Check if cache info is in health response
            if "cache" in data:
                assert data["cache"] is not None

    def test_dns_server_blacklist_status(self, config, http_session):
        """DNS server reports blacklist status"""
        url = f"{config.dns_server_url}/health"

        response = http_session.get(url, timeout=config.request_timeout)

        if response.status_code == 200:
            data = response.json()
            # Check blacklist status is reported
            assert "blacklist_enabled" in data or "status" in data


@pytest.mark.smoke
@pytest.mark.health
class TestServicePorts:
    """Test that services are listening on expected ports"""

    def test_dns_server_port_8080(self, config):
        """DNS server is listening on port 8080"""
        import socket

        # Extract host from URL
        host = config.dns_server_url.replace("http://", "").replace("https://", "")
        host = host.split(":")[0]
        port = 8080

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)

        try:
            result = sock.connect_ex((host, port))
            assert result == 0, f"Port {port} is not open on {host}"
        finally:
            sock.close()

    def test_web_console_port_8005(self, config):
        """Web console is listening on port 8005"""
        import socket

        host = config.web_console_url.replace("http://", "").replace("https://", "")
        host = host.split(":")[0]
        port = 8005

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)

        try:
            result = sock.connect_ex((host, port))
            assert result == 0, f"Port {port} is not open on {host}"
        finally:
            sock.close()


@pytest.mark.smoke
@pytest.mark.health
class TestResponseTimes:
    """Test service response times are acceptable"""

    def test_dns_server_health_response_time(self, config, http_session):
        """DNS server health endpoint responds within 1 second"""
        url = f"{config.dns_server_url}/health"

        start = time.time()
        response = http_session.get(url, timeout=config.request_timeout)
        elapsed = time.time() - start

        assert response.status_code == 200
        assert elapsed < 1.0, f"Health endpoint took {elapsed:.2f}s (max 1s)"

    def test_web_console_health_response_time(self, config, http_session):
        """Web console health endpoint responds within 1 second"""
        url = f"{config.web_console_url}/health"

        start = time.time()
        response = http_session.get(url, timeout=config.request_timeout)
        elapsed = time.time() - start

        assert response.status_code == 200
        assert elapsed < 1.0, f"Health endpoint took {elapsed:.2f}s (max 1s)"
