"""
Test configuration and fixtures for DNS client tests
"""

import pytest
import json
import tempfile
import os
from unittest.mock import Mock, patch
import yaml


@pytest.fixture
def mock_response():
    """Mock HTTP response for DNS queries"""
    response = Mock()
    response.status_code = 200
    response.json.return_value = {
        "Status": 0,
        "Answer": [{"name": "example.com", "type": "A", "data": "93.184.216.34"}],
    }
    return response


@pytest.fixture
def mock_error_response():
    """Mock HTTP error response"""
    response = Mock()
    response.status_code = 403
    response.raise_for_status.side_effect = Exception("Authentication failed")
    return response


@pytest.fixture
def sample_config():
    """Sample configuration data"""
    return {
        "domain": "example.com",
        "type": "A",
        "server": "https://dns.example.com:8443",
        "auth": "test-token-123456789",
    }


@pytest.fixture
def temp_config_file(sample_config):
    """Temporary configuration file"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as tmp:
        yaml.dump(sample_config, tmp)
        tmp_path = tmp.name

    yield tmp_path

    # Cleanup
    os.unlink(tmp_path)


@pytest.fixture
def mock_socket():
    """Mock socket for DNS forwarding tests"""
    socket_mock = Mock()
    socket_mock.bind = Mock()
    socket_mock.listen = Mock()
    socket_mock.accept = Mock(return_value=(Mock(), ("127.0.0.1", 12345)))
    socket_mock.recvfrom = Mock(return_value=(b"fake_dns_query", ("127.0.0.1", 54321)))
    socket_mock.sendto = Mock()
    return socket_mock


@pytest.fixture
def dns_query_samples():
    """Sample DNS queries for testing"""
    return {
        "A": {"domain": "example.com", "type": "A", "expected_ip": "93.184.216.34"},
        "AAAA": {
            "domain": "example.com",
            "type": "AAAA",
            "expected_ip": "2606:2800:220:1:248:1893:25c8:1946",
        },
        "MX": {
            "domain": "example.com",
            "type": "MX",
            "expected_data": "10 mail.example.com",
        },
        "TXT": {
            "domain": "example.com",
            "type": "TXT",
            "expected_data": "v=spf1 include:_spf.example.com ~all",
        },
    }


@pytest.fixture
def invalid_domains():
    """Invalid domain names for testing"""
    return [
        "",  # Empty
        ".",  # Single dot
        "..",  # Double dots
        "domain..com",  # Consecutive dots
        "domain-.com",  # Trailing hyphen
        "-domain.com",  # Leading hyphen
        "domain with spaces.com",  # Spaces
        "domain\x00.com",  # Null character
    ]


@pytest.fixture
def mock_dns_server():
    """Mock DNS server for integration testing"""

    class MockDNSServer:
        def __init__(self):
            self.queries = []
            self.responses = {}

        def add_response(self, domain, record_type, response):
            self.responses[f"{domain}:{record_type}"] = response

        def query(self, domain, record_type):
            key = f"{domain}:{record_type}"
            self.queries.append({"domain": domain, "type": record_type})
            return self.responses.get(
                key, {"Status": 2, "Comment": "Mock server: domain not found"}
            )

    server = MockDNSServer()

    # Add some default responses
    server.add_response(
        "example.com",
        "A",
        {
            "Status": 0,
            "Answer": [{"name": "example.com", "type": "A", "data": "93.184.216.34"}],
        },
    )

    server.add_response(
        "test.com",
        "A",
        {
            "Status": 0,
            "Answer": [{"name": "test.com", "type": "A", "data": "192.168.1.100"}],
        },
    )

    return server
