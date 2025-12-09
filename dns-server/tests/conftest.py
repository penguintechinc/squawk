"""
Minimal test configuration for working features only
"""

import pytest
import asyncio
import os
import sys
from unittest.mock import Mock, patch

# Add bins directory to Python path
bins_path = os.path.join(os.path.dirname(__file__), "..", "bins")
if bins_path not in sys.path:
    sys.path.insert(0, bins_path)


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_dns_resolver():
    """Mock DNS resolver for testing"""
    with patch("dns.resolver.Resolver") as mock_resolver:
        mock_answer = Mock()
        mock_answer.to_text.return_value = "93.184.216.34"

        mock_resolver_instance = Mock()
        mock_resolver_instance.resolve.return_value = [mock_answer]
        mock_resolver.return_value = mock_resolver_instance

        yield mock_resolver_instance


@pytest.fixture
def invalid_domains():
    """List of invalid domain names for testing"""
    return [
        "",  # Empty domain
        "invalid..domain",  # Double dots
        "domain-",  # Trailing hyphen
        "-domain",  # Leading hyphen
        "very-long-domain-name-that-exceeds-the-maximum-length-limit-of-sixty-three-characters.com",
        "domain with spaces",  # Spaces
        "domain@invalid",  # Invalid characters
        "domain\x00.com",  # Null character
        "javascript:alert(1)",  # XSS attempt
    ]


@pytest.fixture
def valid_domains():
    """List of valid domain names for testing"""
    return [
        "example.com",
        "subdomain.example.com",
        "test-domain.co.uk",
        "a.b.c.example.org",
        "123.example.com",
        "localhost",
        "*.example.com",  # Wildcard
    ]
