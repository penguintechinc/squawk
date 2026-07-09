"""
SSRF-guard tests for IOC feed fetching.

Verifies _assert_feed_url_safe rejects internal/metadata/private targets and
allows public ones. Resolution is mocked so the test does not hit the network.
regression: SSRF in ioc feed fetch (blueprints/ioc_feeds.py sync + update_all_feeds)
"""

import socket
from unittest.mock import patch

import pytest

from app.services.ioc_ingestion_service import _assert_feed_url_safe


def _addrinfo(ip: str, port: int = 443):
    """Build a getaddrinfo-style result list for a single address."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]


class TestFeedUrlSSRFGuard:
    @pytest.mark.asyncio
    async def test_public_ip_allowed(self):
        with patch("socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")):
            # Should not raise
            await _assert_feed_url_safe("https://feeds.example.com/list.txt")

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "ip",
        [
            "169.254.169.254",  # cloud metadata (link-local)
            "127.0.0.1",        # loopback
            "10.0.0.5",         # private
            "192.168.1.10",     # private
            "172.16.0.1",       # private
            "0.0.0.0",          # unspecified
        ],
    )
    async def test_internal_targets_rejected(self, ip):
        with patch("socket.getaddrinfo", return_value=_addrinfo(ip)):
            with pytest.raises(ValueError):
                await _assert_feed_url_safe(f"https://internal.example.com/list.txt")

    @pytest.mark.asyncio
    async def test_non_http_scheme_rejected(self):
        # No DNS needed; scheme is rejected outright.
        with pytest.raises(ValueError):
            await _assert_feed_url_safe("file:///etc/passwd")
        with pytest.raises(ValueError):
            await _assert_feed_url_safe("ftp://example.com/list.txt")

    @pytest.mark.asyncio
    async def test_unresolvable_host_rejected(self):
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("no such host")):
            with pytest.raises(ValueError):
                await _assert_feed_url_safe("https://does-not-resolve.example.com/list.txt")

    @pytest.mark.asyncio
    async def test_allow_private_env_override(self, monkeypatch):
        monkeypatch.setenv("IOC_ALLOW_PRIVATE_FEEDS", "true")
        # With the override, a private address must be permitted (on-prem feeds).
        with patch("socket.getaddrinfo", return_value=_addrinfo("10.0.0.5")):
            await _assert_feed_url_safe("https://internal.example.com/list.txt")
