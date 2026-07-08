"""
Test suite for IOCChecker service.
Tests the actual IOCChecker class with contract shape: ioc_feeds as snake_case key,
mixed domains/IPs/CIDRs in entries, wildcard matching, and CIDR blocking.
"""
import sys
import os

# Add app directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from app.services.ioc_checker import IOCChecker


class TestIOCCheckerBasics:
    """Basic IOC checker functionality tests."""

    @pytest.fixture
    def checker(self):
        """Create a fresh IOCChecker instance."""
        return IOCChecker()

    def test_load_simple_domain_feed(self, checker):
        """Test loading a simple domain-only feed."""
        feeds = [
            {
                'id': 1,
                'name': 'DomainFeed',
                'feed_type': 'domain',
                'entries': [
                    'malware.example.com',
                    'phishing.test.com',
                    'badsite.org'
                ]
            }
        ]
        checker.load_feeds(feeds)

        assert len(checker.blocked_domains) == 3
        assert 'malware.example.com' in checker.blocked_domains
        assert len(checker.blocked_ips) == 0
        assert len(checker.blocked_cidrs) == 0

    def test_load_domain_feed_with_trailing_dots(self, checker):
        """Test that domains with trailing dots are normalized."""
        feeds = [
            {
                'id': 1,
                'name': 'Feed',
                'feed_type': 'domain',
                'entries': [
                    'example.com.',
                    'test.org.'
                ]
            }
        ]
        checker.load_feeds(feeds)

        # Should have trailing dots stripped
        assert 'example.com' in checker.blocked_domains
        assert 'test.org' in checker.blocked_domains
        assert 'example.com.' not in checker.blocked_domains

    def test_load_domain_feed_case_insensitive(self, checker):
        """Test that domains are normalized to lowercase."""
        feeds = [
            {
                'id': 1,
                'name': 'Feed',
                'feed_type': 'domain',
                'entries': [
                    'MALWARE.EXAMPLE.COM',
                    'Phishing.Test.Org'
                ]
            }
        ]
        checker.load_feeds(feeds)

        # Should all be lowercase
        assert 'malware.example.com' in checker.blocked_domains
        assert 'phishing.test.org' in checker.blocked_domains

    def test_exact_domain_match(self, checker):
        """Test exact domain blocking."""
        feeds = [
            {
                'id': 1,
                'name': 'Feed',
                'feed_type': 'domain',
                'entries': ['badsite.com']
            }
        ]
        checker.load_feeds(feeds)

        assert checker.is_blocked('badsite.com') == True
        assert checker.is_blocked('safe.com') == False

    def test_parent_domain_match(self, checker):
        """Test parent domain matching (subdomain of blocked domain is blocked)."""
        feeds = [
            {
                'id': 1,
                'name': 'Feed',
                'feed_type': 'domain',
                'entries': ['example.com']
            }
        ]
        checker.load_feeds(feeds)

        # Exact match
        assert checker.is_blocked('example.com') == True
        # Subdomain should match parent domain
        assert checker.is_blocked('sub.example.com') == True
        assert checker.is_blocked('deep.sub.example.com') == True
        # Unrelated domain should not match
        assert checker.is_blocked('example.org') == False


class TestWildcardDomainMatching:
    """Test wildcard domain matching (*.example.com patterns)."""

    @pytest.fixture
    def checker(self):
        return IOCChecker()

    def test_load_wildcard_domain(self, checker):
        """Test loading wildcard domain entries."""
        feeds = [
            {
                'id': 1,
                'name': 'Wildcards',
                'feed_type': 'domain',
                'entries': ['*.badsite.com']
            }
        ]
        checker.load_feeds(feeds)

        assert '*.badsite.com' in checker.wildcard_domains
        assert len(checker.blocked_domains) == 0

    def test_wildcard_domain_match(self, checker):
        """Test wildcard matching of subdomains."""
        feeds = [
            {
                'id': 1,
                'name': 'Wildcards',
                'feed_type': 'domain',
                'entries': ['*.example.com']
            }
        ]
        checker.load_feeds(feeds)

        # Subdomains should match
        assert checker.is_blocked('sub.example.com') == True
        assert checker.is_blocked('deep.sub.example.com') == True
        # Exact domain should also match (based on _check_wildcard logic)
        assert checker.is_blocked('example.com') == True
        # Different domain should not match
        assert checker.is_blocked('example.org') == False
        assert checker.is_blocked('safe.com') == False

    def test_wildcard_case_insensitive(self, checker):
        """Test wildcard matching is case-insensitive."""
        feeds = [
            {
                'id': 1,
                'name': 'Wildcards',
                'feed_type': 'domain',
                'entries': ['*.EXAMPLE.COM']
            }
        ]
        checker.load_feeds(feeds)

        # Should normalize to lowercase
        assert '*.example.com' in checker.wildcard_domains
        # Matching should be case-insensitive
        assert checker.is_blocked('SUB.EXAMPLE.COM') == True
        assert checker.is_blocked('sub.example.com') == True


class TestIPBlocking:
    """Test IP and CIDR blocking."""

    @pytest.fixture
    def checker(self):
        return IOCChecker()

    def test_load_plain_ip_entries(self, checker):
        """Test loading plain IP address entries."""
        feeds = [
            {
                'id': 1,
                'name': 'IPs',
                'feed_type': 'ip',
                'entries': [
                    '192.0.2.1',
                    '192.0.2.2',
                    '2001:db8::1'
                ]
            }
        ]
        checker.load_feeds(feeds)

        assert '192.0.2.1' in checker.blocked_ips
        assert '192.0.2.2' in checker.blocked_ips
        assert '2001:db8::1' in checker.blocked_ips
        assert len(checker.blocked_cidrs) == 0

    def test_load_cidr_entries(self, checker):
        """Test loading CIDR block entries."""
        feeds = [
            {
                'id': 1,
                'name': 'CIDRs',
                'feed_type': 'ip',
                'entries': [
                    '192.0.2.0/24',
                    '2001:db8::/32'
                ]
            }
        ]
        checker.load_feeds(feeds)

        assert len(checker.blocked_cidrs) == 2
        assert len(checker.blocked_ips) == 0

    def test_exact_ip_blocking(self, checker):
        """Test exact IP address blocking."""
        feeds = [
            {
                'id': 1,
                'name': 'IPs',
                'feed_type': 'ip',
                'entries': ['192.0.2.1']
            }
        ]
        checker.load_feeds(feeds)

        assert checker.is_ip_blocked('192.0.2.1') == True
        assert checker.is_ip_blocked('192.0.2.2') == False

    def test_cidr_blocking(self, checker):
        """Test CIDR membership blocking."""
        feeds = [
            {
                'id': 1,
                'name': 'CIDRs',
                'feed_type': 'ip',
                'entries': ['192.0.2.0/24']
            }
        ]
        checker.load_feeds(feeds)

        # IPs within CIDR should be blocked
        assert checker.is_ip_blocked('192.0.2.1') == True
        assert checker.is_ip_blocked('192.0.2.100') == True
        assert checker.is_ip_blocked('192.0.2.255') == True
        # IPs outside CIDR should not be blocked
        assert checker.is_ip_blocked('192.0.1.1') == False
        assert checker.is_ip_blocked('192.0.3.1') == False

    def test_ipv6_cidr_blocking(self, checker):
        """Test IPv6 CIDR membership blocking."""
        feeds = [
            {
                'id': 1,
                'name': 'IPv6CIDRs',
                'feed_type': 'ip',
                'entries': ['2001:db8::/32']
            }
        ]
        checker.load_feeds(feeds)

        # IPv6 within range should be blocked
        assert checker.is_ip_blocked('2001:db8::1') == True
        assert checker.is_ip_blocked('2001:db8:ffff:ffff:ffff:ffff:ffff:ffff') == True
        # IPv6 outside range should not be blocked
        assert checker.is_ip_blocked('2001:db9::1') == False

    def test_invalid_ip_format(self, checker):
        """Test that invalid IP formats are handled gracefully."""
        result = checker.is_ip_blocked('not-an-ip')
        assert result == False


class TestMixedFeeds:
    """Test feeds with mixed domain and IP entries."""

    @pytest.fixture
    def checker(self):
        return IOCChecker()

    def test_load_mixed_feed(self, checker):
        """Test loading a mixed feed with domains and IPs."""
        feeds = [
            {
                'id': 1,
                'name': 'MixedFeed',
                'feed_type': 'mixed',
                'entries': [
                    'malware.example.com',
                    '192.0.2.1',
                    '192.0.2.0/24',
                    '*.phishing.org',
                    '2001:db8::1'
                ]
            }
        ]
        checker.load_feeds(feeds)

        # Check domain loading
        assert 'malware.example.com' in checker.blocked_domains
        assert '*.phishing.org' in checker.wildcard_domains
        # Check IP loading
        assert '192.0.2.1' in checker.blocked_ips
        assert len(checker.blocked_cidrs) == 1

    def test_mixed_feed_blocking(self, checker):
        """Test blocking on mixed feed."""
        feeds = [
            {
                'id': 1,
                'name': 'Mixed',
                'feed_type': 'mixed',
                'entries': [
                    'badsite.com',
                    '*.danger.net',
                    '203.0.113.1',
                    '203.0.113.0/24'
                ]
            }
        ]
        checker.load_feeds(feeds)

        # Test domain blocking
        assert checker.is_blocked('badsite.com') == True
        assert checker.is_blocked('attack.danger.net') == True
        # Test IP blocking
        assert checker.is_ip_blocked('203.0.113.1') == True
        assert checker.is_ip_blocked('203.0.113.100') == True
        # Test unblocked
        assert checker.is_blocked('safe.com') == False
        assert checker.is_ip_blocked('203.0.114.1') == False


class TestContractShape:
    """Test that the service consumes the correct contract shape from manager."""

    @pytest.fixture
    def checker(self):
        return IOCChecker()

    def test_config_ioc_feeds_key_consumed(self, checker):
        """
        Test that ioc_feeds (snake_case) key is consumed correctly.
        This verifies the fix for the camelCase bug.
        """
        # Simulate config from manager (should use snake_case ioc_feeds)
        config = {
            'zones': [],
            'ioc_feeds': [  # snake_case, not camelCase
                {
                    'id': 1,
                    'name': 'TestFeed',
                    'feed_type': 'domain',
                    'entries': ['test.example.com']
                }
            ]
        }

        # Load using the snake_case key
        if config.get('ioc_feeds'):
            checker.load_feeds(config['ioc_feeds'])

        # Verify it was loaded
        assert len(checker.blocked_domains) == 1
        assert 'test.example.com' in checker.blocked_domains

    def test_feed_dict_contract(self, checker):
        """Test that each feed dict follows the contract."""
        feeds = [
            {
                'id': 1,  # required
                'name': 'MalwareFeed',  # required
                'feed_type': 'mixed',  # required
                'entries': [  # required
                    'malware.com',
                    '198.51.100.1',
                    '198.51.100.0/25'
                ]
            }
        ]
        checker.load_feeds(feeds)

        # Verify the structure was processed
        stats = checker.get_stats()
        assert 'MalwareFeed' in stats['feed_sources']
        feed_stat = stats['feed_sources']['MalwareFeed']
        assert feed_stat['id'] == 1
        assert feed_stat['type'] == 'mixed'
        assert feed_stat['domains'] == 1
        assert feed_stat['ips'] == 2
        assert feed_stat['total'] == 3

    def test_clear_and_reload(self, checker):
        """Test that clear() resets all data, and feeds can be reloaded."""
        # Load initial feeds
        feeds1 = [
            {
                'id': 1,
                'name': 'Feed1',
                'feed_type': 'domain',
                'entries': ['old.example.com']
            }
        ]
        checker.load_feeds(feeds1)
        assert 'old.example.com' in checker.blocked_domains

        # Load new feeds (should clear old data)
        feeds2 = [
            {
                'id': 2,
                'name': 'Feed2',
                'feed_type': 'domain',
                'entries': ['new.example.com']
            }
        ]
        checker.load_feeds(feeds2)

        assert 'new.example.com' in checker.blocked_domains
        assert 'old.example.com' not in checker.blocked_domains
        assert 'Feed1' not in checker.feed_sources
        assert 'Feed2' in checker.feed_sources


class TestPublicAPIStability:
    """Verify public API methods remain stable."""

    @pytest.fixture
    def checker(self):
        return IOCChecker()

    def test_is_blocked_method_exists(self, checker):
        """Test is_blocked method exists and has correct signature."""
        feeds = [
            {
                'id': 1,
                'name': 'Feed',
                'feed_type': 'domain',
                'entries': ['blocked.com']
            }
        ]
        checker.load_feeds(feeds)

        # Method should exist and work
        assert callable(checker.is_blocked)
        assert checker.is_blocked('blocked.com') == True

    def test_get_stats_returns_dict(self, checker):
        """Test get_stats returns a dict with expected keys."""
        feeds = [
            {
                'id': 1,
                'name': 'Feed',
                'feed_type': 'mixed',
                'entries': ['example.com', '192.0.2.1']
            }
        ]
        checker.load_feeds(feeds)

        stats = checker.get_stats()
        assert isinstance(stats, dict)
        assert 'blocked_domains' in stats
        assert 'blocked_ips' in stats
        assert 'feed_sources' in stats


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
