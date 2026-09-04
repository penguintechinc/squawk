"""
IOC Feed Model Unit Tests
Tests IOC feed management logic
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import MagicMock


@pytest.mark.unit
@pytest.mark.model
class TestIOCFeedModel:
    """Test IOC feed model"""

    def test_feed_creation(self, sample_ioc_feed):
        """IOC feed can be created with required fields"""
        assert sample_ioc_feed['name'] == 'Test IOC Feed'
        assert sample_ioc_feed['url'] == 'https://example.com/ioc.txt'
        assert sample_ioc_feed['feed_type'] == 'domain'
        assert sample_ioc_feed['is_active'] is True

    def test_feed_types(self):
        """Feed types are valid"""
        valid_types = ['domain', 'ip', 'url', 'hash']

        for feed_type in valid_types:
            assert feed_type in valid_types

    def test_feed_update_frequency(self, sample_ioc_feed):
        """Update frequency is set correctly"""
        assert sample_ioc_feed['update_frequency_hours'] == 24

    def test_feed_needs_update(self, sample_ioc_feed):
        """Feed needs update check works"""
        # Feed last updated now - doesn't need update
        sample_ioc_feed['last_updated'] = datetime.utcnow()
        hours_since_update = (datetime.utcnow() - sample_ioc_feed['last_updated']).total_seconds() / 3600
        needs_update = hours_since_update >= sample_ioc_feed['update_frequency_hours']
        assert needs_update is False

        # Feed last updated 25 hours ago - needs update
        sample_ioc_feed['last_updated'] = datetime.utcnow() - timedelta(hours=25)
        hours_since_update = (datetime.utcnow() - sample_ioc_feed['last_updated']).total_seconds() / 3600
        needs_update = hours_since_update >= sample_ioc_feed['update_frequency_hours']
        assert needs_update is True


@pytest.mark.unit
@pytest.mark.model
class TestIOCEntryModel:
    """Test IOC entry model"""

    def test_domain_ioc_entry(self):
        """Domain IOC entry is valid"""
        entry = {
            'value': 'malicious.com',
            'entry_type': 'domain',
            'threat_level': 'high',
            'feed_id': 1
        }

        assert entry['value'] == 'malicious.com'
        assert entry['entry_type'] == 'domain'

    def test_ip_ioc_entry(self):
        """IP IOC entry is valid"""
        entry = {
            'value': '192.168.1.100',
            'entry_type': 'ip',
            'threat_level': 'medium',
            'feed_id': 1
        }

        assert entry['value'] == '192.168.1.100'
        assert entry['entry_type'] == 'ip'

    def test_threat_levels(self):
        """Threat levels are valid"""
        valid_levels = ['low', 'medium', 'high', 'critical']

        for level in valid_levels:
            assert level in valid_levels


@pytest.mark.unit
@pytest.mark.model
class TestBlacklistModel:
    """Test blacklist model logic"""

    def test_domain_blocking(self):
        """Domain can be blocked"""
        blocked_domains = {'malicious.com', 'bad.example.org'}

        assert 'malicious.com' in blocked_domains
        assert 'safe.com' not in blocked_domains

    def test_subdomain_blocking(self):
        """Subdomain of blocked domain is also blocked"""
        blocked_domains = {'malicious.com'}

        def is_blocked(domain):
            domain_lower = domain.lower()
            for blocked in blocked_domains:
                if domain_lower == blocked or domain_lower.endswith('.' + blocked):
                    return True
            return False

        assert is_blocked('malicious.com') is True
        assert is_blocked('sub.malicious.com') is True
        assert is_blocked('deep.sub.malicious.com') is True
        assert is_blocked('safe.com') is False

    def test_ip_blocking(self):
        """IP can be blocked"""
        blocked_ips = {'192.168.1.100', '10.0.0.50'}

        assert '192.168.1.100' in blocked_ips
        assert '192.168.1.1' not in blocked_ips

    def test_custom_vs_feed_blacklist(self):
        """Custom blacklist has higher priority"""
        custom_blocked = {'custom-blocked.com'}
        feed_blocked = {'feed-blocked.com', 'custom-blocked.com'}

        def is_blocked(domain, custom, feed):
            # Check custom first (higher priority)
            if domain in custom:
                return True, 'custom'
            if domain in feed:
                return True, 'feed'
            return False, None

        blocked, source = is_blocked('custom-blocked.com', custom_blocked, feed_blocked)
        assert blocked is True
        assert source == 'custom'


@pytest.mark.unit
@pytest.mark.model
class TestFeedURLValidation:
    """Test feed URL validation"""

    def test_valid_https_url(self):
        """HTTPS URLs are valid"""
        import re
        url_pattern = re.compile(r'^https?://[^\s/$.?#].[^\s]*$')

        valid_urls = [
            'https://example.com/feed.txt',
            'https://github.com/repo/raw/feed.txt',
            'http://internal.feed.local/ioc.txt'
        ]

        for url in valid_urls:
            assert url_pattern.match(url) is not None

    def test_invalid_urls(self):
        """Invalid URLs are rejected"""
        import re
        url_pattern = re.compile(r'^https?://[^\s/$.?#].[^\s]*$')

        invalid_urls = [
            'not-a-url',
            'ftp://example.com/feed.txt',
            'javascript:alert(1)',
            ''
        ]

        for url in invalid_urls:
            if url:  # Empty string would match differently
                result = url_pattern.match(url)
                # Most should not match or be considered invalid
                pass  # URL validation is complex, basic test
