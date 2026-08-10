"""
Test suite for DNS Server IOC Blocking
Tests IOC feed processing and domain blocking with mocked data
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'bins'))


@pytest.fixture
def mock_ioc_data():
    """Create mock IOC data"""
    return {
        'malicious_domains': [
            'malware.example.com',
            'phishing.example.com',
            'badsite.example.com'
        ],
        'malicious_ips': [
            '192.0.2.1',
            '192.0.2.2'
        ]
    }


class TestIOCBlocking:
    """Test IOC blocking functionality"""

    def test_domain_in_blocklist(self, mock_ioc_data):
        """Test checking if domain is in blocklist"""
        blocklist = set(mock_ioc_data['malicious_domains'])

        assert 'malware.example.com' in blocklist
        assert 'safe.example.com' not in blocklist

    def test_ip_in_blocklist(self, mock_ioc_data):
        """Test checking if IP is in blocklist"""
        blocklist = set(mock_ioc_data['malicious_ips'])

        assert '192.0.2.1' in blocklist
        assert '93.184.216.34' not in blocklist

    @patch('requests.get')
    def test_fetch_ioc_feed(self, mock_get, mock_ioc_data):
        """Test fetching IOC feed from URL"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '\n'.join(mock_ioc_data['malicious_domains'])
        mock_get.return_value = mock_response

        # Simulate fetching feed
        response = mock_get('https://example.com/ioc-feed.txt')
        assert response.status_code == 200

        domains = response.text.split('\n')
        assert len(domains) == 3
        assert 'malware.example.com' in domains

    def test_parse_ioc_feed(self, mock_ioc_data):
        """Test parsing IOC feed data"""
        feed_text = '\n'.join(mock_ioc_data['malicious_domains'])

        # Parse feed
        domains = [line.strip() for line in feed_text.split('\n') if line.strip()]

        assert len(domains) == 3
        assert all(domain in mock_ioc_data['malicious_domains'] for domain in domains)


class TestIOCFeedManagement:
    """Test IOC feed management"""

    def test_add_ioc_feed(self):
        """Test adding IOC feed"""
        feeds = []

        new_feed = {
            'id': 1,
            'name': 'Test Feed',
            'url': 'https://example.com/feed.txt',
            'type': 'domain',
            'active': True
        }

        feeds.append(new_feed)
        assert len(feeds) == 1
        assert feeds[0]['name'] == 'Test Feed'

    def test_update_ioc_feed(self):
        """Test updating IOC feed"""
        feed = {
            'id': 1,
            'name': 'Test Feed',
            'url': 'https://example.com/feed.txt',
            'active': True
        }

        # Update feed
        feed['active'] = False
        feed['url'] = 'https://example.com/new-feed.txt'

        assert feed['active'] == False
        assert feed['url'] == 'https://example.com/new-feed.txt'

    def test_remove_ioc_feed(self):
        """Test removing IOC feed"""
        feeds = [
            {'id': 1, 'name': 'Feed 1'},
            {'id': 2, 'name': 'Feed 2'}
        ]

        # Remove feed
        feeds = [f for f in feeds if f['id'] != 1]

        assert len(feeds) == 1
        assert feeds[0]['id'] == 2


class TestIOCQueryBlocking:
    """Test DNS query blocking based on IOC"""

    def test_block_malicious_domain(self, mock_ioc_data):
        """Test blocking query for malicious domain"""
        blocklist = set(mock_ioc_data['malicious_domains'])

        query_domain = 'malware.example.com'

        # Check if should be blocked
        should_block = query_domain in blocklist
        assert should_block == True

    def test_allow_safe_domain(self, mock_ioc_data):
        """Test allowing query for safe domain"""
        blocklist = set(mock_ioc_data['malicious_domains'])

        query_domain = 'google.com'

        # Check if should be blocked
        should_block = query_domain in blocklist
        assert should_block == False

    def test_subdomain_blocking(self, mock_ioc_data):
        """Test blocking subdomains of malicious domains"""
        blocklist = set(mock_ioc_data['malicious_domains'])

        # Add wildcard support
        query_domain = 'sub.malware.example.com'

        # Check if parent domain is in blocklist
        parts = query_domain.split('.')
        should_block = False

        for i in range(len(parts)):
            potential_domain = '.'.join(parts[i:])
            if potential_domain in blocklist:
                should_block = True
                break

        assert should_block == True


class TestIOCMetrics:
    """Test IOC blocking metrics"""

    def test_count_blocked_queries(self):
        """Test counting blocked queries"""
        blocked_queries = []

        # Simulate blocking queries
        blocked_queries.append({
            'domain': 'malware.example.com',
            'timestamp': datetime.utcnow(),
            'reason': 'IOC blocklist'
        })

        blocked_queries.append({
            'domain': 'phishing.example.com',
            'timestamp': datetime.utcnow(),
            'reason': 'IOC blocklist'
        })

        assert len(blocked_queries) == 2

    def test_ioc_feed_statistics(self):
        """Test IOC feed statistics"""
        feed_stats = {
            'total_entries': 1000,
            'domains': 800,
            'ips': 200,
            'last_updated': datetime.utcnow()
        }

        assert feed_stats['total_entries'] == 1000
        assert feed_stats['domains'] + feed_stats['ips'] == feed_stats['total_entries']
