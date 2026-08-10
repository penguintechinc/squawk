#!/usr/bin/env python3
"""
Unit tests for WHOIS Manager
Tests domain lookups, IP lookups, caching, and search functionality.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timedelta
from whois_manager import WHOISManager

class TestWHOISManager:

    @pytest.fixture
    def whois_manager(self, temp_db):
        """Create WHOIS manager instance with test database"""
        db_url = f"sqlite://{temp_db._uri[9:]}"  # Extract path from DAL URI
        return WHOISManager(db_url)

    @pytest.mark.asyncio
    async def test_lookup_domain_success(self, whois_manager, mock_whois_response):
        """Test successful domain WHOIS lookup"""
        with patch('whois.whois') as mock_whois:
            mock_whois.return_value = {
                'domain_name': 'example.com',
                'registrar': 'Example Registrar Inc.',
                'creation_date': datetime(2000, 1, 1),
                'expiration_date': datetime(2025, 1, 1),
                'name_servers': ['ns1.example.com', 'ns2.example.com'],
                'org': 'Example Organization',
                'status': ['clientTransferProhibited'],
                'emails': ['admin@example.com']
            }

            result = await whois_manager.lookup_domain('example.com', '127.0.0.1')

            assert result['success'] is True
            assert result['domain'] == 'example.com'
            assert result['registrar'] == 'Example Registrar Inc.'
            assert result['query_type'] == 'domain'
            assert 'cached' in result
            mock_whois.assert_called_once_with('example.com')

    @pytest.mark.asyncio
    async def test_lookup_domain_cached(self, whois_manager):
        """Test domain lookup returns cached result"""
        # First lookup
        with patch('whois.whois') as mock_whois:
            mock_whois.return_value = {
                'domain_name': 'cached.example.com',
                'registrar': 'Test Registrar'
            }

            result1 = await whois_manager.lookup_domain('cached.example.com', '127.0.0.1')
            assert result1['cached'] is False

            # Second lookup should be cached
            result2 = await whois_manager.lookup_domain('cached.example.com', '127.0.0.1')
            assert result2['cached'] is True
            assert result2['registrar'] == 'Test Registrar'

            # WHOIS should only be called once
            mock_whois.assert_called_once()

    @pytest.mark.asyncio
    async def test_lookup_domain_force_refresh(self, whois_manager):
        """Test force refresh bypasses cache"""
        with patch('whois.whois') as mock_whois:
            mock_whois.return_value = {
                'domain_name': 'refresh.example.com',
                'registrar': 'Test Registrar'
            }

            # First lookup
            await whois_manager.lookup_domain('refresh.example.com', '127.0.0.1')

            # Second lookup with force refresh
            result = await whois_manager.lookup_domain('refresh.example.com', '127.0.0.1', force_refresh=True)

            assert result['cached'] is False
            # WHOIS should be called twice
            assert mock_whois.call_count == 2

    @pytest.mark.asyncio
    async def test_lookup_domain_whois_failure(self, whois_manager):
        """Test handling of WHOIS lookup failures"""
        with patch('whois.whois') as mock_whois:
            mock_whois.side_effect = Exception("WHOIS lookup failed")

            result = await whois_manager.lookup_domain('invalid.example.com', '127.0.0.1')

            assert result['success'] is False
            assert 'error' in result
            assert result['domain'] == 'invalid.example.com'

    @pytest.mark.asyncio
    async def test_lookup_ip_success(self, whois_manager):
        """Test successful IP WHOIS lookup"""
        with patch('ipwhois.IPWhois') as mock_ipwhois:
            mock_instance = Mock()
            mock_instance.lookup_rdap.return_value = {
                'network': {
                    'name': 'TEST-NET',
                    'country': 'US',
                    'start_address': '192.0.2.0',
                    'end_address': '192.0.2.255'
                },
                'entities': ['TEST-ORG'],
                'remarks': [{'description': ['Test network']}]
            }
            mock_ipwhois.return_value = mock_instance

            result = await whois_manager.lookup_ip('192.0.2.100', '127.0.0.1')

            assert result['success'] is True
            assert result['ip'] == '192.0.2.100'
            assert result['query_type'] == 'ip'
            assert result['network_name'] == 'TEST-NET'
            assert result['country'] == 'US'

    @pytest.mark.asyncio
    async def test_lookup_invalid_domain(self, whois_manager, invalid_domains):
        """Test lookup of invalid domain names"""
        for invalid_domain in invalid_domains[:3]:  # Test first 3 invalid domains
            result = await whois_manager.lookup_domain(invalid_domain, '127.0.0.1')
            assert result['success'] is False
            assert 'invalid' in result['error'].lower() or 'format' in result['error'].lower()

    @pytest.mark.asyncio
    async def test_search_whois_registrar(self, whois_manager):
        """Test WHOIS search by registrar"""
        # First, populate some test data
        with patch('whois.whois') as mock_whois:
            mock_whois.return_value = {
                'domain_name': 'test1.com',
                'registrar': 'Example Registrar Inc.'
            }
            await whois_manager.lookup_domain('test1.com', '127.0.0.1')

            mock_whois.return_value = {
                'domain_name': 'test2.com',
                'registrar': 'Different Registrar LLC'
            }
            await whois_manager.lookup_domain('test2.com', '127.0.0.1')

        # Search by registrar
        results = await whois_manager.search_whois('Example', 'registrar', 10)

        assert len(results) >= 1
        found = any('test1.com' in str(result) for result in results)
        assert found

    @pytest.mark.asyncio
    async def test_search_whois_organization(self, whois_manager):
        """Test WHOIS search by organization"""
        with patch('whois.whois') as mock_whois:
            mock_whois.return_value = {
                'domain_name': 'org-test.com',
                'org': 'Test Organization Inc.'
            }
            await whois_manager.lookup_domain('org-test.com', '127.0.0.1')

        results = await whois_manager.search_whois('Test Organization', 'organization', 10)

        assert len(results) >= 1
        found = any('org-test.com' in str(result) for result in results)
        assert found

    @pytest.mark.asyncio
    async def test_search_whois_nameserver(self, whois_manager):
        """Test WHOIS search by nameserver"""
        with patch('whois.whois') as mock_whois:
            mock_whois.return_value = {
                'domain_name': 'ns-test.com',
                'name_servers': ['ns1.example.com', 'ns2.example.com']
            }
            await whois_manager.lookup_domain('ns-test.com', '127.0.0.1')

        results = await whois_manager.search_whois('ns1.example.com', 'nameserver', 10)

        assert len(results) >= 1
        found = any('ns-test.com' in str(result) for result in results)
        assert found

    @pytest.mark.asyncio
    async def test_search_whois_general(self, whois_manager):
        """Test general WHOIS search across all fields"""
        with patch('whois.whois') as mock_whois:
            mock_whois.return_value = {
                'domain_name': 'general-test.com',
                'registrar': 'Unique Registrar Name',
                'org': 'Unique Organization'
            }
            await whois_manager.lookup_domain('general-test.com', '127.0.0.1')

        results = await whois_manager.search_whois('Unique', None, 10)

        assert len(results) >= 1
        found = any('general-test.com' in str(result) for result in results)
        assert found

    @pytest.mark.asyncio
    async def test_get_stats(self, whois_manager):
        """Test WHOIS statistics collection"""
        # Add some test data
        with patch('whois.whois') as mock_whois:
            mock_whois.return_value = {
                'domain_name': 'stats-test.com',
                'registrar': 'Stats Registrar'
            }
            await whois_manager.lookup_domain('stats-test.com', '127.0.0.1')

        with patch('ipwhois.IPWhois') as mock_ipwhois:
            mock_instance = Mock()
            mock_instance.lookup_rdap.return_value = {
                'network': {'name': 'TEST-NET', 'country': 'US'}
            }
            mock_ipwhois.return_value = mock_instance
            await whois_manager.lookup_ip('192.0.2.1', '127.0.0.1')

        stats = await whois_manager.get_stats()

        assert 'queries' in stats
        assert 'cache' in stats
        assert stats['queries']['total'] >= 2
        assert stats['queries']['domain_queries'] >= 1
        assert stats['queries']['ip_queries'] >= 1
        assert stats['cache']['total_entries'] >= 2

    @pytest.mark.asyncio
    async def test_cleanup_old_data(self, whois_manager):
        """Test cleanup of old WHOIS data"""
        # Add some test data
        with patch('whois.whois') as mock_whois:
            mock_whois.return_value = {
                'domain_name': 'cleanup-test.com',
                'registrar': 'Cleanup Registrar'
            }
            await whois_manager.lookup_domain('cleanup-test.com', '127.0.0.1')

        # Cleanup with 0 days retention (should remove everything)
        deleted = await whois_manager.cleanup_old_data(retention_days=0)

        assert deleted >= 0  # Should return number of deleted records

        # Verify data was cleaned up
        stats = await whois_manager.get_stats()
        assert stats['cache']['total_entries'] == 0

    @pytest.mark.asyncio
    async def test_rate_limiting(self, whois_manager):
        """Test WHOIS rate limiting functionality"""
        with patch('whois.whois') as mock_whois:
            mock_whois.return_value = {'domain_name': 'rate-test.com'}

            # Make multiple rapid requests
            tasks = []
            for i in range(5):
                task = whois_manager.lookup_domain(f'rate-test-{i}.com', '127.0.0.1')
                tasks.append(task)

            results = await asyncio.gather(*tasks, return_exceptions=True)

            # All should complete (rate limiting is internal)
            assert len(results) == 5
            successful = sum(1 for r in results if isinstance(r, dict) and r.get('success'))
            assert successful == 5

    @pytest.mark.asyncio
    async def test_concurrent_cache_access(self, whois_manager):
        """Test concurrent access to WHOIS cache"""
        with patch('whois.whois') as mock_whois:
            mock_whois.return_value = {
                'domain_name': 'concurrent-test.com',
                'registrar': 'Concurrent Registrar'
            }

            # Make concurrent requests for same domain
            tasks = []
            for i in range(3):
                task = whois_manager.lookup_domain('concurrent-test.com', f'127.0.0.{i+1}')
                tasks.append(task)

            results = await asyncio.gather(*tasks)

            # All should succeed
            assert all(r['success'] for r in results)
            assert all(r['domain'] == 'concurrent-test.com' for r in results)

            # Only one should have called the actual WHOIS (others cached)
            cached_count = sum(1 for r in results if r['cached'])
            assert cached_count >= 1  # At least one should be cached

    def test_domain_validation(self, whois_manager, valid_domains, invalid_domains):
        """Test domain name validation"""
        # Test valid domains
        for domain in valid_domains:
            assert whois_manager._is_valid_domain(domain), f"Valid domain failed: {domain}"

        # Test invalid domains
        for domain in invalid_domains:
            assert not whois_manager._is_valid_domain(domain), f"Invalid domain passed: {domain}"

    def test_ip_validation(self, whois_manager):
        """Test IP address validation"""
        valid_ips = ['192.168.1.1', '8.8.8.8', '2001:db8::1', '::1']
        invalid_ips = ['256.256.256.256', 'not.an.ip', '', '192.168.1']

        for ip in valid_ips:
            assert whois_manager._is_valid_ip(ip), f"Valid IP failed: {ip}"

        for ip in invalid_ips:
            assert not whois_manager._is_valid_ip(ip), f"Invalid IP passed: {ip}"

    @pytest.mark.asyncio
    async def test_whois_data_parsing(self, whois_manager):
        """Test WHOIS data parsing and normalization"""
        with patch('whois.whois') as mock_whois:
            # Test with various WHOIS response formats
            mock_whois.return_value = {
                'domain_name': ['EXAMPLE.COM', 'example.com'],  # Multiple formats
                'registrar': 'Example Registrar Inc.',
                'creation_date': [datetime(2000, 1, 1), datetime(2000, 1, 1, 12, 0)],  # Multiple dates
                'name_servers': ['NS1.EXAMPLE.COM', 'ns2.example.com'],  # Mixed case
                'status': ['clientTransferProhibited https://...', 'clientUpdateProhibited']
            }

            result = await whois_manager.lookup_domain('example.com', '127.0.0.1')

            assert result['success'] is True
            assert result['domain'] == 'example.com'  # Normalized to lowercase
            assert isinstance(result['nameservers'], list)
            assert len(result['nameservers']) == 2
            assert all(ns.islower() for ns in result['nameservers'])  # Normalized to lowercase

    @pytest.mark.asyncio
    async def test_error_handling_network_timeout(self, whois_manager):
        """Test handling of network timeouts"""
        with patch('whois.whois') as mock_whois:
            import socket
            mock_whois.side_effect = socket.timeout("Connection timed out")

            result = await whois_manager.lookup_domain('timeout-test.com', '127.0.0.1')

            assert result['success'] is False
            assert 'timeout' in result['error'].lower()

    @pytest.mark.asyncio
    async def test_ip_whois_rdap_fallback(self, whois_manager):
        """Test IP WHOIS RDAP lookup with fallback"""
        with patch('ipwhois.IPWhois') as mock_ipwhois:
            mock_instance = Mock()
            # First try RDAP
            mock_instance.lookup_rdap.side_effect = Exception("RDAP failed")
            # Then fallback to legacy
            mock_instance.lookup_whois.return_value = {
                'nets': [{
                    'name': 'LEGACY-NET',
                    'country': 'US',
                    'description': 'Legacy WHOIS lookup'
                }]
            }
            mock_ipwhois.return_value = mock_instance

            result = await whois_manager.lookup_ip('203.0.113.1', '127.0.0.1')

            assert result['success'] is True
            assert result['network_name'] == 'LEGACY-NET'
            assert result['country'] == 'US'

            # Should have tried RDAP first, then legacy
            mock_instance.lookup_rdap.assert_called_once()
            mock_instance.lookup_whois.assert_called_once()
