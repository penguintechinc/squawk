#!/usr/bin/env python3
"""
Unit tests for IOC Manager
Tests threat intelligence feed management, domain/IP blocking, and overrides.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock, mock_open
from datetime import datetime, timedelta
from ioc_manager import IOCManager

class TestIOCManager:

    @pytest.fixture
    def ioc_manager(self, temp_db):
        """Create IOC manager instance with test database"""
        db_url = f"sqlite://{temp_db._uri[9:]}"  # Extract path from DAL URI
        return IOCManager(db_url)

    @pytest.mark.asyncio
    async def test_check_domain_clean(self, ioc_manager):
        """Test checking clean domain not in IOC feeds"""
        should_block, reason = await ioc_manager.check_domain('clean-domain.com')

        assert should_block is False
        assert reason == "Not blocked"

    @pytest.mark.asyncio
    async def test_check_domain_blocked(self, ioc_manager, mock_ioc_feeds):
        """Test checking domain that should be blocked"""
        # Add test IOC data
        await ioc_manager.update_feed_from_content(
            "Test Feed",
            mock_ioc_feeds[0]['content'],
            mock_ioc_feeds[0]['feed_type'],
            mock_ioc_feeds[0]['format']
        )

        should_block, reason = await ioc_manager.check_domain('malware.example.com')

        assert should_block is True
        assert 'threat intelligence' in reason.lower()

    @pytest.mark.asyncio
    async def test_check_ip_blocked(self, ioc_manager):
        """Test checking IP address that should be blocked"""
        # Add malicious IP to IOC database
        await ioc_manager.update_feed_from_content(
            "Malicious IPs",
            "192.0.2.100\n203.0.113.50\n198.51.100.25\n",
            "ip",
            "txt"
        )

        should_block, reason = await ioc_manager.check_ip('192.0.2.100')

        assert should_block is True
        assert 'threat intelligence' in reason.lower()

    @pytest.mark.asyncio
    async def test_check_ip_clean(self, ioc_manager):
        """Test checking clean IP not in IOC feeds"""
        should_block, reason = await ioc_manager.check_ip('8.8.8.8')

        assert should_block is False
        assert reason == "Not blocked"

    @pytest.mark.asyncio
    async def test_add_override_allow(self, ioc_manager):
        """Test adding override to allow blocked domain"""
        # First add domain to IOC feeds
        await ioc_manager.update_feed_from_content(
            "Test Feed",
            "blocked-domain.com\n",
            "domain",
            "txt"
        )

        # Verify it's blocked
        should_block, _ = await ioc_manager.check_domain('blocked-domain.com', token_id=1)
        assert should_block is True

        # Add override
        success = await ioc_manager.add_override(
            1, 'blocked-domain.com', 'domain', 'allow',
            'Testing override', 'test_user'
        )
        assert success is True

        # Now it should be allowed
        should_block, reason = await ioc_manager.check_domain('blocked-domain.com', token_id=1)
        assert should_block is False
        assert 'override' in reason.lower()

    @pytest.mark.asyncio
    async def test_add_override_block(self, ioc_manager):
        """Test adding override to block clean domain"""
        # Verify domain is clean
        should_block, _ = await ioc_manager.check_domain('clean-domain.com', token_id=1)
        assert should_block is False

        # Add block override
        success = await ioc_manager.add_override(
            1, 'clean-domain.com', 'domain', 'block',
            'Custom block for testing', 'test_user'
        )
        assert success is True

        # Now it should be blocked
        should_block, reason = await ioc_manager.check_domain('clean-domain.com', token_id=1)
        assert should_block is True
        assert 'override' in reason.lower()

    @pytest.mark.asyncio
    async def test_remove_override(self, ioc_manager):
        """Test removing an override"""
        # Add override first
        await ioc_manager.add_override(
            1, 'test-override.com', 'domain', 'block',
            'Test override', 'test_user'
        )

        # Verify override exists
        should_block, _ = await ioc_manager.check_domain('test-override.com', token_id=1)
        assert should_block is True

        # Remove override
        success = await ioc_manager.remove_override(1, 'test-override.com', 'domain')
        assert success is True

        # Should be clean again
        should_block, reason = await ioc_manager.check_domain('test-override.com', token_id=1)
        assert should_block is False
        assert 'override' not in reason.lower()

    @pytest.mark.asyncio
    async def test_get_overrides(self, ioc_manager):
        """Test getting user's overrides"""
        # Add multiple overrides
        await ioc_manager.add_override(1, 'override1.com', 'domain', 'allow', 'Test 1', 'test_user')
        await ioc_manager.add_override(1, 'override2.com', 'domain', 'block', 'Test 2', 'test_user')
        await ioc_manager.add_override(1, '192.0.2.100', 'ip', 'allow', 'Test IP', 'test_user')

        overrides = await ioc_manager.get_overrides(1)

        assert len(overrides) == 3

        # Check that all overrides are returned
        indicators = [o['indicator'] for o in overrides]
        assert 'override1.com' in indicators
        assert 'override2.com' in indicators
        assert '192.0.2.100' in indicators

    @pytest.mark.asyncio
    async def test_expired_override(self, ioc_manager):
        """Test that expired overrides are ignored"""
        # Add expired override
        expired_time = datetime.now() - timedelta(hours=1)
        await ioc_manager.add_override(
            1, 'expired-override.com', 'domain', 'block',
            'Expired override', 'test_user', expired_time
        )

        # Should not be blocked due to expired override
        should_block, reason = await ioc_manager.check_domain('expired-override.com', token_id=1)
        assert should_block is False
        assert 'override' not in reason.lower()

    @pytest.mark.asyncio
    async def test_update_feed_txt_format(self, ioc_manager):
        """Test updating IOC feed with TXT format"""
        content = "malware1.com\nmalware2.com\nphishing.example.org\n"

        result = await ioc_manager.update_feed_from_content(
            "TXT Feed", content, "domain", "txt"
        )

        assert result['success'] is True
        assert result['indicators_added'] == 3

        # Verify domains are blocked
        should_block, _ = await ioc_manager.check_domain('malware1.com')
        assert should_block is True

        should_block, _ = await ioc_manager.check_domain('phishing.example.org')
        assert should_block is True

    @pytest.mark.asyncio
    async def test_update_feed_csv_format(self, ioc_manager):
        """Test updating IOC feed with CSV format"""
        content = "indicator,type,threat_type,confidence\n"
        content += "badware.com,domain,malware,95\n"
        content += "192.0.2.200,ip,botnet,80\n"
        content += "evil.example.net,domain,phishing,90\n"

        result = await ioc_manager.update_feed_from_content(
            "CSV Feed", content, "mixed", "csv"
        )

        assert result['success'] is True
        assert result['indicators_added'] == 3

        # Verify indicators are blocked
        should_block, _ = await ioc_manager.check_domain('badware.com')
        assert should_block is True

        should_block, _ = await ioc_manager.check_ip('192.0.2.200')
        assert should_block is True

    @pytest.mark.asyncio
    async def test_update_feed_json_format(self, ioc_manager):
        """Test updating IOC feed with JSON format"""
        import json

        feed_data = {
            "indicators": [
                {
                    "indicator": "json-malware.com",
                    "type": "domain",
                    "threat_type": "malware",
                    "confidence": 95
                },
                {
                    "indicator": "198.51.100.100",
                    "type": "ip",
                    "threat_type": "c2",
                    "confidence": 85
                }
            ]
        }

        content = json.dumps(feed_data)

        result = await ioc_manager.update_feed_from_content(
            "JSON Feed", content, "mixed", "json"
        )

        assert result['success'] is True
        assert result['indicators_added'] == 2

        # Verify indicators are blocked
        should_block, _ = await ioc_manager.check_domain('json-malware.com')
        assert should_block is True

        should_block, _ = await ioc_manager.check_ip('198.51.100.100')
        assert should_block is True

    @pytest.mark.asyncio
    async def test_update_all_feeds(self, ioc_manager):
        """Test updating all registered feeds"""
        # Mock HTTP requests
        with patch('aiohttp.ClientSession.get') as mock_get:
            # Mock response
            mock_response = Mock()
            mock_response.text = AsyncMock(return_value="threat1.com\nthreat2.com\n")
            mock_response.status = 200
            mock_get.return_value.__aenter__.return_value = mock_response

            # First register a feed
            await ioc_manager.register_feed(
                "Test Online Feed",
                "https://example.com/threats.txt",
                "domain",
                "txt",
                update_frequency_hours=6
            )

            # Update all feeds
            result = await ioc_manager.update_all_feeds()

            assert result['success'] is True
            assert result['feeds_updated'] == 1

            # Verify indicators were added
            should_block, _ = await ioc_manager.check_domain('threat1.com')
            assert should_block is True

    @pytest.mark.asyncio
    async def test_feed_update_frequency(self, ioc_manager):
        """Test that feeds respect update frequency"""
        # Register feed
        await ioc_manager.register_feed(
            "Frequency Test Feed",
            "https://example.com/threats.txt",
            "domain",
            "txt",
            update_frequency_hours=1
        )

        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_response = Mock()
            mock_response.text = AsyncMock(return_value="freq-test.com\n")
            mock_response.status = 200
            mock_get.return_value.__aenter__.return_value = mock_response

            # First update
            result1 = await ioc_manager.update_all_feeds()
            assert result1['feeds_updated'] == 1

            # Immediate second update should skip (frequency not met)
            result2 = await ioc_manager.update_all_feeds()
            assert result2['feeds_updated'] == 0
            assert 'skipped' in result2

    @pytest.mark.asyncio
    async def test_feed_registration(self, ioc_manager):
        """Test registering new IOC feed"""
        result = await ioc_manager.register_feed(
            "Registration Test",
            "https://test.com/feed.txt",
            "domain",
            "txt",
            update_frequency_hours=12,
            enabled=True
        )

        assert result['success'] is True
        assert 'feed_id' in result

        # Verify feed was registered
        stats = await ioc_manager.get_stats()
        assert stats['feeds']['total'] == 1
        assert stats['feeds']['enabled'] == 1

    @pytest.mark.asyncio
    async def test_feed_disable_enable(self, ioc_manager):
        """Test disabling and enabling feeds"""
        # Register feed first
        reg_result = await ioc_manager.register_feed(
            "Disable Test",
            "https://test.com/feed.txt",
            "domain",
            "txt"
        )
        feed_id = reg_result['feed_id']

        # Disable feed
        disable_result = await ioc_manager.set_feed_enabled(feed_id, False)
        assert disable_result['success'] is True

        # Enable feed
        enable_result = await ioc_manager.set_feed_enabled(feed_id, True)
        assert enable_result['success'] is True

        # Verify final state
        stats = await ioc_manager.get_stats()
        assert stats['feeds']['enabled'] == 1

    @pytest.mark.asyncio
    async def test_get_stats(self, ioc_manager):
        """Test IOC statistics collection"""
        # Add some test data
        await ioc_manager.update_feed_from_content(
            "Stats Test",
            "stats1.com\nstats2.com\nstats3.com\n",
            "domain",
            "txt"
        )

        await ioc_manager.add_override(
            1, 'override-stats.com', 'domain', 'block',
            'Stats test', 'test_user'
        )

        stats = await ioc_manager.get_stats()

        assert 'feeds' in stats
        assert 'indicators' in stats
        assert 'overrides' in stats
        assert 'recent_activity' in stats

        assert stats['indicators']['total'] >= 3
        assert stats['overrides']['total'] >= 1
        assert stats['feeds']['total'] >= 1

    @pytest.mark.asyncio
    async def test_wildcard_domain_matching(self, ioc_manager):
        """Test wildcard domain matching in IOC feeds"""
        # Add wildcard domain to feed
        await ioc_manager.update_feed_from_content(
            "Wildcard Test",
            "*.malware-family.com\n*.phishing-kit.org\n",
            "domain",
            "txt"
        )

        # Test wildcard matches
        should_block, _ = await ioc_manager.check_domain('subdomain.malware-family.com')
        assert should_block is True

        should_block, _ = await ioc_manager.check_domain('test.phishing-kit.org')
        assert should_block is True

        # Test non-matches
        should_block, _ = await ioc_manager.check_domain('malware-family.com.evil.org')
        assert should_block is False

    @pytest.mark.asyncio
    async def test_cidr_ip_matching(self, ioc_manager):
        """Test CIDR block matching for IP addresses"""
        # Add CIDR blocks to feed
        await ioc_manager.update_feed_from_content(
            "CIDR Test",
            "192.0.2.0/24\n203.0.113.0/28\n",
            "ip",
            "txt"
        )

        # Test IPs in CIDR blocks
        should_block, _ = await ioc_manager.check_ip('192.0.2.50')
        assert should_block is True

        should_block, _ = await ioc_manager.check_ip('203.0.113.10')
        assert should_block is True

        # Test IPs outside CIDR blocks
        should_block, _ = await ioc_manager.check_ip('192.0.3.50')
        assert should_block is False

        should_block, _ = await ioc_manager.check_ip('203.0.114.10')
        assert should_block is False

    @pytest.mark.asyncio
    async def test_feed_update_error_handling(self, ioc_manager):
        """Test error handling during feed updates"""
        # Register feed with invalid URL
        await ioc_manager.register_feed(
            "Error Test",
            "https://invalid-feed-url.nonexistent/feed.txt",
            "domain",
            "txt"
        )

        # Mock network error
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.side_effect = Exception("Network error")

            result = await ioc_manager.update_all_feeds()

            # Should handle error gracefully
            assert 'error' in result or result['success'] is False

    @pytest.mark.asyncio
    async def test_malformed_feed_content(self, ioc_manager):
        """Test handling of malformed feed content"""
        # Test malformed CSV
        malformed_csv = "indicator,type\nno_type_column.com\n"

        result = await ioc_manager.update_feed_from_content(
            "Malformed CSV", malformed_csv, "domain", "csv"
        )

        # Should handle gracefully and parse what it can
        assert result['success'] is True
        assert result.get('warnings') or result.get('indicators_added', 0) >= 0

        # Test malformed JSON
        malformed_json = '{"indicators": [{"indicator": "test.com", missing_type}]}'

        result = await ioc_manager.update_feed_from_content(
            "Malformed JSON", malformed_json, "domain", "json"
        )

        # Should handle JSON parse error
        assert 'error' in result or result['success'] is False

    @pytest.mark.asyncio
    async def test_indicator_confidence_scoring(self, ioc_manager):
        """Test confidence scoring for indicators"""
        import json

        # Add indicators with different confidence scores
        feed_data = {
            "indicators": [
                {"indicator": "high-conf.com", "type": "domain", "confidence": 95},
                {"indicator": "low-conf.com", "type": "domain", "confidence": 30}
            ]
        }

        await ioc_manager.update_feed_from_content(
            "Confidence Test", json.dumps(feed_data), "domain", "json"
        )

        # Both should be blocked for now (confidence filtering would be a premium feature)
        should_block, _ = await ioc_manager.check_domain('high-conf.com')
        assert should_block is True

        should_block, _ = await ioc_manager.check_domain('low-conf.com')
        assert should_block is True

    @pytest.mark.asyncio
    async def test_cleanup_old_indicators(self, ioc_manager):
        """Test cleanup of old IOC indicators"""
        # Add some test indicators
        await ioc_manager.update_feed_from_content(
            "Cleanup Test",
            "cleanup1.com\ncleanup2.com\n",
            "domain",
            "txt"
        )

        # Run cleanup (with 0 days to remove everything)
        deleted = await ioc_manager.cleanup_old_indicators(retention_days=0)

        assert deleted >= 0  # Should return count of deleted indicators

        # Verify indicators were cleaned up
        should_block, _ = await ioc_manager.check_domain('cleanup1.com')
        assert should_block is False

    @pytest.mark.asyncio
    async def test_concurrent_checks(self, ioc_manager):
        """Test concurrent IOC checks"""
        # Add test data
        await ioc_manager.update_feed_from_content(
            "Concurrent Test",
            "concurrent1.com\nconcurrent2.com\nconcurrent3.com\n",
            "domain",
            "txt"
        )

        # Perform concurrent checks
        domains = ['concurrent1.com', 'concurrent2.com', 'concurrent3.com', 'clean.com']
        tasks = [ioc_manager.check_domain(domain) for domain in domains]

        results = await asyncio.gather(*tasks)

        assert len(results) == 4
        # First 3 should be blocked
        assert results[0][0] is True  # concurrent1.com
        assert results[1][0] is True  # concurrent2.com
        assert results[2][0] is True  # concurrent3.com
        assert results[3][0] is False  # clean.com

    @pytest.mark.asyncio
    async def test_default_feeds_initialization(self, ioc_manager):
        """Test initialization of default IOC feeds"""
        # Initialize default feeds
        await ioc_manager.initialize_default_feeds()

        stats = await ioc_manager.get_stats()

        # Should have registered the default 5 feeds
        assert stats['feeds']['total'] >= 5

        # Check that known feed names exist
        # (This would require checking the actual feed names from the implementation)
        assert stats['feeds']['enabled'] >= 5

    def test_domain_normalization(self, ioc_manager):
        """Test domain name normalization"""
        # Test various domain formats
        test_cases = [
            ('EXAMPLE.COM', 'example.com'),
            ('  example.com  ', 'example.com'),
            ('example.com.', 'example.com'),
            ('*.EXAMPLE.COM', '*.example.com')
        ]

        for input_domain, expected in test_cases:
            normalized = ioc_manager._normalize_domain(input_domain)
            assert normalized == expected, f"Failed for {input_domain}"

    def test_ip_normalization(self, ioc_manager):
        """Test IP address normalization"""
        test_cases = [
            ('  192.168.1.1  ', '192.168.1.1'),
            ('192.168.1.0/24', '192.168.1.0/24'),
            ('2001:DB8::1', '2001:db8::1')  # IPv6 lowercase
        ]

        for input_ip, expected in test_cases:
            normalized = ioc_manager._normalize_ip(input_ip)
            assert normalized == expected, f"Failed for {input_ip}"
