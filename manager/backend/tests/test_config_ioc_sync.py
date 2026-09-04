"""
Integration test for IOC config sync.

Tests that:
1. IOCManager ingest is wired into config service
2. get_active_ioc_feeds() returns feeds with indicators
3. get_config_version() changes after ingestion
"""

import pytest
import asyncio
from datetime import datetime
from app.services.config_service import ConfigService
from app.services.ioc_ingestion_service import IOCManager


class TestConfigIOCSync:
    """Test integration between IOCManager and ConfigService."""

    @pytest.mark.asyncio
    async def test_ioc_feed_ingest_and_config_fetch(self, app, db):
        """Test that IOC indicators are fetched in config after ingestion."""
        with app.app_context():
            # Initial state: no IOC feeds
            feeds = ConfigService.get_active_ioc_feeds()
            assert feeds == []

            # Create a test IOC feed in the database
            feed_id = db.ioc_feed.insert(
                name='Test Malware Feed',
                url='',  # No URL for this test
                feed_type='domain',
                format='txt',
                active=True,
                enabled=True,
                update_interval=6
            )
            db.commit()

            # Ingest test indicators via IOCManager
            ioc_mgr = IOCManager(app.config['DB_URL'])
            test_content = "malware.example.com\nevil.com\ntest.malware.net\n"
            result = await ioc_mgr.update_feed_from_content(
                name='Test Malware Feed',
                content=test_content,
                feed_type='domain',
                format_type='txt'
            )

            assert result['success'] is True
            assert result['indicators_added'] == 3

            # Now fetch config with IOC feeds
            feeds = ConfigService.get_active_ioc_feeds()
            assert len(feeds) == 1

            feed = feeds[0]
            assert feed['id'] == feed_id
            assert feed['name'] == 'Test Malware Feed'
            assert feed['feed_type'] == 'domain'
            assert len(feed['entries']) == 3

            # Verify indicators are normalized (lowercase)
            assert 'malware.example.com' in feed['entries']
            assert 'evil.com' in feed['entries']
            assert 'test.malware.net' in feed['entries']

    @pytest.mark.asyncio
    async def test_config_version_changes_on_ioc_ingest(self, app, db):
        """Test that config version changes after IOC indicator ingestion."""
        with app.app_context():
            # Get initial version
            version_before = ConfigService.get_config_version()

            # Create and ingest IOC feed
            feed_id = db.ioc_feed.insert(
                name='IP Threat Feed',
                url='',
                feed_type='ip',
                format='txt',
                active=True,
                enabled=True,
                update_interval=6
            )
            db.commit()

            ioc_mgr = IOCManager(app.config['DB_URL'])
            test_ips = "192.0.2.100\n203.0.113.50\n198.51.100.0/24\n"
            result = await ioc_mgr.update_feed_from_content(
                name='IP Threat Feed',
                content=test_ips,
                feed_type='ip',
                format_type='txt'
            )

            assert result['success'] is True

            # Version should change after ingestion
            version_after = ConfigService.get_config_version()
            assert version_after != version_before, \
                "Config version should change when IOC entries are added"

    @pytest.mark.asyncio
    async def test_mixed_feed_returns_all_indicators(self, app, db):
        """Test that mixed feeds (domain + ip) return both types."""
        with app.app_context():
            # Create mixed feed
            feed_id = db.ioc_feed.insert(
                name='Mixed Threat Feed',
                url='',
                feed_type='mixed',
                format='txt',
                active=True,
                enabled=True,
                update_interval=6
            )
            db.commit()

            # Ingest mixed content (would normally be CSV with type column)
            ioc_mgr = IOCManager(app.config['DB_URL'])

            # Manually insert both domain and IP indicators
            db.ioc_entry.insert(
                feed_id=feed_id,
                indicator='bad-domain.com',
                indicator_type='domain',
                threat_type='malware',
                confidence=75,
                source_format='txt'
            )
            db.ioc_entry.insert(
                feed_id=feed_id,
                indicator='192.0.2.50',
                indicator_type='ip',
                threat_type='botnet',
                confidence=80,
                source_format='txt'
            )
            db.ioc_entry.insert(
                feed_id=feed_id,
                indicator='198.51.100.0/24',
                indicator_type='ip',
                threat_type='malware',
                confidence=70,
                source_format='txt'
            )
            db.commit()

            # Fetch via config service
            feeds = ConfigService.get_active_ioc_feeds()
            assert len(feeds) == 1

            feed = feeds[0]
            assert feed['feed_type'] == 'mixed'
            assert len(feed['entries']) == 3
            assert 'bad-domain.com' in feed['entries']
            assert '192.0.2.50' in feed['entries']
            assert '198.51.100.0/24' in feed['entries']

    def test_inactive_feed_not_returned(self, app, db):
        """Test that inactive feeds are not returned by get_active_ioc_feeds."""
        with app.app_context():
            # Create active and inactive feeds
            active_id = db.ioc_feed.insert(
                name='Active Feed',
                url='',
                feed_type='domain',
                format='txt',
                active=True,
                enabled=True,
                update_interval=6
            )
            inactive_id = db.ioc_feed.insert(
                name='Inactive Feed',
                url='',
                feed_type='domain',
                format='txt',
                active=False,
                enabled=False,
                update_interval=6
            )
            db.commit()

            # Add indicators to both
            for feed_id in [active_id, inactive_id]:
                db.ioc_entry.insert(
                    feed_id=feed_id,
                    indicator='test.com',
                    indicator_type='domain',
                    threat_type='test',
                    confidence=50,
                    source_format='txt'
                )
            db.commit()

            # Only active feed should be returned
            feeds = ConfigService.get_active_ioc_feeds()
            assert len(feeds) == 1
            assert feeds[0]['id'] == active_id
            assert feeds[0]['name'] == 'Active Feed'

    @pytest.mark.asyncio
    async def test_domain_normalization_in_config(self, app, db):
        """Test that domains are normalized (lowercased) in config."""
        with app.app_context():
            feed_id = db.ioc_feed.insert(
                name='Domain Norm Feed',
                url='',
                feed_type='domain',
                format='txt',
                active=True,
                enabled=True,
                update_interval=6
            )
            db.commit()

            # Insert with mixed case and trailing dots
            db.ioc_entry.insert(
                feed_id=feed_id,
                indicator='EXAMPLE.COM',  # uppercase
                indicator_type='domain',
                threat_type='test',
                confidence=50,
                source_format='txt'
            )
            db.ioc_entry.insert(
                feed_id=feed_id,
                indicator='test.com.',  # trailing dot
                indicator_type='domain',
                threat_type='test',
                confidence=50,
                source_format='txt'
            )
            db.commit()

            feeds = ConfigService.get_active_ioc_feeds()
            assert len(feeds) == 1
            assert 'example.com' in feeds[0]['entries']
            assert 'test.com' in feeds[0]['entries']
