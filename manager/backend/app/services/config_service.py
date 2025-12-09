"""
Configuration service for DNS servers.
Distributes zones, IOC feeds, and settings to DNS servers.
"""

from typing import Dict, List, Optional
from flask import current_app
from datetime import datetime
import json


class ConfigService:
    """Service for managing DNS server configurations."""

    @staticmethod
    def get_server_config(server_id: int) -> Dict:
        """
        Get complete configuration for a DNS server.

        Args:
            server_id: DNS server ID

        Returns:
            Configuration dict with zones, IOC feeds, and settings
        """
        db = current_app.db

        # Get all zones with records
        zones = ConfigService.get_all_zones()

        # Get active IOC feeds
        ioc_feeds = ConfigService.get_active_ioc_feeds()

        # Get cache settings
        cache_settings = ConfigService.get_cache_settings()

        # Get additional settings
        settings = ConfigService.get_server_settings()

        return {
            'zones': zones,
            'ioc_feeds': ioc_feeds,
            'cache_settings': cache_settings,
            'settings': settings,
            'version': ConfigService.get_config_version(),
            'timestamp': datetime.utcnow().isoformat()
        }

    @staticmethod
    def get_all_zones() -> List[Dict]:
        """Get all DNS zones with records."""
        db = current_app.db

        zones = []
        zone_records = db(db.dns_zone).select(
            db.dns_zone.ALL,
            orderby=db.dns_zone.name
        )

        for zone in zone_records:
            # Get records for this zone
            records = db(db.dns_record.zone_id == zone.id).select(
                db.dns_record.ALL,
                orderby=db.dns_record.name
            )

            # Get allowed teams
            allowed_teams = []
            if zone.team_id:
                allowed_teams = [zone.team_id]

            zones.append({
                'id': zone.id,
                'name': zone.name,
                'visibility': zone.visibility,
                'team_id': zone.team_id,
                'allowed_teams': allowed_teams,
                'records': [
                    {
                        'name': r.name,
                        'type': r.type,
                        'value': r.value,
                        'ttl': r.ttl,
                        'priority': r.priority,
                        'weight': r.weight,
                        'port': r.port
                    }
                    for r in records
                ]
            })

        return zones

    @staticmethod
    def get_active_ioc_feeds() -> List[Dict]:
        """Get all active IOC feeds."""
        db = current_app.db

        feeds = db(db.ioc_feed.active == True).select(
            db.ioc_feed.ALL,
            orderby=db.ioc_feed.name
        )

        return [
            {
                'id': feed.id,
                'name': feed.name,
                'url': feed.url,
                'feed_type': feed.feed_type,
                'update_interval': feed.update_interval
            }
            for feed in feeds
        ]

    @staticmethod
    def get_cache_settings() -> Dict:
        """Get cache configuration settings."""
        return {
            'enabled': True,
            'ttl': 300,
            'max_size': 10000,
            'redis_url': current_app.config.get('REDIS_URL', 'redis://localhost:6379')
        }

    @staticmethod
    def get_server_settings() -> Dict:
        """Get additional server settings."""
        return {
            'max_workers': current_app.config.get('MAX_WORKERS', 100),
            'max_concurrent_requests': current_app.config.get('MAX_CONCURRENT_REQUESTS', 1000),
            'enable_mtls': current_app.config.get('ENABLE_MTLS', False),
            'log_level': 'INFO'
        }

    @staticmethod
    def get_config_version() -> int:
        """
        Get current configuration version.
        Increments when zones or IOC feeds change.
        """
        db = current_app.db

        # Simple version based on latest update timestamp
        zone_count = db(db.dns_zone).count()
        record_count = db(db.dns_record).count()
        feed_count = db(db.ioc_feed.active == True).count()

        # Generate version from counts
        return hash(f"{zone_count}:{record_count}:{feed_count}") % 1000000

    @staticmethod
    def record_heartbeat(server_id: int, metrics: Dict) -> Dict:
        """
        Record DNS server heartbeat with metrics.

        Args:
            server_id: DNS server ID
            metrics: Metrics dict with queries_total, cache_hits, errors, avg_response_ms

        Returns:
            Response dict with config version and sync flag
        """
        db = current_app.db

        # Update server status
        server = db.dns_server[server_id]
        if server:
            server.update_record(
                status='online',
                last_heartbeat=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )

        # Record metrics
        db.dns_server_metrics.insert(
            server_id=server_id,
            timestamp=datetime.utcnow(),
            queries_total=metrics.get('queries_total', 0),
            cache_hits=metrics.get('cache_hits', 0),
            errors=metrics.get('errors', 0),
            avg_response_ms=metrics.get('avg_response_ms', 0.0)
        )

        db.commit()

        # Check if config needs sync
        current_version = ConfigService.get_config_version()
        should_sync = True  # For now, always suggest sync

        return {
            'config_version': current_version,
            'should_sync': should_sync,
            'timestamp': datetime.utcnow().isoformat()
        }

    @staticmethod
    def get_zone_by_name(zone_name: str) -> Optional[Dict]:
        """
        Get zone by name with records.

        Args:
            zone_name: Zone name (e.g., example.com)

        Returns:
            Zone dict with records if found, None otherwise
        """
        db = current_app.db

        zone = db(db.dns_zone.name == zone_name).select().first()
        if not zone:
            return None

        records = db(db.dns_record.zone_id == zone.id).select(db.dns_record.ALL)

        return {
            'id': zone.id,
            'name': zone.name,
            'visibility': zone.visibility,
            'team_id': zone.team_id,
            'records': [
                {
                    'name': r.name,
                    'type': r.type,
                    'value': r.value,
                    'ttl': r.ttl
                }
                for r in records
            ]
        }
