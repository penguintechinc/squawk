"""
Configuration service for DNS servers.
Distributes zones, IOC feeds, and settings to DNS servers.
"""

from typing import Dict, List, Optional
from flask import current_app
from datetime import datetime


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
        """
        Get all active IOC feeds with their entries (indicators).

        Returns list of dicts with structure:
        {
            'id': <int>,
            'name': <str>,
            'feed_type': <'domain'|'ip'|'mixed'>,
            'entries': [<normalized indicator str>, ...]
        }
        """
        db = current_app.db

        feeds = db(db.ioc_feed.active == True).select(
            orderby=db.ioc_feed.name
        )

        result = []
        for feed in feeds:
            # Fetch all entries for this feed
            entries = db(db.ioc_entry.feed_id == feed.id).select(
                orderby=db.ioc_entry.indicator
            )

            # Normalize entries: lowercase domains, keep IPs and CIDR as-is
            normalized_entries = []
            for entry in entries:
                if entry.indicator_type == 'domain':
                    # Normalize domain: lowercase and strip trailing dot
                    normalized = entry.indicator.strip().lower().rstrip('.')
                else:
                    # IP or CIDR: use as-is (already normalized at insert)
                    normalized = entry.indicator.strip()
                normalized_entries.append(normalized)

            result.append({
                'id': feed.id,
                'name': feed.name,
                'feed_type': feed.feed_type,
                'entries': normalized_entries
            })

        return result

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
        Increments when zones, IOC feeds, or IOC entries change.

        Version incorporates:
        - Zone and record counts
        - Active feed count
        - IOC entry count (actual indicators)
        - Latest IOC entry modification time
        """
        db = current_app.db

        # Get zone/record counts
        zone_count = db(db.dns_zone.id > 0).count()
        record_count = db(db.dns_record.id > 0).count()

        # Get active feed count and entry count
        feed_count = db(db.ioc_feed.active == True).count()
        entry_count = db(db.ioc_entry.id > 0).count()

        # Get latest IOC entry modification time for change detection
        latest_entry = db(db.ioc_entry.id > 0).select(
            orderby=~db.ioc_entry.updated_at
        ).first()

        # Build version string incorporating all factors
        if latest_entry:
            latest_ts = latest_entry.updated_at.timestamp() if latest_entry.updated_at else 0
        else:
            latest_ts = 0

        version_str = f"{zone_count}:{record_count}:{feed_count}:{entry_count}:{int(latest_ts)}"

        # Generate deterministic version from combined state
        return hash(version_str) % 1000000

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
