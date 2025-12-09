"""
IOC Checker Service
Checks domains against IOC/threat intelligence feeds.
"""
import logging
from typing import Set, Dict, List

logger = logging.getLogger(__name__)


class IOCChecker:
    """IOC/threat intelligence checker."""

    def __init__(self):
        self.blocked_domains: Set[str] = set()
        self.blocked_ips: Set[str] = set()
        self.feed_sources: Dict[str, Dict] = {}

    def load_feeds(self, feeds: List[Dict]):
        """
        Load IOC feeds from Manager config.

        Args:
            feeds: List of IOC feed configurations
        """
        for feed in feeds:
            feed_name = feed.get('name')
            feed_type = feed.get('feed_type', 'domain')
            entries = feed.get('entries', [])

            self.feed_sources[feed_name] = {
                'type': feed_type,
                'count': len(entries)
            }

            if feed_type == 'domain':
                self.blocked_domains.update(entries)
            elif feed_type == 'ip':
                self.blocked_ips.update(entries)

        logger.info(f"Loaded IOC feeds: {len(self.blocked_domains)} domains, {len(self.blocked_ips)} IPs")

    def is_blocked(self, domain: str) -> bool:
        """
        Check if domain is in IOC feeds.

        Args:
            domain: Domain to check

        Returns:
            True if blocked, False otherwise
        """
        # Check exact match
        if domain in self.blocked_domains:
            logger.warning(f"Blocked IOC domain: {domain}")
            return True

        # Check parent domains
        parts = domain.split('.')
        for i in range(len(parts)):
            parent = '.'.join(parts[i:])
            if parent in self.blocked_domains:
                logger.warning(f"Blocked IOC domain (parent): {domain} -> {parent}")
                return True

        return False

    def is_ip_blocked(self, ip: str) -> bool:
        """
        Check if IP is in IOC feeds.

        Args:
            ip: IP address to check

        Returns:
            True if blocked, False otherwise
        """
        if ip in self.blocked_ips:
            logger.warning(f"Blocked IOC IP: {ip}")
            return True

        return False

    def get_stats(self) -> Dict:
        """Get IOC statistics."""
        return {
            'blocked_domains': len(self.blocked_domains),
            'blocked_ips': len(self.blocked_ips),
            'feed_sources': self.feed_sources
        }

    def clear(self):
        """Clear all IOC data."""
        self.blocked_domains.clear()
        self.blocked_ips.clear()
        self.feed_sources.clear()
        logger.info("Cleared all IOC data")
