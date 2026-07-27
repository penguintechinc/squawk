"""
IOC Checker Service
Checks domains against IOC/threat intelligence feeds.
Supports exact domain match, wildcard match, parent domain match, and IP/CIDR matching.
"""
import logging
import ipaddress
from typing import Set, Dict, List

logger = logging.getLogger(__name__)


class IOCChecker:
    """IOC/threat intelligence checker with domain wildcard and IP/CIDR support."""

    def __init__(self):
        self.blocked_domains: Set[str] = set()
        self.wildcard_domains: Set[str] = set()  # e.g., '*.example.com'
        self.blocked_ips: Set[str] = set()  # Plain IPs
        self.blocked_cidrs: List = []  # ipaddress.IPv4Network/IPv6Network objects
        self.feed_sources: Dict[str, Dict] = {}

    def load_feeds(self, feeds: List[Dict]):
        """
        Load IOC feeds from Manager config.

        Contract: Each feed is a dict with:
        - id: int
        - name: str
        - feed_type: "domain" | "ip" | "mixed"
        - entries: [normalized indicators] (lowercase domains, IPs, or CIDR strings)

        Args:
            feeds: List of IOC feed configurations
        """
        self.clear()  # Reset before loading new feeds

        for feed in feeds:
            feed_id = feed.get('id')
            feed_name = feed.get('name')
            feed_type = feed.get('feed_type', 'domain')
            entries = feed.get('entries', [])

            domain_count = 0
            ip_count = 0

            for entry in entries:
                if not entry:
                    continue

                # Normalize entry: strip trailing dot, lowercase
                normalized = entry.strip().rstrip('.').lower()

                # Try to parse as IP or CIDR
                if self._try_load_ip_or_cidr(normalized):
                    ip_count += 1
                else:
                    # Treat as domain (or wildcard)
                    if normalized.startswith('*.'):
                        self.wildcard_domains.add(normalized)
                    else:
                        self.blocked_domains.add(normalized)
                    domain_count += 1

            self.feed_sources[feed_name] = {
                'id': feed_id,
                'type': feed_type,
                'domains': domain_count,
                'ips': ip_count,
                'total': len(entries)
            }

        logger.info(
            f"Loaded IOC feeds: {len(self.blocked_domains)} exact domains, "
            f"{len(self.wildcard_domains)} wildcard domains, "
            f"{len(self.blocked_ips)} plain IPs, "
            f"{len(self.blocked_cidrs)} CIDRs"
        )

    def _try_load_ip_or_cidr(self, entry: str) -> bool:
        """
        Try to parse entry as IP address or CIDR block.

        Args:
            entry: Normalized entry string (lowercase, no trailing dot)

        Returns:
            True if parsed as IP/CIDR and loaded, False otherwise
        """
        try:
            # Try CIDR first (covers both IPs and ranges)
            network = ipaddress.ip_network(entry, strict=False)
            if network.num_addresses == 1:
                # Single IP address
                self.blocked_ips.add(str(network.network_address))
            else:
                # CIDR block
                self.blocked_cidrs.append(network)
            return True
        except ValueError:
            # Not a valid IP or CIDR
            return False

    def is_blocked(self, domain: str) -> bool:
        """
        Check if domain is blocked by IOC feeds.
        Supports exact match, wildcard match (*.example.com), and parent domain match.

        Args:
            domain: Domain to check (will be normalized)

        Returns:
            True if blocked, False otherwise
        """
        # Normalize: strip trailing dot, lowercase
        normalized = domain.strip().rstrip('.').lower()

        # Check exact match
        if normalized in self.blocked_domains:
            logger.warning(f"Blocked IOC domain (exact): {domain}")
            return True

        # Check wildcard patterns
        if self._check_wildcard(normalized):
            logger.warning(f"Blocked IOC domain (wildcard): {domain}")
            return True

        # Check parent domains
        parts = normalized.split('.')
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if parent in self.blocked_domains:
                logger.warning(f"Blocked IOC domain (parent): {domain} -> {parent}")
                return True

        return False

    def _check_wildcard(self, domain: str) -> bool:
        """
        Check if domain matches any wildcard pattern.
        e.g., *.example.com matches sub.example.com

        Args:
            domain: Normalized domain (lowercase, no trailing dot)

        Returns:
            True if matches any wildcard, False otherwise
        """
        for wildcard in self.wildcard_domains:
            # wildcard is *.example.com, remove the *. prefix
            pattern = wildcard[2:]  # Remove '*.'
            if domain.endswith('.' + pattern) or domain == pattern:
                return True
        return False

    def is_ip_blocked(self, ip: str) -> bool:
        """
        Check if IP address is blocked by IOC feeds.
        Supports exact IP and CIDR membership checking.

        Args:
            ip: IP address string to check

        Returns:
            True if blocked, False otherwise
        """
        ip_normalized = ip.strip().lower()

        # Check exact IP match
        if ip_normalized in self.blocked_ips:
            logger.warning(f"Blocked IOC IP (exact): {ip}")
            return True

        # Check CIDR membership
        try:
            ip_obj = ipaddress.ip_address(ip_normalized)
            for cidr in self.blocked_cidrs:
                if ip_obj in cidr:
                    logger.warning(f"Blocked IOC IP (CIDR {cidr}): {ip}")
                    return True
        except ValueError:
            logger.warning(f"Invalid IP address format: {ip}")
            return False

        return False

    def get_stats(self) -> Dict:
        """Get IOC statistics."""
        return {
            'blocked_domains': len(self.blocked_domains),
            'wildcard_domains': len(self.wildcard_domains),
            'blocked_ips': len(self.blocked_ips),
            'blocked_cidrs': len(self.blocked_cidrs),
            'feed_sources': self.feed_sources
        }

    def clear(self):
        """Clear all IOC data."""
        self.blocked_domains.clear()
        self.wildcard_domains.clear()
        self.blocked_ips.clear()
        self.blocked_cidrs.clear()
        self.feed_sources.clear()
        logger.info("Cleared all IOC data")
