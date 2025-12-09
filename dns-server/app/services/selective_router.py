"""
Selective DNS Routing Service
Implements per-user/group zone access control.
"""
import logging
import jwt as pyjwt
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class SelectiveRouter:
    """Selective DNS routing based on user tokens and zone visibility."""

    def __init__(self):
        self.zones: Dict[str, Dict] = {}

    def load_zones(self, zones: List[Dict]):
        """
        Load DNS zones from Manager config.

        Args:
            zones: List of zone configurations
        """
        self.zones.clear()

        for zone in zones:
            zone_name = zone.get('name')
            self.zones[zone_name] = {
                'name': zone_name,
                'visibility': zone.get('visibility', 'public'),
                'allowed_teams': zone.get('allowed_teams', []),
                'records': zone.get('records', [])
            }

        logger.info(f"Loaded {len(self.zones)} DNS zones")

    def check_zone_permission(self, domain: str, token: Optional[str] = None) -> bool:
        """
        Check if user/token has permission to access zone for given domain.

        Args:
            domain: Domain being queried
            token: User authentication token (JWT)

        Returns:
            True if allowed, False otherwise
        """
        # Find matching zone
        zone = self._find_zone_for_domain(domain)

        if not zone:
            # No custom zone, allow (will use public DNS)
            return True

        visibility = zone['visibility']

        # Public zones are always accessible
        if visibility == 'public':
            return True

        # Private/internal zones require authentication
        if not token:
            logger.debug(f"Access denied to {visibility} zone {zone['name']}: no token provided")
            return False

        # Parse token to get user teams
        try:
            payload = pyjwt.decode(token, options={"verify_signature": False})
            user_teams = payload.get('teams', [])
            user_id = payload.get('user_id')

            # Check if user's teams are in allowed teams
            allowed_teams = zone.get('allowed_teams', [])

            if visibility == 'internal':
                # Internal: must be member of allowed teams
                if not allowed_teams or any(team in allowed_teams for team in user_teams):
                    return True
                else:
                    logger.debug(f"Access denied to internal zone {zone['name']}: user teams {user_teams} not in {allowed_teams}")
                    return False

            elif visibility == 'restricted':
                # Restricted: must be in specific allowed teams
                if any(team in allowed_teams for team in user_teams):
                    return True
                else:
                    logger.debug(f"Access denied to restricted zone {zone['name']}: user teams {user_teams} not in {allowed_teams}")
                    return False

            elif visibility == 'private':
                # Private: admin only (check for admin role in token)
                is_admin = payload.get('role') == 'admin'
                if is_admin:
                    return True
                else:
                    logger.debug(f"Access denied to private zone {zone['name']}: user is not admin")
                    return False

            else:
                # Unknown visibility, deny
                return False

        except Exception as e:
            logger.error(f"Token parsing error: {e}")
            return False

    def get_zone_records(self, domain: str) -> Optional[List[Dict]]:
        """
        Get DNS records for domain from custom zones.

        Args:
            domain: Domain to look up

        Returns:
            List of records or None if not in custom zones
        """
        zone = self._find_zone_for_domain(domain)

        if zone:
            return zone.get('records', [])

        return None

    def _find_zone_for_domain(self, domain: str) -> Optional[Dict]:
        """Find the zone that matches the given domain."""
        # Check exact match first
        if domain in self.zones:
            return self.zones[domain]

        # Check if domain is subdomain of any zone
        parts = domain.split('.')
        for i in range(len(parts)):
            parent = '.'.join(parts[i:])
            if parent in self.zones:
                return self.zones[parent]

        return None

    def should_serve_zone(self, domain: str, token: Optional[str], mode: str) -> bool:
        """
        Determine if zone should be served based on operational mode.

        Args:
            domain: Domain being queried
            token: User token
            mode: Operational mode (normal, cached, degraded)

        Returns:
            True if should serve, False otherwise
        """
        zone = self._find_zone_for_domain(domain)

        if not zone:
            # Not a custom zone, always serve
            return True

        if mode == 'normal':
            # Full functionality
            return self.check_zone_permission(domain, token)

        elif mode == 'cached':
            # Use cached permissions
            return self.check_zone_permission(domain, token)

        elif mode == 'degraded':
            # Public-only mode
            visibility = zone.get('visibility', 'public')
            return visibility == 'public'

        return False

    def get_stats(self) -> Dict:
        """Get routing statistics."""
        visibility_counts = {}

        for zone in self.zones.values():
            visibility = zone['visibility']
            visibility_counts[visibility] = visibility_counts.get(visibility, 0) + 1

        return {
            'total_zones': len(self.zones),
            'visibility_breakdown': visibility_counts
        }
