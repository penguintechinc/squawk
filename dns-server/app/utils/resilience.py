"""
Resilience Manager
Implements graceful degradation strategy: normal → cached → degraded.
"""
import logging
from datetime import datetime, timedelta
from typing import Optional

from app.services.manager_client import ManagerClient
from app.config import JWT_PUBLIC_KEY
from app.utils.jwt_verify import verify_squawk_jwt

logger = logging.getLogger(__name__)


class ResilienceManager:
    """Manages operational mode and graceful degradation."""

    def __init__(self, manager_client: ManagerClient, cache_ttl_hours: int = 24):
        self.manager_client = manager_client
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        self.mode = 'normal'  # normal, cached, degraded

    def check_mode(self) -> str:
        """
        Determine current operational mode.

        Returns:
            'normal', 'cached', or 'degraded'
        """
        # Check if we have a valid JWT token
        if self.manager_client.is_jwt_valid():
            self.mode = 'normal'
            return 'normal'

        # JWT invalid or expired, try to refresh
        if self.manager_client.refresh_jwt():
            self.mode = 'normal'
            return 'normal'

        # Cannot refresh JWT, check cache age
        if self.manager_client.cached_at:
            cache_age = datetime.now() - self.manager_client.cached_at

            if cache_age < self.cache_ttl:
                # Cache still valid
                if self.mode != 'cached':
                    logger.warning("Operating in CACHED mode (Manager unreachable)")
                self.mode = 'cached'
                return 'cached'

        # Cache expired or no cache
        if self.mode != 'degraded':
            logger.error("Operating in DEGRADED mode (public-only DNS)")
        self.mode = 'degraded'
        return 'degraded'

    def should_serve_zone(self, zone_name: Optional[str], token: Optional[str]) -> bool:
        """
        Determine if zone should be served based on current mode.

        Args:
            zone_name: Zone being accessed
            token: User token

        Returns:
            True if should serve, False otherwise
        """
        mode = self.check_mode()

        # If no custom zone, always serve
        if not zone_name:
            return True

        # Get zone info from cached config
        zones = self.manager_client.config_cache.get('zones', [])
        zone = None

        for z in zones:
            if z.get('name') == zone_name:
                zone = z
                break

        if not zone:
            # Zone not found, allow (will use public DNS)
            return True

        visibility = zone.get('visibility', 'public')

        if mode == 'normal':
            # Full functionality, check permissions
            return self._check_zone_permission(zone, token)

        elif mode == 'cached':
            # Use cached config, still enforce permissions
            return self._check_zone_permission(zone, token)

        elif mode == 'degraded':
            # Public-only mode
            return visibility == 'public'

        return False

    def _check_zone_permission(self, zone: dict, token: Optional[str]) -> bool:
        """Check if token has permission for zone."""
        visibility = zone.get('visibility', 'public')

        # Public zones always accessible
        if visibility == 'public':
            return True

        # Private zones require token
        if not token:
            return False

        # Verify JWT via the shared verifier (ES256/RS256, iss/aud, required
        # exp/iat/tenant, fail closed) — team authorization stays here.
        payload = verify_squawk_jwt(token, JWT_PUBLIC_KEY)
        if payload is None:
            return False

        user_teams = list(payload.get('team_roles', {}).keys()) if payload.get('team_roles') else []
        allowed_teams = zone.get('allowed_teams', [])

        # Check team membership
        if not allowed_teams:
            # No team restrictions
            return True

        # User must be in at least one allowed team
        return any(team in allowed_teams for team in user_teams)

    def get_mode(self) -> str:
        """Get current operational mode."""
        return self.mode

    def get_status(self) -> dict:
        """Get resilience status information."""
        mode = self.check_mode()

        status = {
            'mode': mode,
            'jwt_valid': self.manager_client.is_jwt_valid(),
            'has_cache': bool(self.manager_client.cached_at),
        }

        if self.manager_client.cached_at:
            cache_age = datetime.now() - self.manager_client.cached_at
            status['cache_age_seconds'] = cache_age.total_seconds()
            status['cache_ttl_seconds'] = self.cache_ttl.total_seconds()
            status['cache_expires_in_seconds'] = (
                self.cache_ttl.total_seconds() - cache_age.total_seconds()
            )

        return status
