"""
Manager Client Service
Handles communication with the Manager API for registration, config sync, and heartbeats.
"""
import requests
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional
import jwt as pyjwt

from app.config import MANAGER_URL, JOIN_KEY, CACHE_DIR

logger = logging.getLogger(__name__)


class ManagerClient:
    """Client for communicating with Manager API."""

    def __init__(self, manager_url: str = MANAGER_URL, join_key: str = JOIN_KEY):
        self.manager_url = manager_url
        self.join_key = join_key
        self.jwt_token: Optional[str] = None
        self.server_id: Optional[str] = None
        self.config_cache: Dict = {}
        self.cached_at: Optional[datetime] = None
        self.cache_file = Path(CACHE_DIR) / 'manager_cache.json'

        # Ensure cache directory exists
        Path(CACHE_DIR).mkdir(parents=True, exist_ok=True)

    def register(self) -> bool:
        """Register with Manager using 64-char hex join key."""
        if not self.join_key:
            logger.error("No join key provided")
            return False

        try:
            response = requests.post(
                f"{self.manager_url}/api/v1/dns-servers/register",
                json={"joinKey": self.join_key},
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                self.jwt_token = data['jwt']
                self.server_id = data['serverId']
                self.config_cache = data.get('config', {})
                self.cached_at = datetime.now()

                # Cache JWT and config to disk for resilience
                self.save_to_cache()
                logger.info(f"Successfully registered with Manager as server {self.server_id}")
                return True
            else:
                logger.error(f"Registration failed: {response.status_code} - {response.text}")
                return False

        except requests.RequestException as e:
            logger.error(f"Failed to register with Manager: {e}")
            return False

    def refresh_jwt(self) -> bool:
        """Refresh JWT token before expiration."""
        if not self.jwt_token:
            logger.info("No JWT token, attempting registration")
            return self.register()

        try:
            response = requests.post(
                f"{self.manager_url}/api/v1/dns-servers/{self.server_id}/refresh",
                headers={"Authorization": f"Bearer {self.jwt_token}"},
                timeout=10
            )

            if response.status_code == 200:
                self.jwt_token = response.json()['jwt']
                self.save_to_cache()
                logger.info("JWT token refreshed successfully")
                return True
            else:
                logger.warning(f"JWT refresh failed: {response.status_code}, attempting re-registration")
                return self.register()

        except requests.RequestException as e:
            logger.error(f"Failed to refresh JWT: {e}")
            return False

    def sync_config(self) -> bool:
        """Fetch latest config from Manager."""
        if not self.jwt_token or not self.server_id:
            logger.warning("Cannot sync config: not registered")
            return False

        try:
            response = requests.get(
                f"{self.manager_url}/api/v1/dns-servers/{self.server_id}/config",
                headers={"Authorization": f"Bearer {self.jwt_token}"},
                timeout=10
            )

            if response.status_code == 200:
                self.config_cache = response.json()
                self.cached_at = datetime.now()
                self.save_to_cache()
                logger.info("Config synced successfully from Manager")
                return True
            elif response.status_code == 401:
                logger.warning("JWT expired, refreshing token")
                if self.refresh_jwt():
                    return self.sync_config()
                return False
            else:
                logger.error(f"Config sync failed: {response.status_code}")
                return False

        except requests.RequestException as e:
            logger.warning(f"Manager unreachable during config sync: {e}, using cached config")
            return False

    def heartbeat(self, metrics: Dict) -> bool:
        """Send heartbeat with metrics to Manager."""
        if not self.jwt_token or not self.server_id:
            logger.debug("Cannot send heartbeat: not registered")
            return False

        try:
            response = requests.post(
                f"{self.manager_url}/api/v1/dns-servers/{self.server_id}/heartbeat",
                headers={"Authorization": f"Bearer {self.jwt_token}"},
                json=metrics,
                timeout=5
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('shouldSync'):
                    logger.info("Manager requested config sync")
                    self.sync_config()
                return True
            elif response.status_code == 401:
                logger.warning("JWT expired during heartbeat")
                self.refresh_jwt()
                return False
            else:
                logger.warning(f"Heartbeat failed: {response.status_code}")
                return False

        except requests.RequestException as e:
            logger.debug(f"Manager unreachable during heartbeat: {e}")
            return False

    def validate_token(self, token: str, domain: str) -> Dict:
        """Validate user token with Manager (cached)."""
        if not self.jwt_token or not self.server_id:
            return {'valid': False}

        try:
            response = requests.post(
                f"{self.manager_url}/api/v1/tokens/validate",
                headers={"Authorization": f"Bearer {self.jwt_token}"},
                json={"token": token, "domain": domain},
                timeout=5
            )

            if response.status_code == 200:
                return response.json()
            else:
                return {'valid': False}

        except requests.RequestException as e:
            logger.debug(f"Token validation failed: {e}")
            return {'valid': False}

    def save_to_cache(self):
        """Persist JWT and config to disk for resilience."""
        try:
            cache_data = {
                'jwt_token': self.jwt_token,
                'server_id': self.server_id,
                'config': self.config_cache,
                'cached_at': self.cached_at.isoformat() if self.cached_at else None
            }

            with open(self.cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)

            logger.debug("Cache saved to disk")

        except Exception as e:
            logger.error(f"Failed to save cache: {e}")

    def load_from_cache(self) -> bool:
        """Load cached JWT and config from disk."""
        try:
            if not self.cache_file.exists():
                logger.info("No cache file found")
                return False

            with open(self.cache_file, 'r') as f:
                cache_data = json.load(f)

            self.jwt_token = cache_data.get('jwt_token')
            self.server_id = cache_data.get('server_id')
            self.config_cache = cache_data.get('config', {})
            cached_at_str = cache_data.get('cached_at')

            if cached_at_str:
                self.cached_at = datetime.fromisoformat(cached_at_str)
            else:
                self.cached_at = None

            logger.info("Cache loaded from disk")
            return True

        except Exception as e:
            logger.error(f"Failed to load cache: {e}")
            return False

    def is_jwt_valid(self) -> bool:
        """Check if current JWT token is valid (not expired).

        NOTE: This is an expiry-only self-check of the server's own token (obtained from Manager).
        Signature verification is intentionally disabled here because we are checking the server's
        own cached token, not making authorization decisions. Authorization decisions in
        selective_router.py and resilience.py DO verify signatures on user-supplied tokens.
        """
        if not self.jwt_token:
            return False

        try:
            payload = pyjwt.decode(
                self.jwt_token,
                options={"verify_signature": False}
            )
            exp = datetime.fromtimestamp(payload['exp'])

            # Check if token expires within next 5 minutes
            return datetime.now() < (exp - timedelta(minutes=5))

        except Exception as e:
            logger.error(f"JWT validation error: {e}")
            return False
