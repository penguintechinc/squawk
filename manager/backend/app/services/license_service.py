"""
License service for Squawk DNS Manager.
Validates with https://license.squawkdns.com and gates SSO features.
"""

from typing import Dict
import requests
import os
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


class LicenseService:
    """Service for license validation and feature gating."""

    def __init__(self):
        self.license_key = os.getenv('PENGUINTECH_LICENSE_KEY')
        self.base_url = os.getenv('PENGUINTECH_LICENSE_SERVER',
                                   'https://license.squawkdns.com')
        self.product = 'squawkdns'
        self.cache = {}
        self.cache_expiry = None

    def validate_license(self) -> Dict:
        """
        Validate license with caching (24-hour TTL).

        Returns:
            Dict with validation result, tier, and features
        """
        # Check cache
        if self.cache and self.cache_expiry and datetime.now() < self.cache_expiry:
            return self.cache

        if not self.license_key:
            logger.info("No license key provided, using community features")
            return {
                'valid': False,
                'tier': 'community',
                'features': self._get_community_features()
            }

        try:
            response = requests.post(
                f"{self.base_url}/api/v2/validate",
                headers={"Authorization": f"Bearer {self.license_key}"},
                json={"product": self.product},
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                self.cache = data
                self.cache_expiry = datetime.now() + timedelta(hours=24)
                logger.info(f"License validated: tier={data.get('tier', 'unknown')}")
                return data

            logger.warning(f"License validation failed: {response.status_code}")

        except requests.RequestException as e:
            logger.warning(f"License server unreachable: {e}")
            # Use cache if available
            if self.cache:
                logger.info("Using cached license validation")
                return self.cache

        # Default to community features
        return {
            'valid': False,
            'tier': 'community',
            'features': self._get_community_features()
        }

    def is_feature_enabled(self, feature_name: str) -> bool:
        """
        Check if a specific feature is enabled.

        Args:
            feature_name: Feature name to check

        Returns:
            True if feature is enabled, False otherwise
        """
        validation = self.validate_license()

        # SSO features are enterprise-only
        sso_features = [
            'sso_authentication',
            'ldap_integration',
            'oauth2_integration',
            'saml_integration'
        ]

        if feature_name in sso_features:
            # Check if enterprise tier
            if validation.get('tier') not in ['enterprise', 'enterprise_self_hosted', 'enterprise_cloud']:
                return False

            # Check feature entitlement
            features = {f['name']: f for f in validation.get('features', [])}
            feature = features.get(feature_name, {})
            return feature.get('entitled', False)

        # All other features are open source
        return True

    def get_tier(self) -> str:
        """
        Get current license tier.

        Returns:
            License tier: 'community', 'enterprise_self_hosted', or 'enterprise_cloud'
        """
        validation = self.validate_license()
        return validation.get('tier', 'community')

    def is_enterprise(self) -> bool:
        """Check if current license is any enterprise tier."""
        tier = self.get_tier()
        return tier in ['enterprise', 'enterprise_self_hosted', 'enterprise_cloud']

    def get_features(self) -> list:
        """Get list of enabled features."""
        validation = self.validate_license()
        return validation.get('features', self._get_community_features())

    def _get_community_features(self) -> list:
        """
        Return community (open source) features.

        Returns:
            List of feature dicts with name and entitled status
        """
        return [
            {'name': 'dns_server', 'entitled': True},
            {'name': 'basic_auth', 'entitled': True},
            {'name': 'token_auth', 'entitled': True},
            {'name': 'mfa', 'entitled': True},
            {'name': 'rbac', 'entitled': True},
            {'name': 'team_management', 'entitled': True},
            {'name': 'ioc_feeds', 'entitled': True},
            {'name': 'whois_lookup', 'entitled': True},
            {'name': 'analytics', 'entitled': True},
            {'name': 'prometheus_metrics', 'entitled': True},
            {'name': 'web_console', 'entitled': True},
            {'name': 'cache_management', 'entitled': True},
            {'name': 'dns_zones', 'entitled': True},
            {'name': 'selective_routing', 'entitled': True},
        ]

    def get_license_info(self) -> Dict:
        """
        Get license information for display.

        Returns:
            Dict with tier, features, and status
        """
        validation = self.validate_license()

        return {
            'tier': validation.get('tier', 'community'),
            'valid': validation.get('valid', False),
            'features': validation.get('features', []),
            'is_enterprise': self.is_enterprise(),
            'sso_enabled': self.is_feature_enabled('sso_authentication'),
            'cached': self.cache_expiry is not None and datetime.now() < self.cache_expiry
        }
