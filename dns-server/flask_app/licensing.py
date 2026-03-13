"""
License Feature Gates for Squawk DNS
Integrates with PenguinTech License Server for feature gating.
Gracefully degrades when RELEASE_MODE=false (development).
"""

import os

RELEASE_MODE = os.environ.get('RELEASE_MODE', 'false').lower() == 'true'
LICENSE_KEY = os.environ.get('LICENSE_KEY', '')
LICENSE_SERVER_URL = os.environ.get('LICENSE_SERVER_URL', 'https://license.penguintech.io')
PRODUCT_NAME = os.environ.get('PRODUCT_NAME', 'squawk')

# Feature constants
FEATURE_SELECTIVE_ROUTING = 'selective_dns_routing'
FEATURE_IOC_BLOCKING_PREMIUM = 'ioc_blocking_premium'
FEATURE_ADVANCED_ANALYTICS = 'advanced_analytics'
FEATURE_SSO = 'sso'
FEATURE_GRPC = 'grpc_api'


def has_feature(feature_name: str) -> bool:
    """
    Check if a feature is available based on license.

    In development mode (RELEASE_MODE=false), all features are available.
    In production mode, validates against the license server.

    Args:
        feature_name: Feature identifier string

    Returns:
        True if feature is available, False otherwise
    """
    if not RELEASE_MODE:
        # Development: all features available
        return True

    if not LICENSE_KEY:
        return False

    try:
        import requests
        response = requests.post(
            f'{LICENSE_SERVER_URL}/api/v2/features',
            json={'license_key': LICENSE_KEY, 'features': [feature_name]},
            timeout=5
        )
        if response.status_code == 200:
            return feature_name in response.json().get('enabled_features', [])
    except Exception:
        pass

    return False


def require_feature(feature_name: str):
    """
    Decorator factory to gate Flask endpoints behind a license feature.

    Usage:
        @require_feature(FEATURE_SSO)
        def my_endpoint():
            ...
    """
    from functools import wraps
    from flask import jsonify

    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not has_feature(feature_name):
                return jsonify({
                    'error': 'Feature not available',
                    'feature': feature_name,
                    'message': 'This feature requires a valid license. '
                               'Contact sales@penguintech.io for licensing.'
                }), 402
            return f(*args, **kwargs)
        return wrapped
    return decorator
