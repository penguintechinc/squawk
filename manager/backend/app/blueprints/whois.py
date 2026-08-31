"""
WHOIS lookup API blueprint.
Handles domain and IP address WHOIS queries with caching and search.
"""

import os
from functools import wraps
from flask import Blueprint, request, jsonify, current_app
from app.middleware.auth import token_required
from app.utils.responses import internal_error

whois_bp = Blueprint('whois', __name__)


def _get_deployment_id() -> str:
    """Get stable deployment identifier for PostHog flag checks."""
    return os.getenv('HOSTNAME', 'squawk-manager')


def _check_whois_flag():
    """
    Decorator to enforce PostHog flag gating for WHOIS operations.

    - PostHog flag 'squawkdns.whois-lookup' must be enabled

    Returns 403 if flag disabled.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check PostHog flag
            posthog = current_app.posthog
            distinct_id = _get_deployment_id()
            flag_enabled = posthog.feature_enabled(
                'squawkdns.whois-lookup',
                distinct_id,
                default=False,
            )

            if not flag_enabled:
                return jsonify({
                    'error': 'WHOIS lookup feature is disabled',
                    'feature_flag': 'squawkdns.whois-lookup',
                }), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator


@whois_bp.route('/api/v1/whois/domain/<domain>', methods=['GET'])
@token_required
@_check_whois_flag()
def lookup_domain(domain: str):
    """
    Lookup WHOIS information for a domain.

    Args:
        domain: Domain name to lookup

    Response:
        {
            "success": true,
            "domain": "example.com",
            "registrar": "Example Registrar",
            "creation_date": "2010-01-01T00:00:00",
            "expiration_date": "2025-01-01T00:00:00",
            "nameservers": ["ns1.example.com", "ns2.example.com"],
            "cached": false
        }

    Status codes:
        200: Successful lookup
        400: Invalid domain
        403: Feature disabled
        502: Lookup service error
        500: Internal error
    """
    import asyncio
    try:
        whois_manager = current_app.whois_manager
        client_ip = request.remote_addr

        # Validate domain format
        if not domain or len(domain) > 255:
            return jsonify({
                'error': 'Invalid domain format',
                'domain': domain,
            }), 400

        # Perform async lookup
        result = asyncio.run(
            whois_manager.lookup_domain(domain, client_ip=client_ip)
        )

        if result.get('success'):
            return jsonify(result), 200
        elif 'Invalid' in result.get('error', ''):
            return jsonify(result), 400
        else:
            # Lookup failed (timeout, network error, etc)
            return jsonify(result), 502

    except Exception as e:
        return internal_error(e, message='WHOIS domain lookup failed')


@whois_bp.route('/api/v1/whois/ip/<ip>', methods=['GET'])
@token_required
@_check_whois_flag()
def lookup_ip(ip: str):
    """
    Lookup WHOIS information for an IP address.

    Args:
        ip: IP address to lookup (IPv4 or IPv6)

    Response:
        {
            "success": true,
            "ip": "192.0.2.1",
            "network_name": "EXAMPLE-NET",
            "country": "US",
            "cached": false
        }

    Status codes:
        200: Successful lookup
        400: Invalid IP address
        403: Feature disabled
        502: Lookup service error
        500: Internal error
    """
    import asyncio
    try:
        whois_manager = current_app.whois_manager
        client_ip = request.remote_addr

        # Validate IP format
        if not ip or len(ip) > 45:
            return jsonify({
                'error': 'Invalid IP address format',
                'ip': ip,
            }), 400

        # Perform async lookup
        result = asyncio.run(
            whois_manager.lookup_ip(ip, client_ip=client_ip)
        )

        if result.get('success'):
            return jsonify(result), 200
        elif 'Invalid' in result.get('error', ''):
            return jsonify(result), 400
        else:
            # Lookup failed (timeout, network error, etc)
            return jsonify(result), 502

    except Exception as e:
        return internal_error(e, message='WHOIS IP lookup failed')


@whois_bp.route('/api/v1/whois/search', methods=['GET'])
@token_required
@_check_whois_flag()
def search_whois():
    """
    Search cached WHOIS data.

    Query params:
        - q: Search term (required)
        - field: Search field (registrar, organization, nameserver, or None for all)
        - limit: Maximum results to return (default 50, max 1000)

    Response:
        [
            {
                "query": "example.com",
                "query_type": "domain",
                "data": { ... }
            }
        ]

    Status codes:
        200: Search successful
        400: Missing search term
        403: Feature disabled
        500: Internal error
    """
    import asyncio
    try:
        search_term = request.args.get('q', '').strip()
        search_field = request.args.get('field')
        limit_str = request.args.get('limit', '50')

        if not search_term:
            return jsonify({
                'error': 'Search term required (q parameter)',
            }), 400

        try:
            limit = int(limit_str)
            if limit < 1 or limit > 1000:
                limit = 50
        except (ValueError, TypeError):
            limit = 50

        whois_manager = current_app.whois_manager

        # Perform async search
        results = asyncio.run(
            whois_manager.search_whois(search_term, search_field, limit)
        )

        return jsonify(results), 200

    except Exception as e:
        return internal_error(e, message='WHOIS search failed')


@whois_bp.route('/api/v1/whois/stats', methods=['GET'])
@token_required
@_check_whois_flag()
def get_whois_stats():
    """
    Get WHOIS service statistics.

    Response:
        {
            "queries": {
                "total": 100,
                "domain_queries": 60,
                "ip_queries": 40
            },
            "cache": {
                "total_entries": 50,
                "domain_entries": 30,
                "ip_entries": 20
            }
        }

    Status codes:
        200: Stats retrieved
        403: Feature disabled
        500: Internal error
    """
    import asyncio
    try:
        whois_manager = current_app.whois_manager

        # Get stats asynchronously
        stats = asyncio.run(whois_manager.get_stats())

        return jsonify(stats), 200

    except Exception as e:
        return internal_error(e, message='WHOIS stats lookup failed')
