"""
IOC Feed management API blueprint.
Handles threat intelligence feed configuration.
"""

import os
from functools import wraps
from typing import Optional
from flask import Blueprint, request, jsonify, current_app
from app.middleware.auth import token_required
from app.middleware.rbac import requires_system_admin, requires_role
from app.utils.decorators import validate_json, audit_log

ioc_feeds_bp = Blueprint('ioc_feeds', __name__)

# Enterprise-only feed formats
ENTERPRISE_FORMATS = {'taxii', 'misp', 'stix', 'openioc'}
COMMUNITY_FORMATS = {'txt', 'csv', 'json', 'xml'}


def _get_deployment_id() -> str:
    """Get stable deployment identifier for PostHog flag checks."""
    return os.getenv('HOSTNAME', 'squawk-manager')


def _check_ioc_flag_and_license(format_type: Optional[str] = None):
    """
    Decorator to enforce PostHog flag + license gating for IOC operations.

    - PostHog flag 'squawkdns.ioc-ingestion' must be enabled
    - If format_type is enterprise, license feature 'ioc_advanced_feeds' must be enabled

    Returns 403 if flag disabled, 402 if license required but not available.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check PostHog flag
            posthog = current_app.posthog
            distinct_id = _get_deployment_id()
            flag_enabled = posthog.feature_enabled(
                'squawkdns.ioc-ingestion',
                distinct_id,
                default=False,
            )

            if not flag_enabled:
                return jsonify({
                    'error': 'IOC ingestion feature is disabled',
                    'feature_flag': 'squawkdns.ioc-ingestion',
                }), 403

            # Check license for enterprise formats
            # Get format from request data or kwargs
            fmt = format_type
            if not fmt and request.is_json:
                data = request.get_json()
                fmt = data.get('format') if data else None

            if fmt and fmt.lower() in ENTERPRISE_FORMATS:
                license_service = current_app.license_service
                if not license_service.is_feature_enabled('ioc_advanced_feeds'):
                    tier = license_service.get_tier()
                    return jsonify({
                        'error': 'Advanced IOC formats require Enterprise license',
                        'feature': 'ioc_advanced_feeds',
                        'format': fmt,
                        'tier_required': 'enterprise',
                        'current_tier': tier,
                    }), 402

            return f(*args, **kwargs)
        return decorated_function
    return decorator


@ioc_feeds_bp.route('/api/v1/ioc-feeds', methods=['GET'])
@token_required
def list_ioc_feeds():
    """
    List all IOC feeds.

    Query params:
        - active: Filter by active status (true/false)
        - type: Filter by feed type (domain/ip/url/hash)

    Response:
        [
            {
                "id": 1,
                "name": "URLhaus Malware URLs",
                "url": "https://urlhaus.abuse.ch/downloads/csv/",
                "feed_type": "url",
                "update_interval": 24,
                "last_updated": "2024-01-01T00:00:00",
                "active": true
            }
        ]
    """
    db = current_app.db

    query = db.ioc_feed

    # Apply filters
    active_filter = request.args.get('active')
    if active_filter is not None:
        active_bool = active_filter.lower() == 'true'
        query = query(db.ioc_feed.active == active_bool)

    feed_type = request.args.get('type')
    if feed_type:
        query = query(db.ioc_feed.feed_type == feed_type)

    feeds = query.select(orderby=db.ioc_feed.name)

    return jsonify([
        {
            'id': feed.id,
            'name': feed.name,
            'url': feed.url,
            'feed_type': feed.feed_type,
            'update_interval': feed.update_interval,
            'last_updated': feed.last_updated.isoformat() if feed.last_updated else None,
            'active': feed.active,
            'description': feed.description,
            'created_at': feed.created_at.isoformat()
        }
        for feed in feeds
    ]), 200


@ioc_feeds_bp.route('/api/v1/ioc-feeds', methods=['POST'])
@token_required
@requires_system_admin
@validate_json('name', 'url', 'feed_type')
@_check_ioc_flag_and_license()
@audit_log('ioc_feed_created')
def create_ioc_feed():
    """
    Create a new IOC feed.

    Request:
        {
            "name": "URLhaus Malware URLs",
            "url": "https://urlhaus.abuse.ch/downloads/csv/",
            "feed_type": "url",
            "update_interval": 24,
            "description": "Malware URL feed",
            "active": true
        }

    Response:
        {
            "id": 1,
            "name": "URLhaus Malware URLs",
            "url": "https://urlhaus.abuse.ch/downloads/csv/",
            "feed_type": "url",
            "active": true
        }
    """
    data = request.get_json()
    db = current_app.db

    # Validate feed type
    valid_types = ['domain', 'ip', 'url', 'hash']
    if data['feed_type'] not in valid_types:
        return jsonify({'error': 'Invalid feed type'}), 400

    # Check if feed name already exists
    if db(db.ioc_feed.name == data['name']).count() > 0:
        return jsonify({'error': 'IOC feed name already exists'}), 409

    # Create feed
    feed_id = db.ioc_feed.insert(
        name=data['name'],
        url=data['url'],
        feed_type=data['feed_type'],
        update_interval=data.get('update_interval', 24),
        description=data.get('description', ''),
        active=data.get('active', True)
    )

    db.commit()

    feed = db.ioc_feed[feed_id]

    return jsonify({
        'id': feed.id,
        'name': feed.name,
        'url': feed.url,
        'feed_type': feed.feed_type,
        'update_interval': feed.update_interval,
        'active': feed.active,
        'description': feed.description,
        'created_at': feed.created_at.isoformat()
    }), 201


@ioc_feeds_bp.route('/api/v1/ioc-feeds/<int:feed_id>', methods=['GET'])
@token_required
def get_ioc_feed(feed_id):
    """Get IOC feed details."""
    db = current_app.db
    feed = db.ioc_feed[feed_id]

    if not feed:
        return jsonify({'error': 'IOC feed not found'}), 404

    return jsonify({
        'id': feed.id,
        'name': feed.name,
        'url': feed.url,
        'feed_type': feed.feed_type,
        'update_interval': feed.update_interval,
        'last_updated': feed.last_updated.isoformat() if feed.last_updated else None,
        'active': feed.active,
        'description': feed.description,
        'created_at': feed.created_at.isoformat()
    }), 200


@ioc_feeds_bp.route('/api/v1/ioc-feeds/<int:feed_id>', methods=['PUT'])
@token_required
@requires_system_admin
@_check_ioc_flag_and_license()
@audit_log('ioc_feed_updated')
def update_ioc_feed(feed_id):
    """
    Update IOC feed.

    Request:
        {
            "url": "https://new-url.example.com",
            "update_interval": 12,
            "active": false
        }
    """
    db = current_app.db
    feed = db.ioc_feed[feed_id]

    if not feed:
        return jsonify({'error': 'IOC feed not found'}), 404

    data = request.get_json()
    update_fields = {}

    if 'url' in data:
        update_fields['url'] = data['url']

    if 'update_interval' in data:
        update_fields['update_interval'] = int(data['update_interval'])

    if 'active' in data:
        update_fields['active'] = bool(data['active'])

    if 'description' in data:
        update_fields['description'] = data['description']

    feed.update_record(**update_fields)
    db.commit()

    return jsonify({
        'id': feed.id,
        'name': feed.name,
        'url': feed.url,
        'feed_type': feed.feed_type,
        'update_interval': feed.update_interval,
        'active': feed.active
    }), 200


@ioc_feeds_bp.route('/api/v1/ioc-feeds/<int:feed_id>', methods=['DELETE'])
@token_required
@requires_system_admin
@_check_ioc_flag_and_license()
@audit_log('ioc_feed_deleted')
def delete_ioc_feed(feed_id):
    """Delete IOC feed."""
    db = current_app.db
    feed = db.ioc_feed[feed_id]

    if not feed:
        return jsonify({'error': 'IOC feed not found'}), 404

    del db.ioc_feed[feed_id]
    db.commit()

    return jsonify({
        'message': 'IOC feed deleted successfully'
    }), 200


@ioc_feeds_bp.route('/api/v1/ioc-feeds/<int:feed_id>/sync', methods=['POST'])
@token_required
@requires_system_admin
@_check_ioc_flag_and_license()
@audit_log('ioc_feed_sync_triggered')
def trigger_ioc_feed_sync(feed_id):
    """
    Trigger immediate IOC feed sync (fetch from URL and ingest).

    Response:
        {
            "message": "Feed sync successful",
            "feed_id": 1,
            "feed_name": "URLhaus",
            "indicators_added": 150
        }

    Error responses:
        400: Feed URL is empty/invalid
        404: Feed not found
        500: Sync failed (network error, parse error, etc.)
    """
    import asyncio
    import aiohttp
    from datetime import datetime
    from app.services.ioc_ingestion_service import IOCManager, _assert_feed_url_safe

    db = current_app.db
    feed = db.ioc_feed[feed_id]

    if not feed:
        return jsonify({'error': 'IOC feed not found'}), 404

    # Validate feed has a URL
    if not feed.url or not feed.url.strip():
        return jsonify({'error': 'Feed URL is empty. Manual upload not yet implemented.'}), 400

    try:
        # Fetch feed content
        async def fetch_and_ingest():
            # SSRF guard: reject internal/metadata targets before fetching,
            # and do not follow redirects (an allowed host could 302 to 169.254.169.254).
            await _assert_feed_url_safe(feed.url)
            async with aiohttp.ClientSession() as session:
                async with session.get(feed.url, timeout=60, allow_redirects=False) as response:
                    if response.status != 200:
                        raise Exception(f"HTTP {response.status} from {feed.url}")
                    content = await response.text()

                    # Use IOCManager to ingest content
                    ioc_mgr = IOCManager(current_app.config['DB_URL'])
                    result = await ioc_mgr.update_feed_from_content(
                        name=feed.name,
                        content=content,
                        feed_type=feed.feed_type,
                        format_type=feed.format or 'txt'
                    )
                    return result

        # Run async ingestion in sync context
        result = asyncio.run(fetch_and_ingest())

        if not result.get('success'):
            error_msg = result.get('error', 'Unknown ingestion error')
            return jsonify({
                'error': f'Feed ingestion failed: {error_msg}',
                'feed_id': feed_id,
                'feed_name': feed.name
            }), 500

        # Update feed metadata on success
        feed.update_record(
            last_updated=datetime.utcnow(),
            last_success=datetime.utcnow()
        )
        db.commit()

        indicators_added = result.get('indicators_added', 0)
        return jsonify({
            'message': 'Feed sync successful',
            'feed_id': feed_id,
            'feed_name': feed.name,
            'indicators_added': indicators_added
        }), 200

    except Exception as e:
        current_app.logger.error(f"IOC feed sync failed for feed {feed_id}: {str(e)}")
        return jsonify({
            'error': f'Feed sync failed: {str(e)}',
            'feed_id': feed_id,
            'feed_name': feed.name
        }), 500
