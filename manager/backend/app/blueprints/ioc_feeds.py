"""
IOC Feed management API blueprint.
Handles threat intelligence feed configuration.
"""

from flask import Blueprint, request, jsonify, current_app
from app.middleware.auth import token_required
from app.middleware.rbac import requires_system_admin, requires_role
from app.utils.decorators import validate_json, audit_log

ioc_feeds_bp = Blueprint('ioc_feeds', __name__)


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
@audit_log('ioc_feed_sync_triggered')
def trigger_ioc_feed_sync(feed_id):
    """
    Trigger immediate IOC feed sync.

    Response:
        {
            "message": "Feed sync triggered",
            "feed_id": 1
        }
    """
    from datetime import datetime

    db = current_app.db
    feed = db.ioc_feed[feed_id]

    if not feed:
        return jsonify({'error': 'IOC feed not found'}), 404

    # Update last_updated timestamp
    feed.update_record(last_updated=datetime.utcnow())
    db.commit()

    # In production, this would trigger an async task to fetch and process the feed
    # For now, just update the timestamp

    return jsonify({
        'message': 'Feed sync triggered successfully',
        'feed_id': feed_id,
        'feed_name': feed.name
    }), 200
