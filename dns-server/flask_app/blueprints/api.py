"""
API Blueprint for Flask Application
REST API endpoints for DNS management and monitoring
"""

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, current_user as jwt_current_user
from flask_login import current_user as login_current_user
import os
import sys
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import shared database instance
from database import db

api_bp = Blueprint('api', __name__)


def get_current_user():
    """
    Helper function to get current user from either JWT or session.
    Checks JWT authentication first, then falls back to session-based login.

    Returns:
        User object or None if not authenticated
    """
    # Check JWT authentication first
    if jwt_current_user and hasattr(jwt_current_user, 'id') and jwt_current_user.id:
        return jwt_current_user
    # Fallback to session-based authentication
    if login_current_user and login_current_user.is_authenticated:
        return login_current_user
    return None


def _is_json_safe(value):
    """Check if a value is JSON-serializable (basic types only).
    Uses exact type checks for containers to exclude PyDAL internal
    types (RecordUpdater, RecordDeleter, LazySet) that inherit from dict.
    """
    if value is None:
        return True
    if isinstance(value, (str, int, float, bool)):
        return True
    # Exact type check for containers - excludes PyDAL dict subclasses
    if type(value) in (list, dict, tuple):
        return True
    # datetime objects are handled by Flask's jsonify
    import datetime as dt
    if isinstance(value, (dt.datetime, dt.date, dt.time)):
        return True
    return False


def serialize_row(row):
    """Convert PyDAL Row to dictionary, filtering non-serializable types."""
    if row is None:
        return None
    result = {}
    for k, v in row.items():
        if _is_json_safe(v):
            result[k] = v
    return result


def serialize_rows(rows):
    """Convert PyDAL Rows to list of dictionaries."""
    return [serialize_row(row) for row in rows]


@api_bp.route('/queries', methods=['GET'])
@jwt_required(optional=True)
def get_queries():
    """Get DNS query logs"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    limit = int(request.args.get('limit', 100))
    offset = int(request.args.get('offset', 0))

    queries = db(db.dns_query_log).select(
        orderby=~db.dns_query_log.timestamp,
        limitby=(offset, offset+limit)
    )

    return jsonify({
        'queries': serialize_rows(queries),
        'total': db(db.dns_query_log).count()
    })


@api_bp.route('/ioc/feeds', methods=['GET', 'POST'])
@jwt_required(optional=True)
def ioc_feeds():
    """Manage IOC feeds"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    if request.method == 'POST':
        if not user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403

        data = request.get_json()
        feed_id = db.ioc_feed.insert(
            name=data['name'],
            url=data['url'],
            feed_type=data.get('feed_type', 'domain'),
            is_active=data.get('is_active', True),
            update_frequency_hours=data.get('update_frequency_hours', 24)
        )
        db.commit()

        return jsonify({'id': feed_id, 'status': 'created'}), 201

    # GET
    feeds = db(db.ioc_feed).select()
    return jsonify({'feeds': serialize_rows(feeds)})


@api_bp.route('/ioc/feeds/<int:feed_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required(optional=True)
def ioc_feed_detail(feed_id):
    """Manage specific IOC feed"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    feed = db(db.ioc_feed.id == feed_id).select().first()
    if not feed:
        return jsonify({'error': 'Feed not found'}), 404

    if request.method == 'DELETE':
        if not user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        db(db.ioc_feed.id == feed_id).delete()
        db.commit()
        return jsonify({'status': 'deleted'}), 200

    if request.method == 'PUT':
        if not user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        data = request.get_json()
        db(db.ioc_feed.id == feed_id).update(**data)
        db.commit()
        return jsonify({'status': 'updated'}), 200

    # GET
    return jsonify(serialize_row(feed))


@api_bp.route('/whois/<domain>', methods=['GET'])
@jwt_required(optional=True)
def whois_lookup(domain):
    """WHOIS lookup with caching"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    # Check cache first
    cached = db(db.whois_cache.domain == domain).select().first()
    if cached and cached.expires_at > datetime.utcnow():
        return jsonify({
            'domain': domain,
            'data': cached.whois_data,
            'cached': True
        })

    # In production, this would call actual WHOIS service
    # For now, return placeholder
    return jsonify({
        'domain': domain,
        'data': {'status': 'WHOIS lookup not implemented yet'},
        'cached': False
    })


@api_bp.route('/stats/summary', methods=['GET'])
@jwt_required(optional=True)
def stats_summary():
    """Get summary statistics"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    from datetime import timedelta
    last_24h = datetime.utcnow() - timedelta(hours=24)

    total_queries = db(db.dns_query_log.timestamp > last_24h).count()
    cache_hits = db((db.dns_query_log.timestamp > last_24h) &
                    (db.dns_query_log.cache_hit == True)).count()

    return jsonify({
        'total_queries_24h': total_queries,
        'cache_hits_24h': cache_hits,
        'cache_hit_rate': (cache_hits / total_queries * 100) if total_queries > 0 else 0,
        'active_feeds': db(db.ioc_feed.is_active == True).count(),
        'total_ioc_entries': db(db.ioc_entry).count()
    })
