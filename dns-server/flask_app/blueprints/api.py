"""
API Blueprint for Flask Application
REST API endpoints for DNS management and monitoring
"""

from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
import os
import sys
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import shared database instance
from database import db

api_bp = Blueprint('api', __name__)

@api_bp.route('/queries', methods=['GET'])
@login_required
def get_queries():
    """Get DNS query logs"""
    limit = int(request.args.get('limit', 100))
    offset = int(request.args.get('offset', 0))
    
    queries = db(db.dns_query_log).select(
        orderby=~db.dns_query_log.timestamp,
        limitby=(offset, offset+limit)
    )
    
    return jsonify({
        'queries': [dict(q) for q in queries],
        'total': db(db.dns_query_log).count()
    })

@api_bp.route('/ioc/feeds', methods=['GET', 'POST'])
@login_required
def ioc_feeds():
    """Manage IOC feeds"""
    if request.method == 'POST':
        if not current_user.is_admin:
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
    return jsonify({'feeds': [dict(f) for f in feeds]})

@api_bp.route('/ioc/feeds/<int:feed_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def ioc_feed_detail(feed_id):
    """Manage specific IOC feed"""
    feed = db(db.ioc_feed.id == feed_id).select().first()
    if not feed:
        return jsonify({'error': 'Feed not found'}), 404
    
    if request.method == 'DELETE':
        if not current_user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        db(db.ioc_feed.id == feed_id).delete()
        db.commit()
        return jsonify({'status': 'deleted'}), 200
    
    if request.method == 'PUT':
        if not current_user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        data = request.get_json()
        db(db.ioc_feed.id == feed_id).update(**data)
        db.commit()
        return jsonify({'status': 'updated'}), 200
    
    # GET
    return jsonify(dict(feed))

@api_bp.route('/whois/<query>', methods=['GET'])
@login_required
def whois_lookup(query):
    """WHOIS lookup with caching using WHOISManager"""
    import asyncio
    from ipaddress import ip_address

    # Import WHOISManager
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'bins'))
    from whois_manager import WHOISManager

    # Get database URL from environment
    db_url = os.getenv('DATABASE_URL', 'sqlite://storage.sqlite')
    manager = WHOISManager(db_url)

    # Determine if query is IP or domain
    try:
        ip_address(query)
        is_ip = True
    except ValueError:
        is_ip = False

    # Get client IP for logging
    client_ip = request.remote_addr
    force_refresh = request.args.get('refresh', 'false').lower() == 'true'

    # Run async lookup
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        if is_ip:
            result = loop.run_until_complete(
                manager.lookup_ip(query, client_ip, force_refresh)
            )
        else:
            result = loop.run_until_complete(
                manager.lookup_domain(query, client_ip, force_refresh)
            )
    finally:
        loop.close()

    return jsonify(result)

@api_bp.route('/stats/summary', methods=['GET'])
@login_required
def stats_summary():
    """Get summary statistics"""
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
