"""
Analytics API blueprint.
Provides aggregated DNS query statistics and performance metrics.
"""

from flask import Blueprint, request, jsonify, current_app
from app.middleware.auth import token_required
from app.middleware.rbac import filter_teams_by_access
from datetime import datetime, timedelta

analytics_bp = Blueprint('analytics', __name__)


@analytics_bp.route('/api/v1/analytics/queries', methods=['GET'])
@token_required
def get_query_analytics():
    """
    Get DNS query analytics.

    Query params:
        - period: Time period in hours (default: 24)
        - server_id: Filter by specific server
        - team_id: Filter by team

    Response:
        {
            "total_queries": 12345,
            "cache_hits": 8901,
            "cache_hit_rate": 72.1,
            "errors": 45,
            "error_rate": 0.36,
            "timeline": [
                {
                    "timestamp": "2024-01-01T00:00:00",
                    "queries": 500,
                    "cache_hits": 350,
                    "errors": 2
                }
            ]
        }
    """
    db = current_app.db

    # Parse query parameters
    period_hours = int(request.args.get('period', 24))
    server_id = request.args.get('server_id')
    team_id = request.args.get('team_id')

    since = datetime.utcnow() - timedelta(hours=period_hours)

    # Build query
    query = db.dns_server_metrics.timestamp >= since

    if server_id:
        query = query & (db.dns_server_metrics.server_id == int(server_id))

    # Get metrics
    metrics = db(query).select(
        db.dns_server_metrics.ALL,
        orderby=db.dns_server_metrics.timestamp
    )

    # Aggregate data
    total_queries = sum(m.queries_total for m in metrics)
    total_cache_hits = sum(m.cache_hits for m in metrics)
    total_errors = sum(m.errors for m in metrics)

    cache_hit_rate = (total_cache_hits / total_queries * 100) if total_queries > 0 else 0
    error_rate = (total_errors / total_queries * 100) if total_queries > 0 else 0

    # Build timeline
    timeline = [
        {
            'timestamp': m.timestamp.isoformat(),
            'queries': m.queries_total,
            'cache_hits': m.cache_hits,
            'errors': m.errors,
            'avg_response_ms': m.avg_response_ms,
            'server_id': m.server_id
        }
        for m in metrics
    ]

    return jsonify({
        'total_queries': total_queries,
        'cache_hits': total_cache_hits,
        'cache_hit_rate': round(cache_hit_rate, 2),
        'errors': total_errors,
        'error_rate': round(error_rate, 2),
        'period_hours': period_hours,
        'timeline': timeline
    }), 200


@analytics_bp.route('/api/v1/analytics/performance', methods=['GET'])
@token_required
def get_performance_analytics():
    """
    Get DNS performance analytics.

    Query params:
        - period: Time period in hours (default: 24)
        - server_id: Filter by specific server

    Response:
        {
            "avg_response_time": 15.5,
            "min_response_time": 5.2,
            "max_response_time": 145.3,
            "p50_response_time": 12.1,
            "p95_response_time": 45.7,
            "p99_response_time": 98.2
        }
    """
    db = current_app.db

    period_hours = int(request.args.get('period', 24))
    server_id = request.args.get('server_id')

    since = datetime.utcnow() - timedelta(hours=period_hours)

    query = db.dns_server_metrics.timestamp >= since

    if server_id:
        query = query & (db.dns_server_metrics.server_id == int(server_id))

    metrics = db(query).select(db.dns_server_metrics.avg_response_ms)

    if not metrics:
        return jsonify({
            'avg_response_time': 0,
            'min_response_time': 0,
            'max_response_time': 0
        }), 200

    response_times = [m.avg_response_ms for m in metrics if m.avg_response_ms > 0]

    if not response_times:
        return jsonify({
            'avg_response_time': 0,
            'min_response_time': 0,
            'max_response_time': 0
        }), 200

    # Calculate statistics
    response_times.sort()
    avg_response = sum(response_times) / len(response_times)
    min_response = min(response_times)
    max_response = max(response_times)

    # Calculate percentiles
    def percentile(data, p):
        n = len(data)
        index = int(n * p / 100)
        return data[min(index, n - 1)]

    return jsonify({
        'avg_response_time': round(avg_response, 2),
        'min_response_time': round(min_response, 2),
        'max_response_time': round(max_response, 2),
        'p50_response_time': round(percentile(response_times, 50), 2),
        'p95_response_time': round(percentile(response_times, 95), 2),
        'p99_response_time': round(percentile(response_times, 99), 2),
        'sample_count': len(response_times)
    }), 200


@analytics_bp.route('/api/v1/analytics/servers', methods=['GET'])
@token_required
def get_server_analytics():
    """
    Get per-server analytics summary.

    Query params:
        - period: Time period in hours (default: 24)

    Response:
        [
            {
                "server_id": 1,
                "server_name": "dns-server-1",
                "status": "online",
                "total_queries": 5000,
                "cache_hits": 3500,
                "errors": 10,
                "avg_response_ms": 15.5
            }
        ]
    """
    db = current_app.db

    period_hours = int(request.args.get('period', 24))
    since = datetime.utcnow() - timedelta(hours=period_hours)

    # Get all servers
    servers = db(db.dns_server).select(db.dns_server.ALL)

    result = []
    for server in servers:
        # Get metrics for this server
        metrics = db(
            (db.dns_server_metrics.server_id == server.id) &
            (db.dns_server_metrics.timestamp >= since)
        ).select(db.dns_server_metrics.ALL)

        if not metrics:
            continue

        total_queries = sum(m.queries_total for m in metrics)
        total_cache_hits = sum(m.cache_hits for m in metrics)
        total_errors = sum(m.errors for m in metrics)
        avg_response = sum(m.avg_response_ms for m in metrics) / len(metrics)

        result.append({
            'server_id': server.id,
            'server_name': server.name,
            'hostname': server.hostname,
            'status': server.status,
            'region': server.region,
            'total_queries': total_queries,
            'cache_hits': total_cache_hits,
            'cache_hit_rate': round((total_cache_hits / total_queries * 100) if total_queries > 0 else 0, 2),
            'errors': total_errors,
            'error_rate': round((total_errors / total_queries * 100) if total_queries > 0 else 0, 2),
            'avg_response_ms': round(avg_response, 2),
            'last_heartbeat': server.last_heartbeat.isoformat() if server.last_heartbeat else None
        })

    return jsonify(result), 200


@analytics_bp.route('/api/v1/analytics/summary', methods=['GET'])
@token_required
def get_analytics_summary():
    """
    Get overall analytics summary.

    Response:
        {
            "total_servers": 3,
            "online_servers": 2,
            "offline_servers": 1,
            "total_zones": 10,
            "total_records": 150,
            "total_teams": 5,
            "total_users": 25,
            "queries_24h": 50000,
            "cache_hit_rate_24h": 72.5
        }
    """
    db = current_app.db

    # Server stats
    total_servers = db(db.dns_server).count()
    online_servers = db(db.dns_server.status == 'online').count()
    offline_servers = total_servers - online_servers

    # Zone stats
    total_zones = db(db.dns_zone).count()
    total_records = db(db.dns_record).count()

    # Team stats
    total_teams = db(db.team).count()

    # User stats
    total_users = db(db.auth_user).count()
    active_users = db(db.auth_user.active == True).count()

    # Query stats (last 24 hours)
    since_24h = datetime.utcnow() - timedelta(hours=24)
    metrics_24h = db(db.dns_server_metrics.timestamp >= since_24h).select(
        db.dns_server_metrics.queries_total,
        db.dns_server_metrics.cache_hits
    )

    queries_24h = sum(m.queries_total for m in metrics_24h)
    cache_hits_24h = sum(m.cache_hits for m in metrics_24h)
    cache_hit_rate_24h = (cache_hits_24h / queries_24h * 100) if queries_24h > 0 else 0

    return jsonify({
        'total_servers': total_servers,
        'online_servers': online_servers,
        'offline_servers': offline_servers,
        'total_zones': total_zones,
        'total_records': total_records,
        'total_teams': total_teams,
        'total_users': total_users,
        'active_users': active_users,
        'queries_24h': queries_24h,
        'cache_hits_24h': cache_hits_24h,
        'cache_hit_rate_24h': round(cache_hit_rate_24h, 2)
    }), 200
