"""
DNS Server management API blueprint.
Handles server registration, configuration distribution, and heartbeats.
"""

from flask import Blueprint, request, jsonify, current_app
from app.services.join_key_service import JoinKeyService
from app.services.auth_service import AuthService
from app.services.config_service import ConfigService
from app.middleware.auth import token_required, server_token_required, get_current_server
from app.middleware.rbac import requires_scope
from app.utils.decorators import validate_json, audit_log

dns_servers_bp = Blueprint('dns_servers', __name__)


@dns_servers_bp.route('/api/v1/dns-servers', methods=['GET'])
@token_required
@requires_scope('servers:write')
def list_dns_servers():
    """
    List all DNS servers.

    Response:
        [
            {
                "id": 1,
                "name": "dns-server-1",
                "hostname": "server1.example.com",
                "status": "online",
                "version": "2.1.0",
                "region": "us-east-1",
                "last_heartbeat": "2024-01-01T12:00:00"
            }
        ]
    """
    db = current_app.db

    servers = db(db.dns_server).select(orderby=db.dns_server.name)

    return jsonify([
        {
            'id': server.id,
            'name': server.name,
            'hostname': server.hostname,
            'status': server.status,
            'version': server.version,
            'region': server.region,
            'last_heartbeat': server.last_heartbeat.isoformat() if server.last_heartbeat else None,
            'created_at': server.created_at.isoformat()
        }
        for server in servers
    ]), 200


@dns_servers_bp.route('/api/v1/dns-servers', methods=['POST'])
@token_required
@requires_scope('servers:write')
@validate_json('name')
@audit_log('dns_server_created')
def create_dns_server():
    """
    Create a new DNS server and generate join key.

    Request:
        {
            "name": "dns-server-1",
            "region": "us-east-1"
        }

    Response:
        {
            "id": 1,
            "name": "dns-server-1",
            "joinKey": "64-char-hex-key",
            "region": "us-east-1"
        }
    """
    data = request.get_json()

    # Create DNS server with join key
    server = JoinKeyService.create_dns_server(
        name=data['name'],
        region=data.get('region', 'default')
    )

    return jsonify(server), 201


@dns_servers_bp.route('/api/v1/dns-servers/<int:server_id>', methods=['GET'])
@token_required
@requires_scope('servers:write')
def get_dns_server(server_id):
    """Get DNS server details."""
    server = JoinKeyService.get_server_by_id(server_id)

    if not server:
        return jsonify({'error': 'DNS server not found'}), 404

    return jsonify(server), 200


@dns_servers_bp.route('/api/v1/dns-servers/<int:server_id>', methods=['DELETE'])
@token_required
@requires_scope('servers:admin')
@audit_log('dns_server_deleted')
def delete_dns_server(server_id):
    """Delete DNS server."""
    db = current_app.db

    server = db.dns_server[server_id]
    if not server:
        return jsonify({'error': 'DNS server not found'}), 404

    # Delete server (cascade will delete metrics)
    del db.dns_server[server_id]
    db.commit()

    return jsonify({
        'message': 'DNS server deleted successfully'
    }), 200


@dns_servers_bp.route('/api/v1/dns-servers/<int:server_id>/regenerate-key', methods=['POST'])
@token_required
@requires_scope('servers:admin')
@audit_log('dns_server_key_regenerated')
def regenerate_join_key(server_id):
    """
    Regenerate join key for DNS server.
    Forces server to re-register.

    Response:
        {
            "message": "Join key regenerated",
            "server_id": 1
        }
    """
    success = JoinKeyService.revoke_join_key(server_id)

    if not success:
        return jsonify({'error': 'DNS server not found'}), 404

    return jsonify({
        'message': 'Join key regenerated successfully. Server will need to re-register.',
        'server_id': server_id
    }), 200


@dns_servers_bp.route('/api/v1/dns-servers/register', methods=['POST'])
@validate_json('joinKey')
@audit_log('dns_server_registered')
def register_dns_server():
    """
    Register DNS server using join key.
    Returns JWT token and initial configuration.

    Request:
        {
            "joinKey": "64-char-hex-key",
            "hostname": "server1.example.com",
            "version": "2.1.0"
        }

    Response:
        {
            "jwt": "server-jwt-token",
            "serverId": 1,
            "config": {
                "zones": [...],
                "ioc_feeds": [...],
                "cache_settings": {...},
                "settings": {...}
            }
        }
    """
    data = request.get_json()

    # Register server with join key
    server_info = JoinKeyService.register_server(
        join_key=data['joinKey'],
        hostname=data.get('hostname', 'unknown'),
        version=data.get('version', 'unknown')
    )

    if not server_info:
        return jsonify({'error': 'Invalid join key'}), 401

    # Generate server JWT
    jwt_token = AuthService.create_server_jwt(
        server_id=server_info['id'],
        jwt_secret=server_info['jwt_secret']
    )

    # Get initial configuration
    config = ConfigService.get_server_config(server_info['id'])

    return jsonify({
        'jwt': jwt_token,
        'serverId': server_info['id'],
        'serverName': server_info['name'],
        'config': config
    }), 200


@dns_servers_bp.route('/api/v1/dns-servers/<int:server_id>/config', methods=['GET'])
@server_token_required
def get_dns_server_config(server_id):
    """
    Get DNS server configuration.
    Requires valid server JWT token.

    Response:
        {
            "zones": [...],
            "ioc_feeds": [...],
            "cache_settings": {...},
            "settings": {...},
            "version": 123456,
            "timestamp": "2024-01-01T12:00:00"
        }
    """
    current_server = get_current_server()

    # Verify server_id matches token
    if current_server['server_id'] != server_id:
        return jsonify({'error': 'Server ID mismatch'}), 403

    config = ConfigService.get_server_config(server_id)

    return jsonify(config), 200


@dns_servers_bp.route('/api/v1/dns-servers/<int:server_id>/heartbeat', methods=['POST'])
@server_token_required
@validate_json('queries_total', 'cache_hits', 'errors')
def dns_server_heartbeat(server_id):
    """
    Receive heartbeat from DNS server with metrics.

    Request:
        {
            "queries_total": 1234,
            "cache_hits": 890,
            "errors": 2,
            "avg_response_ms": 15.5
        }

    Response:
        {
            "config_version": 123456,
            "should_sync": false,
            "timestamp": "2024-01-01T12:00:00"
        }
    """
    current_server = get_current_server()

    # Verify server_id matches token
    if current_server['server_id'] != server_id:
        return jsonify({'error': 'Server ID mismatch'}), 403

    data = request.get_json()

    # Record heartbeat and metrics
    response = ConfigService.record_heartbeat(server_id, {
        'queries_total': data['queries_total'],
        'cache_hits': data['cache_hits'],
        'errors': data['errors'],
        'avg_response_ms': data.get('avg_response_ms', 0.0)
    })

    return jsonify(response), 200


@dns_servers_bp.route('/api/v1/dns-servers/<int:server_id>/refresh-token', methods=['POST'])
@server_token_required
def refresh_server_token(server_id):
    """
    Refresh DNS server JWT token.

    Response:
        {
            "jwt": "new-jwt-token"
        }
    """
    current_server = get_current_server()

    # Verify server_id matches token
    if current_server['server_id'] != server_id:
        return jsonify({'error': 'Server ID mismatch'}), 403

    db = current_app.db
    server = db.dns_server[server_id]

    if not server:
        return jsonify({'error': 'Server not found'}), 404

    # Generate new JWT
    new_jwt = AuthService.create_server_jwt(
        server_id=server.id,
        jwt_secret=server.jwt_secret
    )

    return jsonify({
        'jwt': new_jwt
    }), 200


@dns_servers_bp.route('/api/v1/dns-servers/<int:server_id>/metrics', methods=['GET'])
@token_required
@requires_scope('servers:write')
def get_dns_server_metrics(server_id):
    """
    Get historical metrics for DNS server.

    Query params:
        - hours: Number of hours to fetch (default: 24)

    Response:
        [
            {
                "timestamp": "2024-01-01T12:00:00",
                "queries_total": 1234,
                "cache_hits": 890,
                "errors": 2,
                "avg_response_ms": 15.5
            }
        ]
    """
    from datetime import datetime, timedelta

    db = current_app.db

    hours = int(request.args.get('hours', 24))
    since = datetime.utcnow() - timedelta(hours=hours)

    metrics = db(
        (db.dns_server_metrics.server_id == server_id) &
        (db.dns_server_metrics.timestamp >= since)
    ).select(
        db.dns_server_metrics.ALL,
        orderby=db.dns_server_metrics.timestamp
    )

    return jsonify([
        {
            'timestamp': m.timestamp.isoformat(),
            'queries_total': m.queries_total,
            'cache_hits': m.cache_hits,
            'errors': m.errors,
            'avg_response_ms': m.avg_response_ms
        }
        for m in metrics
    ]), 200
