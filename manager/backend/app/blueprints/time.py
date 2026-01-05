"""
Time synchronization management API blueprint.
Handles time servers (PTP/NTP), sync operations, and logging.
"""

from flask import Blueprint, request, jsonify, current_app
from app.middleware.auth import token_required, get_current_user
from app.middleware.rbac import requires_role
from app.utils.decorators import validate_json, audit_log
from datetime import datetime, timedelta

time_bp = Blueprint('time', __name__)


# =============================================================================
# Time Server Endpoints
# =============================================================================

@time_bp.route('/api/v1/time/servers', methods=['GET'])
@token_required
def list_time_servers():
    """
    List all time servers visible to the current user.

    Query params:
        - protocol: Filter by protocol (ptp, ntp)
        - team_id: Filter by team
        - active: Filter by active status

    Response:
        [
            {
                "id": 1,
                "name": "Primary PTP Server",
                "serverUrl": "ptp://time.internal.local",
                "protocol": "ptp",
                "stratum": 1,
                "priority": 100,
                "status": "synchronized",
                ...
            }
        ]
    """
    db = current_app.db
    user = get_current_user()

    query = db.time_server.id > 0

    protocol = request.args.get('protocol')
    if protocol:
        query &= db.time_server.protocol == protocol

    team_id = request.args.get('team_id', type=int)
    if team_id:
        query &= db.time_server.team_id == team_id

    active = request.args.get('active')
    if active is not None:
        query &= db.time_server.active == (active.lower() == 'true')

    # Apply team-based access control if not SystemAdmin
    if user.get('globalRole') not in ['SystemAdmin', 'OrgAdmin']:
        accessible_teams = _get_user_team_ids(user['id'])
        query &= (db.time_server.team_id.belongs(accessible_teams) | (db.time_server.team_id == None))

    servers = db(query).select(orderby=db.time_server.priority)

    return jsonify([
        {
            'id': server.id,
            'name': server.name,
            'serverUrl': server.server_url,
            'protocol': server.protocol,
            'stratum': server.stratum,
            'priority': server.priority,
            'teamId': server.team_id,
            'active': server.active,
            'status': server.status,
            'lastSync': server.last_sync.isoformat() if server.last_sync else None,
            'lastOffsetMs': server.last_offset_ms,
            'lastDelayMs': server.last_delay_ms,
            'ptpConfig': server.ptp_config,
            'createdAt': server.created_at.isoformat()
        }
        for server in servers
    ]), 200


@time_bp.route('/api/v1/time/servers', methods=['POST'])
@token_required
@requires_role('SystemAdmin', 'OrgAdmin')
@validate_json('name', 'serverUrl', 'protocol')
@audit_log('time_server_created')
def create_time_server():
    """
    Create a new time server.

    Request:
        {
            "name": "Datacenter PTP Master",
            "serverUrl": "ptp://192.168.100.1",
            "protocol": "ptp",
            "stratum": 1,
            "priority": 50,
            "teamId": 1,
            "ptpConfig": {
                "domain": 0,
                "transport": "udp",
                "delayMechanism": "e2e"
            }
        }
    """
    data = request.get_json()
    db = current_app.db

    # Validate protocol
    if data['protocol'] not in ['ptp', 'ntp']:
        return jsonify({'error': 'Invalid protocol. Must be "ptp" or "ntp"'}), 400

    server_id = db.time_server.insert(
        name=data['name'],
        server_url=data['serverUrl'],
        protocol=data['protocol'],
        stratum=data.get('stratum', 2),
        priority=data.get('priority', 100),
        team_id=data.get('teamId'),
        active=data.get('active', True),
        ptp_config=data.get('ptpConfig')
    )
    db.commit()

    server = db.time_server[server_id]
    return jsonify({
        'id': server.id,
        'name': server.name,
        'serverUrl': server.server_url,
        'protocol': server.protocol,
        'stratum': server.stratum,
        'priority': server.priority,
        'createdAt': server.created_at.isoformat()
    }), 201


@time_bp.route('/api/v1/time/servers/<int:server_id>', methods=['GET'])
@token_required
def get_time_server(server_id):
    """Get time server details with statistics."""
    db = current_app.db

    server = db.time_server[server_id]
    if not server:
        return jsonify({'error': 'Time server not found'}), 404

    user = get_current_user()
    if not _can_access_server(user, server):
        return jsonify({'error': 'Access denied'}), 403

    # Get sync statistics
    since = datetime.utcnow() - timedelta(hours=24)
    logs = db(
        (db.time_sync_log.server_id == server_id) &
        (db.time_sync_log.timestamp >= since)
    ).select()

    success_count = sum(1 for l in logs if l.status == 'success')
    fail_count = sum(1 for l in logs if l.status == 'failed')

    avg_offset = 0
    max_offset = 0
    avg_delay = 0

    if success_count > 0:
        success_logs = [l for l in logs if l.status == 'success']
        avg_offset = sum(abs(l.offset_ms) for l in success_logs) / success_count
        max_offset = max(abs(l.offset_ms) for l in success_logs)
        avg_delay = sum(l.delay_ms for l in success_logs) / success_count

    return jsonify({
        'id': server.id,
        'name': server.name,
        'serverUrl': server.server_url,
        'protocol': server.protocol,
        'stratum': server.stratum,
        'priority': server.priority,
        'teamId': server.team_id,
        'active': server.active,
        'status': server.status,
        'lastSync': server.last_sync.isoformat() if server.last_sync else None,
        'lastOffsetMs': server.last_offset_ms,
        'lastDelayMs': server.last_delay_ms,
        'ptpConfig': server.ptp_config,
        'statistics': {
            'syncCount': success_count,
            'syncFailures': fail_count,
            'avgOffsetMs': round(avg_offset, 6),
            'maxOffsetMs': round(max_offset, 6),
            'avgDelayMs': round(avg_delay, 6)
        },
        'createdAt': server.created_at.isoformat(),
        'updatedAt': server.updated_at.isoformat() if server.updated_at else None
    }), 200


@time_bp.route('/api/v1/time/servers/<int:server_id>', methods=['PUT'])
@token_required
@requires_role('SystemAdmin', 'OrgAdmin')
@audit_log('time_server_updated')
def update_time_server(server_id):
    """Update time server configuration."""
    db = current_app.db
    data = request.get_json()

    server = db.time_server[server_id]
    if not server:
        return jsonify({'error': 'Time server not found'}), 404

    update_fields = {}
    allowed_fields = ['name', 'serverUrl', 'stratum', 'priority', 'active', 'ptpConfig']

    field_mapping = {
        'serverUrl': 'server_url',
        'ptpConfig': 'ptp_config'
    }

    for field in allowed_fields:
        if field in data:
            db_field = field_mapping.get(field, field)
            update_fields[db_field] = data[field]

    if update_fields:
        server.update_record(**update_fields)
        db.commit()

    return jsonify({'message': 'Time server updated successfully'}), 200


@time_bp.route('/api/v1/time/servers/<int:server_id>', methods=['DELETE'])
@token_required
@requires_role('SystemAdmin')
@audit_log('time_server_deleted')
def delete_time_server(server_id):
    """Delete a time server."""
    db = current_app.db

    server = db.time_server[server_id]
    if not server:
        return jsonify({'error': 'Time server not found'}), 404

    del db.time_server[server_id]
    db.commit()

    return jsonify({'message': 'Time server deleted successfully'}), 200


# =============================================================================
# Time Status & Sync Endpoints
# =============================================================================

@time_bp.route('/api/v1/time/status', methods=['GET'])
@token_required
def get_time_status():
    """
    Get current time synchronization status.

    Response:
        {
            "currentTime": "2026-01-05T10:00:00.000000Z",
            "synchronized": true,
            "activeSource": {
                "id": 1,
                "name": "Primary PTP Server",
                "protocol": "ptp",
                "stratum": 1
            },
            "offsetMs": 0.0012,
            "delayMs": 0.0045,
            "lastSync": "2026-01-05T10:00:00Z",
            "fallbackAvailable": true
        }
    """
    db = current_app.db

    # Get active servers ordered by priority
    servers = db(
        (db.time_server.active == True) &
        (db.time_server.status == 'synchronized')
    ).select(orderby=db.time_server.priority, limitby=(0, 1))

    active_source = None
    if servers:
        s = servers.first()
        active_source = {
            'id': s.id,
            'name': s.name,
            'protocol': s.protocol,
            'stratum': s.stratum
        }

    # Check for fallback
    fallback_count = db(
        (db.time_server.active == True) &
        (db.time_server.protocol == 'ntp')
    ).count()

    # Get latest sync info
    latest_sync = db(db.time_sync_log.status == 'success').select(
        orderby=~db.time_sync_log.timestamp,
        limitby=(0, 1)
    ).first()

    return jsonify({
        'currentTime': datetime.utcnow().isoformat() + 'Z',
        'synchronized': active_source is not None,
        'activeSource': active_source,
        'offsetMs': latest_sync.offset_ms if latest_sync else None,
        'delayMs': latest_sync.delay_ms if latest_sync else None,
        'lastSync': latest_sync.timestamp.isoformat() if latest_sync else None,
        'fallbackAvailable': fallback_count > 0
    }), 200


@time_bp.route('/api/v1/time/sync', methods=['POST'])
@token_required
@requires_role('SystemAdmin', 'OrgAdmin')
@audit_log('time_sync_triggered')
def trigger_time_sync():
    """
    Trigger immediate time synchronization.

    Request (optional):
        {
            "serverId": 1
        }

    Response:
        {
            "syncedFrom": "Primary PTP Server",
            "protocol": "ptp",
            "offsetBeforeMs": 1.234,
            "offsetAfterMs": 0.001,
            "adjustmentMs": -1.233
        }
    """
    db = current_app.db
    data = request.get_json() or {}

    server_id = data.get('serverId')

    if server_id:
        server = db.time_server[server_id]
        if not server or not server.active:
            return jsonify({'error': 'Time server not found or inactive'}), 404
    else:
        # Get highest priority active server
        server = db(db.time_server.active == True).select(
            orderby=db.time_server.priority,
            limitby=(0, 1)
        ).first()

        if not server:
            return jsonify({'error': 'No active time servers available'}), 404

    # Simulate sync (in production, this would trigger actual NTP/PTP sync)
    # For now, log the sync request
    import random
    offset_before = random.uniform(-5, 5)
    offset_after = random.uniform(-0.01, 0.01)
    delay = random.uniform(0.001, 0.1)

    # Log the sync
    db.time_sync_log.insert(
        server_id=server.id,
        offset_ms=offset_after,
        delay_ms=delay,
        protocol=server.protocol,
        status='success'
    )

    # Update server status
    server.update_record(
        status='synchronized',
        last_sync=datetime.utcnow(),
        last_offset_ms=offset_after,
        last_delay_ms=delay
    )
    db.commit()

    return jsonify({
        'syncedFrom': server.name,
        'protocol': server.protocol,
        'offsetBeforeMs': round(offset_before, 6),
        'offsetAfterMs': round(offset_after, 6),
        'adjustmentMs': round(offset_after - offset_before, 6)
    }), 200


# =============================================================================
# Time Sync Log Endpoints
# =============================================================================

@time_bp.route('/api/v1/time/logs', methods=['GET'])
@token_required
def list_time_logs():
    """
    Get historical time synchronization logs.

    Query params:
        - server_id: Filter by server
        - start_date: Start date (ISO 8601)
        - end_date: End date (ISO 8601)
        - status: Filter by status (success, failed, timeout)
        - page: Page number
        - per_page: Results per page (max 500)
    """
    db = current_app.db

    query = db.time_sync_log.id > 0

    server_id = request.args.get('server_id', type=int)
    if server_id:
        query &= db.time_sync_log.server_id == server_id

    start_date = request.args.get('start_date')
    if start_date:
        try:
            start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            query &= db.time_sync_log.timestamp >= start_dt
        except ValueError:
            pass

    end_date = request.args.get('end_date')
    if end_date:
        try:
            end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            query &= db.time_sync_log.timestamp <= end_dt
        except ValueError:
            pass

    status = request.args.get('status')
    if status:
        query &= db.time_sync_log.status == status

    # Pagination
    page = max(1, request.args.get('page', 1, type=int))
    per_page = min(500, max(1, request.args.get('per_page', 100, type=int)))
    offset = (page - 1) * per_page

    total = db(query).count()
    logs = db(query).select(
        orderby=~db.time_sync_log.timestamp,
        limitby=(offset, offset + per_page)
    )

    # Get server names
    server_ids = set(log.server_id for log in logs)
    servers = {s.id: s.name for s in db(db.time_server.id.belongs(server_ids)).select()}

    return jsonify({
        'data': [
            {
                'id': log.id,
                'serverId': log.server_id,
                'serverName': servers.get(log.server_id, 'Unknown'),
                'protocol': log.protocol,
                'offsetMs': log.offset_ms,
                'delayMs': log.delay_ms,
                'status': log.status,
                'errorMessage': log.error_message,
                'timestamp': log.timestamp.isoformat()
            }
            for log in logs
        ],
        'pagination': {
            'page': page,
            'perPage': per_page,
            'total': total,
            'totalPages': (total + per_page - 1) // per_page
        }
    }), 200


# =============================================================================
# Helper Functions
# =============================================================================

def _get_user_team_ids(user_id):
    """Get list of team IDs user belongs to."""
    db = current_app.db
    memberships = db(db.team_member.user_id == user_id).select(db.team_member.team_id)
    return [m.team_id for m in memberships]


def _can_access_server(user, server):
    """Check if user can access a time server."""
    if user.get('globalRole') in ['SystemAdmin', 'OrgAdmin']:
        return True
    if server.team_id is None:
        return True
    return server.team_id in _get_user_team_ids(user['id'])
