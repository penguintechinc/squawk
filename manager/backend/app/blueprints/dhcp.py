"""
DHCP management API blueprint.
Handles DHCP pools, reservations, and leases.
"""

from flask import Blueprint, request, jsonify, current_app
from app.middleware.auth import token_required, get_current_user
from app.middleware.rbac import requires_scope, check_team_access
from app.utils.decorators import validate_json, audit_log
from datetime import datetime

dhcp_bp = Blueprint('dhcp', __name__)


# =============================================================================
# DHCP Pool Endpoints
# =============================================================================

@dhcp_bp.route('/api/v1/dhcp/pools', methods=['GET'])
@token_required
def list_dhcp_pools():
    """
    List all DHCP pools visible to the current user.

    Query params:
        - team_id: Filter by team (optional)
        - active: Filter by active status (optional)

    Response:
        [
            {
                "id": 1,
                "name": "Office Network",
                "network": "192.168.1.0/24",
                "range_start": "192.168.1.100",
                "range_end": "192.168.1.200",
                "active": true,
                ...
            }
        ]
    """
    db = current_app.db
    user = get_current_user()

    # Build query with optional filters
    query = db.dhcp_pool.id > 0

    team_id = request.args.get('team_id', type=int)
    if team_id:
        query &= db.dhcp_pool.team_id == team_id

    active = request.args.get('active')
    if active is not None:
        query &= db.dhcp_pool.active == (active.lower() == 'true')

    # Apply team-based access control if not SystemAdmin
    if user.get('globalRole') not in ['SystemAdmin', 'OrgAdmin']:
        accessible_teams = get_user_team_ids(user['id'])
        query &= db.dhcp_pool.team_id.belongs(accessible_teams)

    pools = db(query).select(orderby=db.dhcp_pool.name)

    # Calculate statistics for each pool
    result = []
    for pool in pools:
        # Count leases
        active_leases = db(
            (db.dhcp_lease.pool_id == pool.id) &
            (db.dhcp_lease.status == 'active')
        ).count()

        reserved_count = db(db.dhcp_reservation.pool_id == pool.id).count()

        result.append({
            'id': pool.id,
            'name': pool.name,
            'network': pool.network,
            'rangeStart': pool.range_start,
            'rangeEnd': pool.range_end,
            'gateway': pool.gateway,
            'dnsServers': pool.dns_servers or [],
            'ntpServers': pool.ntp_servers or [],
            'domainName': pool.domain_name,
            'leaseDuration': pool.lease_duration,
            'teamId': pool.team_id,
            'active': pool.active,
            'enableDdns': pool.enable_ddns,
            'ddnsZoneId': pool.ddns_zone_id,
            'activeLeases': active_leases,
            'reservedIps': reserved_count,
            'createdAt': pool.created_at.isoformat()
        })

    return jsonify(result), 200


@dhcp_bp.route('/api/v1/dhcp/pools', methods=['POST'])
@token_required
@requires_scope('dhcp:write')
@validate_json('name', 'network', 'rangeStart', 'rangeEnd')
@audit_log('dhcp_pool_created')
def create_dhcp_pool():
    """
    Create a new DHCP pool.

    Request:
        {
            "name": "Guest Network",
            "network": "10.10.0.0/24",
            "rangeStart": "10.10.0.50",
            "rangeEnd": "10.10.0.200",
            "gateway": "10.10.0.1",
            "dnsServers": ["10.10.0.1"],
            "ntpServers": ["time.local"],
            "domainName": "guest.local",
            "leaseDuration": 3600,
            "teamId": 1
        }
    """
    data = request.get_json()
    db = current_app.db

    # Validate IP ranges (basic validation)
    if not _validate_ip_range(data['rangeStart'], data['rangeEnd']):
        return jsonify({'error': 'Invalid IP range: start must be less than end'}), 400

    pool_id = db.dhcp_pool.insert(
        name=data['name'],
        network=data['network'],
        range_start=data['rangeStart'],
        range_end=data['rangeEnd'],
        gateway=data.get('gateway'),
        dns_servers=data.get('dnsServers', []),
        ntp_servers=data.get('ntpServers', []),
        domain_name=data.get('domainName'),
        lease_duration=data.get('leaseDuration', 86400),
        team_id=data.get('teamId'),
        active=data.get('active', True),
        enable_ddns=data.get('enableDdns', False),
        ddns_zone_id=data.get('ddnsZoneId')
    )
    db.commit()

    pool = db.dhcp_pool[pool_id]
    return jsonify({
        'id': pool.id,
        'name': pool.name,
        'network': pool.network,
        'rangeStart': pool.range_start,
        'rangeEnd': pool.range_end,
        'createdAt': pool.created_at.isoformat()
    }), 201


@dhcp_bp.route('/api/v1/dhcp/pools/<int:pool_id>', methods=['GET'])
@token_required
def get_dhcp_pool(pool_id):
    """Get DHCP pool details with statistics."""
    db = current_app.db

    pool = db.dhcp_pool[pool_id]
    if not pool:
        return jsonify({'error': 'DHCP pool not found'}), 404

    # Check access
    user = get_current_user()
    if not _can_access_pool(user, pool):
        return jsonify({'error': 'Access denied'}), 403

    # Calculate statistics
    active_leases = db(
        (db.dhcp_lease.pool_id == pool_id) &
        (db.dhcp_lease.status == 'active')
    ).count()

    reserved_count = db(db.dhcp_reservation.pool_id == pool_id).count()
    total_ips = _calculate_pool_size(pool.range_start, pool.range_end)

    return jsonify({
        'id': pool.id,
        'name': pool.name,
        'network': pool.network,
        'rangeStart': pool.range_start,
        'rangeEnd': pool.range_end,
        'gateway': pool.gateway,
        'dnsServers': pool.dns_servers or [],
        'ntpServers': pool.ntp_servers or [],
        'domainName': pool.domain_name,
        'leaseDuration': pool.lease_duration,
        'teamId': pool.team_id,
        'active': pool.active,
        'enableDdns': pool.enable_ddns,
        'ddnsZoneId': pool.ddns_zone_id,
        'statistics': {
            'totalIps': total_ips,
            'activeLeases': active_leases,
            'reservedIps': reserved_count,
            'availableIps': total_ips - active_leases - reserved_count,
            'utilizationPercent': round((active_leases + reserved_count) / total_ips * 100, 2) if total_ips > 0 else 0
        },
        'createdAt': pool.created_at.isoformat(),
        'updatedAt': pool.updated_at.isoformat() if pool.updated_at else None
    }), 200


@dhcp_bp.route('/api/v1/dhcp/pools/<int:pool_id>', methods=['PUT'])
@token_required
@requires_scope('dhcp:write')
@audit_log('dhcp_pool_updated')
def update_dhcp_pool(pool_id):
    """Update DHCP pool configuration."""
    db = current_app.db
    data = request.get_json()

    pool = db.dhcp_pool[pool_id]
    if not pool:
        return jsonify({'error': 'DHCP pool not found'}), 404

    # Update allowed fields
    update_fields = {}
    allowed_fields = ['name', 'gateway', 'dnsServers', 'ntpServers', 'domainName',
                      'leaseDuration', 'active', 'enableDdns', 'ddnsZoneId']

    field_mapping = {
        'dnsServers': 'dns_servers',
        'ntpServers': 'ntp_servers',
        'domainName': 'domain_name',
        'leaseDuration': 'lease_duration',
        'enableDdns': 'enable_ddns',
        'ddnsZoneId': 'ddns_zone_id',
        'rangeStart': 'range_start',
        'rangeEnd': 'range_end'
    }

    for field in allowed_fields:
        if field in data:
            db_field = field_mapping.get(field, field)
            update_fields[db_field] = data[field]

    # Handle range updates with validation
    if 'rangeStart' in data or 'rangeEnd' in data:
        start = data.get('rangeStart', pool.range_start)
        end = data.get('rangeEnd', pool.range_end)
        if not _validate_ip_range(start, end):
            return jsonify({'error': 'Invalid IP range'}), 400
        update_fields['range_start'] = start
        update_fields['range_end'] = end

    if update_fields:
        pool.update_record(**update_fields)
        db.commit()

    return jsonify({'message': 'Pool updated successfully'}), 200


@dhcp_bp.route('/api/v1/dhcp/pools/<int:pool_id>', methods=['DELETE'])
@token_required
@requires_scope('dhcp:admin')
@audit_log('dhcp_pool_deleted')
def delete_dhcp_pool(pool_id):
    """Delete DHCP pool and all associated leases/reservations."""
    db = current_app.db

    pool = db.dhcp_pool[pool_id]
    if not pool:
        return jsonify({'error': 'DHCP pool not found'}), 404

    # Cascade delete will remove leases and reservations
    del db.dhcp_pool[pool_id]
    db.commit()

    return jsonify({'message': 'DHCP pool deleted successfully'}), 200


# =============================================================================
# DHCP Lease Endpoints
# =============================================================================

@dhcp_bp.route('/api/v1/dhcp/pools/<int:pool_id>/leases', methods=['GET'])
@token_required
def list_pool_leases(pool_id):
    """
    List leases for a DHCP pool.

    Query params:
        - status: Filter by status (active, expired, released)
        - mac: Filter by MAC address
    """
    db = current_app.db

    pool = db.dhcp_pool[pool_id]
    if not pool:
        return jsonify({'error': 'DHCP pool not found'}), 404

    user = get_current_user()
    if not _can_access_pool(user, pool):
        return jsonify({'error': 'Access denied'}), 403

    query = db.dhcp_lease.pool_id == pool_id

    status = request.args.get('status')
    if status:
        query &= db.dhcp_lease.status == status

    mac = request.args.get('mac')
    if mac:
        query &= db.dhcp_lease.mac_address == mac.upper()

    leases = db(query).select(orderby=~db.dhcp_lease.lease_start)

    now = datetime.utcnow()
    return jsonify([
        {
            'id': lease.id,
            'poolId': lease.pool_id,
            'macAddress': lease.mac_address,
            'ipAddress': lease.ip_address,
            'hostname': lease.hostname,
            'leaseStart': lease.lease_start.isoformat(),
            'leaseEnd': lease.lease_end.isoformat(),
            'status': lease.status,
            'remainingSeconds': max(0, int((lease.lease_end - now).total_seconds())) if lease.status == 'active' else 0
        }
        for lease in leases
    ]), 200


@dhcp_bp.route('/api/v1/dhcp/pools/<int:pool_id>/leases/<int:lease_id>', methods=['DELETE'])
@token_required
@requires_scope('dhcp:write')
@audit_log('dhcp_lease_released')
def release_lease(pool_id, lease_id):
    """Manually release a DHCP lease."""
    db = current_app.db

    lease = db.dhcp_lease[lease_id]
    if not lease or lease.pool_id != pool_id:
        return jsonify({'error': 'Lease not found'}), 404

    # Mark as released
    lease.update_record(status='released')
    db.commit()

    return jsonify({
        'message': 'Lease released successfully',
        'ipAddress': lease.ip_address,
        'macAddress': lease.mac_address
    }), 200


# =============================================================================
# DHCP Reservation Endpoints
# =============================================================================

@dhcp_bp.route('/api/v1/dhcp/reservations', methods=['GET'])
@token_required
def list_reservations():
    """
    List all DHCP reservations.

    Query params:
        - pool_id: Filter by pool
    """
    db = current_app.db
    user = get_current_user()

    query = db.dhcp_reservation.id > 0

    pool_id = request.args.get('pool_id', type=int)
    if pool_id:
        query &= db.dhcp_reservation.pool_id == pool_id

    reservations = db(query).select(orderby=db.dhcp_reservation.ip_address)

    return jsonify([
        {
            'id': res.id,
            'poolId': res.pool_id,
            'macAddress': res.mac_address,
            'ipAddress': res.ip_address,
            'hostname': res.hostname,
            'description': res.description,
            'createdAt': res.created_at.isoformat()
        }
        for res in reservations
    ]), 200


@dhcp_bp.route('/api/v1/dhcp/reservations', methods=['POST'])
@token_required
@requires_scope('dhcp:write')
@validate_json('poolId', 'macAddress', 'ipAddress')
@audit_log('dhcp_reservation_created')
def create_reservation():
    """Create a static IP reservation."""
    data = request.get_json()
    db = current_app.db

    # Validate pool exists
    pool = db.dhcp_pool[data['poolId']]
    if not pool:
        return jsonify({'error': 'DHCP pool not found'}), 404

    # Check for conflicts
    mac = data['macAddress'].upper()
    ip = data['ipAddress']

    existing = db(
        (db.dhcp_reservation.pool_id == data['poolId']) &
        ((db.dhcp_reservation.mac_address == mac) | (db.dhcp_reservation.ip_address == ip))
    ).select().first()

    if existing:
        return jsonify({'error': 'Reservation conflict: MAC or IP already reserved'}), 409

    res_id = db.dhcp_reservation.insert(
        pool_id=data['poolId'],
        mac_address=mac,
        ip_address=ip,
        hostname=data.get('hostname'),
        description=data.get('description')
    )
    db.commit()

    res = db.dhcp_reservation[res_id]
    return jsonify({
        'id': res.id,
        'poolId': res.pool_id,
        'macAddress': res.mac_address,
        'ipAddress': res.ip_address,
        'hostname': res.hostname,
        'createdAt': res.created_at.isoformat()
    }), 201


@dhcp_bp.route('/api/v1/dhcp/reservations/<int:reservation_id>', methods=['DELETE'])
@token_required
@requires_scope('dhcp:write')
@audit_log('dhcp_reservation_deleted')
def delete_reservation(reservation_id):
    """Delete a DHCP reservation."""
    db = current_app.db

    res = db.dhcp_reservation[reservation_id]
    if not res:
        return jsonify({'error': 'Reservation not found'}), 404

    del db.dhcp_reservation[reservation_id]
    db.commit()

    return jsonify({'message': 'Reservation deleted successfully'}), 200


# =============================================================================
# Helper Functions
# =============================================================================

def get_user_team_ids(user_id):
    """Get list of team IDs user belongs to."""
    db = current_app.db
    memberships = db(db.team_member.user_id == user_id).select(db.team_member.team_id)
    return [m.team_id for m in memberships]


def _can_access_pool(user, pool):
    """Check if user can access a DHCP pool."""
    if user.get('globalRole') in ['SystemAdmin', 'OrgAdmin']:
        return True
    if pool.team_id is None:
        return True
    return pool.team_id in get_user_team_ids(user['id'])


def _validate_ip_range(start, end):
    """Validate that start IP is less than end IP."""
    try:
        import ipaddress
        start_ip = ipaddress.ip_address(start)
        end_ip = ipaddress.ip_address(end)
        return start_ip < end_ip
    except ValueError:
        return False


def _calculate_pool_size(start, end):
    """Calculate number of IPs in a range."""
    try:
        import ipaddress
        start_ip = int(ipaddress.ip_address(start))
        end_ip = int(ipaddress.ip_address(end))
        return end_ip - start_ip + 1
    except ValueError:
        return 0
