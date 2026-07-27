"""
DNS Zone management API blueprint.
Handles zone and record CRUD with team-based access control.
"""

from flask import Blueprint, request, jsonify, current_app
from app.middleware.auth import token_required
from app.middleware.rbac import check_zone_access, filter_zones_by_access
from app.utils.decorators import validate_json, audit_log
from app.utils.validators import validate_domain_name, validate_dns_record_type, validate_ttl, validate_visibility

zones_bp = Blueprint('zones', __name__)


@zones_bp.route('/api/v1/zones', methods=['GET'])
@token_required
def list_zones():
    """
    List DNS zones accessible to current user.

    Query params:
        - visibility: Filter by visibility (public/internal/restricted/private)
        - team_id: Filter by team

    Response:
        [
            {
                "id": 1,
                "name": "example.com",
                "visibility": "public",
                "team_id": null,
                "record_count": 5
            }
        ]
    """
    db = current_app.db

    # Get accessible zone IDs
    accessible_zone_ids = filter_zones_by_access()

    if not accessible_zone_ids:
        return jsonify([]), 200

    query = db.dns_zone.id.belongs(accessible_zone_ids)

    # Apply filters
    visibility = request.args.get('visibility')
    if visibility and validate_visibility(visibility):
        query = query & (db.dns_zone.visibility == visibility)

    team_id = request.args.get('team_id')
    if team_id:
        query = query & (db.dns_zone.team_id == int(team_id))

    zones = db(query).select(db.dns_zone.ALL, orderby=db.dns_zone.name)

    result = []
    for zone in zones:
        record_count = db(db.dns_record.zone_id == zone.id).count()
        result.append({
            'id': zone.id,
            'name': zone.name,
            'visibility': zone.visibility,
            'team_id': zone.team_id,
            'description': zone.description,
            'record_count': record_count,
            'created_at': zone.created_at.isoformat()
        })

    return jsonify(result), 200


@zones_bp.route('/api/v1/zones', methods=['POST'])
@token_required
@validate_json('name', 'visibility')
@audit_log('zone_created')
def create_zone():
    """
    Create a new DNS zone.

    Request:
        {
            "name": "example.com",
            "visibility": "public",
            "team_id": 1,
            "description": "Public zone"
        }

    Response:
        {
            "id": 1,
            "name": "example.com",
            "visibility": "public",
            "team_id": 1
        }
    """
    data = request.get_json()
    db = current_app.db

    # Validate domain name
    if not validate_domain_name(data['name']):
        return jsonify({'error': 'Invalid domain name'}), 400

    # Validate visibility
    if not validate_visibility(data['visibility']):
        return jsonify({'error': 'Invalid visibility'}), 400

    # Check if zone already exists
    if db(db.dns_zone.name == data['name']).count() > 0:
        return jsonify({'error': 'Zone already exists'}), 409

    # Create zone
    zone_id = db.dns_zone.insert(
        name=data['name'],
        visibility=data['visibility'],
        team_id=data.get('team_id'),
        description=data.get('description', '')
    )

    db.commit()

    zone = db.dns_zone[zone_id]

    return jsonify({
        'id': zone.id,
        'name': zone.name,
        'visibility': zone.visibility,
        'team_id': zone.team_id,
        'description': zone.description,
        'created_at': zone.created_at.isoformat()
    }), 201


@zones_bp.route('/api/v1/zones/<int:zone_id>', methods=['GET'])
@token_required
def get_zone(zone_id):
    """Get zone details with records."""
    if not check_zone_access(zone_id):
        return jsonify({'error': 'Access denied'}), 403

    db = current_app.db
    zone = db.dns_zone[zone_id]

    if not zone:
        return jsonify({'error': 'Zone not found'}), 404

    # Get records
    records = db(db.dns_record.zone_id == zone_id).select(
        db.dns_record.ALL,
        orderby=db.dns_record.name
    )

    return jsonify({
        'id': zone.id,
        'name': zone.name,
        'visibility': zone.visibility,
        'team_id': zone.team_id,
        'description': zone.description,
        'records': [
            {
                'id': r.id,
                'name': r.name,
                'type': r.type,
                'value': r.value,
                'ttl': r.ttl,
                'priority': r.priority,
                'weight': r.weight,
                'port': r.port
            }
            for r in records
        ],
        'created_at': zone.created_at.isoformat()
    }), 200


@zones_bp.route('/api/v1/zones/<int:zone_id>', methods=['PUT'])
@token_required
@audit_log('zone_updated')
def update_zone(zone_id):
    """
    Update zone information.

    Request:
        {
            "visibility": "internal",
            "description": "Updated description"
        }
    """
    if not check_zone_access(zone_id):
        return jsonify({'error': 'Access denied'}), 403

    db = current_app.db
    zone = db.dns_zone[zone_id]

    if not zone:
        return jsonify({'error': 'Zone not found'}), 404

    data = request.get_json()

    if 'visibility' in data:
        if not validate_visibility(data['visibility']):
            return jsonify({'error': 'Invalid visibility'}), 400
        zone.update_record(visibility=data['visibility'])

    if 'description' in data:
        zone.update_record(description=data['description'])

    if 'team_id' in data:
        zone.update_record(team_id=data['team_id'])

    db.commit()

    return jsonify({
        'id': zone.id,
        'name': zone.name,
        'visibility': zone.visibility,
        'team_id': zone.team_id,
        'description': zone.description
    }), 200


@zones_bp.route('/api/v1/zones/<int:zone_id>', methods=['DELETE'])
@token_required
@audit_log('zone_deleted')
def delete_zone(zone_id):
    """Delete zone and all records."""
    if not check_zone_access(zone_id):
        return jsonify({'error': 'Access denied'}), 403

    db = current_app.db
    zone = db.dns_zone[zone_id]

    if not zone:
        return jsonify({'error': 'Zone not found'}), 404

    # Delete zone (cascade will delete records)
    del db.dns_zone[zone_id]
    db.commit()

    return jsonify({
        'message': 'Zone deleted successfully'
    }), 200


@zones_bp.route('/api/v1/zones/<int:zone_id>/records', methods=['GET'])
@token_required
def list_zone_records(zone_id):
    """List all records in zone."""
    if not check_zone_access(zone_id):
        return jsonify({'error': 'Access denied'}), 403

    db = current_app.db

    records = db(db.dns_record.zone_id == zone_id).select(
        db.dns_record.ALL,
        orderby=db.dns_record.name
    )

    return jsonify([
        {
            'id': r.id,
            'name': r.name,
            'type': r.type,
            'value': r.value,
            'ttl': r.ttl,
            'priority': r.priority,
            'weight': r.weight,
            'port': r.port,
            'created_at': r.created_at.isoformat()
        }
        for r in records
    ]), 200


@zones_bp.route('/api/v1/zones/<int:zone_id>/records', methods=['POST'])
@token_required
@validate_json('name', 'type', 'value')
@audit_log('dns_record_created')
def create_dns_record(zone_id):
    """
    Create a new DNS record.

    Request:
        {
            "name": "www.example.com",
            "type": "A",
            "value": "192.168.1.1",
            "ttl": 300,
            "priority": 10  // For MX records
        }
    """
    if not check_zone_access(zone_id):
        return jsonify({'error': 'Access denied'}), 403

    data = request.get_json()
    db = current_app.db

    # Validate record type
    if not validate_dns_record_type(data['type']):
        return jsonify({'error': 'Invalid DNS record type'}), 400

    # Validate TTL
    ttl = data.get('ttl', 300)
    if not validate_ttl(ttl):
        return jsonify({'error': 'Invalid TTL value'}), 400

    # Create record
    record_id = db.dns_record.insert(
        zone_id=zone_id,
        name=data['name'],
        type=data['type'].upper(),
        value=data['value'],
        ttl=ttl,
        priority=data.get('priority'),
        weight=data.get('weight'),
        port=data.get('port')
    )

    db.commit()

    record = db.dns_record[record_id]

    return jsonify({
        'id': record.id,
        'zone_id': record.zone_id,
        'name': record.name,
        'type': record.type,
        'value': record.value,
        'ttl': record.ttl,
        'priority': record.priority,
        'weight': record.weight,
        'port': record.port,
        'created_at': record.created_at.isoformat()
    }), 201


@zones_bp.route('/api/v1/zones/<int:zone_id>/records/<int:record_id>', methods=['PUT'])
@token_required
@audit_log('dns_record_updated')
def update_dns_record(zone_id, record_id):
    """Update DNS record."""
    if not check_zone_access(zone_id):
        return jsonify({'error': 'Access denied'}), 403

    db = current_app.db
    record = db.dns_record[record_id]

    if not record or record.zone_id != zone_id:
        return jsonify({'error': 'Record not found'}), 404

    data = request.get_json()
    update_fields = {}

    if 'value' in data:
        update_fields['value'] = data['value']

    if 'ttl' in data:
        if not validate_ttl(data['ttl']):
            return jsonify({'error': 'Invalid TTL value'}), 400
        update_fields['ttl'] = data['ttl']

    if 'priority' in data:
        update_fields['priority'] = data['priority']

    if 'weight' in data:
        update_fields['weight'] = data['weight']

    if 'port' in data:
        update_fields['port'] = data['port']

    record.update_record(**update_fields)
    db.commit()

    return jsonify({
        'id': record.id,
        'name': record.name,
        'type': record.type,
        'value': record.value,
        'ttl': record.ttl,
        'priority': record.priority
    }), 200


@zones_bp.route('/api/v1/zones/<int:zone_id>/records/<int:record_id>', methods=['DELETE'])
@token_required
@audit_log('dns_record_deleted')
def delete_dns_record(zone_id, record_id):
    """Delete DNS record."""
    if not check_zone_access(zone_id):
        return jsonify({'error': 'Access denied'}), 403

    db = current_app.db
    record = db.dns_record[record_id]

    if not record or record.zone_id != zone_id:
        return jsonify({'error': 'Record not found'}), 404

    del db.dns_record[record_id]
    db.commit()

    return jsonify({
        'message': 'DNS record deleted successfully'
    }), 200
