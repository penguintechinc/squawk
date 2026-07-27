"""
Machine client management API blueprint.
Handles CRUD for OAuth2 client_credentials machine identities.
"""

from flask import Blueprint, request, jsonify, current_app
from app.middleware.auth import token_required, get_current_user
from app.middleware.rbac import requires_system_admin
from app.services.auth_service import AuthService
from app.services.scopes import SUPERADMIN_SCOPE
from app.utils.decorators import validate_json, audit_log
from app.utils.domain_validation import validate_allowed_domains
from datetime import datetime
import logging
import json

machine_clients_bp = Blueprint('machine_clients', __name__)
log = logging.getLogger(__name__)


@machine_clients_bp.route('/api/v1/machine-clients', methods=['GET'])
@token_required
@requires_system_admin
def list_machine_clients():
    """
    List all machine clients (admin only).

    Query params:
        - active: Filter by active status (true/false)
        - tenant: Filter by tenant (default: 'default')

    Response:
        [
            {
                "id": 1,
                "client_id": "sqk_mc_...",
                "tenant": "default",
                "scopes": "users:read servers:write",
                "description": "CI/CD pipeline",
                "active": true,
                "created_at": "2024-01-01T00:00:00",
                "last_used_at": "2024-01-02T10:00:00"
            }
        ]
    """
    db = current_app.db

    # Start with tenant filter (always filter by tenant)
    tenant = request.args.get('tenant', 'default')
    query = db.machine_client.tenant == tenant

    # Filter by active status
    active_filter = request.args.get('active')
    if active_filter is not None:
        active_bool = active_filter.lower() == 'true'
        query = query & (db.machine_client.active == active_bool)

    # Pagination
    limit = min(int(request.args.get('limit', 100)), 1000)
    offset = int(request.args.get('offset', 0))

    clients = db(query).select(
        orderby=db.machine_client.created_at,
        limitby=(offset, offset + limit)
    )

    result = []
    for c in clients:
        allowed_domains = None
        if c.allowed_domains:
            try:
                allowed_domains = json.loads(c.allowed_domains)
            except (json.JSONDecodeError, TypeError):
                allowed_domains = None
        result.append({
            'id': c.id,
            'client_id': c.client_id,
            'tenant': c.tenant,
            'scopes': c.scopes,
            'allowed_domains': allowed_domains,
            'description': c.description,
            'active': c.active,
            'created_at': c.created_at.isoformat(),
            'last_used_at': c.last_used_at.isoformat() if c.last_used_at else None,
        })
    return jsonify(result), 200


@machine_clients_bp.route('/api/v1/machine-clients', methods=['POST'])
@token_required
@requires_system_admin
@validate_json('scopes', 'description')
@audit_log('machine_client_created')
def create_machine_client():
    """
    Create a new machine client (admin only).

    Request:
        {
            "scopes": "users:read servers:write",
            "description": "CI/CD deployment automation",
            "tenant": "default"  (optional)
        }

    Response:
        {
            "id": 1,
            "client_id": "sqk_mc_...",
            "client_secret": "...",  (plaintext, returned exactly once)
            "tenant": "default",
            "scopes": "users:read servers:write",
            "description": "CI/CD deployment automation",
            "active": true,
            "created_at": "2024-01-01T00:00:00"
        }
    """
    data = request.get_json()
    scopes = data.get('scopes', '').strip()
    description = data.get('description', '').strip()
    tenant = data.get('tenant', 'default').strip()
    allowed_domains = data.get('allowed_domains')  # None or list

    if not scopes:
        return jsonify({'error': 'scopes required and must be non-empty'}), 400

    # Validate allowed_domains if provided
    is_valid, error_msg = validate_allowed_domains(allowed_domains)
    if not is_valid:
        return jsonify({'error': error_msg}), 400

    # Validate scopes exist in the system
    from app.services.scopes import ROLE_SCOPES, _READ_SCOPES
    all_valid_scopes = set()
    for scope_bundle in ROLE_SCOPES.values():
        all_valid_scopes.update(scope_bundle)

    requested = set(scopes.split())
    if not requested.issubset(all_valid_scopes):
        invalid = requested - all_valid_scopes
        return jsonify({
            'error': 'Invalid scopes',
            'invalid_scopes': list(invalid)
        }), 400

    client_id, secret_plaintext, secret_hash = AuthService.create_machine_client(
        tenant=tenant,
        description=description,
        registered_scopes=scopes
    )

    # Update allowed_domains if provided
    if allowed_domains is not None:
        db = current_app.db
        db(db.machine_client.client_id == client_id).update(
            allowed_domains=json.dumps(allowed_domains)
        )
        db.commit()

    # Log with client_id only (never secret)
    log.info(f"Machine client created: client_id={client_id}, scopes={scopes}",
             extra={'audit': True})

    return jsonify({
        'id': 1,  # Will be set by DB
        'client_id': client_id,
        'client_secret': secret_plaintext,
        'tenant': tenant,
        'scopes': scopes,
        'allowed_domains': allowed_domains,
        'description': description,
        'active': True,
        'created_at': datetime.utcnow().isoformat()
    }), 201


@machine_clients_bp.route('/api/v1/machine-clients/<int:client_id>', methods=['GET'])
@token_required
@requires_system_admin
def get_machine_client(client_id: int):
    """
    Get a specific machine client (admin only).

    Response:
        {
            "id": 1,
            "client_id": "sqk_mc_...",
            "tenant": "default",
            "scopes": "users:read servers:write",
            "description": "CI/CD pipeline",
            "active": true,
            "created_at": "2024-01-01T00:00:00",
            "last_used_at": "2024-01-02T10:00:00"
        }
    """
    db = current_app.db
    client = db.machine_client[client_id]

    if not client:
        return jsonify({'error': 'Machine client not found'}), 404

    allowed_domains = None
    if client.allowed_domains:
        try:
            allowed_domains = json.loads(client.allowed_domains)
        except (json.JSONDecodeError, TypeError):
            allowed_domains = None

    return jsonify({
        'id': client.id,
        'client_id': client.client_id,
        'tenant': client.tenant,
        'scopes': client.scopes,
        'allowed_domains': allowed_domains,
        'description': client.description,
        'active': client.active,
        'created_at': client.created_at.isoformat(),
        'last_used_at': client.last_used_at.isoformat() if client.last_used_at else None,
    }), 200


@machine_clients_bp.route('/api/v1/machine-clients/<int:client_id>', methods=['PATCH'])
@token_required
@requires_system_admin
@audit_log('machine_client_updated')
def update_machine_client(client_id: int):
    """
    Update a machine client (admin only).

    Request:
        {
            "scopes": "users:read servers:read",  (optional)
            "description": "Updated description",  (optional)
            "active": true  (optional)
        }

    Response:
        Updated client record
    """
    db = current_app.db
    client = db.machine_client[client_id]

    if not client:
        return jsonify({'error': 'Machine client not found'}), 404

    data = request.get_json(silent=True) or {}

    # Validate and update scopes if provided
    update_fields = {}
    if 'scopes' in data:
        scopes = data['scopes'].strip()
        from app.services.scopes import ROLE_SCOPES
        all_valid_scopes = set()
        for scope_bundle in ROLE_SCOPES.values():
            all_valid_scopes.update(scope_bundle)

        requested = set(scopes.split())
        if not requested.issubset(all_valid_scopes):
            invalid = requested - all_valid_scopes
            return jsonify({
                'error': 'Invalid scopes',
                'invalid_scopes': list(invalid)
            }), 400
        update_fields['scopes'] = scopes

    if 'description' in data:
        update_fields['description'] = data['description']

    if 'active' in data:
        update_fields['active'] = bool(data['active'])

    if 'allowed_domains' in data:
        allowed_domains = data['allowed_domains']
        is_valid, error_msg = validate_allowed_domains(allowed_domains)
        if not is_valid:
            return jsonify({'error': error_msg}), 400
        update_fields['allowed_domains'] = json.dumps(allowed_domains) if allowed_domains is not None else None

    if update_fields:
        db(db.machine_client.id == client_id).update(**update_fields)
        db.commit()
        # Refetch after update
        client = db.machine_client[client_id]
    else:
        db.commit()

    log.info(f"Machine client updated: client_id={client.client_id}",
             extra={'audit': True})

    allowed_domains = None
    if client.allowed_domains:
        try:
            allowed_domains = json.loads(client.allowed_domains)
        except (json.JSONDecodeError, TypeError):
            allowed_domains = None

    return jsonify({
        'id': client.id,
        'client_id': client.client_id,
        'tenant': client.tenant,
        'scopes': client.scopes,
        'allowed_domains': allowed_domains,
        'description': client.description,
        'active': client.active,
        'created_at': client.created_at.isoformat(),
        'last_used_at': client.last_used_at.isoformat() if client.last_used_at else None,
    }), 200


@machine_clients_bp.route('/api/v1/machine-clients/<int:client_id>', methods=['DELETE'])
@token_required
@requires_system_admin
@audit_log('machine_client_deleted')
def delete_machine_client(client_id: int):
    """
    Delete a machine client (admin only).

    Response:
        {
            "message": "Machine client deleted"
        }
    """
    db = current_app.db
    client = db.machine_client[client_id]

    if not client:
        return jsonify({'error': 'Machine client not found'}), 404

    client_id_val = client.client_id
    db(db.machine_client.id == client_id).delete()
    db.commit()

    log.info(f"Machine client deleted: client_id={client_id_val}",
             extra={'audit': True})

    return jsonify({'message': 'Machine client deleted'}), 200


@machine_clients_bp.route('/api/v1/machine-clients/<int:client_id>/rotate-secret', methods=['POST'])
@token_required
@requires_system_admin
@audit_log('machine_client_secret_rotated')
def rotate_machine_client_secret(client_id: int):
    """
    Rotate (regenerate) the client secret for a machine client (admin only).
    Old secret immediately becomes invalid.

    Response:
        {
            "client_id": "sqk_mc_...",
            "client_secret": "...",  (plaintext, returned exactly once)
            "created_at": "2024-01-01T00:00:00"
        }
    """
    db = current_app.db
    client = db.machine_client[client_id]

    if not client:
        return jsonify({'error': 'Machine client not found'}), 404

    # Generate new secret (same process as create)
    import secrets
    import bcrypt

    new_secret = secrets.token_urlsafe(32)
    new_hash = bcrypt.hashpw(new_secret.encode('utf-8'),
                            bcrypt.gensalt()).decode('utf-8')

    db(db.machine_client.id == client_id).update(client_secret_hash=new_hash)
    db.commit()

    log.info(f"Machine client secret rotated: client_id={client.client_id}",
             extra={'audit': True})

    return jsonify({
        'client_id': client.client_id,
        'client_secret': new_secret,
        'created_at': client.created_at.isoformat()
    }), 200
