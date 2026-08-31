"""
Token management API blueprint.
Handles DNS authentication token CRUD.

At-rest protection: only `token_hash` (SHA-256 hex digest) is persisted --
the plaintext value is returned to the caller once, at create/regenerate
time, and never again (list/get responses only carry metadata).
"""

from flask import Blueprint, request, jsonify, current_app
from app.middleware.auth import token_required, get_current_user
from app.middleware.rbac import can_access_team
from app.utils.crypto import sha256_hex
from app.utils.decorators import validate_json, audit_log
import secrets

tokens_bp = Blueprint('tokens', __name__)


def _can_manage_token(token, user) -> bool:
    """Authorization check shared by get/update/delete/revoke/regenerate.

    Team-scoped tokens: caller needs access to that team. Team-less
    (global) tokens default-deny to SystemAdmin only. Previously
    `if token.team_id and not can_access_team(token.team_id)` skipped the
    check entirely whenever team_id was NULL, letting any authenticated
    user GET/PUT/DELETE/regenerate/revoke any global token by id (IDOR,
    finding H5) -- default-deny closes that gap.
    """
    if token.team_id:
        return can_access_team(token.team_id)
    return bool(user) and user.get('global_role') == 'SystemAdmin'


def _serialize_token(token, *, plaintext_token=None):
    """Build a token API response. `plaintext_token` is included ONLY at
    create/regenerate time -- every other response omits the secret value."""
    data = {
        'id': token.id,
        'name': token.name,
        'team_id': token.team_id,
        'active': token.active,
        'expires_at': token.expires_at.isoformat() if token.expires_at else None,
        'last_used': token.last_used.isoformat() if token.last_used else None,
        'created_at': token.created_at.isoformat()
    }
    if plaintext_token is not None:
        data['token'] = plaintext_token
    return data


@tokens_bp.route('/api/v1/tokens', methods=['GET'])
@token_required
def list_tokens():
    """
    List tokens accessible to current user.

    Query params:
        - active: Filter by active status (true/false)
        - team_id: Filter by team

    Response:
        [
            {
                "id": 1,
                "name": "Production Token",
                "team_id": 1,
                "active": true,
                "created_at": "2024-01-01T00:00:00",
                "last_used": "2024-01-02T10:00:00"
            }
        ]
    """
    db = current_app.db
    user = get_current_user()

    # System admins see all tokens (tautological condition, not a bare
    # TableProxy, so it's a valid penguin-dal Query -- db() requires one)
    if user.get('global_role') == 'SystemAdmin':
        query = db.token.id > 0
    else:
        # Users see tokens for teams they're members of
        accessible_team_ids = list(user.get('team_roles', {}).keys())
        if not accessible_team_ids:
            return jsonify([]), 200
        query = db.token.team_id.belongs(accessible_team_ids)

    # Apply filters
    active_filter = request.args.get('active')
    if active_filter is not None:
        active_bool = active_filter.lower() == 'true'
        query = query & (db.token.active == active_bool)

    team_id = request.args.get('team_id')
    if team_id:
        query = query & (db.token.team_id == int(team_id))

    tokens = db(query).select(orderby=db.token.created_at)

    return jsonify([_serialize_token(t) for t in tokens]), 200


@tokens_bp.route('/api/v1/tokens', methods=['POST'])
@token_required
@validate_json('name')
@audit_log('token_created')
def create_token():
    """
    Create a new DNS authentication token.

    Request:
        {
            "name": "Production Token",
            "team_id": 1,
            "expires_at": "2025-12-31T23:59:59"
        }

    Response (plaintext token shown ONCE):
        {
            "id": 1,
            "token": "generated-token-value",
            "name": "Production Token",
            "team_id": 1,
            "active": true
        }
    """
    data = request.get_json()
    db = current_app.db
    user = get_current_user()

    # Check team access if team_id provided
    team_id = data.get('team_id')
    if team_id and not can_access_team(team_id):
        return jsonify({'error': 'Access denied to specified team'}), 403

    # Generate secure token; only its hash is persisted.
    token_value = secrets.token_urlsafe(32)
    token_hash = sha256_hex(token_value)

    # Parse expiration date
    expires_at = None
    if 'expires_at' in data:
        from datetime import datetime
        try:
            expires_at = datetime.fromisoformat(data['expires_at'].replace('Z', '+00:00'))
        except ValueError:
            return jsonify({'error': 'Invalid expiration date format'}), 400

    # Create token
    token_id = db.token.insert(
        token_hash=token_hash,
        name=data['name'],
        team_id=team_id,
        created_by=user['user_id'],
        active=True,
        expires_at=expires_at
    )

    db.commit()

    token = db.token[token_id]

    return jsonify(_serialize_token(token, plaintext_token=token_value)), 201


@tokens_bp.route('/api/v1/tokens/<int:token_id>', methods=['GET'])
@token_required
def get_token(token_id):
    """Get token details (metadata only -- plaintext value is never returned
    after creation)."""
    db = current_app.db
    token = db.token[token_id]

    if not token:
        return jsonify({'error': 'Token not found'}), 404

    if not _can_manage_token(token, get_current_user()):
        return jsonify({'error': 'Access denied'}), 403

    return jsonify(_serialize_token(token)), 200


@tokens_bp.route('/api/v1/tokens/<int:token_id>', methods=['PUT'])
@token_required
@audit_log('token_updated')
def update_token(token_id):
    """
    Update token.

    Request:
        {
            "name": "Updated Name",
            "active": false
        }
    """
    db = current_app.db
    token = db.token[token_id]

    if not token:
        return jsonify({'error': 'Token not found'}), 404

    if not _can_manage_token(token, get_current_user()):
        return jsonify({'error': 'Access denied'}), 403

    data = request.get_json()
    update_fields = {}

    if 'name' in data:
        update_fields['name'] = data['name']

    if 'active' in data:
        update_fields['active'] = bool(data['active'])

    if 'expires_at' in data:
        from datetime import datetime
        try:
            expires_at = datetime.fromisoformat(data['expires_at'].replace('Z', '+00:00'))
            update_fields['expires_at'] = expires_at
        except ValueError:
            return jsonify({'error': 'Invalid expiration date format'}), 400

    db(db.token.id == token_id).update(**update_fields)
    db.commit()

    return jsonify(_serialize_token(db.token[token_id])), 200


@tokens_bp.route('/api/v1/tokens/<int:token_id>', methods=['DELETE'])
@token_required
@audit_log('token_deleted')
def delete_token(token_id):
    """Delete token."""
    db = current_app.db
    token = db.token[token_id]

    if not token:
        return jsonify({'error': 'Token not found'}), 404

    if not _can_manage_token(token, get_current_user()):
        return jsonify({'error': 'Access denied'}), 403

    # penguin-dal TableProxy has no __delitem__; use the QuerySet delete idiom.
    db(db.token.id == token_id).delete()
    db.commit()

    return jsonify({
        'message': 'Token deleted successfully'
    }), 200


@tokens_bp.route('/api/v1/tokens/<int:token_id>/revoke', methods=['POST'])
@token_required
@audit_log('token_revoked')
def revoke_token(token_id):
    """
    Revoke token (set active=false).

    Response:
        {
            "message": "Token revoked successfully"
        }
    """
    db = current_app.db
    token = db.token[token_id]

    if not token:
        return jsonify({'error': 'Token not found'}), 404

    if not _can_manage_token(token, get_current_user()):
        return jsonify({'error': 'Access denied'}), 403

    db(db.token.id == token_id).update(active=False)
    db.commit()

    return jsonify({
        'message': 'Token revoked successfully'
    }), 200


@tokens_bp.route('/api/v1/tokens/<int:token_id>/regenerate', methods=['POST'])
@token_required
@audit_log('token_regenerated')
def regenerate_token(token_id):
    """
    Regenerate token value.

    Response (plaintext token shown ONCE):
        {
            "token": "new-token-value"
        }
    """
    db = current_app.db
    token = db.token[token_id]

    if not token:
        return jsonify({'error': 'Token not found'}), 404

    if not _can_manage_token(token, get_current_user()):
        return jsonify({'error': 'Access denied'}), 403

    # Generate new token value; only its hash is persisted.
    new_token_value = secrets.token_urlsafe(32)
    db(db.token.id == token_id).update(token_hash=sha256_hex(new_token_value))
    db.commit()

    return jsonify({
        'message': 'Token regenerated successfully',
        'token': new_token_value
    }), 200
