"""
Token management API blueprint.
Handles DNS authentication token CRUD.
"""

from flask import Blueprint, request, jsonify, current_app
from app.middleware.auth import token_required, get_current_user
from app.middleware.rbac import can_access_team
from app.utils.decorators import validate_json, audit_log
import secrets

tokens_bp = Blueprint('tokens', __name__)


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
                "token": "token-value",
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

    # System admins see all tokens
    if user.get('global_role') == 'SystemAdmin':
        query = db.token
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

    tokens = db(query).select(
        db.token.ALL,
        orderby=db.token.created_at
    )

    return jsonify([
        {
            'id': t.id,
            'token': t.token,
            'name': t.name,
            'team_id': t.team_id,
            'active': t.active,
            'expires_at': t.expires_at.isoformat() if t.expires_at else None,
            'last_used': t.last_used.isoformat() if t.last_used else None,
            'created_at': t.created_at.isoformat()
        }
        for t in tokens
    ]), 200


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

    Response:
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

    # Generate secure token
    token_value = secrets.token_urlsafe(32)

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
        token=token_value,
        name=data['name'],
        team_id=team_id,
        created_by=user['user_id'],
        active=True,
        expires_at=expires_at
    )

    db.commit()

    token = db.token[token_id]

    return jsonify({
        'id': token.id,
        'token': token.token,
        'name': token.name,
        'team_id': token.team_id,
        'active': token.active,
        'expires_at': token.expires_at.isoformat() if token.expires_at else None,
        'created_at': token.created_at.isoformat()
    }), 201


@tokens_bp.route('/api/v1/tokens/<int:token_id>', methods=['GET'])
@token_required
def get_token(token_id):
    """Get token details."""
    db = current_app.db
    token = db.token[token_id]

    if not token:
        return jsonify({'error': 'Token not found'}), 404

    # Check access
    if token.team_id and not can_access_team(token.team_id):
        return jsonify({'error': 'Access denied'}), 403

    return jsonify({
        'id': token.id,
        'token': token.token,
        'name': token.name,
        'team_id': token.team_id,
        'active': token.active,
        'expires_at': token.expires_at.isoformat() if token.expires_at else None,
        'last_used': token.last_used.isoformat() if token.last_used else None,
        'created_at': token.created_at.isoformat()
    }), 200


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

    # Check access
    if token.team_id and not can_access_team(token.team_id):
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

    token.update_record(**update_fields)
    db.commit()

    return jsonify({
        'id': token.id,
        'token': token.token,
        'name': token.name,
        'team_id': token.team_id,
        'active': token.active,
        'expires_at': token.expires_at.isoformat() if token.expires_at else None
    }), 200


@tokens_bp.route('/api/v1/tokens/<int:token_id>', methods=['DELETE'])
@token_required
@audit_log('token_deleted')
def delete_token(token_id):
    """Delete token."""
    db = current_app.db
    token = db.token[token_id]

    if not token:
        return jsonify({'error': 'Token not found'}), 404

    # Check access
    if token.team_id and not can_access_team(token.team_id):
        return jsonify({'error': 'Access denied'}), 403

    del db.token[token_id]
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

    # Check access
    if token.team_id and not can_access_team(token.team_id):
        return jsonify({'error': 'Access denied'}), 403

    token.update_record(active=False)
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

    Response:
        {
            "token": "new-token-value"
        }
    """
    db = current_app.db
    token = db.token[token_id]

    if not token:
        return jsonify({'error': 'Token not found'}), 404

    # Check access
    if token.team_id and not can_access_team(token.team_id):
        return jsonify({'error': 'Access denied'}), 403

    # Generate new token value
    new_token_value = secrets.token_urlsafe(32)
    token.update_record(token=new_token_value)
    db.commit()

    return jsonify({
        'message': 'Token regenerated successfully',
        'token': new_token_value
    }), 200
