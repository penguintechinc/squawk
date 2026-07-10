"""
User management API blueprint.
RBAC protected - SystemAdmin and UserManager only.
"""

from flask import Blueprint, request, jsonify, current_app
from app.services.auth_service import AuthService
from app.middleware.auth import token_required
from app.middleware.rbac import requires_scope
from app.utils.decorators import validate_json, audit_log
from app.utils.validators import validate_email, validate_username, validate_global_role

users_bp = Blueprint('users', __name__)


@users_bp.route('/api/v1/users', methods=['GET'])
@token_required
@requires_scope('users:write')
def list_users():
    """
    List all users.

    Query params:
        - active: Filter by active status (true/false)
        - role: Filter by global role

    Response:
        [
            {
                "id": 1,
                "username": "admin",
                "email": "admin@example.com",
                "global_role": "SystemAdmin",
                "active": true,
                "created_at": "2024-01-01T00:00:00"
            }
        ]
    """
    db = current_app.db

    query = db.auth_user

    # Apply filters
    active_filter = request.args.get('active')
    if active_filter is not None:
        active_bool = active_filter.lower() == 'true'
        query = query(db.auth_user.active == active_bool)

    role_filter = request.args.get('role')
    if role_filter:
        query = query(db.auth_user.global_role == role_filter)

    users = query.select(orderby=db.auth_user.username)

    return jsonify([
        {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'global_role': user.global_role,
            'active': user.active,
            'created_at': user.created_at.isoformat()
        }
        for user in users
    ]), 200


@users_bp.route('/api/v1/users', methods=['POST'])
@token_required
@requires_scope('users:write')
@validate_json('username', 'email', 'password', 'global_role')
@audit_log('user_created')
def create_user():
    """
    Create a new user.

    Request:
        {
            "username": "newuser",
            "email": "user@example.com",
            "password": "password123",
            "global_role": "Viewer"
        }

    Response:
        {
            "id": 2,
            "username": "newuser",
            "email": "user@example.com",
            "global_role": "Viewer"
        }
    """
    data = request.get_json()

    # Validate input
    if not validate_username(data['username']):
        return jsonify({'error': 'Invalid username format'}), 400

    if not validate_email(data['email']):
        return jsonify({'error': 'Invalid email format'}), 400

    if not validate_global_role(data['global_role']):
        return jsonify({'error': 'Invalid global role'}), 400

    db = current_app.db

    # Check if username or email already exists
    if db(db.auth_user.username == data['username']).count() > 0:
        return jsonify({'error': 'Username already exists'}), 409

    if db(db.auth_user.email == data['email']).count() > 0:
        return jsonify({'error': 'Email already exists'}), 409

    # Hash password
    password_hash = AuthService.hash_password(data['password'])

    # Create user
    user_id = db.auth_user.insert(
        username=data['username'],
        email=data['email'],
        password_hash=password_hash,
        global_role=data['global_role'],
        active=True
    )

    db.commit()

    user = db.auth_user[user_id]

    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'global_role': user.global_role,
        'active': user.active,
        'created_at': user.created_at.isoformat()
    }), 201


@users_bp.route('/api/v1/users/<int:user_id>', methods=['GET'])
@token_required
@requires_scope('users:write')
def get_user(user_id):
    """Get user by ID."""
    db = current_app.db
    user = db.auth_user[user_id]

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Get team memberships
    memberships = db(db.team_member.user_id == user_id).select(
        db.team_member.ALL,
        db.team.ALL,
        left=db.team.on(db.team_member.team_id == db.team.id)
    )

    teams = [
        {
            'team_id': m.team_member.team_id,
            'team_name': m.team.name,
            'role': m.team_member.role,
            'joined_at': m.team_member.joined_at.isoformat()
        }
        for m in memberships
    ]

    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'global_role': user.global_role,
        'active': user.active,
        'teams': teams,
        'created_at': user.created_at.isoformat()
    }), 200


@users_bp.route('/api/v1/users/<int:user_id>', methods=['PUT'])
@token_required
@requires_scope('users:write')
@audit_log('user_updated')
def update_user(user_id):
    """
    Update user information.

    Request:
        {
            "email": "newemail@example.com",
            "global_role": "OrgAdmin",
            "active": true
        }
    """
    db = current_app.db
    user = db.auth_user[user_id]

    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()
    update_fields = {}

    if 'email' in data:
        if not validate_email(data['email']):
            return jsonify({'error': 'Invalid email format'}), 400
        update_fields['email'] = data['email']

    if 'global_role' in data:
        if not validate_global_role(data['global_role']):
            return jsonify({'error': 'Invalid global role'}), 400
        update_fields['global_role'] = data['global_role']

    if 'active' in data:
        update_fields['active'] = bool(data['active'])

    # Update user
    user.update_record(**update_fields)
    db.commit()

    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'global_role': user.global_role,
        'active': user.active
    }), 200


@users_bp.route('/api/v1/users/<int:user_id>', methods=['DELETE'])
@token_required
@requires_scope('users:admin')
@audit_log('user_deleted')
def delete_user(user_id):
    """
    Delete user (soft delete - set active=false).

    Response:
        {
            "message": "User deleted successfully"
        }
    """
    db = current_app.db
    user = db.auth_user[user_id]

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Soft delete
    user.update_record(active=False)
    db.commit()

    return jsonify({
        'message': 'User deleted successfully'
    }), 200
