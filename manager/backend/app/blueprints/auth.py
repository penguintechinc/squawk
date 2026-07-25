"""
Authentication API blueprint.
Handles login, logout, token refresh, and user info.
"""

from flask import Blueprint, request, jsonify, current_app
from app.services.auth_service import AuthService
from app.middleware.auth import token_required, get_current_user
from app.utils.decorators import validate_json, audit_log

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/api/v1/auth/login', methods=['POST'])
@validate_json('username', 'password')
@audit_log('user_login')
def login():
    """
    Authenticate user and return JWT tokens.

    Request:
        {
            "username": "admin",
            "password": "password123"
        }

    Response:
        {
            "accessToken": "...",
            "refreshToken": "...",
            "user": {
                "id": 1,
                "username": "admin",
                "email": "admin@example.com",
                "global_role": "SystemAdmin"
            }
        }
    """
    data = request.get_json()
    username = data['username']
    password = data['password']

    # Authenticate user
    user = AuthService.authenticate_user(username, password)
    if not user:
        return jsonify({'error': 'Invalid username or password'}), 401

    # Check if MFA is enabled
    db = current_app.db
    user_record = db.auth_user[user['id']]
    if user_record and user_record.mfa_enabled:
        # Return pre-auth token instead of full tokens
        from app.services.mfa_service import MFAService
        pre_auth_token = MFAService.create_pre_auth_token(user['id'])
        return jsonify({
            'mfa_required': True,
            'pre_auth_token': pre_auth_token,
            'message': 'MFA verification required'
        }), 200

    # Generate tokens
    access_token = AuthService.create_access_token(
        user['id'],
        user['username'],
        user['global_role'],
        user['team_roles']
    )
    refresh_token = AuthService.create_refresh_token(user['id'])

    return jsonify({
        'accessToken': access_token,
        'refreshToken': refresh_token,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'global_role': user['global_role'],
            'team_roles': user['team_roles']
        }
    }), 200


@auth_bp.route('/api/v1/auth/refresh', methods=['POST'])
@validate_json('refreshToken')
def refresh():
    """
    Refresh (rotate) tokens using a refresh token.

    The presented refresh token is single-use: it is revoked and a new
    access + refresh token pair is issued. Reusing a rotated or revoked
    refresh token returns 401.

    Request:
        {
            "refreshToken": "..."
        }

    Response:
        {
            "accessToken": "...",
            "refreshToken": "..."
        }
    """
    data = request.get_json()
    refresh_token = data['refreshToken']

    tokens = AuthService.refresh_access_token(refresh_token)
    if not tokens:
        return jsonify({'error': 'Invalid or expired refresh token'}), 401

    return jsonify({
        'accessToken': tokens['access_token'],
        'refreshToken': tokens['refresh_token']
    }), 200


@auth_bp.route('/api/v1/auth/logout', methods=['POST'])
@token_required
@audit_log('user_logout')
def logout():
    """
    Logout user: revoke the refresh token server-side.

    Request (optional body):
        {
            "refreshToken": "..."
        }

    The access token (15 min) simply ages out; the long-lived refresh token
    is revoked here so it cannot mint new access tokens after logout.

    Response:
        {
            "message": "Logged out successfully"
        }
    """
    data = request.get_json(silent=True) or {}
    refresh_token = data.get('refreshToken')
    if refresh_token:
        AuthService.revoke_refresh_token(refresh_token, reason='logout')

    return jsonify({
        'message': 'Logged out successfully'
    }), 200


@auth_bp.route('/api/v1/auth/me', methods=['GET'])
@token_required
def me():
    """
    Get current user information.

    Response:
        {
            "id": 1,
            "username": "admin",
            "global_role": "SystemAdmin",
            "team_roles": {
                "1": "TeamAdmin",
                "2": "TeamMember"
            }
        }
    """
    user = get_current_user()

    db = current_app.db
    user_record = db.auth_user[user['user_id']]

    if not user_record:
        return jsonify({'error': 'User not found'}), 404

    return jsonify({
        'id': user_record.id,
        'username': user_record.username,
        'email': user_record.email,
        'global_role': user_record.global_role,
        'active': user_record.active,
        'team_roles': user.get('team_roles', {}),
        'created_at': user_record.created_at.isoformat()
    }), 200


@auth_bp.route('/api/v1/auth/change-password', methods=['POST'])
@token_required
@validate_json('current_password', 'new_password')
@audit_log('password_changed')
def change_password():
    """
    Change user password.

    Request:
        {
            "current_password": "oldpass",
            "new_password": "newpass"
        }

    Response:
        {
            "message": "Password changed successfully"
        }
    """
    user = get_current_user()
    data = request.get_json()

    db = current_app.db
    user_record = db.auth_user[user['user_id']]

    if not user_record:
        return jsonify({'error': 'User not found'}), 404

    # Verify current password
    if not AuthService.verify_password(data['current_password'], user_record.password_hash):
        return jsonify({'error': 'Current password is incorrect'}), 401

    # Hash and update new password
    new_password_hash = AuthService.hash_password(data['new_password'])
    user_record.update_record(password_hash=new_password_hash)
    db.commit()

    return jsonify({
        'message': 'Password changed successfully'
    }), 200
