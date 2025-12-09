"""
Authentication middleware for JWT token validation.
"""

from functools import wraps
from flask import request, jsonify, current_app, g
from app.services.auth_service import AuthService


def token_required(f):
    """
    Decorator to require valid JWT token.
    Extracts user information from token and stores in g.current_user.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                token = auth_header.split(' ')[1]  # Bearer <token>
            except IndexError:
                return jsonify({'error': 'Invalid authorization header format'}), 401

        if not token:
            return jsonify({'error': 'Authentication token required'}), 401

        # Decode and validate token
        payload = AuthService.decode_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401

        # Check token type
        if payload.get('type') not in ['access', 'server']:
            return jsonify({'error': 'Invalid token type'}), 401

        # Store user info in g for access in route
        g.current_user = {
            'user_id': payload.get('user_id'),
            'server_id': payload.get('server_id'),
            'username': payload.get('username'),
            'global_role': payload.get('global_role'),
            'team_roles': payload.get('team_roles', {}),
            'token_type': payload.get('type')
        }

        return f(*args, **kwargs)

    return decorated


def server_token_required(f):
    """
    Decorator to require valid DNS server JWT token.
    Validates using server-specific JWT secret.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                token = auth_header.split(' ')[1]
            except IndexError:
                return jsonify({'error': 'Invalid authorization header format'}), 401

        if not token:
            return jsonify({'error': 'Server authentication token required'}), 401

        # Decode token without verification first to get server_id
        try:
            import jwt
            unverified = jwt.decode(token, options={"verify_signature": False})
            server_id = unverified.get('server_id')
            token_type = unverified.get('type')

            if not server_id or token_type != 'server':
                return jsonify({'error': 'Invalid server token'}), 401

            # Get server's JWT secret
            db = current_app.db
            server = db.dns_server[server_id]
            if not server:
                return jsonify({'error': 'Server not found'}), 401

            # Validate with server-specific secret
            payload = AuthService.decode_token(token, server.jwt_secret)
            if not payload:
                return jsonify({'error': 'Invalid or expired server token'}), 401

            # Store server info in g
            g.current_server = {
                'server_id': server_id,
                'name': server.name,
                'region': server.region
            }

            return f(*args, **kwargs)

        except Exception as e:
            return jsonify({'error': f'Token validation failed: {str(e)}'}), 401

    return decorated


def optional_token(f):
    """
    Decorator that allows optional token authentication.
    If token is present, validates it and sets g.current_user.
    If token is absent, continues without authentication.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                token = auth_header.split(' ')[1]
            except IndexError:
                pass

        if token:
            # Validate token if present
            payload = AuthService.decode_token(token)
            if payload:
                g.current_user = {
                    'user_id': payload.get('user_id'),
                    'username': payload.get('username'),
                    'global_role': payload.get('global_role'),
                    'team_roles': payload.get('team_roles', {}),
                    'token_type': payload.get('type')
                }
        else:
            g.current_user = None

        return f(*args, **kwargs)

    return decorated


def get_current_user():
    """Get current user from g context."""
    return getattr(g, 'current_user', None)


def get_current_server():
    """Get current server from g context."""
    return getattr(g, 'current_server', None)
