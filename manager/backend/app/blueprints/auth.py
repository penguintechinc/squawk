"""
Authentication API blueprint.
Handles login, logout, token refresh, and user info.
"""

from flask import Blueprint, request, jsonify, current_app
from app.services.auth_service import AuthService
from app.middleware.auth import token_required, get_current_user
from app.utils.decorators import validate_json, audit_log
import json

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


@auth_bp.route('/api/v1/auth/token', methods=['POST'])
def token():
    """
    OAuth2 token endpoint supporting multiple grant types.

    Grants supported:
    - client_credentials: Machine-to-machine authentication
    - urn:ietf:params:oauth:grant-type:token-exchange: Federated workload identity

    --- client_credentials (Part 1) ---
    Request (HTTP Basic Auth):
        Authorization: Basic base64(client_id:client_secret)
        POST /api/v1/auth/token
        Content-Type: application/x-www-form-urlencoded

        grant_type=client_credentials
        scope=optional_scope_subset (optional; defaults to registered scopes)

    Or (Form body):
        grant_type=client_credentials
        client_id=...
        client_secret=...
        scope=optional (optional)

    Response (200 OK):
        {
            "access_token": "...",
            "token_type": "Bearer",
            "expires_in": 900,  (15 min in seconds)
            "scope": "granted scopes"
        }

    Errors:
        400 Bad Request:
            {
                "error": "invalid_request",
                "error_description": "..."
            }
        401 Unauthorized:
            {
                "error": "invalid_client",
                "error_description": "Client authentication failed"
            }

    --- token-exchange (Part 2) ---
    Request:
        grant_type=urn:ietf:params:oauth:grant-type:token-exchange
        subject_token=<JWT from external issuer>
        subject_token_type=urn:ietf:params:oauth:token-type:jwt
        scope=optional (optional; must be subset of anchor's allowed_scopes)

    Response (200 OK):
        Same as client_credentials

    Errors:
        401 Unauthorized:
            {
                "error": "invalid_grant",
                "error_description": "External token validation failed"
            }
    """
    # Determine grant type
    grant_type = request.form.get('grant_type') or ''

    # ── client_credentials grant ─────────────────────────────────────────────

    if grant_type == 'client_credentials':
        # Extract client credentials from HTTP Basic Auth or form body
        client_id = None
        client_secret = None

        # Try HTTP Basic Auth first
        if request.authorization:
            client_id = request.authorization.username
            client_secret = request.authorization.password
        else:
            # Fall back to form body
            client_id = request.form.get('client_id', '').strip()
            client_secret = request.form.get('client_secret', '').strip()

        if not client_id or not client_secret:
            return jsonify({
                'error': 'invalid_request',
                'error_description': 'Missing client credentials'
            }), 400

        # Verify client (constant-time check)
        client = AuthService.verify_machine_client(client_id, client_secret)
        if not client:
            return jsonify({
                'error': 'invalid_client',
                'error_description': 'Client authentication failed'
            }), 401

        # Determine granted scopes (requested ⊆ registered)
        requested_scope = request.form.get('scope', '').strip()
        if requested_scope:
            if not AuthService.validate_scope_subset(requested_scope, client['scopes']):
                return jsonify({
                    'error': 'invalid_scope',
                    'error_description': 'Requested scopes exceed registered scopes'
                }), 400
            granted_scopes = requested_scope
        else:
            granted_scopes = client['scopes']

        # Fetch allowed_domains from DB and parse JSON
        db = current_app.db
        mc_record = db((db.machine_client.client_id == client['client_id']) &
                       (db.machine_client.active == True)).select().first()
        allowed_domains = None
        if mc_record and mc_record.allowed_domains:
            try:
                allowed_domains = json.loads(mc_record.allowed_domains)
            except (json.JSONDecodeError, TypeError):
                allowed_domains = None

        # Issue token
        access_token = AuthService.create_machine_access_token(
            client_id=client['client_id'],
            tenant=client['tenant'],
            granted_scopes=granted_scopes,
            allowed_domains=allowed_domains
        )

        # Update last_used_at
        AuthService.update_machine_client_last_used(client['client_id'])

        ttl_config = current_app.config.get('MACHINE_ACCESS_TOKEN_EXPIRES')
        expires_in = ttl_config.total_seconds() if hasattr(ttl_config, 'total_seconds') else ttl_config or 900

        return jsonify({
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': int(expires_in),
            'scope': granted_scopes
        }), 200

    # ── token-exchange grant (Part 2) ───────────────────────────────────────

    elif grant_type == 'urn:ietf:params:oauth:grant-type:token-exchange':
        subject_token = request.form.get('subject_token', '').strip()
        subject_token_type = request.form.get('subject_token_type', '').strip()

        if not subject_token or subject_token_type != 'urn:ietf:params:oauth:token-type:jwt':
            return jsonify({
                'error': 'invalid_request',
                'error_description': 'subject_token and subject_token_type=urn:ietf:params:oauth:token-type:jwt required'
            }), 400

        # Decode external token (without verification yet)
        try:
            import jwt as pyjwt
            unverified = pyjwt.decode(subject_token, options={'verify_signature': False})
        except Exception:
            return jsonify({
                'error': 'invalid_grant',
                'error_description': 'Invalid subject_token format'
            }), 401

        # Find matching trust anchor
        db = current_app.db
        issuer = unverified.get('iss')
        if not issuer:
            return jsonify({
                'error': 'invalid_grant',
                'error_description': 'Token missing issuer claim'
            }), 401

        trust_anchor = db((db.oidc_trust_anchor.issuer == issuer) &
                         (db.oidc_trust_anchor.active == True)).select().first()

        if not trust_anchor:
            return jsonify({
                'error': 'invalid_grant',
                'error_description': 'Issuer not in trust anchors'
            }), 401

        # Validate token against trust anchor
        anchor_dict = {
            'issuer': trust_anchor.issuer,
            'audience': trust_anchor.audience,
            'static_jwks_pem': trust_anchor.static_jwks_pem,
        }

        payload = AuthService.validate_oidc_token(subject_token, anchor_dict)
        if not payload:
            return jsonify({
                'error': 'invalid_grant',
                'error_description': 'Token validation failed (signature/claims)'
            }), 401

        # Check subject pattern
        subject = payload.get('sub', '')
        if not AuthService.subject_matches_pattern(subject, trust_anchor.subject_pattern):
            return jsonify({
                'error': 'invalid_grant',
                'error_description': 'Subject does not match anchor pattern'
            }), 401

        # Determine granted scopes
        requested_scope = request.form.get('scope', '').strip()
        if requested_scope:
            if not AuthService.validate_scope_subset(requested_scope, trust_anchor.allowed_scopes):
                return jsonify({
                    'error': 'invalid_scope',
                    'error_description': 'Requested scopes exceed allowed scopes'
                }), 400
            granted_scopes = requested_scope
        else:
            granted_scopes = trust_anchor.allowed_scopes

        # Fetch allowed_domains from trust anchor and parse JSON
        allowed_domains = None
        if trust_anchor.allowed_domains:
            try:
                allowed_domains = json.loads(trust_anchor.allowed_domains)
            except (json.JSONDecodeError, TypeError):
                allowed_domains = None

        # Issue token (with machine marker, tenant from anchor)
        access_token = AuthService.create_machine_access_token(
            client_id=f"oidc:{subject}",  # Synthetic client_id for logging
            tenant=trust_anchor.tenant,
            granted_scopes=granted_scopes,
            allowed_domains=allowed_domains
        )

        ttl_config = current_app.config.get('MACHINE_ACCESS_TOKEN_EXPIRES')
        expires_in = ttl_config.total_seconds() if hasattr(ttl_config, 'total_seconds') else ttl_config or 900

        return jsonify({
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': int(expires_in),
            'scope': granted_scopes
        }), 200

    else:
        return jsonify({
            'error': 'unsupported_grant_type',
            'error_description': f'Grant type {grant_type} not supported'
        }), 400
