"""
Authentication API blueprint.
Handles login, logout, token refresh, and user info.
"""

from flask import Blueprint, request, jsonify, current_app, g
from app.services.auth_service import AuthService
from app.middleware.auth import token_required, get_current_user
from app.utils.decorators import validate_json, audit_log
from app.extensions import limiter
import json

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/api/v1/auth/login', methods=['POST'])
@limiter.limit('10/minute')
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

    # Resolve the targeted account for audit attribution *before*
    # authenticating. get_current_user() is always None here (no JWT exists
    # yet at login), so without this a brute-force campaign against a valid
    # username would write audit rows with actor_id=NULL on every failed
    # attempt -- untraceable to the account under attack. This is a
    # read-only lookup (independent of password/lockout state) and never
    # reveals account existence to the caller; only the audit trail sees it.
    target_user = current_app.db(
        current_app.db.auth_user.username == username
    ).select().first()
    if target_user:
        g.audit_actor_id = target_user.id
        g.audit_resource_type = 'user'
        g.audit_resource_id = target_user.id

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
@limiter.limit('20/minute')
@validate_json('refreshToken')
@audit_log('token_refresh', resource_type='user')
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

    # Resolve the token's subject for audit attribution before rotation --
    # get_current_user() has nothing to return here (no access token on this
    # route). decode_token() verifies the signature, so this is safe even
    # for an attacker-supplied token (bad signature simply yields None).
    payload = AuthService.decode_token(refresh_token)
    if payload and payload.get('type') == 'refresh':
        g.audit_actor_id = payload.get('user_id')
        g.audit_resource_id = payload.get('user_id')

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
@limiter.limit('5/minute')
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

    # Hash and update new password. penguin-dal has no Row.update_record();
    # use the QuerySet idiom.
    new_password_hash = AuthService.hash_password(data['new_password'])
    db(db.auth_user.id == user_record.id).update(password_hash=new_password_hash)
    db.commit()

    return jsonify({
        'message': 'Password changed successfully'
    }), 200


@auth_bp.route('/api/v1/auth/token', methods=['POST'])
@limiter.limit('30/minute')
@audit_log('machine_token_grant', resource_type='machine_client')
def token():
    """
    OAuth2 token endpoint supporting multiple grant types.

    Grants supported:
    - client_credentials: Machine-to-machine authentication
    - urn:ietf:params:oauth:grant-type:token-exchange: Federated workload identity

    DPoP (RFC 9449) sender-constrained tokens:
    Optional DPoP header for both grant types. If present, token is bound to the
    proof's public key via cnf.jkt claim, and token_type becomes DPoP instead of Bearer.

    --- client_credentials (Part 1) ---
    Request (HTTP Basic Auth):
        Authorization: Basic base64(client_id:client_secret)
        POST /api/v1/auth/token
        Content-Type: application/x-www-form-urlencoded
        DPoP: <proof JWT> (optional)

        grant_type=client_credentials
        scope=optional_scope_subset (optional; defaults to registered scopes)

    Response (200 OK):
        {
            "access_token": "...",
            "token_type": "Bearer" or "DPoP",
            "expires_in": 900,  (15 min in seconds)
            "scope": "granted scopes"
        }

    --- token-exchange (Part 2) ---
    Request:
        DPoP: <proof JWT> (optional)
        grant_type=urn:ietf:params:oauth:grant-type:token-exchange
        subject_token=<JWT from external issuer>
        subject_token_type=urn:ietf:params:oauth:token-type:jwt
        scope=optional (optional; must be subset of anchor's allowed_scopes)

    Errors:
        400 Bad Request:
            {
                "error": "invalid_request",
                "error_description": "..."
            }
        401 Unauthorized:
            {
                "error": "invalid_client" or "invalid_grant",
                "error_description": "..."
            }
    """
    from app.services.dpop_service import DPoPService

    # Determine grant type
    grant_type = request.form.get('grant_type') or ''

    # Validate DPoP proof if present (applies to both grant types)
    dpop_header = request.headers.get('DPoP', '').strip()
    dpop_jkt = None
    token_type = 'Bearer'

    if dpop_header:
        # Validate DPoP proof against this request
        dpop_proof = DPoPService.validate_proof(
            dpop_header,
            http_method=request.method,
            http_uri=request.base_url + (f'?{request.query_string.decode()}' if request.query_string else '')
        )
        if not dpop_proof:
            return jsonify({
                'error': 'invalid_request',
                'error_description': 'Invalid DPoP proof'
            }), 400
        dpop_jkt = dpop_proof.jkt
        token_type = 'DPoP'

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
            # Attribute the audit failure to the targeted client_id even
            # though authentication failed, so repeated bad-secret attempts
            # against one client are traceable (mirrors the login target
            # attribution below). This performs the same lookup
            # verify_machine_client already did internally, so it adds no
            # new distinguishable timing signal.
            existing = current_app.db(
                current_app.db.machine_client.client_id == client_id
            ).select().first()
            g.audit_resource_id = existing.id if existing else None
            return jsonify({
                'error': 'invalid_client',
                'error_description': 'Client authentication failed'
            }), 401

        g.audit_resource_id = client['id']

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

        # Issue token (optionally DPoP-bound if proof provided)
        access_token = AuthService.create_machine_access_token(
            client_id=client['client_id'],
            tenant=client['tenant'],
            granted_scopes=granted_scopes,
            dpop_jkt=dpop_jkt,
            allowed_domains=allowed_domains
        )

        # Update last_used_at
        AuthService.update_machine_client_last_used(client['client_id'])

        ttl_config = current_app.config.get('MACHINE_ACCESS_TOKEN_EXPIRES')
        expires_in = ttl_config.total_seconds() if hasattr(ttl_config, 'total_seconds') else ttl_config or 900

        return jsonify({
            'access_token': access_token,
            'token_type': token_type,
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

        if trust_anchor:
            # Attribute the audit event to the trust anchor for both the
            # success path and any validation failure below (subject
            # pattern mismatch, signature/claims failure).
            g.audit_resource_type = 'oidc_trust_anchor'
            g.audit_resource_id = trust_anchor.id

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

        # Issue token (with machine marker, tenant from anchor; optionally DPoP-bound)
        access_token = AuthService.create_machine_access_token(
            client_id=f"oidc:{subject}",  # Synthetic client_id for logging
            tenant=trust_anchor.tenant,
            granted_scopes=granted_scopes,
            dpop_jkt=dpop_jkt,
            allowed_domains=allowed_domains
        )

        ttl_config = current_app.config.get('MACHINE_ACCESS_TOKEN_EXPIRES')
        expires_in = ttl_config.total_seconds() if hasattr(ttl_config, 'total_seconds') else ttl_config or 900

        return jsonify({
            'access_token': access_token,
            'token_type': token_type,
            'expires_in': int(expires_in),
            'scope': granted_scopes
        }), 200

    else:
        return jsonify({
            'error': 'unsupported_grant_type',
            'error_description': f'Grant type {grant_type} not supported'
        }), 400
