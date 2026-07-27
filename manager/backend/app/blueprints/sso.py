"""
OIDC SSO Login flow API (public endpoints, security-hardened).

Handles the OAuth 2.0 Authorization Code + PKCE flow with CSRF protection:
1. GET /api/v1/auth/sso/providers - List enabled providers (public)
2. GET /api/v1/auth/sso/<name>/authorize - Get authorization URL + set browser binding cookie
3. POST /api/v1/auth/sso/<name>/callback - Exchange code for tokens + JIT provision

SSO logins bypass TOTP MFA because the IdP owns MFA.
"""

import secrets
from flask import Blueprint, request, jsonify, current_app, make_response
from app.services.sso_service import SSOService, OIDCConfig
from app.services.auth_service import AuthService
from app.utils.decorators import validate_json

sso_bp = Blueprint('sso', __name__)

# Browser binding cookie name
BINDING_COOKIE_NAME = '__Host-sso_binding'
BINDING_COOKIE_TTL = 600  # 10 minutes (matches login attempt expiry)


@sso_bp.route('/api/v1/auth/sso/providers', methods=['GET'])
def list_providers():
    """
    List enabled SSO providers (PUBLIC - no auth required).

    Returns only enabled providers' name and display_name (leak nothing else).
    Login page uses this to render provider buttons.

    Response:
        {
            "providers": [
                {
                    "name": "okta",
                    "display_name": "Okta"
                }
            ]
        }
    """
    db = current_app.db
    providers = db(db.sso_providers.enabled == True).select()

    return jsonify({
        'providers': [
            {
                'name': p['name'],
                'display_name': p['display_name']
            }
            for p in providers
        ]
    }), 200


@sso_bp.route('/api/v1/auth/sso/<name>/authorize', methods=['GET'])
def authorize(name: str):
    """
    Get authorization URL to redirect user to IdP.

    Sets an httpOnly, Secure, SameSite=Lax cookie for browser binding (CSRF).
    Creates server-side login attempt record (stores verifier + nonce + binding hash).
    Returns opaque state token (NOT decodable, no verifier exposed).

    Response:
        {
            "authorization_url": "https://idp.example.com/oauth/authorize?...",
            "state": "opaque_random_token"  # NOT JWT, no secrets inside
        }
    """
    db = current_app.db
    provider = db((db.sso_providers.name == name) & (db.sso_providers.enabled == True)).select()

    if not provider:
        return jsonify({
            'error': f'SSO provider "{name}" not found or disabled'
        }), 404

    p = provider[0]

    # Reconstruct OIDCConfig from database record
    config = OIDCConfig(
        name=p['name'],
        display_name=p['display_name'],
        issuer=p['issuer'],
        client_id=p['client_id'],
        client_secret=SSOService.decrypt_secret(p['client_secret']),
        authorization_endpoint=p['authorization_endpoint'],
        token_endpoint=p['token_endpoint'],
        jwks_url=p['jwks_url'],
        scopes=p['scopes']
    )

    # Generate browser binding token (for CSRF protection)
    binding_token = secrets.token_urlsafe(32)

    # Build authorization request (stores code_verifier + nonce server-side)
    auth_req = SSOService.build_authorization_url(config, name, db, binding_token)

    # Return response with opaque state and browser binding cookie
    response = make_response(jsonify({
        'authorization_url': auth_req.authorization_url,
        'state': auth_req.state
    }), 200)

    # Set httpOnly, Secure, SameSite=Lax cookie for browser binding
    response.set_cookie(
        BINDING_COOKIE_NAME,
        binding_token,
        max_age=BINDING_COOKIE_TTL,
        httponly=True,
        secure=True,  # HTTPS only
        samesite='Lax'
    )

    return response


@sso_bp.route('/api/v1/auth/sso/<name>/callback', methods=['POST'])
@validate_json('code', 'state')
def callback(name: str):
    """
    Handle IdP callback: exchange code for tokens, validate ID token, JIT provision.

    Validates:
    - State exists, not used, not expired
    - Browser binding cookie matches stored hash
    - Code can be exchanged for tokens
    - ID token signature, iss, aud, exp, nonce all valid
    - Email is verified (for JIT)
    - No email-based account takeover (refuse auto-link existing local users)

    Request:
        {
            "code": "authorization_code_from_idp",
            "state": "opaque_state_from_authorize"
        }

    Response (on success):
        {
            "accessToken": "...",
            "refreshToken": "...",
            "user": {
                "id": 1,
                "email": "user@example.com",
                "global_role": "Viewer",
                "sso_provider": "okta",
                "sso": true
            }
        }

    Response (on failure):
        {
            "error": "..."
        }
    """
    data = request.get_json()
    code = data['code']
    state = data['state']

    db = current_app.db
    provider = db((db.sso_providers.name == name) & (db.sso_providers.enabled == True)).select()

    if not provider:
        return jsonify({
            'error': f'SSO provider "{name}" not found or disabled'
        }), 404

    p = provider[0]

    # Reconstruct OIDCConfig from database record
    config = OIDCConfig(
        name=p['name'],
        display_name=p['display_name'],
        issuer=p['issuer'],
        client_id=p['client_id'],
        client_secret=SSOService.decrypt_secret(p['client_secret']),
        authorization_endpoint=p['authorization_endpoint'],
        token_endpoint=p['token_endpoint'],
        jwks_url=p['jwks_url'],
        scopes=p['scopes']
    )

    # Get browser binding cookie (CSRF protection)
    binding_cookie = request.cookies.get(BINDING_COOKIE_NAME)
    if not binding_cookie:
        return jsonify({
            'error': 'Missing browser binding cookie (CSRF protection)'
        }), 400

    # Exchange code for tokens (validates state, binding, retrieves stored nonce)
    token_result = SSOService.exchange_code_for_token(
        config,
        code,
        state,
        binding_cookie,
        db
    )

    if not token_result or not token_result.id_token:
        return jsonify({
            'error': 'Failed to exchange authorization code for tokens'
        }), 400

    # Retrieve login attempt to get stored nonce
    attempt = SSOService.get_login_attempt(state, db)
    if not attempt:
        return jsonify({
            'error': 'Login attempt not found or invalid'
        }), 400

    expected_nonce = attempt['nonce']

    # Validate ID token (signature, iss, aud, exp, nonce)
    validated_token = SSOService.validate_id_token(
        config,
        token_result.id_token,
        expected_nonce
    )

    if not validated_token:
        return jsonify({
            'error': 'ID token validation failed'
        }), 400

    if not validated_token.email:
        return jsonify({
            'error': 'ID token missing email claim'
        }), 400

    # JIT provision or match user by (sso_provider, sso_subject)
    # Returns None if: email not verified, or existing local account found (refuses auto-link)
    user_id = SSOService.jit_provision_or_match_user(
        config,
        validated_token,
        db
    )

    if not user_id:
        if not validated_token.email_verified:
            return jsonify({
                'error': 'Email not verified with IdP; cannot create account'
            }), 403
        else:
            # Email exists locally; refuse auto-link
            return jsonify({
                'error': 'Email account exists; link via admin'
            }), 403

    # Get user record
    user_record = db.auth_user[user_id]

    if not user_record:
        return jsonify({
            'error': 'User not found after provisioning'
        }), 500

    # Issue tokens (no MFA required for SSO)
    access_token = AuthService.create_access_token(
        user_record['id'],
        user_record['username'],
        user_record['global_role'],
        {}  # No team roles yet
    )
    refresh_token = AuthService.create_refresh_token(user_record['id'])

    return jsonify({
        'accessToken': access_token,
        'refreshToken': refresh_token,
        'user': {
            'id': user_record['id'],
            'email': user_record['email'],
            'global_role': user_record['global_role'],
            'sso_provider': user_record['sso_provider'],
            'sso': True
        }
    }), 200
