"""
OIDC SSO Login flow API (public endpoints).

Handles the OAuth 2.0 Authorization Code + PKCE flow:
1. GET /api/v1/auth/sso/providers - List enabled providers (public)
2. GET /api/v1/auth/sso/<name>/authorize - Get authorization URL
3. POST /api/v1/auth/sso/<name>/callback - Exchange code for tokens + JIT provision

SSO logins bypass TOTP MFA because the IdP owns MFA.
"""

from flask import Blueprint, request, jsonify, current_app
from app.services.sso_service import SSOService, OIDCConfig
from app.services.auth_service import AuthService
from app.utils.decorators import validate_json

sso_bp = Blueprint('sso', __name__)


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

    Generates PKCE code_verifier/challenge, creates signed state token,
    and returns authorization URL.

    Query parameters:
        redirect_uri (optional): Where to redirect after IdP callback
                                (default: OIDC_REDIRECT_URI from config)

    Response:
        {
            "authorization_url": "https://idp.example.com/oauth/authorize?...",
            "state": "eyJ..."  # State token (send to callback)
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

    # Build authorization request
    auth_req = SSOService.build_authorization_url(config)

    return jsonify({
        'authorization_url': auth_req.authorization_url,
        'state': auth_req.state
    }), 200


@sso_bp.route('/api/v1/auth/sso/<name>/callback', methods=['POST'])
@validate_json('code', 'state')
def callback(name: str):
    """
    Handle IdP callback: exchange code for tokens, validate ID token, JIT provision.

    Request:
        {
            "code": "authorization_code_from_idp",
            "state": "state_token_from_authorize"
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
            "error": "Invalid authorization code" | "Invalid state" | ...
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

    redirect_uri = request.args.get(
        'redirect_uri',
        current_app.config.get('OIDC_REDIRECT_URI', 'http://localhost:3000/callback')
    )

    # Exchange code for tokens
    token_result = SSOService.exchange_code_for_token(
        config,
        code,
        state,
        redirect_uri
    )

    if not token_result or not token_result.id_token:
        return jsonify({
            'error': 'Failed to exchange authorization code for tokens'
        }), 400

    # Validate ID token (note: we're not validating nonce here; it's in the authorize call)
    validated_token = SSOService.validate_id_token(
        config,
        token_result.id_token,
        nonce=None  # Nonce validation happens at IdP
    )

    if not validated_token:
        return jsonify({
            'error': 'ID token validation failed'
        }), 400

    if not validated_token.email:
        return jsonify({
            'error': 'ID token missing email claim'
        }), 400

    # JIT provision or match user by email/sub
    user_id = SSOService.jit_provision_or_match_user(
        config,
        validated_token,
        db
    )

    if not user_id:
        return jsonify({
            'error': 'Failed to provision SSO user'
        }), 500

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
