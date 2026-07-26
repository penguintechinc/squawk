"""
SSO Provider Admin API.

CRUD operations for OIDC provider configuration (Enterprise tier only).
Enabling a provider requires Enterprise tier validation via license_service.
All URLs are validated to be https:// at create/update time.
"""

from flask import Blueprint, request, jsonify, current_app
from app.middleware.auth import token_required
from app.middleware.rbac import requires_scope
from app.utils.decorators import validate_json, audit_log
from app.services.sso_service import SSOService

sso_admin_bp = Blueprint('sso_admin', __name__)


@sso_admin_bp.route('/api/v1/admin/sso/providers', methods=['GET'])
@token_required
@requires_scope('sso:read')
def list_sso_providers():
    """
    List all SSO OIDC providers (admin only).

    Response:
        {
            "providers": [
                {
                    "id": 1,
                    "name": "okta",
                    "display_name": "Okta",
                    "issuer": "https://example.okta.com",
                    "enabled": true,
                    "created_at": "2026-01-01T00:00:00Z"
                }
            ]
        }
    """
    db = current_app.db
    providers = db(db.sso_providers).select()

    return jsonify({
        'providers': [
            {
                'id': p['id'],
                'name': p['name'],
                'display_name': p['display_name'],
                'issuer': p['issuer'],
                'enabled': p['enabled'],
                'created_at': p['created_at'].isoformat() if p['created_at'] else None,
            }
            for p in providers
        ]
    }), 200


@sso_admin_bp.route('/api/v1/admin/sso/providers', methods=['POST'])
@token_required
@requires_scope('sso:write')
@validate_json('name', 'display_name', 'issuer', 'client_id', 'client_secret',
               'authorization_endpoint', 'token_endpoint', 'jwks_url')
@audit_log('sso_provider_created')
def create_sso_provider():
    """
    Create a new OIDC provider configuration.

    Requires Enterprise tier. All endpoint URLs must be https://.

    Request:
        {
            "name": "okta",
            "display_name": "Okta",
            "issuer": "https://example.okta.com",
            "client_id": "...",
            "client_secret": "...",
            "authorization_endpoint": "https://example.okta.com/oauth2/v1/authorize",
            "token_endpoint": "https://example.okta.com/oauth2/v1/token",
            "jwks_url": "https://example.okta.com/oauth2/v1/keys",
            "scopes": "openid email profile"  # optional
        }

    Response:
        {
            "id": 1,
            "name": "okta",
            "display_name": "Okta"
        }
    """
    # Check Enterprise tier
    license_tier = current_app.license_service.get_tier()
    if not current_app.license_service.is_enterprise():
        return jsonify({
            'error': 'SSO is only available on Enterprise tier',
            'tier': license_tier
        }), 403

    data = request.get_json()

    # Validate HTTPS on all endpoints
    https_endpoints = [
        'authorization_endpoint',
        'token_endpoint',
        'jwks_url'
    ]
    for endpoint_key in https_endpoints:
        url = data.get(endpoint_key, '')
        if not url.startswith('https://'):
            return jsonify({
                'error': f'{endpoint_key} must use https://',
                'provided': url
            }), 400

    # Encrypt client_secret before storage
    encrypted_secret = SSOService.encrypt_secret(data['client_secret'])

    db = current_app.db
    provider = db.sso_providers.insert(
        name=data['name'],
        display_name=data['display_name'],
        issuer=data['issuer'],
        client_id=data['client_id'],
        client_secret=encrypted_secret,
        authorization_endpoint=data['authorization_endpoint'],
        token_endpoint=data['token_endpoint'],
        jwks_url=data['jwks_url'],
        scopes=data.get('scopes', 'openid email profile'),
        enabled=False,  # Providers start disabled
        tenant=current_app.config.get('TENANT_ID', 'default')
    )
    db.commit()

    return jsonify({
        'id': provider['id'],
        'name': provider['name'],
        'display_name': provider['display_name']
    }), 201


@sso_admin_bp.route('/api/v1/admin/sso/providers/<int:provider_id>', methods=['GET'])
@token_required
@requires_scope('sso:read')
def get_sso_provider(provider_id: int):
    """
    Get a single SSO provider configuration (admin only).

    Note: client_secret is not returned; it is encrypted at rest and write-only.
    """
    db = current_app.db
    provider = db.sso_providers[provider_id]

    if not provider:
        return jsonify({'error': 'Provider not found'}), 404

    return jsonify({
        'id': provider['id'],
        'name': provider['name'],
        'display_name': provider['display_name'],
        'issuer': provider['issuer'],
        'client_id': provider['client_id'],
        'authorization_endpoint': provider['authorization_endpoint'],
        'token_endpoint': provider['token_endpoint'],
        'jwks_url': provider['jwks_url'],
        'scopes': provider['scopes'],
        'enabled': provider['enabled'],
        'created_at': provider['created_at'].isoformat() if provider['created_at'] else None,
    }), 200


@sso_admin_bp.route('/api/v1/admin/sso/providers/<int:provider_id>', methods=['PATCH'])
@token_required
@requires_scope('sso:write')
@audit_log('sso_provider_updated')
def update_sso_provider(provider_id: int):
    """
    Update an SSO provider configuration.

    Requires Enterprise tier. All endpoint URLs must be https://.

    Request (partial):
        {
            "display_name": "Okta Production",
            "enabled": true
        }
    """
    # Check Enterprise tier
    if not current_app.license_service.is_enterprise():
        return jsonify({
            'error': 'SSO is only available on Enterprise tier'
        }), 403

    db = current_app.db
    provider = db.sso_providers[provider_id]

    if not provider:
        return jsonify({'error': 'Provider not found'}), 404

    data = request.get_json(silent=True) or {}

    # Validate HTTPS on any endpoints being updated
    https_endpoints = ['authorization_endpoint', 'token_endpoint', 'jwks_url']
    for endpoint_key in https_endpoints:
        if endpoint_key in data:
            url = data[endpoint_key]
            if not url.startswith('https://'):
                return jsonify({
                    'error': f'{endpoint_key} must use https://',
                    'provided': url
                }), 400

    # Encrypt client_secret if provided
    if 'client_secret' in data:
        data['client_secret'] = SSOService.encrypt_secret(data['client_secret'])

    # Update only provided fields
    update_fields = {}
    for field in ['display_name', 'issuer', 'client_id', 'client_secret',
                  'authorization_endpoint', 'token_endpoint', 'jwks_url',
                  'scopes', 'enabled']:
        if field in data:
            update_fields[field] = data[field]

    if update_fields:
        provider.update_record(**update_fields)
        db.commit()

    return jsonify({
        'id': provider['id'],
        'name': provider['name'],
        'enabled': provider['enabled']
    }), 200


@sso_admin_bp.route('/api/v1/admin/sso/providers/<int:provider_id>', methods=['DELETE'])
@token_required
@requires_scope('sso:write')
@audit_log('sso_provider_deleted')
def delete_sso_provider(provider_id: int):
    """
    Delete an SSO provider configuration.

    Requires Enterprise tier.
    """
    if not current_app.license_service.is_enterprise():
        return jsonify({
            'error': 'SSO is only available on Enterprise tier'
        }), 403

    db = current_app.db
    provider = db.sso_providers[provider_id]

    if not provider:
        return jsonify({'error': 'Provider not found'}), 404

    db.sso_providers.delete(id=provider_id)
    db.commit()

    return jsonify({
        'message': f'Provider {provider["name"]} deleted'
    }), 200
