"""
SAML Provider Admin API.

CRUD operations for SAML 2.0 SP provider configuration (Enterprise tier only).
Enabling a provider requires Enterprise tier validation via license_service.
All URLs are validated to be https:// at create/update time.
X.509 certificates are validated to ensure they can be parsed.
"""

from flask import Blueprint, request, jsonify, current_app
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from app.middleware.auth import token_required
from app.middleware.rbac import requires_scope
from app.utils.decorators import validate_json, audit_log

saml_admin_bp = Blueprint('saml_admin', __name__)


@saml_admin_bp.route('/api/v1/admin/saml/providers', methods=['GET'])
@token_required
@requires_scope('sso:read')
def list_saml_providers():
    """
    List all SAML 2.0 providers (admin only).

    Response:
        {
            "providers": [
                {
                    "id": 1,
                    "name": "shibboleth",
                    "display_name": "Shibboleth",
                    "idp_entity_id": "urn:mace:example.edu:idp",
                    "enabled": true,
                    "created_at": "2026-01-01T00:00:00Z"
                }
            ]
        }
    """
    db = current_app.db
    providers = db(db.saml_providers).select()

    return jsonify({
        'providers': [
            {
                'id': p['id'],
                'name': p['name'],
                'display_name': p['display_name'],
                'idp_entity_id': p['idp_entity_id'],
                'enabled': p['enabled'],
                'created_at': p['created_at'].isoformat() if p['created_at'] else None,
            }
            for p in providers
        ]
    }), 200


@saml_admin_bp.route('/api/v1/admin/saml/providers', methods=['POST'])
@token_required
@requires_scope('sso:write')
@validate_json('name', 'display_name', 'idp_entity_id', 'idp_sso_url', 'idp_x509_cert',
               'sp_entity_id', 'sp_acs_url')
@audit_log('saml_provider_created')
def create_saml_provider():
    """
    Create a new SAML 2.0 provider configuration.

    Requires Enterprise tier. All endpoint URLs must be https://.
    X.509 certificate must be valid PEM format.

    Request:
        {
            "name": "shibboleth",
            "display_name": "Shibboleth",
            "idp_entity_id": "urn:mace:example.edu:idp",
            "idp_sso_url": "https://idp.example.edu/idp/profile/SAML2/Redirect/SSO",
            "idp_x509_cert": "-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----",
            "sp_entity_id": "https://app.example.com/saml/metadata",
            "sp_acs_url": "https://app.example.com/api/v1/auth/saml/shibboleth/acs",
            "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",  # optional
            "want_assertions_signed": true  # optional, defaults to true
        }

    Response:
        {
            "id": 1,
            "name": "shibboleth",
            "display_name": "Shibboleth"
        }
    """
    # Check Enterprise tier
    license_tier = current_app.license_service.get_tier()
    if not current_app.license_service.is_enterprise():
        return jsonify({
            'error': 'SAML SSO is only available on Enterprise tier',
            'tier': license_tier
        }), 403

    data = request.get_json()

    # Validate HTTPS on all endpoint URLs
    https_endpoints = [
        'idp_sso_url',
        'sp_acs_url'
    ]
    for endpoint_key in https_endpoints:
        url = data.get(endpoint_key, '')
        if not url.startswith('https://'):
            return jsonify({
                'error': f'{endpoint_key} must use https://',
                'provided': url
            }), 400

    # Validate X.509 certificate format
    cert_pem = data.get('idp_x509_cert', '')
    try:
        load_pem_x509_certificate(cert_pem.encode('utf-8'), default_backend())
    except Exception as e:
        return jsonify({
            'error': 'Invalid X.509 certificate format',
            'detail': str(e)
        }), 400

    db = current_app.db
    provider = db.saml_providers.insert(
        name=data['name'],
        display_name=data['display_name'],
        idp_entity_id=data['idp_entity_id'],
        idp_sso_url=data['idp_sso_url'],
        idp_x509_cert=cert_pem,
        sp_entity_id=data['sp_entity_id'],
        sp_acs_url=data['sp_acs_url'],
        name_id_format=data.get('name_id_format',
                               'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'),
        want_assertions_signed=data.get('want_assertions_signed', True),
        enabled=False,  # Providers start disabled
        tenant=current_app.config.get('TENANT_ID', 'default')
    )
    db.commit()

    return jsonify({
        'id': provider['id'],
        'name': provider['name'],
        'display_name': provider['display_name']
    }), 201


@saml_admin_bp.route('/api/v1/admin/saml/providers/<int:provider_id>', methods=['GET'])
@token_required
@requires_scope('sso:read')
def get_saml_provider(provider_id: int):
    """
    Get a single SAML provider configuration (admin only).

    Note: idp_x509_cert is not returned in this view for security reasons.
    """
    db = current_app.db
    provider = db.saml_providers[provider_id]

    if not provider:
        return jsonify({
            'error': 'Provider not found'
        }), 404

    return jsonify({
        'id': provider['id'],
        'name': provider['name'],
        'display_name': provider['display_name'],
        'idp_entity_id': provider['idp_entity_id'],
        'idp_sso_url': provider['idp_sso_url'],
        'sp_entity_id': provider['sp_entity_id'],
        'sp_acs_url': provider['sp_acs_url'],
        'name_id_format': provider['name_id_format'],
        'want_assertions_signed': provider['want_assertions_signed'],
        'enabled': provider['enabled'],
        'created_at': provider['created_at'].isoformat() if provider['created_at'] else None,
    }), 200


@saml_admin_bp.route('/api/v1/admin/saml/providers/<int:provider_id>', methods=['PATCH'])
@token_required
@requires_scope('sso:write')
@audit_log('saml_provider_updated')
def update_saml_provider(provider_id: int):
    """
    Update a SAML provider configuration.

    Requires Enterprise tier. Updating idp_x509_cert or endpoint URLs
    triggers re-validation.
    """
    # Check Enterprise tier
    if not current_app.license_service.is_enterprise():
        return jsonify({
            'error': 'SAML SSO is only available on Enterprise tier'
        }), 403

    db = current_app.db
    provider = db.saml_providers[provider_id]

    if not provider:
        return jsonify({
            'error': 'Provider not found'
        }), 404

    data = request.get_json() or {}

    # Validate HTTPS on updated endpoint URLs
    for endpoint_key in ['idp_sso_url', 'sp_acs_url']:
        if endpoint_key in data:
            url = data[endpoint_key]
            if not url.startswith('https://'):
                return jsonify({
                    'error': f'{endpoint_key} must use https://',
                    'provided': url
                }), 400

    # Validate X.509 certificate if provided
    if 'idp_x509_cert' in data:
        cert_pem = data['idp_x509_cert']
        try:
            load_pem_x509_certificate(cert_pem.encode('utf-8'), default_backend())
        except Exception as e:
            return jsonify({
                'error': 'Invalid X.509 certificate format',
                'detail': str(e)
            }), 400

    # Update only allowlisted fields — never mass-assign the raw request
    # body (would let a caller overwrite id/name/tenant, mirrors
    # sso_admin.py's update_sso_provider pattern).
    update_fields = {}
    for field in ['display_name', 'idp_entity_id', 'idp_sso_url', 'idp_x509_cert',
                  'sp_entity_id', 'sp_acs_url', 'name_id_format',
                  'want_assertions_signed', 'enabled']:
        if field in data:
            update_fields[field] = data[field]

    if update_fields:
        db(db.saml_providers.id == provider_id).update(**update_fields)
        db.commit()

    return jsonify({
        'id': provider_id,
        'name': provider['name'],
        'display_name': provider['display_name']
    }), 200


@saml_admin_bp.route('/api/v1/admin/saml/providers/<int:provider_id>', methods=['DELETE'])
@token_required
@requires_scope('sso:write')
@audit_log('saml_provider_deleted')
def delete_saml_provider(provider_id: int):
    """
    Delete a SAML provider configuration.

    Requires Enterprise tier.
    """
    # Check Enterprise tier
    if not current_app.license_service.is_enterprise():
        return jsonify({
            'error': 'SAML SSO is only available on Enterprise tier'
        }), 403

    db = current_app.db
    provider = db.saml_providers[provider_id]

    if not provider:
        return jsonify({
            'error': 'Provider not found'
        }), 404

    db(db.saml_providers.id == provider_id).delete()
    db.commit()

    return '', 204


@saml_admin_bp.route('/api/v1/admin/saml/providers/<int:provider_id>/toggle', methods=['POST'])
@token_required
@requires_scope('sso:write')
@audit_log('saml_provider_toggled')
def toggle_saml_provider(provider_id: int):
    """
    Enable or disable a SAML provider.

    Requires Enterprise tier. Enabling a provider is only allowed on Enterprise tier.

    Request:
        {
            "enabled": true
        }

    Response:
        {
            "id": 1,
            "name": "shibboleth",
            "enabled": true
        }
    """
    # Check Enterprise tier
    if not current_app.license_service.is_enterprise():
        return jsonify({
            'error': 'SAML SSO is only available on Enterprise tier'
        }), 403

    data = request.get_json() or {}
    enabled = data.get('enabled', False)

    db = current_app.db
    provider = db.saml_providers[provider_id]

    if not provider:
        return jsonify({
            'error': 'Provider not found'
        }), 404

    db(db.saml_providers.id == provider_id).update(enabled=enabled)
    db.commit()

    return jsonify({
        'id': provider_id,
        'name': provider['name'],
        'enabled': enabled
    }), 200
