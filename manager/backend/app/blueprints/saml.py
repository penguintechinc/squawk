"""
SAML 2.0 SSO Login flow API (public endpoints, security-hardened).

Handles the SAML 2.0 Web Browser SSO Profile (HTTP-POST binding):
1. GET /api/v1/auth/saml/<name>/login - Redirect to IdP with AuthnRequest + browser binding cookie
2. POST /api/v1/auth/saml/<name>/acs - Handle IdP callback (ACS), validate assertion, JIT provision
3. GET /api/v1/auth/saml/<name>/metadata - Serve SP metadata XML (public)

SAML logins bypass TOTP MFA because the IdP owns MFA.
"""

import secrets
from flask import Blueprint, request, jsonify, current_app, make_response, redirect
from app.services.saml_service import SAMLService, SAMLConfig
from app.services.auth_service import AuthService
from app.utils.decorators import validate_json

saml_bp = Blueprint('saml', __name__)

# Browser binding cookie name
BINDING_COOKIE_NAME = '__Host-saml_binding'
BINDING_COOKIE_TTL = 600  # 10 minutes (matches login attempt expiry)


@saml_bp.route('/api/v1/auth/saml/<name>/login', methods=['GET'])
def login(name: str):
    """
    Redirect user to IdP's SAML SSO endpoint.

    Builds a SAML AuthnRequest, stores it server-side, sets a browser binding cookie,
    and redirects to the IdP.

    Response (redirect 302):
        Location: https://idp.example.com/sso?SAMLRequest=...&RelayState=...
    """
    db = current_app.db
    provider = db((db.saml_providers.name == name) & (db.saml_providers.enabled == True)).select()

    if not provider:
        return jsonify({
            'error': f'SAML provider "{name}" not found or disabled'
        }), 404

    p = provider[0]

    # Reconstruct SAMLConfig from database record
    config = SAMLConfig(
        name=p['name'],
        display_name=p['display_name'],
        idp_entity_id=p['idp_entity_id'],
        idp_sso_url=p['idp_sso_url'],
        idp_x509_cert=p['idp_x509_cert'],
        sp_entity_id=p['sp_entity_id'],
        sp_acs_url=p['sp_acs_url'],
        name_id_format=p['name_id_format'],
        want_assertions_signed=bool(p['want_assertions_signed'])
    )

    # Generate browser binding token (for CSRF protection)
    binding_token = secrets.token_urlsafe(32)

    # Build AuthnRequest (stores request ID server-side)
    authn_info = SAMLService.build_authn_request(config, name, db, binding_token)

    # Redirect to IdP, with httpOnly, Secure, SameSite=Lax cookie
    response = redirect(authn_info.redirect_url, code=302)
    response.set_cookie(
        BINDING_COOKIE_NAME,
        binding_token,
        max_age=BINDING_COOKIE_TTL,
        httponly=True,
        secure=True,  # HTTPS only
        samesite='Lax'
    )

    return response


@saml_bp.route('/api/v1/auth/saml/<name>/acs', methods=['POST'])
def acs(name: str):
    """
    SAML Assertion Consumer Service (ACS): handle IdP callback.

    Validates:
    - RelayState exists, not used, not expired
    - Browser binding cookie matches stored hash
    - SAML Response can be parsed
    - Assertion XML signature (against IdP X.509 cert)
    - Issuer == idp_entity_id
    - Destination == sp_acs_url
    - Audience == sp_entity_id
    - NotBefore/NotOnOrAfter valid
    - InResponseTo matches stored request ID
    - Assertion ID not seen before (replay prevention)
    - Email is present (for JIT)
    - No email-based account takeover (refuse auto-link existing local users)

    Request (form):
        SAMLResponse: Base64-encoded SAML Response
        RelayState: Opaque relay state from login

    Response (on success):
        {
            "accessToken": "...",
            "refreshToken": "...",
            "user": {
                "id": 1,
                "email": "user@example.com",
                "global_role": "Viewer",
                "sso_provider": "okta-saml",
                "sso": true
            }
        }

    Response (on failure):
        {
            "error": "..."
        }
    """
    db = current_app.db
    provider = db((db.saml_providers.name == name) & (db.saml_providers.enabled == True)).select()

    if not provider:
        return jsonify({
            'error': f'SAML provider "{name}" not found or disabled'
        }), 404

    p = provider[0]

    # Reconstruct SAMLConfig from database record
    config = SAMLConfig(
        name=p['name'],
        display_name=p['display_name'],
        idp_entity_id=p['idp_entity_id'],
        idp_sso_url=p['idp_sso_url'],
        idp_x509_cert=p['idp_x509_cert'],
        sp_entity_id=p['sp_entity_id'],
        sp_acs_url=p['sp_acs_url'],
        name_id_format=p['name_id_format'],
        want_assertions_signed=bool(p['want_assertions_signed'])
    )

    # Get SAML Response and RelayState from POST form
    saml_response_b64 = request.form.get('SAMLResponse')
    relay_state = request.form.get('RelayState')

    if not saml_response_b64 or not relay_state:
        return jsonify({
            'error': 'Missing SAMLResponse or RelayState'
        }), 400

    # Get browser binding cookie (CSRF protection)
    binding_cookie = request.cookies.get(BINDING_COOKIE_NAME)
    if not binding_cookie:
        return jsonify({
            'error': 'Missing browser binding cookie (CSRF protection)'
        }), 400

    # Parse, validate, and extract SAML assertion
    validated_assertion = SAMLService.parse_and_validate_response(
        config,
        saml_response_b64,
        relay_state,
        binding_cookie,
        db
    )

    if not validated_assertion:
        return jsonify({
            'error': 'SAML assertion validation failed'
        }), 400

    # JIT provision or match user by (sso_provider, sso_subject/NameID)
    # Returns None if: existing local account found (refuses auto-link)
    user_id = SAMLService.jit_provision_or_match_user(
        config,
        validated_assertion,
        db
    )

    if not user_id:
        # Email exists locally; refuse auto-link
        return jsonify({
            'error': 'Email account exists; link via admin'
        }), 403

    # Fetch user details
    user = db.auth_user[user_id]

    # Generate tokens (SSO users bypass TOTP)
    access_token, refresh_token = AuthService.create_tokens(
        user_id=user['id'],
        email=user['email'],
        global_role=user['global_role'],
        sso=True  # SSO user, bypass TOTP
    )

    return jsonify({
        'accessToken': access_token,
        'refreshToken': refresh_token,
        'user': {
            'id': user['id'],
            'email': user['email'],
            'global_role': user['global_role'],
            'sso_provider': user['sso_provider'],
            'sso': True,
        }
    }), 200


@saml_bp.route('/api/v1/auth/saml/<name>/metadata', methods=['GET'])
def metadata(name: str):
    """
    Serve SAML Service Provider metadata XML.

    This is a PUBLIC endpoint (no auth required) used by IdP administrators
    to configure the SP in their SAML identity provider.

    The metadata contains:
    - SP EntityID
    - Assertion Consumer Service (ACS) URL
    - Supported NameID formats
    - Signature requirements

    Response (XML):
        <?xml version="1.0"?>
        <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
            entityID="https://app.example.com/saml/metadata">
          <SPSSODescriptor ...>
            <AssertionConsumerService .../>
          </SPSSODescriptor>
        </EntityDescriptor>
    """
    db = current_app.db
    provider = db((db.saml_providers.name == name) & (db.saml_providers.enabled == True)).select()

    if not provider:
        return jsonify({
            'error': f'SAML provider "{name}" not found or disabled'
        }), 404

    p = provider[0]

    # Generate SP metadata XML
    metadata_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{p['sp_entity_id']}">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="{str(p['want_assertions_signed']).lower()}">
    <NameIDFormat>{p['name_id_format']}</NameIDFormat>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{p['sp_acs_url']}" index="0" isDefault="true"/>
  </SPSSODescriptor>
</EntityDescriptor>'''

    response = make_response(metadata_xml)
    response.headers['Content-Type'] = 'application/samlmetadata+xml'
    return response
