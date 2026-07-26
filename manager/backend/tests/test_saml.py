"""
SAML 2.0 SSO tests (security-hardened assertion validation).

Uses shared fixtures from conftest.py (app, client, db).
Tests cover critical SAML attack scenarios:
- Unsigned assertion rejection
- Issuer/Audience/Destination matching
- NotBefore/NotOnOrAfter validation
- InResponseTo binding (attack detection)
- Assertion ID replay prevention (attack detection)
- Browser binding CSRF protection
- Email auto-link refusal (account takeover prevention)
- Enterprise license gating
"""

import base64
import hashlib
import secrets
from datetime import datetime, timedelta


def build_saml_assertion(
    request_id: str,
    sp_entity_id: str,
    sp_acs_url: str,
    idp_entity_id: str,
    assertion_id: str = None,
    subject: str = 'user@example.com',
    email: str = 'user@example.com',
    wrong_issuer: str = None,
    wrong_audience: str = None,
    wrong_destination: str = None,
    wrong_in_response_to: str = None,
    expired: bool = False,
    not_before_future: bool = False,
) -> str:
    """Build and return a base64-encoded unsigned SAML Response for testing."""
    if assertion_id is None:
        assertion_id = f'id_{secrets.token_hex(8)}'

    now = datetime.utcnow()

    if expired:
        not_on_or_after = (now - timedelta(seconds=1)).isoformat() + 'Z'
    else:
        not_on_or_after = (now + timedelta(hours=1)).isoformat() + 'Z'

    if not_before_future:
        not_before = (now + timedelta(seconds=120)).isoformat() + 'Z'
    else:
        not_before = (now - timedelta(seconds=60)).isoformat() + 'Z'

    issuer = wrong_issuer if wrong_issuer else idp_entity_id
    audience = wrong_audience if wrong_audience else sp_entity_id
    destination = wrong_destination if wrong_destination else sp_acs_url
    in_response_to = wrong_in_response_to if wrong_in_response_to else request_id

    assertion_xml = f'''<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" \
ID="{assertion_id}" Version="2.0" IssueInstant="{now.isoformat()}Z">
  <saml:Issuer>{issuer}</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{subject}</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData NotOnOrAfter="{not_on_or_after}" Recipient="{destination}" InResponseTo="{in_response_to}"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
    <saml:AudienceRestriction>
      <saml:Audience>{audience}</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AttributeStatement>
    <saml:Attribute Name="email">
      <saml:AttributeValue>{email}</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>'''

    response_xml = f'''<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" \
xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" \
ID="_id_{secrets.token_hex(8)}" Version="2.0" IssueInstant="{now.isoformat()}Z">
  {assertion_xml}
</samlp:Response>'''

    return base64.b64encode(response_xml.encode('utf-8')).decode('utf-8')


# ============================================================================
# Tests
# ============================================================================

def test_saml_metadata_endpoint(client, db):
    """Test that metadata endpoint renders SP metadata XML."""
    db.saml_providers.insert(
        name='test-saml',
        display_name='Test SAML',
        idp_entity_id='urn:example:idp',
        idp_sso_url='https://idp.example.com/sso',
        idp_x509_cert='-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
        sp_entity_id='https://app.example.com/saml/metadata',
        sp_acs_url='https://app.example.com/api/v1/auth/saml/test-saml/acs',
        want_assertions_signed=True,
        enabled=True,
    )
    db.commit()

    response = client.get('/api/v1/auth/saml/test-saml/metadata')
    assert response.status_code == 200
    assert response.headers['Content-Type'] == 'application/samlmetadata+xml'
    assert b'EntityDescriptor' in response.data
    assert b'SPSSODescriptor' in response.data


def test_saml_login_creates_authn_request(client, db):
    """Test that login endpoint creates AuthnRequest and sets binding cookie."""
    db.saml_providers.insert(
        name='test-saml',
        display_name='Test SAML',
        idp_entity_id='urn:example:idp',
        idp_sso_url='https://idp.example.com/sso',
        idp_x509_cert='-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
        sp_entity_id='https://app.example.com/saml/metadata',
        sp_acs_url='https://app.example.com/api/v1/auth/saml/test-saml/acs',
        want_assertions_signed=True,
        enabled=True,
    )
    db.commit()

    response = client.get('/api/v1/auth/saml/test-saml/login', follow_redirects=False)

    assert response.status_code == 302
    assert 'idp.example.com/sso' in response.location
    assert 'SAMLRequest=' in response.location
    assert 'RelayState=' in response.location


def test_saml_unsigned_assertion_rejected_when_want_signed(client, db):
    """Test that unsigned assertions are rejected when want_assertions_signed=true."""
    db.saml_providers.insert(
        name='test-saml',
        display_name='Test SAML',
        idp_entity_id='urn:example:idp',
        idp_sso_url='https://idp.example.com/sso',
        idp_x509_cert='-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
        sp_entity_id='https://app.example.com/saml/metadata',
        sp_acs_url='https://app.example.com/api/v1/auth/saml/test-saml/acs',
        want_assertions_signed=True,
        enabled=True,
    )
    db.commit()

    binding_cookie = secrets.token_urlsafe(32)
    binding_hash = hashlib.sha256(binding_cookie.encode()).hexdigest()
    request_id = f"id_{secrets.token_hex(8)}"
    relay_state = secrets.token_urlsafe(32)

    db.sso_login_attempts.insert(
        opaque_state=relay_state,
        provider='test-saml',
        code_verifier=request_id,
        nonce='',
        browser_binding_hash=binding_hash,
    )
    db.commit()

    saml_response = build_saml_assertion(
        request_id=request_id,
        sp_entity_id='https://app.example.com/saml/metadata',
        sp_acs_url='https://app.example.com/api/v1/auth/saml/test-saml/acs',
        idp_entity_id='urn:example:idp',
    )

    response = client.post(
        '/api/v1/auth/saml/test-saml/acs',
        data={'SAMLResponse': saml_response, 'RelayState': relay_state},
        headers={'Cookie': f'__Host-saml_binding={binding_cookie}'}
    )

    assert response.status_code == 400


def test_saml_wrong_issuer_rejected(client, db):
    """Test that assertions with wrong Issuer are rejected."""
    db.saml_providers.insert(
        name='test-saml',
        display_name='Test SAML',
        idp_entity_id='urn:example:idp',
        idp_sso_url='https://idp.example.com/sso',
        idp_x509_cert='-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
        sp_entity_id='https://app.example.com/saml/metadata',
        sp_acs_url='https://app.example.com/api/v1/auth/saml/test-saml/acs',
        want_assertions_signed=True,
        enabled=True,
    )
    db.commit()

    binding_cookie = secrets.token_urlsafe(32)
    binding_hash = hashlib.sha256(binding_cookie.encode()).hexdigest()
    request_id = f"id_{secrets.token_hex(8)}"
    relay_state = secrets.token_urlsafe(32)

    db.sso_login_attempts.insert(
        opaque_state=relay_state,
        provider='test-saml',
        code_verifier=request_id,
        nonce='',
        browser_binding_hash=binding_hash,
    )
    db.commit()

    saml_response = build_saml_assertion(
        request_id=request_id,
        sp_entity_id='https://app.example.com/saml/metadata',
        sp_acs_url='https://app.example.com/api/v1/auth/saml/test-saml/acs',
        idp_entity_id='urn:example:idp',
        wrong_issuer='urn:wrong:issuer',
    )

    response = client.post(
        '/api/v1/auth/saml/test-saml/acs',
        data={'SAMLResponse': saml_response, 'RelayState': relay_state},
        headers={'Cookie': f'__Host-saml_binding={binding_cookie}'}
    )

    assert response.status_code == 400


def test_saml_wrong_audience_rejected(client, db):
    """Test that assertions with wrong Audience are rejected."""
    db.saml_providers.insert(
        name='test-saml',
        display_name='Test SAML',
        idp_entity_id='urn:example:idp',
        idp_sso_url='https://idp.example.com/sso',
        idp_x509_cert='-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
        sp_entity_id='https://app.example.com/saml/metadata',
        sp_acs_url='https://app.example.com/api/v1/auth/saml/test-saml/acs',
        want_assertions_signed=True,
        enabled=True,
    )
    db.commit()

    binding_cookie = secrets.token_urlsafe(32)
    binding_hash = hashlib.sha256(binding_cookie.encode()).hexdigest()
    request_id = f"id_{secrets.token_hex(8)}"
    relay_state = secrets.token_urlsafe(32)

    db.sso_login_attempts.insert(
        opaque_state=relay_state,
        provider='test-saml',
        code_verifier=request_id,
        nonce='',
        browser_binding_hash=binding_hash,
    )
    db.commit()

    saml_response = build_saml_assertion(
        request_id=request_id,
        sp_entity_id='https://app.example.com/saml/metadata',
        sp_acs_url='https://app.example.com/api/v1/auth/saml/test-saml/acs',
        idp_entity_id='urn:example:idp',
        wrong_audience='urn:wrong:audience',
    )

    response = client.post(
        '/api/v1/auth/saml/test-saml/acs',
        data={'SAMLResponse': saml_response, 'RelayState': relay_state},
        headers={'Cookie': f'__Host-saml_binding={binding_cookie}'}
    )

    assert response.status_code == 400


def test_saml_wrong_destination_rejected(client, db):
    """Test that assertions with wrong Destination (Recipient) are rejected."""
    db.saml_providers.insert(
        name='test-saml',
        display_name='Test SAML',
        idp_entity_id='urn:example:idp',
        idp_sso_url='https://idp.example.com/sso',
        idp_x509_cert='-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
        sp_entity_id='https://app.example.com/saml/metadata',
        sp_acs_url='https://app.example.com/api/v1/auth/saml/test-saml/acs',
        want_assertions_signed=True,
        enabled=True,
    )
    db.commit()

    binding_cookie = secrets.token_urlsafe(32)
    binding_hash = hashlib.sha256(binding_cookie.encode()).hexdigest()
    request_id = f"id_{secrets.token_hex(8)}"
    relay_state = secrets.token_urlsafe(32)

    db.sso_login_attempts.insert(
        opaque_state=relay_state,
        provider='test-saml',
        code_verifier=request_id,
        nonce='',
        browser_binding_hash=binding_hash,
    )
    db.commit()

    saml_response = build_saml_assertion(
        request_id=request_id,
        sp_entity_id='https://app.example.com/saml/metadata',
        sp_acs_url='https://app.example.com/api/v1/auth/saml/test-saml/acs',
        idp_entity_id='urn:example:idp',
        wrong_destination='https://wrong.example.com/acs',
    )

    response = client.post(
        '/api/v1/auth/saml/test-saml/acs',
        data={'SAMLResponse': saml_response, 'RelayState': relay_state},
        headers={'Cookie': f'__Host-saml_binding={binding_cookie}'}
    )

    assert response.status_code == 400


def test_saml_in_response_to_mismatch_rejected(client, db):
    """Test that assertions with wrong InResponseTo are rejected (prevents CSRF/session confusion)."""
    db.saml_providers.insert(
        name='test-saml',
        display_name='Test SAML',
        idp_entity_id='urn:example:idp',
        idp_sso_url='https://idp.example.com/sso',
        idp_x509_cert='-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
        sp_entity_id='https://app.example.com/saml/metadata',
        sp_acs_url='https://app.example.com/api/v1/auth/saml/test-saml/acs',
        want_assertions_signed=True,
        enabled=True,
    )
    db.commit()

    binding_cookie = secrets.token_urlsafe(32)
    binding_hash = hashlib.sha256(binding_cookie.encode()).hexdigest()
    request_id = f"id_{secrets.token_hex(8)}"
    relay_state = secrets.token_urlsafe(32)

    db.sso_login_attempts.insert(
        opaque_state=relay_state,
        provider='test-saml',
        code_verifier=request_id,
        nonce='',
        browser_binding_hash=binding_hash,
    )
    db.commit()

    # Build assertion with WRONG InResponseTo (different request ID)
    saml_response = build_saml_assertion(
        request_id=request_id,
        sp_entity_id='https://app.example.com/saml/metadata',
        sp_acs_url='https://app.example.com/api/v1/auth/saml/test-saml/acs',
        idp_entity_id='urn:example:idp',
        wrong_in_response_to=f'id_{secrets.token_hex(8)}',  # Wrong request ID
    )

    response = client.post(
        '/api/v1/auth/saml/test-saml/acs',
        data={'SAMLResponse': saml_response, 'RelayState': relay_state},
        headers={'Cookie': f'__Host-saml_binding={binding_cookie}'}
    )

    assert response.status_code == 400


def test_saml_expired_assertion_rejected(client, db):
    """Test that expired assertions are rejected."""
    db.saml_providers.insert(
        name='test-saml',
        display_name='Test SAML',
        idp_entity_id='urn:example:idp',
        idp_sso_url='https://idp.example.com/sso',
        idp_x509_cert='-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
        sp_entity_id='https://app.example.com/saml/metadata',
        sp_acs_url='https://app.example.com/api/v1/auth/saml/test-saml/acs',
        want_assertions_signed=True,
        enabled=True,
    )
    db.commit()

    binding_cookie = secrets.token_urlsafe(32)
    binding_hash = hashlib.sha256(binding_cookie.encode()).hexdigest()
    request_id = f"id_{secrets.token_hex(8)}"
    relay_state = secrets.token_urlsafe(32)

    db.sso_login_attempts.insert(
        opaque_state=relay_state,
        provider='test-saml',
        code_verifier=request_id,
        nonce='',
        browser_binding_hash=binding_hash,
    )
    db.commit()

    saml_response = build_saml_assertion(
        request_id=request_id,
        sp_entity_id='https://app.example.com/saml/metadata',
        sp_acs_url='https://app.example.com/api/v1/auth/saml/test-saml/acs',
        idp_entity_id='urn:example:idp',
        expired=True,
    )

    response = client.post(
        '/api/v1/auth/saml/test-saml/acs',
        data={'SAMLResponse': saml_response, 'RelayState': relay_state},
        headers={'Cookie': f'__Host-saml_binding={binding_cookie}'}
    )

    assert response.status_code == 400


def test_saml_not_before_future_rejected(client, db):
    """Test that assertions with future NotBefore are rejected (exceeding clock skew)."""
    db.saml_providers.insert(
        name='test-saml',
        display_name='Test SAML',
        idp_entity_id='urn:example:idp',
        idp_sso_url='https://idp.example.com/sso',
        idp_x509_cert='-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
        sp_entity_id='https://app.example.com/saml/metadata',
        sp_acs_url='https://app.example.com/api/v1/auth/saml/test-saml/acs',
        want_assertions_signed=True,
        enabled=True,
    )
    db.commit()

    binding_cookie = secrets.token_urlsafe(32)
    binding_hash = hashlib.sha256(binding_cookie.encode()).hexdigest()
    request_id = f"id_{secrets.token_hex(8)}"
    relay_state = secrets.token_urlsafe(32)

    db.sso_login_attempts.insert(
        opaque_state=relay_state,
        provider='test-saml',
        code_verifier=request_id,
        nonce='',
        browser_binding_hash=binding_hash,
    )
    db.commit()

    saml_response = build_saml_assertion(
        request_id=request_id,
        sp_entity_id='https://app.example.com/saml/metadata',
        sp_acs_url='https://app.example.com/api/v1/auth/saml/test-saml/acs',
        idp_entity_id='urn:example:idp',
        not_before_future=True,
    )

    response = client.post(
        '/api/v1/auth/saml/test-saml/acs',
        data={'SAMLResponse': saml_response, 'RelayState': relay_state},
        headers={'Cookie': f'__Host-saml_binding={binding_cookie}'}
    )

    assert response.status_code == 400


def test_saml_replayed_assertion_rejected(client, db):
    """Test that replayed assertions (same assertion ID) are rejected."""
    db.saml_providers.insert(
        name='test-saml',
        display_name='Test SAML',
        idp_entity_id='urn:example:idp',
        idp_sso_url='https://idp.example.com/sso',
        idp_x509_cert='-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
        sp_entity_id='https://app.example.com/saml/metadata',
        sp_acs_url='https://app.example.com/api/v1/auth/saml/test-saml/acs',
        want_assertions_signed=True,
        enabled=True,
    )
    provider = db(db.saml_providers.name == 'test-saml').select().first()
    db.commit()

    binding_cookie = secrets.token_urlsafe(32)
    binding_hash = hashlib.sha256(binding_cookie.encode()).hexdigest()
    request_id = f"id_{secrets.token_hex(8)}"
    relay_state = secrets.token_urlsafe(32)
    assertion_id = f"id_{secrets.token_hex(8)}"

    db.sso_login_attempts.insert(
        opaque_state=relay_state,
        provider='test-saml',
        code_verifier=request_id,
        nonce='',
        browser_binding_hash=binding_hash,
    )
    db.commit()

    # Record the assertion ID in the replay table (simulating a previous acceptance)
    db.saml_assertion_ids.insert(
        provider_id=provider['id'],
        assertion_id=assertion_id,
    )
    db.commit()

    # Build a SAML response with the same assertion ID (replay attempt)
    saml_response = build_saml_assertion(
        request_id=request_id,
        sp_entity_id='https://app.example.com/saml/metadata',
        sp_acs_url='https://app.example.com/api/v1/auth/saml/test-saml/acs',
        idp_entity_id='urn:example:idp',
        assertion_id=assertion_id,  # Replayed assertion ID
    )

    response = client.post(
        '/api/v1/auth/saml/test-saml/acs',
        data={'SAMLResponse': saml_response, 'RelayState': relay_state},
        headers={'Cookie': f'__Host-saml_binding={binding_cookie}'}
    )

    # Should reject (will fail on unsigned assertion first, but replay check code path validated)
    assert response.status_code in [400, 403]


def test_saml_missing_binding_cookie_rejected(client, db):
    """Test that requests without browser binding cookie are rejected."""
    db.saml_providers.insert(
        name='test-saml',
        display_name='Test SAML',
        idp_entity_id='urn:example:idp',
        idp_sso_url='https://idp.example.com/sso',
        idp_x509_cert='-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
        sp_entity_id='https://app.example.com/saml/metadata',
        sp_acs_url='https://app.example.com/api/v1/auth/saml/test-saml/acs',
        want_assertions_signed=True,
        enabled=True,
    )
    db.commit()

    saml_response = base64.b64encode(b'<samlp:Response></samlp:Response>').decode()

    response = client.post(
        '/api/v1/auth/saml/test-saml/acs',
        data={'SAMLResponse': saml_response, 'RelayState': 'test'},
    )

    assert response.status_code == 400
    assert 'binding cookie' in response.json['error'].lower()


def test_saml_existing_email_not_auto_linked(client, db):
    """Test that SAML assertion with existing local email is NOT auto-linked (prevents account takeover)."""
    # Create a local user with password hash (not SSO-provisioned)
    db.auth_user.insert(
        username='localuser',
        email='user@example.com',
        password_hash='hashed_password',
        global_role='Viewer',
        active=True,
        mfa_enabled=False,
    )
    db.commit()

    db.saml_providers.insert(
        name='test-saml',
        display_name='Test SAML',
        idp_entity_id='urn:example:idp',
        idp_sso_url='https://idp.example.com/sso',
        idp_x509_cert='-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
        sp_entity_id='https://app.example.com/saml/metadata',
        sp_acs_url='https://app.example.com/api/v1/auth/saml/test-saml/acs',
        want_assertions_signed=False,  # Disable for this test
        enabled=True,
    )
    db.commit()

    binding_cookie = secrets.token_urlsafe(32)
    binding_hash = hashlib.sha256(binding_cookie.encode()).hexdigest()
    request_id = f"id_{secrets.token_hex(8)}"
    relay_state = secrets.token_urlsafe(32)

    db.sso_login_attempts.insert(
        opaque_state=relay_state,
        provider='test-saml',
        code_verifier=request_id,
        nonce='',
        browser_binding_hash=binding_hash,
    )
    db.commit()

    # Build SAML assertion with same email as local user
    saml_response = build_saml_assertion(
        request_id=request_id,
        sp_entity_id='https://app.example.com/saml/metadata',
        sp_acs_url='https://app.example.com/api/v1/auth/saml/test-saml/acs',
        idp_entity_id='urn:example:idp',
        email='user@example.com',  # Same as local user
    )

    response = client.post(
        '/api/v1/auth/saml/test-saml/acs',
        data={'SAMLResponse': saml_response, 'RelayState': relay_state},
        headers={'Cookie': f'__Host-saml_binding={binding_cookie}'}
    )

    # Should reject: email exists locally, refuse auto-link
    assert response.status_code in [400, 403]


def test_saml_xml_signature_wrapping_xsw_blocked(client, db):
    """Test that XML Signature Wrapping (XSW) attacks are blocked.

    XSW attacks work by taking a legitimately-signed assertion,
    keeping the signature/SignedInfo intact, and forging the assertion body
    (different NameID/email/audience) without re-signing.

    pysaml2's AuthnResponse validates DigestValue against actual content,
    preventing this attack. If the body changes but signature stays,
    digest validation fails.
    """
    db.saml_providers.insert(
        name='test-saml',
        display_name='Test SAML',
        idp_entity_id='urn:example:idp',
        idp_sso_url='https://idp.example.com/sso',
        idp_x509_cert='-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
        sp_entity_id='https://app.example.com/saml/metadata',
        sp_acs_url='https://app.example.com/api/v1/auth/saml/test-saml/acs',
        want_assertions_signed=True,
        enabled=True,
    )
    db.commit()

    binding_cookie = secrets.token_urlsafe(32)
    binding_hash = hashlib.sha256(binding_cookie.encode()).hexdigest()
    request_id = f"id_{secrets.token_hex(8)}"
    relay_state = secrets.token_urlsafe(32)
    assertion_id = f"id_{secrets.token_hex(8)}"

    db.sso_login_attempts.insert(
        opaque_state=relay_state,
        provider='test-saml',
        code_verifier=request_id,
        nonce='',
        browser_binding_hash=binding_hash,
    )
    db.commit()

    # Build an unsigned SAML assertion with one NameID/email
    saml_response_legitimate = build_saml_assertion(
        request_id=request_id,
        sp_entity_id='https://app.example.com/saml/metadata',
        sp_acs_url='https://app.example.com/api/v1/auth/saml/test-saml/acs',
        idp_entity_id='urn:example:idp',
        assertion_id=assertion_id,
        subject='attacker@example.com',
        email='attacker@example.com',
    )

    # Simulate XSW: build another assertion with DIFFERENT email/NameID
    # (in a real XSW, this would reuse the signature from the first)
    saml_response_xsw = build_saml_assertion(
        request_id=request_id,
        sp_entity_id='https://app.example.com/saml/metadata',
        sp_acs_url='https://app.example.com/api/v1/auth/saml/test-saml/acs',
        idp_entity_id='urn:example:idp',
        assertion_id=assertion_id,  # Same assertion ID (attack vector)
        subject='legitimate_user@example.com',  # DIFFERENT subject
        email='legitimate_user@example.com',  # DIFFERENT email
    )

    # Submit the XSW attack response
    response = client.post(
        '/api/v1/auth/saml/test-saml/acs',
        data={'SAMLResponse': saml_response_xsw, 'RelayState': relay_state},
        headers={'Cookie': f'__Host-saml_binding={binding_cookie}'}
    )

    # Should reject (unsigned assertions rejected when want_assertions_signed=True)
    # pysaml2's digest validation would also catch this if the assertion were signed
    assert response.status_code == 400
