"""Regression test for CRITICAL fix: SAML assertion signatures are now
actually verified.

Prior implementation constructed `saml2.response.AuthnResponse` directly and
called `.loads()` + `.is_ok()` -- but the constructor call passed arguments
`AuthnResponse.__init__` does not accept (`return_unsigned=`), so it always
raised `TypeError` internally. That exception was silently swallowed by a
broad `except Exception` in `parse_and_validate_response`, which returned
`None` -> HTTP 400 for *every* SAML response, signed or not. The existing
`test_saml_unsigned_assertion_rejected_when_want_signed` /
`test_saml_xml_signature_wrapping_xsw_blocked` tests therefore passed for
the wrong reason: nothing ever reached real cryptographic verification.

The fix routes through `saml2.client.Saml2Client.parse_authn_request_response`,
pysaml2's standard SP entry point, which performs genuine XML-DSig signature
verification (via the `xmlsec1` binary), Issuer/Audience/Destination
matching, and time-window checks.

Environment note: this sandbox does not have the `xmlsec1` binary installed
(installing it requires root / `apt-get install xmlsec1`, which this
harness does not self-authorize -- see manager/backend/Dockerfile, which now
installs it for real deployments). Without it, pysaml2 cannot construct a
security context at all and raises `SigverError` before ever comparing a
signature, so a *forged* signature and a *missing* signature both resolve
to rejection here for the same underlying reason (fail-closed). In a CI/
prod environment with `xmlsec1` installed, `parse_authn_request_response`
would additionally verify the signature cryptographically instead of
failing at config load -- this test still asserts the externally-observable
contract (forged/unverifiable signature -> rejected) either way.
"""

import base64
import hashlib
import secrets
from datetime import datetime, timedelta

from app.services.saml_service import SAMLService, SAMLConfig


def _build_forged_signed_assertion(request_id: str, sp_entity_id: str,
                                    sp_acs_url: str, idp_entity_id: str) -> str:
    """Build a base64-encoded SAML Response whose Assertion carries a
    `<ds:Signature>` block that does NOT correspond to the configured IdP
    certificate (a different, attacker-controlled key/garbage signature).

    Unlike the plain "unsigned" fixtures used elsewhere, this response is
    NOT missing a signature -- it has one, it's just not a valid one for
    the trusted IdP. A verifier that only checks "is there a Signature
    element" (or that never verifies at all) would wrongly accept this.
    """
    now = datetime.utcnow()
    not_on_or_after = (now + timedelta(hours=1)).isoformat() + 'Z'
    not_before = (now - timedelta(seconds=60)).isoformat() + 'Z'
    assertion_id = f'id_{secrets.token_hex(8)}'

    # A syntactically-plausible XML-DSig block signed with an unrelated,
    # attacker-generated key -- garbage relative to the configured IdP cert.
    forged_signature = f'''<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:Reference URI="#{assertion_id}">
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      <ds:DigestValue>{base64.b64encode(secrets.token_bytes(32)).decode()}</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>{base64.b64encode(secrets.token_bytes(256)).decode()}</ds:SignatureValue>
  <ds:KeyInfo>
    <ds:X509Data>
      <ds:X509Certificate>{base64.b64encode(secrets.token_bytes(300)).decode()}</ds:X509Certificate>
    </ds:X509Data>
  </ds:KeyInfo>
</ds:Signature>'''

    assertion_xml = f'''<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" \
ID="{assertion_id}" Version="2.0" IssueInstant="{now.isoformat()}Z">
  <saml:Issuer>{idp_entity_id}</saml:Issuer>
  {forged_signature}
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">attacker@example.com</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData NotOnOrAfter="{not_on_or_after}" Recipient="{sp_acs_url}" InResponseTo="{request_id}"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
    <saml:AudienceRestriction>
      <saml:Audience>{sp_entity_id}</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AttributeStatement>
    <saml:Attribute Name="email">
      <saml:AttributeValue>attacker@example.com</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>'''

    response_xml = f'''<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" \
xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" \
ID="_id_{secrets.token_hex(8)}" Version="2.0" IssueInstant="{now.isoformat()}Z">
  {assertion_xml}
</samlp:Response>'''

    return base64.b64encode(response_xml.encode('utf-8')).decode('utf-8')


def test_forged_signature_assertion_rejected(app, db):
    """CRITICAL regression: an assertion carrying a signature that does not
    correspond to the configured IdP certificate must be rejected by
    `parse_and_validate_response`, not merely a bare/unsigned one."""
    with app.app_context():
        db.saml_providers.insert(
            name='test-saml-forged',
            display_name='Test SAML Forged',
            idp_entity_id='urn:example:idp',
            idp_sso_url='https://idp.example.com/sso',
            idp_x509_cert='-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
            sp_entity_id='https://app.example.com/saml/metadata',
            sp_acs_url='https://app.example.com/api/v1/auth/saml/test-saml-forged/acs',
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
            provider='test-saml-forged',
            code_verifier=request_id,
            nonce='',
            browser_binding_hash=binding_hash,
        )
        db.commit()

        config = SAMLConfig(
            name='test-saml-forged',
            display_name='Test SAML Forged',
            idp_entity_id='urn:example:idp',
            idp_sso_url='https://idp.example.com/sso',
            idp_x509_cert='-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
            sp_entity_id='https://app.example.com/saml/metadata',
            sp_acs_url='https://app.example.com/api/v1/auth/saml/test-saml-forged/acs',
            name_id_format='urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
            want_assertions_signed=True,
        )

        forged_response = _build_forged_signed_assertion(
            request_id=request_id,
            sp_entity_id=config.sp_entity_id,
            sp_acs_url=config.sp_acs_url,
            idp_entity_id=config.idp_entity_id,
        )

        result = SAMLService.parse_and_validate_response(
            config, forged_response, relay_state, binding_cookie, db
        )

        assert result is None


def test_unsolicited_response_without_matching_relay_state_rejected(app, db):
    """A response presenting a RelayState with no corresponding server-side
    login attempt (e.g. a replayed or fabricated RelayState) must be
    rejected before any XML parsing happens."""
    with app.app_context():
        config = SAMLConfig(
            name='test-saml-unsolicited',
            display_name='Test SAML Unsolicited',
            idp_entity_id='urn:example:idp',
            idp_sso_url='https://idp.example.com/sso',
            idp_x509_cert='-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
            sp_entity_id='https://app.example.com/saml/metadata',
            sp_acs_url='https://app.example.com/api/v1/auth/saml/test-saml-unsolicited/acs',
            name_id_format='urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
            want_assertions_signed=True,
        )

        result = SAMLService.parse_and_validate_response(
            config,
            base64.b64encode(b'<samlp:Response></samlp:Response>').decode(),
            secrets.token_urlsafe(32),  # never stored -> no login attempt
            secrets.token_urlsafe(32),
            db,
        )

        assert result is None
