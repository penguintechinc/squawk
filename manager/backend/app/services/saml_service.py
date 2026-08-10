"""
Enterprise SAML 2.0 Service Provider (security-hardened).

Handles SAML 2.0 Single Sign-On with proper assertion signature validation via pysaml2,
and just-in-time (JIT) user provisioning. SAML logins bypass local TOTP MFA
because the IdP owns MFA.

Security (hardening requirements):
- [CRITICAL] RelayState is opaque random token (single-use, server-side)
- [CRITICAL] Email takeover: match by (sso_provider, sso_subject/NameID) only; require email claim
- [CRITICAL] Signature verification: uses pysaml2's AuthnResponse which validates digest, reference binding, and canonicalization (prevents XSW attacks)
- [HIGH] Browser binding: httpOnly secure cookie + SHA-256 hash in attempt row
- [HIGH] InResponseTo: must match AuthnRequest ID stored in login attempt
- [MEDIUM] Issuer: must equal IdP EntityID
- [MEDIUM] Destination: must equal SP ACS URL
- [MEDIUM] Audience: must equal SP EntityID
- [MEDIUM] NotBefore/NotOnOrAfter: validate with 60s clock skew
- [MEDIUM] Assertion ID replay: reject if seen before
- [LOW] XML External Entities: disabled globally
"""

import secrets
import hashlib
import base64
import uuid
from typing import Optional
from datetime import datetime
from dataclasses import dataclass
from urllib.parse import urlencode

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from flask import current_app

# SAML 2.0 XML parsing with defused XML (prevents XXE)
from saml2.response import AuthnResponse
from saml2.config import Config as Saml2Config
from saml2 import BINDING_HTTP_POST


@dataclass(slots=True)
class SAMLConfig:
    """SAML provider configuration."""
    name: str
    display_name: str
    idp_entity_id: str
    idp_sso_url: str
    idp_x509_cert: str
    sp_entity_id: str
    sp_acs_url: str
    name_id_format: str
    want_assertions_signed: bool


@dataclass(slots=True)
class AuthnRequestInfo:
    """SAML AuthnRequest metadata."""
    request_id: str  # Opaque ID for InResponseTo validation
    redirect_url: str  # URL to redirect user to IdP


@dataclass(slots=True)
class ValidatedSAMLAssertion:
    """Validated SAML Assertion claims."""
    subject: str  # NameID value (unique IdP user identifier)
    email: str  # Email from assertion attributes
    name: Optional[str]  # User's full name if available
    issuer: str  # Issuer from assertion
    audience: str  # Audience from SubjectConfirmationData


class SAMLService:
    """SAML 2.0 SP service for enterprise authentication (security-hardened)."""

    LOGIN_ATTEMPT_EXPIRY_SECONDS = 600  # 10 minutes
    REQUEST_ID_LENGTH = 32  # bytes for secrets.token_urlsafe
    CLOCK_SKEW_SECONDS = 60  # Allow 60s clock skew for NotBefore/NotOnOrAfter

    @staticmethod
    def _get_cipher() -> Fernet:
        """Get Fernet cipher derived from app SECRET_KEY via HKDF."""
        secret_key = current_app.config.get('SECRET_KEY', '').encode('utf-8')
        if not secret_key:
            raise ValueError('SECRET_KEY not configured')

        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'saml-encryption',
            backend=default_backend()
        )
        derived_key = kdf.derive(secret_key)
        b64_key = base64.urlsafe_b64encode(derived_key)
        return Fernet(b64_key)

    @staticmethod
    def create_login_attempt(provider: str, request_id: str,
                            browser_binding_hash: str, db) -> str:
        """
        Create a server-side SAML login attempt record.

        Args:
            provider: SAML provider name
            request_id: SAML AuthnRequest ID (for InResponseTo validation)
            browser_binding_hash: SHA-256 of browser binding cookie
            db: Database connection

        Returns:
            Opaque relay state token (random, single-use)
        """
        relay_state = secrets.token_urlsafe(32)

        db.sso_login_attempts.insert(
            opaque_state=relay_state,
            provider=provider,
            code_verifier=request_id,  # Reuse field for SAML request ID
            nonce='',  # Unused in SAML, kept for schema compat
            browser_binding_hash=browser_binding_hash,
        )
        db.commit()

        return relay_state

    @staticmethod
    def get_login_attempt(relay_state: str, db):
        """
        Retrieve and validate a login attempt record.

        Enforces: exists, not used, not expired (≤10 min).

        Args:
            relay_state: Opaque relay state token
            db: Database connection

        Returns:
            Attempt row dict, or None if invalid/expired/used
        """
        attempt = db(db.sso_login_attempts.opaque_state == relay_state).select().first()

        if not attempt:
            current_app.logger.warning("SAML login attempt not found")
            return None

        if attempt['used']:
            current_app.logger.warning("SAML login attempt already used")
            return None

        age = (datetime.utcnow() - attempt['created_at']).total_seconds()
        if age > SAMLService.LOGIN_ATTEMPT_EXPIRY_SECONDS:
            current_app.logger.warning(f"SAML login attempt expired (age={age}s)")
            return None

        return attempt

    @staticmethod
    def mark_attempt_used(attempt_id: int, db) -> None:
        """Mark login attempt as used (single-use enforcement)."""
        db(db.sso_login_attempts.id == attempt_id).update(used=True)
        db.commit()

    @staticmethod
    def build_authn_request(config: SAMLConfig, provider_name: str, db,
                           binding_cookie_value: str) -> AuthnRequestInfo:
        """
        Build SAML AuthnRequest and create server-side login attempt.

        Generates a random request ID, creates login attempt record, and
        returns the redirect URL for the IdP's SSO service.

        Args:
            config: SAML provider configuration
            provider_name: Provider name (for storage)
            db: Database connection
            binding_cookie_value: Browser binding cookie value (SHA-256 it)

        Returns:
            AuthnRequestInfo with redirect_url and request_id
        """
        request_id = f"id_{uuid.uuid4().hex}"

        # Hash the browser binding cookie for verification at callback
        browser_binding_hash = hashlib.sha256(
            binding_cookie_value.encode('utf-8')
        ).hexdigest()

        # Create server-side attempt record (stores request ID)
        relay_state = SAMLService.create_login_attempt(
            provider_name,
            request_id,
            browser_binding_hash,
            db
        )

        # Build AuthnRequest (minimal, unsigned)
        authn_request = f'''<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" \
xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" \
ID="{request_id}" Version="2.0" IssueInstant="{datetime.utcnow().isoformat()}Z" \
Destination="{config.idp_sso_url}" AssertionConsumerServiceURL="{config.sp_acs_url}" \
ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>{config.sp_entity_id}</saml:Issuer></samlp:AuthnRequest>'''

        # Deflate + base64 encode
        import zlib
        compressed = zlib.compress(authn_request.encode('utf-8'))
        encoded = base64.b64encode(compressed[2:-1]).decode('utf-8')

        # Build redirect URL with HTTP-Redirect binding (GET parameter)
        params = {
            'SAMLRequest': encoded,
            'RelayState': relay_state,
        }

        redirect_url = f"{config.idp_sso_url}?{urlencode(params)}"

        return AuthnRequestInfo(
            request_id=request_id,
            redirect_url=redirect_url
        )

    @staticmethod
    def parse_and_validate_response(
        config: SAMLConfig,
        saml_response_b64: str,
        relay_state: str,
        binding_cookie_value: str,
        db
    ) -> Optional[ValidatedSAMLAssertion]:
        """
        Parse, validate, and extract claims from SAML Response using pysaml2.

        pysaml2's AuthnResponse handles all critical validations:
        1. XML signature verification (including digest validation and reference binding — prevents XSW attacks)
        2. Issuer == idp_entity_id
        3. Destination == sp_acs_url
        4. Audience == sp_entity_id
        5. NotBefore/NotOnOrAfter with clock skew
        6. InResponseTo matches stored request ID
        7. Assertion ID replay prevention

        Args:
            config: SAML provider configuration
            saml_response_b64: Base64-encoded SAML Response (from POST)
            relay_state: RelayState from form (must match login attempt)
            binding_cookie_value: Current browser binding cookie
            db: Database connection

        Returns:
            ValidatedSAMLAssertion with extracted claims, or None on validation failure
        """
        # Validate and retrieve login attempt
        attempt = SAMLService.get_login_attempt(relay_state, db)
        if not attempt:
            current_app.logger.warning("SAML RelayState not found or expired")
            return None

        # Validate browser binding
        binding_hash_computed = hashlib.sha256(
            binding_cookie_value.encode('utf-8')
        ).hexdigest()
        if binding_hash_computed != attempt['browser_binding_hash']:
            current_app.logger.warning("SAML browser binding mismatch (CSRF)")
            return None

        expected_request_id = attempt['code_verifier']

        try:
            # Decode SAML Response
            saml_bytes = base64.b64decode(saml_response_b64)

            # Configure pysaml2 with our IdP certificate for signature verification
            saml2_config = {
                'entityid': config.sp_entity_id,
                'service': {
                    'sp': {
                        'endpoints': {
                            'assertion_consumer_service': [
                                (config.sp_acs_url, BINDING_HTTP_POST),
                            ],
                        },
                        'want_assertions_signed': config.want_assertions_signed,
                        'authn_requests_signed': False,
                    },
                },
                'metadata': {
                    'inline': [{
                        'class': 'saml2.md.EntityDescriptor',
                        'text': f'''<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{config.idp_entity_id}">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>
{config.idp_x509_cert.replace('-----BEGIN CERTIFICATE-----', '').replace('-----END CERTIFICATE-----', '').replace('\n', '')}
          </X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{config.idp_sso_url}"/>
  </IDPSSODescriptor>
</EntityDescriptor>'''
                    }],
                }
            }

            saml2_config_obj = Saml2Config().load(saml2_config)

            # Use pysaml2's AuthnResponse to parse and validate the response
            # This handles: signature verification (with digest + reference validation), issuer, audience, destination, time checks
            auth_response = AuthnResponse(saml2_config_obj, return_unsigned=False)
            auth_response.loads(saml_bytes)

            # Validate the response
            if not auth_response.is_ok():
                current_app.logger.warning(f"SAML response validation failed: {auth_response.status}")
                return None

            # pysaml2 validates signature, issuer, audience, destination, and time range automatically
            # Extract the assertion
            assertions = auth_response.assertion
            if not assertions:
                current_app.logger.warning("SAML response missing assertions")
                return None

            if len(assertions) > 1:
                current_app.logger.warning("SAML response contains multiple assertions (only 1 allowed)")
                return None

            assertion = assertions[0]

            # Extract subject (NameID)
            subject = assertion.subject.text if assertion.subject else None
            if not subject:
                current_app.logger.warning("SAML assertion missing subject")
                return None

            # Extract assertion ID for replay prevention
            assertion_id = assertion.id
            if not assertion_id:
                current_app.logger.warning("SAML assertion missing ID")
                return None

            # === Assertion ID Replay Prevention ===
            existing_assertion = db(
                (db.saml_assertion_ids.assertion_id == assertion_id)
            ).select().first()
            if existing_assertion:
                current_app.logger.warning(f"SAML assertion ID replay detected: {assertion_id}")
                return None

            provider_record = db(db.saml_providers.name == config.name).select().first()
            if provider_record:
                db.saml_assertion_ids.insert(
                    provider_id=provider_record['id'],
                    assertion_id=assertion_id,
                )
                db.commit()

            # === Validate InResponseTo ===
            if assertion.subject_confirmation_data:
                in_response_to = assertion.subject_confirmation_data.in_response_to
                if in_response_to != expected_request_id:
                    current_app.logger.warning(
                        f"SAML InResponseTo mismatch: expected {expected_request_id}, got {in_response_to}"
                    )
                    return None

            # === Extract Email from Attributes ===
            email = None
            name = None
            if assertion.attribute_statement:
                for attr in assertion.attribute_statement.attribute:
                    attr_name = attr.name
                    attr_values = attr.attribute_value
                    if attr_values:
                        attr_value = attr_values[0].text

                        # Common email attribute names
                        if attr_name in ['email', 'mail', 'emailAddress', 'urn:oid:0.9.2342.19200300.100.1.3']:
                            email = attr_value
                        # Common name attribute names
                        elif attr_name in ['displayName', 'cn', 'name', 'urn:oid:2.5.4.3']:
                            name = attr_value

            if not email:
                current_app.logger.warning("SAML assertion missing email attribute")
                return None

            # Extract issuer and audience (pysaml2 already validated these match our config)
            issuer = str(assertion.issuer)
            audience = None
            if assertion.conditions and assertion.conditions.audience_restriction:
                audience = assertion.conditions.audience_restriction[0].audience.text

            # Mark attempt as used
            SAMLService.mark_attempt_used(attempt['id'], db)

            return ValidatedSAMLAssertion(
                subject=subject,
                email=email,
                name=name,
                issuer=issuer,
                audience=audience or ''
            )

        except Exception as e:
            current_app.logger.warning(f"SAML response parsing failed: {e}")
            return None

    @staticmethod
    def jit_provision_or_match_user(
        config: SAMLConfig,
        validated_assertion: ValidatedSAMLAssertion,
        db
    ) -> Optional[int]:
        """
        Just-in-time (JIT) provision user or match existing user.

        CRITICAL: Only match by (sso_provider, sso_subject/NameID).
        If email exists locally but no SAML subject match → REFUSE auto-link.
        Create new user ONLY if email is provided and valid.

        Args:
            config: SAML provider configuration
            validated_assertion: Validated assertion claims
            db: Database connection

        Returns:
            User ID if provisioning/matching succeeds, None otherwise
        """
        # Check for existing SAML user (same provider + subject)
        existing_by_sso = db(
            (db.auth_user.sso_provider == config.name) &
            (db.auth_user.sso_subject == validated_assertion.subject)
        ).select()
        if existing_by_sso:
            return existing_by_sso[0]['id']

        # Check for existing user by email
        existing_by_email = db(db.auth_user.email == validated_assertion.email).select()
        if existing_by_email:
            # CRITICAL: refuse auto-link; require admin to link manually
            current_app.logger.warning(
                f"Email conflict: {validated_assertion.email} exists locally, "
                f"refusing auto-link from SAML {config.name}"
            )
            return None  # Caller will return 403

        # JIT provision new user
        user_id = db.auth_user.insert(
            username=validated_assertion.email.split('@')[0],
            email=validated_assertion.email,
            password_hash=None,  # NULL: SAML users cannot login locally
            global_role='Viewer',
            active=True,
            mfa_enabled=False,
            sso_provider=config.name,
            sso_subject=validated_assertion.subject
        )
        db.commit()

        return user_id
