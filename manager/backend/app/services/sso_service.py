"""
Enterprise OIDC Single Sign-On service (security-hardened).

Handles OAuth 2.0 Authorization Code Flow with PKCE, ID token validation,
and just-in-time (JIT) user provisioning. SSO logins bypass local TOTP MFA
because the IdP owns MFA. SAML 2.0 is deferred.

Security (FindingsFixed):
- [CRITICAL] State is opaque random token, NOT a decodable JWT
- [CRITICAL] Email takeover: match by (sso_provider, sso_subject) only; require email_verified
- [HIGH] Browser binding: httpOnly secure cookie + SHA-256 hash in attempt row
- [MEDIUM] Nonce: persisted in attempt row, validated via ID token claim
- [MEDIUM] Redirect URI: server-configured only (no query param override)
- [LOW] Password: NULL hash for SSO users, short-circuit bcrypt check
"""

import secrets
import hashlib
import base64
from typing import Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from urllib.parse import urlencode

import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import jwt
from jwt.exceptions import InvalidSignatureError, InvalidTokenError
from jwt import PyJWKClient
from flask import current_app


@dataclass(slots=True)
class OIDCConfig:
    """OIDC provider configuration."""
    name: str
    display_name: str
    issuer: str
    client_id: str
    client_secret: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_url: str
    scopes: str


@dataclass(slots=True)
class AuthorizationRequest:
    """Authorization request parameters."""
    authorization_url: str
    state: str  # Opaque random token (NOT decodable, no verifier)


@dataclass(slots=True)
class TokenExchangeResult:
    """Result of code exchange at token endpoint."""
    access_token: str
    id_token: str
    token_type: str
    expires_in: int


@dataclass(slots=True)
class ValidatedIDToken:
    """Validated ID token claims."""
    sub: str  # Subject (unique IdP user identifier)
    email: str  # Email claim
    email_verified: bool  # Email verification status (CRITICAL for JIT)
    name: Optional[str]  # User's full name or preferred name
    iss: str
    aud: str


class SSOService:
    """OIDC SSO service for enterprise authentication (security-hardened)."""

    # ID token validation: only allow RS256 and ES256
    ALLOWED_ALGS = ['RS256', 'ES256']
    LOGIN_ATTEMPT_EXPIRY_SECONDS = 600  # 10 minutes
    STATE_LENGTH = 32  # secrets.token_urlsafe(32) ~= 43 chars base64

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
            info=b'sso-encryption',
            backend=default_backend()
        )
        derived_key = kdf.derive(secret_key)
        b64_key = base64.urlsafe_b64encode(derived_key)
        return Fernet(b64_key)

    @staticmethod
    def encrypt_secret(secret: str) -> str:
        """Encrypt a secret (e.g. client_secret) with Fernet."""
        cipher = SSOService._get_cipher()
        encrypted = cipher.encrypt(secret.encode('utf-8'))
        return encrypted.decode('utf-8')

    @staticmethod
    def decrypt_secret(encrypted: str) -> str:
        """Decrypt a Fernet-encrypted secret."""
        cipher = SSOService._get_cipher()
        decrypted = cipher.decrypt(encrypted.encode('utf-8'))
        return decrypted.decode('utf-8')

    @staticmethod
    def _generate_pkce_pair() -> Tuple[str, str]:
        """
        Generate PKCE code_verifier and code_challenge (S256).

        Returns:
            (code_verifier, code_challenge_s256)
        """
        code_verifier = base64.urlsafe_b64encode(
            secrets.token_bytes(32)
        ).decode('utf-8').rstrip('=')

        challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        code_challenge = base64.urlsafe_b64encode(challenge).decode('utf-8').rstrip('=')

        return code_verifier, code_challenge

    @staticmethod
    def create_login_attempt(provider: str, code_verifier: str, nonce: str,
                            browser_binding_hash: str, db) -> str:
        """
        Create a server-side login attempt record.

        Args:
            provider: SSO provider name
            code_verifier: PKCE verifier (NOT sent to frontend)
            nonce: Random nonce for ID token validation
            browser_binding_hash: SHA-256 of browser binding cookie
            db: Database connection

        Returns:
            Opaque state token (random, no decodable content)
        """
        opaque_state = secrets.token_urlsafe(SSOService.STATE_LENGTH)

        db.sso_login_attempts.insert(
            opaque_state=opaque_state,
            provider=provider,
            code_verifier=code_verifier,
            nonce=nonce,
            browser_binding_hash=browser_binding_hash,
        )
        db.commit()

        return opaque_state

    @staticmethod
    def get_login_attempt(state: str, db):
        """
        Retrieve and validate a login attempt record.

        Enforces: exists, not used, not expired (≤10 min).

        Args:
            state: Opaque state token
            db: Database connection

        Returns:
            Attempt row dict, or None if invalid/expired/used
        """
        attempt = db(db.sso_login_attempts.opaque_state == state).select().first()

        if not attempt:
            current_app.logger.warning(f"Login attempt not found for state")
            return None

        if attempt['used']:
            current_app.logger.warning(f"Login attempt already used")
            return None

        age = (datetime.utcnow() - attempt['created_at']).total_seconds()
        if age > SSOService.LOGIN_ATTEMPT_EXPIRY_SECONDS:
            current_app.logger.warning(f"Login attempt expired (age={age}s)")
            return None

        return attempt

    @staticmethod
    def mark_attempt_used(attempt_id: int, db) -> None:
        """Mark login attempt as used (single-use enforcement)."""
        db(db.sso_login_attempts.id == attempt_id).update(used=True)
        db.commit()

    @staticmethod
    def build_authorization_url(config: OIDCConfig, provider_name: str, db,
                                binding_cookie_value: str) -> AuthorizationRequest:
        """
        Build the authorization URL to redirect to IdP.

        Generates PKCE code_verifier/challenge, nonce, creates server-side
        login attempt record, and returns authorization URL with OPAQUE state.

        Args:
            config: OIDC provider configuration
            provider_name: Provider name (for storage)
            db: Database connection
            binding_cookie_value: Browser binding cookie value (SHA-256 it)

        Returns:
            AuthorizationRequest with authorization_url and opaque state
        """
        code_verifier, code_challenge = SSOService._generate_pkce_pair()
        nonce = secrets.token_urlsafe(32)

        # Hash the browser binding cookie for verification at callback
        browser_binding_hash = hashlib.sha256(
            binding_cookie_value.encode('utf-8')
        ).hexdigest()

        # Create server-side attempt record (stores verifier + nonce)
        opaque_state = SSOService.create_login_attempt(
            provider_name,
            code_verifier,
            nonce,
            browser_binding_hash,
            db
        )

        params = {
            'client_id': config.client_id,
            'response_type': 'code',
            'scope': config.scopes,
            'redirect_uri': current_app.config.get('OIDC_REDIRECT_URI'),
            'state': opaque_state,  # OPAQUE, NOT JWT-encoded
            'nonce': nonce,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
        }

        authorization_url = f"{config.authorization_endpoint}?{urlencode(params)}"

        return AuthorizationRequest(
            authorization_url=authorization_url,
            state=opaque_state
        )

    @staticmethod
    def exchange_code_for_token(
        config: OIDCConfig,
        code: str,
        state: str,
        binding_cookie_value: str,
        db
    ) -> Optional[TokenExchangeResult]:
        """
        Exchange authorization code for tokens at token endpoint.

        Validates state/browser-binding, retrieves stored code_verifier,
        performs server-side code exchange, marks attempt used.

        Args:
            config: OIDC provider configuration
            code: Authorization code from callback
            state: Opaque state token (from attempt table)
            binding_cookie_value: Current browser binding cookie
            db: Database connection

        Returns:
            TokenExchangeResult with access/ID tokens, or None on failure
        """
        # Retrieve and validate login attempt
        attempt = SSOService.get_login_attempt(state, db)
        if not attempt:
            return None

        # Validate browser binding (CSRF protection)
        binding_hash_computed = hashlib.sha256(
            binding_cookie_value.encode('utf-8')
        ).hexdigest()
        if binding_hash_computed != attempt['browser_binding_hash']:
            current_app.logger.warning("Browser binding mismatch (CSRF)")
            return None

        code_verifier = attempt['code_verifier']
        client_secret = SSOService.decrypt_secret(config.client_secret)

        payload = {
            'grant_type': 'authorization_code',
            'code': code,
            'client_id': config.client_id,
            'client_secret': client_secret,
            'redirect_uri': current_app.config.get('OIDC_REDIRECT_URI'),
            'code_verifier': code_verifier,
        }

        try:
            response = requests.post(
                config.token_endpoint,
                data=payload,
                timeout=10
            )

            if response.status_code != 200:
                current_app.logger.warning(
                    f"Token endpoint returned {response.status_code} for {config.name}"
                )
                return None

            data = response.json()

            # Mark attempt as used AFTER successful code exchange
            SSOService.mark_attempt_used(attempt['id'], db)

            return TokenExchangeResult(
                access_token=data.get('access_token', ''),
                id_token=data.get('id_token', ''),
                token_type=data.get('token_type', 'Bearer'),
                expires_in=data.get('expires_in', 3600)
            )

        except requests.RequestException as e:
            current_app.logger.warning(f"Token endpoint request failed: {e}")
            return None

    @staticmethod
    def validate_id_token(
        config: OIDCConfig,
        id_token: str,
        expected_nonce: str
    ) -> Optional[ValidatedIDToken]:
        """
        Validate ID token signature and claims.

        Signature verified via JWKS; iss, aud, exp, nonce checked.
        Only RS256 and ES256 algorithms accepted.

        Args:
            config: OIDC provider configuration
            id_token: ID token JWT
            expected_nonce: Expected nonce value (from attempt row)

        Returns:
            ValidatedIDToken with claims, or None if validation fails
        """
        try:
            jwks_client = PyJWKClient(config.jwks_url, timeout=10)
            signing_key = jwks_client.get_signing_key_from_jwt(id_token)

            payload = jwt.decode(
                id_token,
                signing_key.key,
                algorithms=SSOService.ALLOWED_ALGS,
                audience=config.client_id,
                issuer=config.issuer,
                options={'verify_aud': True}
            )

            # Validate nonce (NOW with server-side enforcement)
            if payload.get('nonce') != expected_nonce:
                current_app.logger.warning("ID token nonce mismatch")
                return None

            # CRITICAL: require email_verified for JIT provisioning
            email_verified = payload.get('email_verified', False)

            return ValidatedIDToken(
                sub=payload.get('sub', ''),
                email=payload.get('email', ''),
                email_verified=email_verified,
                name=payload.get('name'),
                iss=payload.get('iss', ''),
                aud=payload.get('aud', '')
            )

        except (InvalidSignatureError, InvalidTokenError) as e:
            current_app.logger.warning(f"ID token validation failed: {e}")
            return None
        except Exception as e:
            current_app.logger.warning(f"ID token validation error: {e}")
            return None

    @staticmethod
    def jit_provision_or_match_user(
        config: OIDCConfig,
        validated_token: ValidatedIDToken,
        db
    ) -> Optional[int]:
        """
        Just-in-time (JIT) provision user or match existing user.

        CRITICAL: Only match by (sso_provider, sso_subject).
        If email exists locally but no SSO subject match → REFUSE auto-link.
        Create new user ONLY if email_verified == true.

        Args:
            config: OIDC provider configuration
            validated_token: Validated ID token claims
            db: Database connection

        Returns:
            User ID if provisioning/matching succeeds, None otherwise
        """
        # Check for existing SSO user (same provider + subject)
        existing_by_sso = db(
            (db.auth_user.sso_provider == config.name) &
            (db.auth_user.sso_subject == validated_token.sub)
        ).select()
        if existing_by_sso:
            return existing_by_sso[0]['id']

        # Check for existing user by email
        existing_by_email = db(db.auth_user.email == validated_token.email).select()
        if existing_by_email:
            # CRITICAL: refuse auto-link; require admin to link manually
            current_app.logger.warning(
                f"Email conflict: {validated_token.email} exists locally, "
                f"refusing auto-link from SSO {config.name}"
            )
            return None  # Caller will return 403

        # JIT provision new user ONLY if email is verified
        if not validated_token.email_verified:
            current_app.logger.warning(
                f"Refusing JIT: email_verified=false for {validated_token.email}"
            )
            return None

        # Create new Viewer user with NULL password (no local login)
        user_id = db.auth_user.insert(
            username=validated_token.email.split('@')[0],
            email=validated_token.email,
            password_hash=None,  # NULL: SSO users cannot login locally
            global_role='Viewer',
            active=True,
            mfa_enabled=False,
            sso_provider=config.name,
            sso_subject=validated_token.sub
        )
        db.commit()

        return user_id
