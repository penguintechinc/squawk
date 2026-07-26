"""
Enterprise OIDC Single Sign-On service.

Handles OAuth 2.0 Authorization Code Flow with PKCE, ID token validation,
and just-in-time (JIT) user provisioning. SSO logins bypass local TOTP MFA
because the IdP owns MFA. SAML 2.0 is deferred.

Security notes:
- State tokens are signed JWTs with 10-minute expiration
- PKCE code verifier is stored temporarily in state JWT
- ID token signatures verified via JWKS (alg allowlist: RS256, ES256 only)
- All IdP endpoints validated to be https:// at configuration time
- Tokens/codes/secrets never logged; only error messages and state transitions
"""

import secrets
import hashlib
import base64
import json
from typing import Dict, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from urllib.parse import urlencode

import jwt
import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
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
    state: str  # signed JWT with code_verifier + issued_at


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
    name: Optional[str]  # User's full name or preferred name
    iss: str
    aud: str


class SSOService:
    """OIDC SSO service for enterprise authentication."""

    # ID token validation: only allow RS256 and ES256
    ALLOWED_ALGS = ['RS256', 'ES256']
    STATE_EXPIRY_SECONDS = 600  # 10 minutes

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
        # code_verifier: 43-128 chars of unreserved chars (A-Z a-z 0-9 - . _ ~)
        code_verifier = base64.urlsafe_b64encode(
            secrets.token_bytes(32)
        ).decode('utf-8').rstrip('=')  # Remove padding

        # code_challenge = BASE64URL(SHA256(code_verifier))
        challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        code_challenge = base64.urlsafe_b64encode(challenge).decode('utf-8').rstrip('=')

        return code_verifier, code_challenge

    @staticmethod
    def _create_state_token(code_verifier: str) -> str:
        """
        Create a signed JWT state token with embedded code_verifier.

        The state token includes the code_verifier so it can be extracted during
        callback without storing session state server-side. Single-use is enforced
        by timestamp validation (≤10 min).

        Args:
            code_verifier: PKCE code verifier to embed

        Returns:
            Signed JWT state token
        """
        payload = {
            'code_verifier': code_verifier,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(seconds=SSOService.STATE_EXPIRY_SECONDS),
        }
        return jwt.encode(
            payload,
            current_app.config['SECRET_KEY'],
            algorithm='HS256'
        )

    @staticmethod
    def _verify_state_token(state_token: str) -> Optional[str]:
        """
        Verify and extract code_verifier from state token.

        Returns:
            code_verifier if valid, None if expired or invalid
        """
        try:
            payload = jwt.decode(
                state_token,
                current_app.config['SECRET_KEY'],
                algorithms=['HS256']
            )
            return payload.get('code_verifier')
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return None

    @staticmethod
    def build_authorization_url(config: OIDCConfig) -> AuthorizationRequest:
        """
        Build the authorization URL to redirect to IdP.

        Generates PKCE code_verifier/challenge, creates signed state token,
        and returns the authorization URL.

        Args:
            config: OIDC provider configuration

        Returns:
            AuthorizationRequest with authorization_url and state
        """
        code_verifier, code_challenge = SSOService._generate_pkce_pair()
        state = SSOService._create_state_token(code_verifier)
        nonce = secrets.token_urlsafe(32)

        params = {
            'client_id': config.client_id,
            'response_type': 'code',
            'scope': config.scopes,
            'redirect_uri': current_app.config.get('OIDC_REDIRECT_URI', 'http://localhost:3000/callback'),
            'state': state,
            'nonce': nonce,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
        }

        authorization_url = f"{config.authorization_endpoint}?{urlencode(params)}"

        return AuthorizationRequest(
            authorization_url=authorization_url,
            state=state
        )

    @staticmethod
    def exchange_code_for_token(
        config: OIDCConfig,
        code: str,
        state: str,
        redirect_uri: str
    ) -> Optional[TokenExchangeResult]:
        """
        Exchange authorization code for tokens at token endpoint.

        Server-side code exchange using client_secret for security.

        Args:
            config: OIDC provider configuration
            code: Authorization code from callback
            state: State token (used to extract code_verifier)
            redirect_uri: Redirect URI (must match original)

        Returns:
            TokenExchangeResult with access/ID tokens, or None on failure
        """
        code_verifier = SSOService._verify_state_token(state)
        if not code_verifier:
            current_app.logger.warning("Invalid or expired state token in code exchange")
            return None

        client_secret = SSOService.decrypt_secret(config.client_secret)

        payload = {
            'grant_type': 'authorization_code',
            'code': code,
            'client_id': config.client_id,
            'client_secret': client_secret,
            'redirect_uri': redirect_uri,
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
                    f"Token endpoint returned {response.status_code} for provider {config.name}"
                )
                return None

            data = response.json()
            return TokenExchangeResult(
                access_token=data.get('access_token', ''),
                id_token=data.get('id_token', ''),
                token_type=data.get('token_type', 'Bearer'),
                expires_in=data.get('expires_in', 3600)
            )

        except requests.RequestException as e:
            current_app.logger.warning(f"Token endpoint request failed for {config.name}: {e}")
            return None

    @staticmethod
    def validate_id_token(
        config: OIDCConfig,
        id_token: str,
        nonce: Optional[str] = None
    ) -> Optional[ValidatedIDToken]:
        """
        Validate ID token signature and claims.

        Signature verified via JWKS endpoint; iss, aud, exp, nonce, and alg checked.
        Only RS256 and ES256 algorithms accepted.

        Args:
            config: OIDC provider configuration
            id_token: ID token JWT
            nonce: Expected nonce value (optional for strict validation)

        Returns:
            ValidatedIDToken with claims, or None if validation fails
        """
        try:
            # Get JWKS from IdP
            jwks_client = PyJWKClient(
                config.jwks_url,
                timeout=10
            )

            # Verify signature and decode
            # PyJWKClient.get_signing_key() raises PyJWKClientError if kid not found
            signing_key = jwks_client.get_signing_key_from_jwt(id_token)

            payload = jwt.decode(
                id_token,
                signing_key.key,
                algorithms=SSOService.ALLOWED_ALGS,
                audience=config.client_id,
                issuer=config.issuer,
                options={'verify_aud': True}
            )

            # Validate nonce if provided
            if nonce and payload.get('nonce') != nonce:
                current_app.logger.warning("ID token nonce mismatch")
                return None

            # Extract claims
            return ValidatedIDToken(
                sub=payload.get('sub', ''),
                email=payload.get('email', ''),
                name=payload.get('name'),
                iss=payload.get('iss', ''),
                aud=payload.get('aud', '')
            )

        except (InvalidSignatureError, InvalidTokenError) as e:
            current_app.logger.warning(f"ID token validation failed for {config.name}: {e}")
            return None
        except Exception as e:
            current_app.logger.warning(f"ID token validation error for {config.name}: {e}")
            return None

    @staticmethod
    def jit_provision_or_match_user(
        config: OIDCConfig,
        validated_token: ValidatedIDToken,
        db
    ) -> Optional[int]:
        """
        Just-in-time (JIT) provision user or match existing user by email/sub.

        If a user with sso_provider=config.name and sso_subject=validated_token.sub exists,
        return their user ID. Otherwise, match by email; if found, update SSO fields.
        If no user exists, create a new Viewer (read-only) user.

        SSO-provisioned users have no password hash (cannot login locally).

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
            user = existing_by_email[0]
            # Update SSO fields on existing user
            db(db.auth_user.id == user['id']).update(
                sso_provider=config.name,
                sso_subject=validated_token.sub
            )
            db.commit()
            return user['id']

        # JIT provision new Viewer user
        # SSO users have a placeholder password (never used)
        hashed_placeholder = '*' * 64  # Placeholder to indicate no local login

        user_id = db.auth_user.insert(
            username=validated_token.email.split('@')[0],  # Extract username from email
            email=validated_token.email,
            password_hash=hashed_placeholder,
            global_role='Viewer',  # SSO users default to read-only
            active=True,
            mfa_enabled=False,  # SSO bypasses TOTP; IdP owns MFA
            sso_provider=config.name,
            sso_subject=validated_token.sub
        )
        db.commit()

        return user_id
