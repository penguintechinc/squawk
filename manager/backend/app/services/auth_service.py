"""
Authentication service for Squawk DNS Manager.
Handles JWT generation (asymmetric ES256/RS256), token refresh, password hashing,
machine-client OAuth2 client_credentials, and OIDC token exchange.
"""

import uuid
import jwt
import bcrypt
import secrets
import fnmatch
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from flask import current_app
from jwt.exceptions import (
    ExpiredSignatureError, InvalidSignatureError, InvalidTokenError,
    InvalidAudienceError, InvalidIssuerError, MissingRequiredClaimError
)


class AuthService:
    """Authentication service for JWT and password management."""

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt."""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """Verify password against hash."""
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

    @staticmethod
    def create_access_token(user_id: int, username: str, global_role: str,
                           team_roles: Optional[Dict] = None) -> str:
        """
        Create JWT access token (15 minutes expiry) signed with ES256/RS256 private key.

        Every token includes a `kid` header derived from the public key so
        rotation can select the correct key for verification.

        Args:
            user_id: User ID
            username: Username
            global_role: Global role (SystemAdmin, OrgAdmin, UserManager, Viewer)
            team_roles: Dict of team_id -> role mappings
        """
        # TODO: extract tenant from user.org if schema adds org/tenant column
        tenant = current_app.config.get('TENANT_ID', 'default')

        # Expand the role into its concrete scope bundle at issuance. Authz
        # decisions are made on `scope`; global_role/team_roles are retained
        # for audit and per-team membership checks only.
        from app.services.scopes import scope_string

        payload = {
            'sub': str(user_id),
            'iss': current_app.config['JWT_ISSUER'],
            'aud': current_app.config['JWT_AUDIENCE'],
            'tenant': tenant,
            'user_id': user_id,
            'username': username,
            'scope': scope_string(global_role, team_roles),
            'global_role': global_role,
            'team_roles': team_roles or {},
            'type': 'access',
            'exp': datetime.utcnow() + current_app.config['JWT_ACCESS_TOKEN_EXPIRES'],
            'iat': datetime.utcnow()
        }

        # Use the configured signing provider (local or KMS)
        signing_provider = current_app.config.get('JWT_SIGNING_PROVIDER')
        if signing_provider and signing_provider.__class__.__name__ != 'LocalPemProvider':
            # Non-local provider: use manual JWS assembly
            from app.services.signing_provider import build_jws_manually
            return build_jws_manually(payload, signing_provider)
        else:
            # Local provider or legacy path: use PyJWT directly
            from app.utils.crypto import compute_kid_from_private_pem
            kid = compute_kid_from_private_pem(current_app.config['JWT_PRIVATE_KEY'])
            return jwt.encode(
                payload,
                current_app.config['JWT_PRIVATE_KEY'],
                algorithm=current_app.config['JWT_ALGORITHM'],
                headers={'kid': kid}
            )

    @staticmethod
    def create_refresh_token(user_id: int) -> str:
        """Create JWT refresh token (7 days expiry) signed with ES256/RS256 private key.

        Every token includes a `kid` header derived from the public key so
        rotation can select the correct key for verification.
        """
        tenant = current_app.config.get('TENANT_ID', 'default')

        payload = {
            'sub': str(user_id),
            'iss': current_app.config['JWT_ISSUER'],
            'aud': current_app.config['JWT_AUDIENCE'],
            'tenant': tenant,
            'user_id': user_id,
            'type': 'refresh',
            # Unique token id enables one-time-use rotation and revocation.
            'jti': str(uuid.uuid4()),
            'exp': datetime.utcnow() + current_app.config['JWT_REFRESH_TOKEN_EXPIRES'],
            'iat': datetime.utcnow()
        }

        # Use the configured signing provider (local or KMS)
        signing_provider = current_app.config.get('JWT_SIGNING_PROVIDER')
        if signing_provider and signing_provider.__class__.__name__ != 'LocalPemProvider':
            # Non-local provider: use manual JWS assembly
            from app.services.signing_provider import build_jws_manually
            return build_jws_manually(payload, signing_provider)
        else:
            # Local provider or legacy path: use PyJWT directly
            from app.utils.crypto import compute_kid_from_private_pem
            kid = compute_kid_from_private_pem(current_app.config['JWT_PRIVATE_KEY'])
            return jwt.encode(
                payload,
                current_app.config['JWT_PRIVATE_KEY'],
                algorithm=current_app.config['JWT_ALGORITHM'],
                headers={'kid': kid}
            )

    @staticmethod
    def create_server_jwt(server_id: int, jwt_secret: str) -> str:
        """
        Create JWT for DNS server (24 hours expiry).
        Uses server-specific secret for added security.
        """
        payload = {
            'server_id': server_id,
            'type': 'server',
            'exp': datetime.utcnow() + timedelta(hours=24),
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, jwt_secret, algorithm='HS256')

    @staticmethod
    def decode_token(token: str, secret_key: Optional[str] = None) -> Optional[Dict]:
        """
        Decode and validate JWT token.

        Args:
            token: JWT token string
            secret_key: Optional custom secret (for server tokens only; uses HS256)

        Returns:
            Decoded payload if valid, None otherwise.
            For user tokens: verifies with public key (ES256/RS256), requires tenant claim.
            For server tokens: verifies with server-specific secret (HS256).
        """
        try:
            # If a custom secret is provided, this is a server token (HS256)
            if secret_key:
                payload = jwt.decode(token, secret_key, algorithms=['HS256'])
                return payload

            # User token: verify with public key (ES256/RS256), require tenant
            public_key = current_app.config['JWT_PUBLIC_KEY']
            if not public_key:
                return None

            payload = jwt.decode(
                token,
                public_key,
                algorithms=['ES256', 'RS256'],
                audience=current_app.config['JWT_AUDIENCE'],
                issuer=current_app.config['JWT_ISSUER'],
                options={'require': ['exp', 'iat', 'tenant']}
            )

            # Fail closed: tenant claim must be present and non-empty
            if not payload.get('tenant'):
                return None

            return payload

        except ExpiredSignatureError:
            return None
        except (InvalidAudienceError, InvalidIssuerError, MissingRequiredClaimError):
            return None
        except (InvalidSignatureError, InvalidTokenError):
            return None

    @staticmethod
    def authenticate_user(username: str, password: str) -> Optional[Dict]:
        """
        Authenticate user with username and password.

        Returns:
            User dict if authenticated, None otherwise
        """
        db = current_app.db

        user = db(db.auth_user.username == username).select().first()
        if not user or not user.active:
            return None

        if not AuthService.verify_password(password, user.password_hash):
            return None

        # Get user's team roles
        team_roles = {}
        memberships = db(db.team_member.user_id == user.id).select(
            db.team_member.team_id,
            db.team_member.role
        )
        for membership in memberships:
            team_roles[membership.team_id] = membership.role

        return {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'global_role': user.global_role,
            'team_roles': team_roles
        }

    @staticmethod
    def _revoke_jti(jti: str, user_id: Optional[int], expires_at: datetime,
                    reason: str) -> None:
        """Add a refresh-token jti to the revocation denylist.

        Also purges denylist rows whose tokens have already expired (they can
        never be presented again), keeping the table small.
        """
        db = current_app.db
        now = datetime.utcnow()
        db(db.revoked_token.expires_at < now).delete()
        # Idempotent: a jti already on the denylist stays revoked.
        if not db(db.revoked_token.jti == jti).count():
            db.revoked_token.insert(
                jti=jti, user_id=user_id, reason=reason, expires_at=expires_at
            )
        db.commit()

    @staticmethod
    def is_refresh_token_revoked(jti: str) -> bool:
        """True if the refresh-token jti has been revoked (rotation/logout)."""
        db = current_app.db
        return bool(db(db.revoked_token.jti == jti).count())

    @staticmethod
    def revoke_refresh_token(refresh_token: str, reason: str = 'logout') -> bool:
        """Revoke a refresh token (e.g. on logout). Returns True if revoked.

        Invalid/expired/legacy (no-jti) tokens are ignored — they can't be
        used to mint access tokens anyway.
        """
        payload = AuthService.decode_token(refresh_token)
        if not payload or payload.get('type') != 'refresh':
            return False
        jti = payload.get('jti')
        if not jti:
            return False
        expires_at = datetime.utcfromtimestamp(payload['exp'])
        AuthService._revoke_jti(jti, payload.get('user_id'), expires_at, reason)
        return True

    @staticmethod
    def refresh_access_token(refresh_token: str) -> Optional[Dict[str, str]]:
        """
        Rotate a refresh token: validate, check revocation, then issue a new
        access token AND a new refresh token, revoking the presented one
        (one-time use). Reuse of a rotated/revoked token fails.

        Args:
            refresh_token: Valid, unrevoked refresh token

        Returns:
            {'access_token': ..., 'refresh_token': ...} if valid, None otherwise
        """
        payload = AuthService.decode_token(refresh_token)
        if not payload or payload.get('type') != 'refresh':
            return None

        # Fail closed: rotation requires a jti. Legacy jti-less refresh tokens
        # cannot be revoked, so they are no longer accepted (forces one
        # re-login after upgrade).
        jti = payload.get('jti')
        if not jti or AuthService.is_refresh_token_revoked(jti):
            return None

        db = current_app.db
        user = db.auth_user[payload['user_id']]
        if not user or not user.active:
            return None

        # Get user's team roles
        team_roles = {}
        memberships = db(db.team_member.user_id == user.id).select(
            db.team_member.team_id,
            db.team_member.role
        )
        for membership in memberships:
            team_roles[membership.team_id] = membership.role

        # Rotate: the presented token is single-use.
        expires_at = datetime.utcfromtimestamp(payload['exp'])
        AuthService._revoke_jti(jti, user.id, expires_at, reason='rotated')

        return {
            'access_token': AuthService.create_access_token(
                user.id, user.username, user.global_role, team_roles
            ),
            'refresh_token': AuthService.create_refresh_token(user.id),
        }

    @staticmethod
    def validate_dns_token(token: str, domain: Optional[str] = None) -> Dict:
        """
        Validate DNS authentication token and return permissions.

        Args:
            token: Token string
            domain: Optional domain for permission check

        Returns:
            Dict with validation result and permissions
        """
        db = current_app.db

        token_record = db((db.token.token == token) & (db.token.active == True)).select().first()
        if not token_record:
            return {'valid': False}

        # Check expiration
        if token_record.expires_at and token_record.expires_at < datetime.utcnow():
            return {'valid': False}

        # Update last used
        token_record.update_record(last_used=datetime.utcnow())

        # Get allowed zones for this token's team
        allowed_zones = []
        if token_record.team_id:
            zones = db(db.dns_zone.team_id == token_record.team_id).select(db.dns_zone.name)
            allowed_zones = [z.name for z in zones]

        return {
            'valid': True,
            'token_id': token_record.id,
            'team_id': token_record.team_id,
            'allowed_zones': allowed_zones
        }

    @staticmethod
    def create_machine_client(tenant: str, description: str,
                             registered_scopes: str) -> Tuple[str, str, str]:
        """
        Create a new machine client for OAuth2 client_credentials.

        Args:
            tenant: Tenant ID for multi-tenancy
            description: Human-readable description
            registered_scopes: Space-separated scopes (must be valid)

        Returns:
            Tuple of (client_id, client_secret_plaintext, hashed_secret)
            Plaintext secret is returned ONCE for the client to store securely.
        """
        client_id = f"sqk_mc_{secrets.token_urlsafe(16)}"
        client_secret = secrets.token_urlsafe(32)
        secret_hash = bcrypt.hashpw(client_secret.encode('utf-8'),
                                    bcrypt.gensalt()).decode('utf-8')

        db = current_app.db
        db.machine_client.insert(
            client_id=client_id,
            client_secret_hash=secret_hash,
            tenant=tenant,
            scopes=registered_scopes,
            description=description,
            active=True,
            created_at=datetime.utcnow()
        )
        db.commit()

        return client_id, client_secret, secret_hash

    @staticmethod
    def verify_machine_client(client_id: str, client_secret: str) -> Optional[Dict]:
        """
        Verify machine client credentials (constant-time comparison).

        Args:
            client_id: Client identifier
            client_secret: Client secret

        Returns:
            Client record dict if valid and active, None otherwise
        """
        db = current_app.db
        client = db((db.machine_client.client_id == client_id) &
                    (db.machine_client.active == True)).select().first()

        if not client:
            return None

        # Use bcrypt constant-time comparison to prevent timing attacks
        if not bcrypt.checkpw(client_secret.encode('utf-8'),
                            client.client_secret_hash.encode('utf-8')):
            return None

        return {
            'id': client.id,
            'client_id': client.client_id,
            'tenant': client.tenant,
            'scopes': client.scopes,
        }

    @staticmethod
    def create_machine_access_token(client_id: str, tenant: str,
                                   granted_scopes: str,
                                   expires_in: Optional[int] = None,
                                   dpop_jkt: Optional[str] = None,
                                   allowed_domains: Optional[List[str]] = None) -> str:
        """
        Create a short-lived JWT access token for a machine client.

        Args:
            client_id: Machine client identifier
            tenant: Tenant ID
            granted_scopes: Space-separated scope grant (validated subset)
            expires_in: Token TTL in seconds (default 15 min from config)
            dpop_jkt: Optional DPoP JWK thumbprint. If provided, token is
                      bound to this key via RFC 9449 cnf claim.
            allowed_domains: List of allowed DNS domains (or None for unrestricted)

        Returns:
            Signed JWT access token (token_type Bearer or DPoP based on dpop_jkt)
        """
        ttl_seconds = expires_in or current_app.config.get(
            'MACHINE_ACCESS_TOKEN_EXPIRES', timedelta(minutes=15)
        )
        if isinstance(ttl_seconds, timedelta):
            ttl = ttl_seconds
        else:
            ttl = timedelta(seconds=ttl_seconds)

        payload = {
            'sub': f'client:{client_id}',
            'iss': current_app.config['JWT_ISSUER'],
            'aud': current_app.config['JWT_AUDIENCE'],
            'tenant': tenant,
            'client_id': client_id,
            'scope': granted_scopes,
            'type': 'access',
            'machine': True,  # Marker for machine vs. user token
            'exp': datetime.utcnow() + ttl,
            'iat': datetime.utcnow()
        }

        # RFC 9449: DPoP binding via cnf (confirmation) claim
        if dpop_jkt:
            payload['cnf'] = {'jkt': dpop_jkt}

        # Include dns_domains claim ONLY if allowed_domains is non-NULL
        if allowed_domains is not None:
            payload['dns_domains'] = allowed_domains

        return jwt.encode(
            payload,
            current_app.config['JWT_PRIVATE_KEY'],
            algorithm=current_app.config['JWT_ALGORITHM']
        )

    @staticmethod
    def validate_scope_subset(requested_scopes: str,
                            registered_scopes: str) -> bool:
        """
        Check if requested scopes are a subset of registered scopes.

        Args:
            requested_scopes: Space-separated scopes requested
            registered_scopes: Space-separated scopes registered

        Returns:
            True if requested ⊆ registered, False otherwise
        """
        requested = set(requested_scopes.split()) if requested_scopes else set()
        registered = set(registered_scopes.split()) if registered_scopes else set()
        return requested.issubset(registered)

    @staticmethod
    def update_machine_client_last_used(client_id: str) -> None:
        """Update last_used_at timestamp for a machine client."""
        db = current_app.db
        db(db.machine_client.client_id == client_id).update(
            last_used_at=datetime.utcnow()
        )
        db.commit()

    @staticmethod
    def validate_oidc_token(external_token: str,
                           trust_anchor: Dict) -> Optional[Dict]:
        """
        Validate an external OIDC token against a trust anchor.

        Args:
            external_token: JWT token from external issuer
            trust_anchor: Trust anchor record with issuer, audience, jwks_url, etc.

        Returns:
            Decoded payload if valid, None otherwise
        """
        try:
            # For simplicity in this implementation, use PyJWT with direct public key.
            # In production, use PyJWKClient for dynamic JWKS fetching.
            # Here we support static PEM JWKS for testing/simple cases.
            if trust_anchor.get('static_jwks_pem'):
                # Use provided PEM (for testing)
                public_key = trust_anchor['static_jwks_pem']
            else:
                # In production, fetch from jwks_url using PyJWKClient
                # For now, raise to indicate jwks_url is not yet implemented
                raise NotImplementedError(
                    "Dynamic JWKS fetching (jwks_url) requires PyJWKClient "
                    "implementation (deferred to Part 2 detailed work)"
                )

            payload = jwt.decode(
                external_token,
                public_key,
                algorithms=['RS256', 'ES256'],  # Restrict to safe algorithms
                audience=trust_anchor['audience'],
                issuer=trust_anchor['issuer'],
                options={'require': ['exp', 'iat']}
            )
            return payload

        except (ExpiredSignatureError, InvalidSignatureError, InvalidTokenError,
                InvalidAudienceError, InvalidIssuerError, MissingRequiredClaimError):
            return None

    @staticmethod
    def subject_matches_pattern(subject: str, pattern: Optional[str]) -> bool:
        """
        Check if subject claim matches the configured pattern (glob).

        Args:
            subject: Subject claim from token
            pattern: Glob pattern (e.g. 'system:serviceaccount:*:*')

        Returns:
            True if pattern matches or is None (match-all), False otherwise
        """
        if not pattern:
            return True  # No pattern = match all subjects
        return fnmatch.fnmatch(subject, pattern)
