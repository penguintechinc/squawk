"""
Authentication service for Squawk DNS Manager.
Handles JWT generation (asymmetric ES256/RS256), token refresh, and password hashing.
"""

import uuid
import jwt
import bcrypt
from datetime import datetime, timedelta
from typing import Dict, Optional
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
