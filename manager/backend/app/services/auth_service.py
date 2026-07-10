"""
Authentication service for Squawk DNS Manager.
Handles JWT generation (asymmetric ES256/RS256), token refresh, and password hashing.
"""

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

        Args:
            user_id: User ID
            username: Username
            global_role: Global role (SystemAdmin, OrgAdmin, UserManager, Viewer)
            team_roles: Dict of team_id -> role mappings
        """
        # TODO: extract tenant from user.org if schema adds org/tenant column
        tenant = current_app.config.get('TENANT_ID', 'default')

        payload = {
            'sub': str(user_id),
            'iss': current_app.config['JWT_ISSUER'],
            'aud': current_app.config['JWT_AUDIENCE'],
            'tenant': tenant,
            'user_id': user_id,
            'username': username,
            'global_role': global_role,
            'team_roles': team_roles or {},
            'type': 'access',
            'exp': datetime.utcnow() + current_app.config['JWT_ACCESS_TOKEN_EXPIRES'],
            'iat': datetime.utcnow()
        }
        return jwt.encode(
            payload,
            current_app.config['JWT_PRIVATE_KEY'],
            algorithm=current_app.config['JWT_ALGORITHM']
        )

    @staticmethod
    def create_refresh_token(user_id: int) -> str:
        """Create JWT refresh token (7 days expiry) signed with ES256/RS256 private key."""
        tenant = current_app.config.get('TENANT_ID', 'default')

        payload = {
            'sub': str(user_id),
            'iss': current_app.config['JWT_ISSUER'],
            'aud': current_app.config['JWT_AUDIENCE'],
            'tenant': tenant,
            'user_id': user_id,
            'type': 'refresh',
            'exp': datetime.utcnow() + current_app.config['JWT_REFRESH_TOKEN_EXPIRES'],
            'iat': datetime.utcnow()
        }
        return jwt.encode(
            payload,
            current_app.config['JWT_PRIVATE_KEY'],
            algorithm=current_app.config['JWT_ALGORITHM']
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
    def refresh_access_token(refresh_token: str) -> Optional[str]:
        """
        Generate new access token from refresh token.

        Args:
            refresh_token: Valid refresh token

        Returns:
            New access token if valid, None otherwise
        """
        payload = AuthService.decode_token(refresh_token)
        if not payload or payload.get('type') != 'refresh':
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

        return AuthService.create_access_token(
            user.id, user.username, user.global_role, team_roles
        )

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
