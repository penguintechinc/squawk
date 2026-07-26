"""SCIM 2.0 token management and provisioning support.

Handles dedicated SCIM bearer tokens (separate from user JWTs) for enterprise
IdP (Okta, Entra) provisioning. Tokens are bcrypt-hashed and validated with
constant-time comparison to prevent timing attacks.
"""

import secrets
import bcrypt
from datetime import datetime
from typing import Optional, Tuple
from flask import current_app


class SCIMTokenService:
    """Service for SCIM 2.0 bearer token management."""

    TOKEN_LENGTH = 32  # 256-bit token for security

    @staticmethod
    def generate_token() -> str:
        """Generate a cryptographically-secure random token (plaintext).

        Returns:
            Base64url-encoded 256-bit random token (shown only once to user)
        """
        return secrets.token_urlsafe(SCIMTokenService.TOKEN_LENGTH)

    @staticmethod
    def hash_token(token: str) -> str:
        """Hash token using bcrypt (consistent with user password hashing).

        Args:
            token: Plaintext token from generate_token()

        Returns:
            bcrypt hash of token
        """
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(token.encode('utf-8'), salt).decode('utf-8')

    @staticmethod
    def verify_token(token: str, token_hash: str) -> bool:
        """Verify token against stored hash using constant-time comparison.

        Args:
            token: Plaintext token from request
            token_hash: Stored bcrypt hash

        Returns:
            True if token matches hash, False otherwise
        """
        try:
            return bcrypt.checkpw(token.encode('utf-8'), token_hash.encode('utf-8'))
        except (ValueError, TypeError):
            # Invalid hash format; fail securely
            return False

    @staticmethod
    def create_token(description: str, tenant: str) -> Tuple[str, str]:
        """Create a new SCIM token (plaintext + hash).

        Args:
            description: Human-readable token description (e.g., "Okta provisioning")
            tenant: Tenant ID for scoping

        Returns:
            (plaintext_token, token_hash) tuple
        """
        plaintext = SCIMTokenService.generate_token()
        token_hash = SCIMTokenService.hash_token(plaintext)
        return plaintext, token_hash

    @staticmethod
    def store_token(plaintext: str, description: str, tenant: str) -> int:
        """Store SCIM token hash in database.

        Args:
            plaintext: Token from create_token()
            description: Human-readable description
            tenant: Tenant ID

        Returns:
            Token ID
        """
        db = current_app.db
        token_hash = SCIMTokenService.hash_token(plaintext)

        db.scim_tokens.insert(
            token_hash=token_hash,
            description=description,
            tenant=tenant,
            active=True,
        )
        db.commit()

        # Retrieve the token ID to return
        token_rec = db(
            (db.scim_tokens.token_hash == token_hash) &
            (db.scim_tokens.tenant == tenant)
        ).select().first()
        return token_rec.id if token_rec else None

    @staticmethod
    def validate_scim_token(token: str, tenant: str) -> Optional[int]:
        """Validate SCIM bearer token and update last_used_at.

        Args:
            token: Bearer token from Authorization header
            tenant: Tenant ID to scope the search

        Returns:
            Token ID if valid and active, None otherwise
        """
        db = current_app.db

        # Find active tokens for this tenant
        tokens = db(
            (db.scim_tokens.tenant == tenant) &
            (db.scim_tokens.active == True)
        ).select()

        for token_rec in tokens:
            if SCIMTokenService.verify_token(token, token_rec.token_hash):
                # Update last_used_at
                db(db.scim_tokens.id == token_rec.id).update(last_used_at=datetime.utcnow())
                db.commit()
                return token_rec.id

        return None

    @staticmethod
    def revoke_token(token_id: int) -> bool:
        """Revoke a SCIM token by ID.

        Args:
            token_id: Token ID to revoke

        Returns:
            True if revoked, False if not found
        """
        db = current_app.db
        token_rec = db.scim_tokens[token_id]

        if not token_rec:
            return False

        db(db.scim_tokens.id == token_id).update(active=False)
        db.commit()
        return True

