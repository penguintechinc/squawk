"""
Join key service for DNS server registration.
Generates and validates 64-character hex join keys.

At-rest protection:
- `join_key` is matched by exact equality only, so it is stored as a SHA-256
  hash (`join_key_hash`) and looked up by hash -- the plaintext value is
  returned to the caller once, at creation/regeneration, and never persisted.
- `jwt_secret` is the HMAC key used to sign/verify server JWTs, so it must
  stay recoverable: it is Fernet-encrypted at rest (via the shared
  SECRET_KEY-derived cipher in app.utils.crypto) and decrypted on read.
"""

import secrets
from typing import Optional, Dict
from datetime import datetime
from flask import current_app

from app.utils.crypto import sha256_hex, get_fernet_cipher

# Scopes the derived Fernet key to this specific use case (see
# get_fernet_cipher docstring) so it never collides with MFA/SSO/SAML secrets
# encrypted under the same app-wide SECRET_KEY.
_JWT_SECRET_INFO = b"dns-server-jwt-secret-encryption"


class JoinKeyService:
    """Service for managing DNS server join keys."""

    @staticmethod
    def generate_join_key() -> str:
        """Generate a 64-character hex join key (256-bit entropy)."""
        return secrets.token_hex(32)  # 32 bytes = 64 hex chars

    @staticmethod
    def generate_jwt_secret() -> str:
        """Generate a unique JWT secret for a DNS server."""
        return secrets.token_hex(32)

    @staticmethod
    def hash_join_key(join_key: str) -> str:
        """Hash a join key for at-rest storage and equality lookup."""
        return sha256_hex(join_key)

    @staticmethod
    def encrypt_jwt_secret(jwt_secret: str) -> str:
        """Encrypt a server's JWT signing secret for at-rest storage."""
        cipher = get_fernet_cipher(_JWT_SECRET_INFO)
        return cipher.encrypt(jwt_secret.encode('utf-8')).decode('utf-8')

    @staticmethod
    def decrypt_jwt_secret(encrypted_jwt_secret: str) -> str:
        """Decrypt a server's JWT signing secret read from storage."""
        cipher = get_fernet_cipher(_JWT_SECRET_INFO)
        return cipher.decrypt(encrypted_jwt_secret.encode('utf-8')).decode('utf-8')

    @staticmethod
    def create_dns_server(name: str, region: str = 'default') -> Dict:
        """
        Create a new DNS server with join key.

        Args:
            name: Server name
            region: Server region

        Returns:
            Dict with server ID and the plaintext join key (shown once; only
            its hash is persisted).
        """
        db = current_app.db

        join_key = JoinKeyService.generate_join_key()
        jwt_secret = JoinKeyService.generate_jwt_secret()

        server_id = db.dns_server.insert(
            name=name,
            join_key_hash=JoinKeyService.hash_join_key(join_key),
            jwt_secret=JoinKeyService.encrypt_jwt_secret(jwt_secret),
            region=region,
            status='offline',
            created_at=datetime.utcnow()
        )

        db.commit()

        return {
            'id': server_id,
            'name': name,
            'join_key': join_key,
            'region': region
        }

    @staticmethod
    def validate_join_key(join_key: str) -> Optional[Dict]:
        """
        Validate join key and return server info.

        Args:
            join_key: 64-char hex join key (plaintext)

        Returns:
            Server info dict (with decrypted jwt_secret) if valid, None otherwise
        """
        db = current_app.db

        server = db(db.dns_server.join_key_hash == JoinKeyService.hash_join_key(join_key)
                    ).select().first()
        if not server:
            return None

        return {
            'id': server.id,
            'name': server.name,
            'jwt_secret': JoinKeyService.decrypt_jwt_secret(server.jwt_secret),
            'region': server.region
        }

    @staticmethod
    def register_server(join_key: str, hostname: str, version: str) -> Optional[Dict]:
        """
        Register DNS server using join key.
        Updates server status and metadata.

        Args:
            join_key: 64-char hex join key (plaintext)
            hostname: Server hostname
            version: Server version

        Returns:
            Server info with decrypted JWT secret if valid, None otherwise
        """
        db = current_app.db

        server = db(db.dns_server.join_key_hash == JoinKeyService.hash_join_key(join_key)
                    ).select().first()
        if not server:
            return None

        # Update server registration info
        db(db.dns_server.id == server.id).update(
            hostname=hostname,
            version=version,
            status='online',
            last_heartbeat=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )

        db.commit()

        return {
            'id': server.id,
            'name': server.name,
            'jwt_secret': JoinKeyService.decrypt_jwt_secret(server.jwt_secret),
            'region': server.region,
            'hostname': hostname,
            'version': version
        }

    @staticmethod
    def revoke_join_key(server_id: int) -> bool:
        """
        Revoke join key by generating a new one.
        Forces server to re-register.

        Args:
            server_id: DNS server ID

        Returns:
            True if revoked, False if server not found
        """
        db = current_app.db

        server = db.dns_server[server_id]
        if not server:
            return False

        new_join_key = JoinKeyService.generate_join_key()
        new_jwt_secret = JoinKeyService.generate_jwt_secret()

        db(db.dns_server.id == server_id).update(
            join_key_hash=JoinKeyService.hash_join_key(new_join_key),
            jwt_secret=JoinKeyService.encrypt_jwt_secret(new_jwt_secret),
            status='offline',
            updated_at=datetime.utcnow()
        )

        db.commit()

        return True

    @staticmethod
    def get_server_by_id(server_id: int) -> Optional[Dict]:
        """
        Get DNS server by ID.

        Args:
            server_id: Server ID

        Returns:
            Server dict if found, None otherwise
        """
        db = current_app.db

        server = db.dns_server[server_id]
        if not server:
            return None

        return {
            'id': server.id,
            'name': server.name,
            'hostname': server.hostname,
            'version': server.version,
            'status': server.status,
            'region': server.region,
            'last_heartbeat': server.last_heartbeat.isoformat() if server.last_heartbeat else None,
            'created_at': server.created_at.isoformat()
        }
