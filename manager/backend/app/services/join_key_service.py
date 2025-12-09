"""
Join key service for DNS server registration.
Generates and validates 64-character hex join keys.
"""

import secrets
from typing import Optional, Dict
from datetime import datetime
from flask import current_app


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
    def create_dns_server(name: str, region: str = 'default') -> Dict:
        """
        Create a new DNS server with join key.

        Args:
            name: Server name
            region: Server region

        Returns:
            Dict with server ID and join key
        """
        db = current_app.db

        join_key = JoinKeyService.generate_join_key()
        jwt_secret = JoinKeyService.generate_jwt_secret()

        server_id = db.dns_server.insert(
            name=name,
            join_key=join_key,
            jwt_secret=jwt_secret,
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
            join_key: 64-char hex join key

        Returns:
            Server info dict if valid, None otherwise
        """
        db = current_app.db

        server = db(db.dns_server.join_key == join_key).select().first()
        if not server:
            return None

        return {
            'id': server.id,
            'name': server.name,
            'jwt_secret': server.jwt_secret,
            'region': server.region
        }

    @staticmethod
    def register_server(join_key: str, hostname: str, version: str) -> Optional[Dict]:
        """
        Register DNS server using join key.
        Updates server status and metadata.

        Args:
            join_key: 64-char hex join key
            hostname: Server hostname
            version: Server version

        Returns:
            Server info with JWT secret if valid, None otherwise
        """
        db = current_app.db

        server = db(db.dns_server.join_key == join_key).select().first()
        if not server:
            return None

        # Update server registration info
        server.update_record(
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
            'jwt_secret': server.jwt_secret,
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

        server.update_record(
            join_key=new_join_key,
            jwt_secret=new_jwt_secret,
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
