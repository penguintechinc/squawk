"""
Client Configuration Service for Squawk DNS Manager.

Manages client configurations that can be pulled from the server.
Features:
- JWT-based client authentication
- Per-client configuration profiles
- Deployment domain grouping
- Role-based access (Client-Reader, Client-Maintainer)
- Configuration versioning and rollback
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from functools import wraps
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import jwt
from penguin_dal import DB

logger = logging.getLogger(__name__)

# Verifiers accept asymmetric algorithms only. HS256/none are rejected to block
# the public-key-as-HMAC algorithm-confusion attack, consistent with the rest of
# the platform (dns-server/dhcp-server/ntp-server verifiers).
_DOMAIN_JWT_ALGORITHMS = ["ES256", "RS256"]


@dataclass(slots=True)
class ConfigData:
    """Validated client configuration data."""
    server_url: str
    dns_port: int
    cache_enabled: bool
    cache_ttl: Optional[int] = None
    auth_token: Optional[str] = None
    use_mtls: bool = False
    cert_path: Optional[str] = None
    key_path: Optional[str] = None
    ca_cert_path: Optional[str] = None
    log_level: str = "INFO"
    timeout: int = 5
    retries: int = 3


@dataclass(slots=True, frozen=True)
class OverrideRecord:
    """Represents a config override record."""
    token_id: int
    indicator: str
    override_type: str
    reason: Optional[str] = None
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None



def _generate_ephemeral_es256_keypair() -> tuple[str, str]:
    """Generate an in-process ES256 keypair (PEM strings).

    Intentionally self-contained (duplicates app.utils.crypto): this module is
    imported BARE (as ``client_config_service``) by the acceptance-test harness
    with the services dir on sys.path, where ``app.*`` resolves to a different
    package — so it must not import from ``app.*``.
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


def _with_db(method):
    """Open a DB connection for the wrapped method and guarantee it closes.

    The wrapped method receives the connection as its first argument after
    ``self``. Centralizes the get/close lifecycle previously duplicated in
    every method (``db = self._get_db()`` ... ``finally: db.close()``).
    """
    @wraps(method)
    def wrapper(self, *args, **kwargs):
        db = self._get_db()
        try:
            return method(self, db, *args, **kwargs)
        finally:
            db.close()
    return wrapper


class ClientConfigManager:
    """Manages client configurations using penguin-dal."""

    def __init__(
        self,
        db_url: str,
        private_key: Optional[str] = None,
        public_key: Optional[str] = None,
        algorithm: str = "ES256",
        issuer: str = "squawk-manager",
        audience: str = "squawk",
    ) -> None:
        """Initialize client config manager.

        Deployment-domain tokens are signed asymmetrically (ES256 default,
        RS256 fallback) with the manager's private key and verified with the
        public key — matching the platform-wide JWT scheme. Supply the manager's
        configured keypair so tokens remain valid across replicas/restarts; if
        omitted, an ephemeral keypair is generated for the process (dev/test).

        Args:
            db_url: Database connection string
            private_key: PEM private key used to sign domain tokens
            public_key: PEM public key used to verify domain tokens
            algorithm: Signing algorithm (ES256 or RS256)
            issuer: Expected/emitted `iss` claim
            audience: Expected/emitted `aud` claim
        """
        self.db_url = db_url
        if not private_key or not public_key:
            private_key, public_key = _generate_ephemeral_es256_keypair()
            logger.warning(
                "ClientConfigManager: no JWT keypair supplied; using an "
                "ephemeral in-process keypair. Domain tokens will not be "
                "verifiable across replicas or restarts."
            )
        self.private_key = private_key
        self.public_key = public_key
        self.algorithm = algorithm if algorithm in _DOMAIN_JWT_ALGORITHMS else "ES256"
        self.issuer = issuer
        self.audience = audience
        self._initialize_default_roles()

    def _get_db(self) -> DB:
        """Get a fresh database connection."""
        return DB(self.db_url)

    def _generate_domain_jwt(self, domain_name: str) -> str:
        """Generate an asymmetrically-signed JWT for a deployment domain.

        Signed with the manager's private key (ES256/RS256). Uses standard
        `iat`/`exp` claims so PyJWT enforces expiry natively, plus `iss`/`aud`.
        """
        now = datetime.now(timezone.utc)
        payload = {
            "domain": domain_name,
            "type": "deployment_domain",
            "iss": self.issuer,
            "aud": self.audience,
            "iat": now,
            "exp": now + timedelta(days=365),
        }
        return jwt.encode(payload, self.private_key, algorithm=self.algorithm)

    def _validate_config_data(self, config_data: Dict[str, Any]) -> bool:
        """Validate client configuration data structure.

        Required fields: server_url, dns_port, cache_enabled
        """
        required_fields = ["server_url", "dns_port", "cache_enabled"]

        try:
            for field in required_fields:
                if field not in config_data:
                    return False

            # Validate server_url format
            server_url = config_data["server_url"]
            if not server_url.startswith(("http://", "https://")):
                return False

            # Validate port
            dns_port = config_data["dns_port"]
            if not isinstance(dns_port, int) or dns_port < 1 or dns_port > 65535:
                return False

            return True
        except Exception:
            return False

    def _extract_cn_from_subject(self, subject_dn: str) -> Optional[str]:
        """Extract Common Name from certificate subject DN.

        Parses format: "CN=client-name,O=organization,..."
        """
        try:
            parts = subject_dn.split(",")
            for part in parts:
                part = part.strip()
                if part.startswith("CN="):
                    return part[3:]
        except Exception:
            pass
        return None

    @_with_db
    def _initialize_default_roles(self, db: DB) -> None:
        """Create default configuration roles if they don't exist."""
        try:
            # Define default roles
            default_roles = [
                {
                    "name": "Client-Reader",
                    "permissions": "read_config,pull_config",
                    "description": "Can read and pull client configurations",
                },
                {
                    "name": "Client-Maintainer",
                    "permissions": "read_config,create_config,update_config,pull_config",
                    "description": "Can maintain client configurations",
                },
                {
                    "name": "Domain-Admin",
                    "permissions": "read_config,create_config,update_config,delete_config,pull_config,rollover_jwt,manage_clients",
                    "description": "Full domain administration",
                },
            ]

            for role in default_roles:
                # Check if role exists
                existing = db(db.config_role.name == role["name"]).select().first()
                if not existing:
                    db.config_role.insert(
                        name=role["name"],
                        permissions=role["permissions"],
                        description=role["description"],
                    )
            db.commit()
        except Exception as e:
            logger.warning(f"Failed to initialize default roles: {e}")

    @_with_db
    def create_deployment_domain(
        self,
        db: DB,
        name: str,
        description: str = "",
        created_by: str = "",
    ) -> Dict[str, Any]:
        """Create a new deployment domain with JWT token."""
        try:
            # Check for duplicate
            existing = db(db.deployment_domain.name == name).select().first()
            if existing:
                return {"success": False, "error": "Domain already exists"}

            # Generate JWT token
            domain_jwt = self._generate_domain_jwt(name)

            # Insert domain
            domain_id = db.deployment_domain.insert(
                name=name,
                description=description,
                jwt_token=domain_jwt,
                jwt_expires=datetime.now() + timedelta(days=365),
                active=True,
            )

            db.commit()

            return {
                "success": True,
                "id": domain_id,
                "name": name,
                "jwt_token": domain_jwt,
            }

        except Exception as e:
            logger.error(f"Failed to create deployment domain: {e}")
            return {"success": False, "error": str(e)}

    @_with_db
    def rollover_domain_jwt(self, db: DB, domain_id: int, admin_user: str = "") -> Dict[str, Any]:
        """Generate new JWT token for deployment domain."""
        try:
            domain = db(db.deployment_domain.id == domain_id).select().first()
            if not domain:
                return {"success": False, "error": "Domain not found"}

            new_jwt = self._generate_domain_jwt(domain.name)

            # Update domain
            db(db.deployment_domain.id == domain_id).update(
                jwt_token=new_jwt,
                jwt_expires=datetime.now() + timedelta(days=365),
            )

            db.commit()
            logger.info(f"JWT rolled over for domain {domain.name} by {admin_user}")

            return {
                "success": True,
                "new_jwt": new_jwt,
                "expires_at": (datetime.now() + timedelta(days=365)).isoformat(),
            }

        except Exception as e:
            logger.error(f"Failed to rollover JWT: {e}")
            return {"success": False, "error": str(e)}

    @_with_db
    def create_client_config(
        self,
        db: DB,
        name: str,
        domain_id: int,
        config_data: Dict[str, Any],
        description: str = "",
        created_by: str = "",
    ) -> Dict[str, Any]:
        """Create a new client configuration."""
        try:
            # Validate config data
            if not self._validate_config_data(config_data):
                return {"success": False, "error": "Invalid configuration data"}

            # Insert config
            config_id = db.client_config.insert(
                name=name,
                domain_id=domain_id,
                config_data=config_data,
                version=1,
                description=description,
                created_by=created_by,
                active=True,
            )

            # Store in history
            db.config_history.insert(
                config_id=config_id,
                version=1,
                config_data=config_data,
                change_description="Initial configuration",
                changed_by=created_by,
            )

            db.commit()

            return {"success": True, "config_id": config_id, "version": 1}

        except Exception as e:
            logger.error(f"Failed to create client config: {e}")
            return {"success": False, "error": str(e)}

    @_with_db
    def update_client_config(
        self,
        db: DB,
        config_id: int,
        config_data: Dict[str, Any],
        description: str = "",
        changed_by: str = "",
    ) -> Dict[str, Any]:
        """Update an existing client configuration."""
        try:
            config = db(db.client_config.id == config_id).select().first()
            if not config:
                return {"success": False, "error": "Configuration not found"}

            # Validate config data
            if not self._validate_config_data(config_data):
                return {"success": False, "error": "Invalid configuration data"}

            # Increment version
            new_version = config.version + 1

            # Update config
            db(db.client_config.id == config_id).update(
                config_data=config_data,
                version=new_version,
                description=description,
            )

            # Store in history
            db.config_history.insert(
                config_id=config_id,
                version=new_version,
                config_data=config_data,
                change_description=description,
                changed_by=changed_by,
            )

            db.commit()

            return {"success": True, "version": new_version}

        except Exception as e:
            logger.error(f"Failed to update client config: {e}")
            return {"success": False, "error": str(e)}

    @_with_db
    def _verify_domain_jwt(self, db: DB, jwt_token: str) -> Optional[Dict[str, Any]]:
        """Verify domain JWT token and return domain info."""
        try:
            # Verify signature with the public key. Expiry (`exp`) is enforced
            # natively by PyJWT; iss/aud are validated. HS256/none are rejected.
            payload = jwt.decode(
                jwt_token,
                self.public_key,
                algorithms=_DOMAIN_JWT_ALGORITHMS,
                issuer=self.issuer,
                audience=self.audience,
                options={"require": ["exp", "iat"]},
            )

            domain_name = payload.get("domain")
            if not domain_name:
                return None

            # Find domain in database
            domain = db(
                (db.deployment_domain.name == domain_name)
                & (db.deployment_domain.jwt_token == jwt_token)
                & (db.deployment_domain.active == True)
            ).select().first()

            if domain:
                return {
                    "id": domain.id,
                    "name": domain.name,
                    "description": domain.description,
                }

        except jwt.ExpiredSignatureError:
            logger.warning("Expired JWT token used for domain verification")
        except jwt.InvalidTokenError:
            logger.warning("Invalid JWT token used for domain verification")
        except Exception as e:
            logger.error(f"JWT verification failed: {e}")

        return None

    def _verify_user_token(
        self,
        db: DB,
        user_token: str,
        client_cert_subject: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Verify user authentication token with optional mTLS cert validation."""
        try:
            # Check if token exists and is active
            token_record = db(
                (db.token.token == user_token) & (db.token.active == True)
            ).select().first()

            if not token_record:
                return {"valid": False, "reason": "Invalid or inactive token"}

            # If mTLS is enabled, verify client cert matches token
            if client_cert_subject:
                cert_cn = self._extract_cn_from_subject(client_cert_subject)
                if cert_cn and cert_cn != token_record.name:
                    return {
                        "valid": False,
                        "reason": "Certificate subject does not match token",
                    }

            # Update last used timestamp
            db(db.token.id == token_record.id).update(last_used=datetime.now())

            return {
                "valid": True,
                "token_id": token_record.id,
                "token_name": token_record.name,
            }

        except Exception as e:
            logger.error(f"User token verification failed: {e}")
            return {"valid": False, "reason": "Token verification error"}

    @_with_db
    def register_client(
        self,
        db: DB,
        client_id: str,
        domain_jwt: str,
        hostname: str,
        ip_address: str,
        client_version: str = "",
        os_info: str = "",
        user_token: Optional[str] = None,
        client_cert_subject: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Register a new client instance."""
        try:
            # Verify user auth if provided
            if user_token:
                auth_result = self._verify_user_token(
                    db, user_token, client_cert_subject
                )
                if not auth_result["valid"]:
                    return {
                        "success": False,
                        "error": f"Authentication failed: {auth_result['reason']}",
                    }

            # Verify JWT token
            domain = self._verify_domain_jwt(domain_jwt)
            if not domain:
                return {"success": False, "error": "Invalid or expired JWT token"}

            # Check if client already exists in this domain (tenant isolation: IDOR fix)
            existing = db(
                (db.client_instance.client_id == client_id) &
                (db.client_instance.domain_id == domain["id"])
            ).select().first()

            # Reject cross-domain collision attempt
            if not existing:
                cross_domain = db(db.client_instance.client_id == client_id).select().first()
                if cross_domain:
                    return {
                        "success": False,
                        "error": "client_id already registered in another domain"
                    }

            if existing:
                # Update existing (scoped to this domain)
                db(
                    (db.client_instance.client_id == client_id) &
                    (db.client_instance.domain_id == domain["id"])
                ).update(
                    hostname=hostname,
                    ip_address=ip_address,
                    last_checkin=datetime.now(),
                    client_version=client_version,
                    os_info=os_info,
                    status="active",
                )
                client_record_id = existing.id
            else:
                # Insert new
                client_record_id = db.client_instance.insert(
                    client_id=client_id,
                    domain_id=domain["id"],
                    hostname=hostname,
                    ip_address=ip_address,
                    last_checkin=datetime.now(),
                    client_version=client_version,
                    os_info=os_info,
                    status="active",
                )

            db.commit()

            return {
                "success": True,
                "client_record_id": client_record_id,
                "domain_name": domain["name"],
            }

        except Exception as e:
            logger.error(f"Failed to register client: {e}")
            return {"success": False, "error": str(e)}

    @_with_db
    def pull_client_config(
        self,
        db: DB,
        client_id: str,
        domain_jwt: str,
        user_token: Optional[str] = None,
        client_cert_subject: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Pull configuration for a client."""
        try:
            # Verify user auth if provided
            if user_token:
                auth_result = self._verify_user_token(
                    db, user_token, client_cert_subject
                )
                if not auth_result["valid"]:
                    return {
                        "success": False,
                        "error": f"Authentication failed: {auth_result['reason']}",
                    }

            # Verify JWT token
            domain = self._verify_domain_jwt(domain_jwt)
            if not domain:
                return {"success": False, "error": "Invalid or expired JWT token"}

            # Find client
            client = db(
                (db.client_instance.client_id == client_id)
                & (db.client_instance.domain_id == domain["id"])
                & (db.client_instance.status == "active")
            ).select().first()

            if not client:
                return {"success": False, "error": "Client not registered"}

            # Get config
            config = None
            if client.config_id:
                config = db(
                    (db.client_config.id == client.config_id)
                    & (db.client_config.active == True)
                ).select().first()
            else:
                # Use default config
                config = db(
                    (db.client_config.domain_id == domain["id"])
                    & (db.client_config.name == "default")
                    & (db.client_config.active == True)
                ).select().first()

            if not config:
                return {"success": False, "error": "No configuration available"}

            # Update client last pull
            db(db.client_instance.id == client.id).update(
                last_config_pull=datetime.now(),
                last_checkin=datetime.now(),
            )

            db.commit()

            return {
                "success": True,
                "config": config.config_data,
                "version": config.version,
                "config_name": config.name,
                "description": config.description,
                "last_updated": config.created_at.isoformat(),
            }

        except Exception as e:
            logger.error(f"Failed to pull client config: {e}")
            return {"success": False, "error": str(e)}

    @_with_db
    def assign_config_to_client(
        self,
        db: DB,
        client_id: str,
        config_id: int,
        assigned_by: str = "",
    ) -> Dict[str, Any]:
        """Assign a specific configuration to a client."""
        try:
            client = db(db.client_instance.client_id == client_id).select().first()
            if not client:
                return {"success": False, "error": "Client not found"}

            config = db(db.client_config.id == config_id).select().first()
            if not config:
                return {"success": False, "error": "Configuration not found"}

            # Tenant isolation: config's domain_id must match client's domain_id (IDOR fix)
            if config.domain_id != client.domain_id:
                return {
                    "success": False,
                    "error": "Configuration belongs to a different domain"
                }

            # Update client config assignment
            db(db.client_instance.client_id == client_id).update(config_id=config_id)

            db.commit()

            logger.info(
                f"Config {config.name} assigned to client {client_id} by {assigned_by}"
            )

            return {"success": True}

        except Exception as e:
            logger.error(f"Failed to assign config to client: {e}")
            return {"success": False, "error": str(e)}

    @_with_db
    def get_domain_clients(self, db: DB, domain_id: int) -> List[Dict[str, Any]]:
        """Get all clients in a deployment domain."""
        try:
            clients = db(db.client_instance.domain_id == domain_id).select()

            result = []
            for client in clients:
                config_name = None
                if client.config_id:
                    config = db(db.client_config.id == client.config_id).select().first()
                    if config:
                        config_name = config.name

                result.append({
                    "client_id": client.client_id,
                    "hostname": client.hostname,
                    "ip_address": client.ip_address,
                    "last_checkin": (
                        client.last_checkin.isoformat() if client.last_checkin else None
                    ),
                    "last_config_pull": (
                        client.last_config_pull.isoformat()
                        if client.last_config_pull
                        else None
                    ),
                    "client_version": client.client_version,
                    "os_info": client.os_info,
                    "status": client.status,
                    "config_name": config_name,
                    "registered_at": client.registered_at.isoformat(),
                })

            return result

        except Exception as e:
            logger.error(f"Failed to get domain clients: {e}")
            return []

    @_with_db
    def get_client_stats(self, db: DB) -> Dict[str, Any]:
        """Get client configuration statistics."""
        try:
            # Domain stats
            all_domains = db(db.deployment_domain.id > 0).count()  # All deployment domains
            active_domains = db(db.deployment_domain.active == True).count()

            # Client stats
            all_clients = db(db.client_instance.id > 0).count()  # All clients
            active_clients = db(db.client_instance.status == "active").count()

            # Recent activity
            recent_checkins = db(
                db.client_instance.last_checkin
                >= (datetime.now() - timedelta(hours=24))
            ).count()

            recent_config_pulls = db(
                db.client_instance.last_config_pull
                >= (datetime.now() - timedelta(hours=24))
            ).count()

            # Config stats
            all_configs = db(db.client_config.id > 0).count()  # All configs
            active_configs = db(db.client_config.active == True).count()

            return {
                "domains": {"total": all_domains, "active": active_domains},
                "clients": {
                    "total": all_clients,
                    "active": active_clients,
                    "recent_checkins_24h": recent_checkins,
                    "recent_config_pulls_24h": recent_config_pulls,
                },
                "configurations": {"total": all_configs, "active": active_configs},
                "timestamp": datetime.now().isoformat(),
            }

        except Exception as e:
            logger.error(f"Failed to get client stats: {e}")
            return {}

    @_with_db
    def cleanup_inactive_clients(self, db: DB, inactive_days: int = 30) -> int:
        """Remove clients that haven't checked in for specified days."""
        try:
            cutoff_time = datetime.now() - timedelta(days=inactive_days)

            deleted = db(
                (db.client_instance.last_checkin < cutoff_time)
                | (db.client_instance.last_checkin == None)
            ).delete()

            db.commit()

            logger.info(f"Cleaned up {deleted} inactive clients")
            return deleted

        except Exception as e:
            logger.error(f"Failed to cleanup inactive clients: {e}")
            return 0
