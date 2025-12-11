#!/usr/bin/env python3
"""
Client Configuration API for Squawk DNS
Implements Issue #10: Client pulls configuration from server
Allows clients to retrieve their configuration from the server via API
"""

import json
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from pydal import DAL, Field
import jwt
import secrets

logger = logging.getLogger(__name__)


class ClientConfigManager:
    """
    Manages client configurations that can be pulled from the server.
    Features:
    - JWT-based client authentication
    - Per-client configuration profiles
    - Deployment domain grouping
    - Role-based access (Client-Reader, Client-Maintainer)
    - Configuration versioning and rollback
    """

    def __init__(self, db_url: str, jwt_secret: str = None):
        self.db_url = db_url
        self.jwt_secret = jwt_secret or secrets.token_urlsafe(32)
        self._init_database()

    def _init_database(self):
        """Initialize client configuration database schema"""
        db = DAL(self.db_url)

        # Deployment domains (client groupings)
        db.define_table(
            "deployment_domains",
            Field("name", "string", unique=True),
            Field("description", "text"),
            Field("jwt_token", "string", unique=True),  # 32-bit JWT for this domain
            Field("jwt_expires", "datetime"),
            Field("created_at", "datetime", default=datetime.now),
            Field("active", "boolean", default=True),
            migrate=True,
        )

        # Client configuration profiles
        db.define_table(
            "client_configs",
            Field("name", "string"),
            Field("domain_id", "reference deployment_domains"),
            Field("config_data", "json"),  # Full client configuration
            Field("version", "integer", default=1),
            Field("description", "text"),
            Field("created_by", "string"),
            Field("created_at", "datetime", default=datetime.now),
            Field("active", "boolean", default=True),
            migrate=True,
        )

        # Client configuration access roles
        db.define_table(
            "config_roles",
            Field("name", "string", unique=True),  # Client-Reader, Client-Maintainer
            Field("permissions", "json"),  # List of permissions
            Field("description", "text"),
            Field("created_at", "datetime", default=datetime.now),
            migrate=True,
        )

        # User role assignments for client config
        db.define_table(
            "config_user_roles",
            Field("user_token_id", "reference tokens"),
            Field("role_id", "reference config_roles"),
            Field(
                "domain_id", "reference deployment_domains"
            ),  # Can be null for global access
            Field("granted_by", "string"),
            Field("granted_at", "datetime", default=datetime.now),
            migrate=True,
        )

        # Client instances (registered clients)
        db.define_table(
            "client_instances",
            Field("client_id", "string", unique=True),
            Field("domain_id", "reference deployment_domains"),
            Field("config_id", "reference client_configs"),
            Field("hostname", "string"),
            Field("ip_address", "string"),
            Field("last_checkin", "datetime"),
            Field("last_config_pull", "datetime"),
            Field("client_version", "string"),
            Field("os_info", "string"),
            Field("status", "string", default="active"),  # active, inactive, error
            Field("registered_at", "datetime", default=datetime.now),
            migrate=True,
        )

        # Configuration change history
        db.define_table(
            "config_history",
            Field("config_id", "reference client_configs"),
            Field("version", "integer"),
            Field("config_data", "json"),
            Field("change_description", "text"),
            Field("changed_by", "string"),
            Field("changed_at", "datetime", default=datetime.now),
            migrate=True,
        )

        # Create default roles
        self._create_default_roles(db)

        db.commit()
        db.close()

    def _create_default_roles(self, db: DAL):
        """Create default configuration roles"""
        default_roles = [
            {
                "name": "Client-Reader",
                "permissions": ["read_config", "pull_config"],
                "description": "Can read and pull client configurations",
            },
            {
                "name": "Client-Maintainer",
                "permissions": [
                    "read_config",
                    "pull_config",
                    "update_config",
                    "create_config",
                ],
                "description": "Can read, pull, update, and create client configurations",
            },
            {
                "name": "Domain-Admin",
                "permissions": [
                    "read_config",
                    "pull_config",
                    "update_config",
                    "create_config",
                    "manage_clients",
                    "rollover_jwt",
                ],
                "description": "Full administrative access to deployment domain",
            },
        ]

        for role in default_roles:
            existing = db(db.config_roles.name == role["name"]).select().first()
            if not existing:
                db.config_roles.insert(**role)

    def create_deployment_domain(
        self, name: str, description: str = "", created_by: str = ""
    ) -> Dict:
        """Create a new deployment domain with JWT token"""
        db = DAL(self.db_url)

        try:
            # Generate JWT token for this domain
            domain_jwt = self._generate_domain_jwt(name)

            domain_id = db.deployment_domains.insert(
                name=name,
                description=description,
                jwt_token=domain_jwt,
                jwt_expires=datetime.now() + timedelta(days=365),  # 1 year expiry
            )

            db.commit()

            return {
                "id": domain_id,
                "name": name,
                "jwt_token": domain_jwt,
                "success": True,
            }

        except Exception as e:
            logger.error(f"Failed to create deployment domain: {e}")
            return {"success": False, "error": str(e)}
        finally:
            db.close()

    def _generate_domain_jwt(self, domain_name: str) -> str:
        """Generate JWT token for deployment domain"""
        payload = {
            "domain": domain_name,
            "type": "deployment_domain",
            "issued_at": datetime.now().timestamp(),
            "expires_at": (datetime.now() + timedelta(days=365)).timestamp(),
        }

        return jwt.encode(payload, self.jwt_secret, algorithm="HS256")

    def rollover_domain_jwt(self, domain_id: int, admin_user: str) -> Dict:
        """Generate new JWT token for deployment domain"""
        db = DAL(self.db_url)

        try:
            domain = db(db.deployment_domains.id == domain_id).select().first()
            if not domain:
                return {"success": False, "error": "Domain not found"}

            # Generate new JWT
            new_jwt = self._generate_domain_jwt(domain.name)

            # Update domain
            domain.update_record(
                jwt_token=new_jwt, jwt_expires=datetime.now() + timedelta(days=365)
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
        finally:
            db.close()

    def create_client_config(
        self,
        name: str,
        domain_id: int,
        config_data: Dict,
        description: str = "",
        created_by: str = "",
    ) -> Dict:
        """Create a new client configuration"""
        db = DAL(self.db_url)

        try:
            # Validate config_data
            if not self._validate_config_data(config_data):
                return {"success": False, "error": "Invalid configuration data"}

            config_id = db.client_configs.insert(
                name=name,
                domain_id=domain_id,
                config_data=config_data,
                description=description,
                created_by=created_by,
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
        finally:
            db.close()

    def update_client_config(
        self,
        config_id: int,
        config_data: Dict,
        description: str = "",
        changed_by: str = "",
    ) -> Dict:
        """Update an existing client configuration"""
        db = DAL(self.db_url)

        try:
            config = db(db.client_configs.id == config_id).select().first()
            if not config:
                return {"success": False, "error": "Configuration not found"}

            # Validate config_data
            if not self._validate_config_data(config_data):
                return {"success": False, "error": "Invalid configuration data"}

            # Increment version
            new_version = config.version + 1

            # Update config
            config.update_record(
                config_data=config_data, version=new_version, description=description
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
        finally:
            db.close()

    def _validate_config_data(self, config_data: Dict) -> bool:
        """Validate client configuration data structure"""
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

    def register_client(
        self,
        client_id: str,
        domain_jwt: str,
        hostname: str,
        ip_address: str,
        client_version: str = "",
        os_info: str = "",
        user_token: str = None,
        client_cert_subject: str = None,
    ) -> Dict:
        """Register a new client instance"""
        db = DAL(self.db_url)

        try:
            # Verify user authentication if provided
            if user_token:
                auth_result = self._verify_user_token(
                    db, user_token, client_cert_subject
                )
                if not auth_result["valid"]:
                    return {
                        "success": False,
                        "error": f'Authentication failed: {auth_result["reason"]}',
                    }

            # Verify JWT token
            domain = self._verify_domain_jwt(domain_jwt)
            if not domain:
                return {"success": False, "error": "Invalid or expired JWT token"}

            # Check if client already exists
            existing = db(db.client_instances.client_id == client_id).select().first()
            if existing:
                # Update existing client
                existing.update_record(
                    hostname=hostname,
                    ip_address=ip_address,
                    last_checkin=datetime.now(),
                    client_version=client_version,
                    os_info=os_info,
                    status="active",
                )
                client_record_id = existing.id
            else:
                # Register new client
                client_record_id = db.client_instances.insert(
                    client_id=client_id,
                    domain_id=domain["id"],
                    hostname=hostname,
                    ip_address=ip_address,
                    last_checkin=datetime.now(),
                    client_version=client_version,
                    os_info=os_info,
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
        finally:
            db.close()

    def _verify_domain_jwt(self, jwt_token: str) -> Optional[Dict]:
        """Verify domain JWT token and return domain info"""
        db = DAL(self.db_url)

        try:
            # Decode JWT
            payload = jwt.decode(jwt_token, self.jwt_secret, algorithms=["HS256"])

            # Check if token is expired
            expires_at = payload.get("expires_at")
            if expires_at and datetime.now().timestamp() > expires_at:
                return None

            domain_name = payload.get("domain")
            if not domain_name:
                return None

            # Find domain in database
            domain = (
                db(
                    (db.deployment_domains.name == domain_name)
                    & (db.deployment_domains.jwt_token == jwt_token)
                    & (db.deployment_domains.active == True)
                )
                .select()
                .first()
            )

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
        finally:
            db.close()

        return None

    def _verify_user_token(
        self, db: DAL, user_token: str, client_cert_subject: str = None
    ) -> Dict:
        """Verify user authentication token with optional mTLS certificate validation"""
        try:
            # Define tokens table if not already defined
            if "tokens" not in db.tables:
                db.define_table(
                    "tokens",
                    Field("token", "string"),
                    Field("name", "string"),
                    Field("active", "boolean"),
                    Field("last_used", "datetime"),
                    migrate=False,
                )

            # Check if token exists and is active
            token_record = (
                db((db.tokens.token == user_token) & (db.tokens.active == True))
                .select()
                .first()
            )

            if not token_record:
                return {"valid": False, "reason": "Invalid or inactive token"}

            # If mTLS is enabled, verify client certificate matches token
            if client_cert_subject:
                # Extract CN from certificate subject
                cert_cn = self._extract_cn_from_subject(client_cert_subject)
                if cert_cn and cert_cn != token_record.name:
                    return {
                        "valid": False,
                        "reason": "Certificate subject does not match token",
                    }

            # Update last used timestamp
            token_record.update_record(last_used=datetime.now())

            return {
                "valid": True,
                "token_id": token_record.id,
                "token_name": token_record.name,
            }

        except Exception as e:
            logger.error(f"User token verification failed: {e}")
            return {"valid": False, "reason": "Token verification error"}

    def _extract_cn_from_subject(self, subject_dn: str) -> Optional[str]:
        """Extract Common Name from certificate subject DN"""
        try:
            # Parse subject DN format: "CN=client-name,O=organization,..."
            parts = subject_dn.split(",")
            for part in parts:
                part = part.strip()
                if part.startswith("CN="):
                    return part[3:]  # Remove "CN=" prefix
        except Exception:
            pass
        return None

    def _check_config_permission(
        self, db: DAL, token_id: int, domain_id: int, permission: str
    ) -> bool:
        """Check if user has specific permission for configuration management"""
        try:
            # Get user's roles for this domain (or global roles)
            user_roles = db(
                (db.config_user_roles.user_token_id == token_id)
                & (
                    (db.config_user_roles.domain_id == domain_id)
                    | (db.config_user_roles.domain_id == None)
                )
                & (db.config_roles.id == db.config_user_roles.role_id)
            ).select(db.config_roles.permissions)

            for role in user_roles:
                if permission in role.permissions:
                    return True

            return False

        except Exception as e:
            logger.error(f"Permission check failed: {e}")
            return False

    def pull_client_config(
        self,
        client_id: str,
        domain_jwt: str,
        user_token: str = None,
        client_cert_subject: str = None,
    ) -> Dict:
        """Pull configuration for a client with proper authentication and security"""
        db = DAL(self.db_url)

        try:
            # First, verify user authentication token if provided
            if user_token:
                auth_result = self._verify_user_token(
                    db, user_token, client_cert_subject
                )
                if not auth_result["valid"]:
                    return {
                        "success": False,
                        "error": f'Authentication failed: {auth_result["reason"]}',
                    }

            # Verify JWT token for domain access
            domain = self._verify_domain_jwt(domain_jwt)
            if not domain:
                return {"success": False, "error": "Invalid or expired JWT token"}

            # Check if user has permission to pull config for this domain
            if user_token:
                has_permission = self._check_config_permission(
                    db, auth_result["token_id"], domain["id"], "pull_config"
                )
                if not has_permission:
                    return {
                        "success": False,
                        "error": "Insufficient permissions to pull configuration",
                    }

            # Find client instance
            client = (
                db(
                    (db.client_instances.client_id == client_id)
                    & (db.client_instances.domain_id == domain["id"])
                    & (db.client_instances.status == "active")
                )
                .select()
                .first()
            )

            if not client:
                return {"success": False, "error": "Client not registered"}

            # Get client configuration
            config = None
            if client.config_id:
                # Client has specific config assigned
                config = (
                    db(
                        (db.client_configs.id == client.config_id)
                        & (db.client_configs.active == True)
                    )
                    .select()
                    .first()
                )
            else:
                # Use default config for domain
                config = (
                    db(
                        (db.client_configs.domain_id == domain["id"])
                        & (db.client_configs.name == "default")
                        & (db.client_configs.active == True)
                    )
                    .select()
                    .first()
                )

            if not config:
                return {"success": False, "error": "No configuration available"}

            # Update client last config pull time
            client.update_record(
                last_config_pull=datetime.now(), last_checkin=datetime.now()
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
        finally:
            db.close()

    def assign_config_to_client(
        self, client_id: str, config_id: int, assigned_by: str = ""
    ) -> Dict:
        """Assign a specific configuration to a client"""
        db = DAL(self.db_url)

        try:
            client = db(db.client_instances.client_id == client_id).select().first()
            if not client:
                return {"success": False, "error": "Client not found"}

            config = db(db.client_configs.id == config_id).select().first()
            if not config:
                return {"success": False, "error": "Configuration not found"}

            # Update client config assignment
            client.update_record(config_id=config_id)

            db.commit()

            logger.info(
                f"Config {config.name} assigned to client {client_id} by {assigned_by}"
            )

            return {"success": True}

        except Exception as e:
            logger.error(f"Failed to assign config to client: {e}")
            return {"success": False, "error": str(e)}
        finally:
            db.close()

    def get_domain_clients(self, domain_id: int) -> List[Dict]:
        """Get all clients in a deployment domain"""
        db = DAL(self.db_url)

        try:
            clients = db(db.client_instances.domain_id == domain_id).select()

            result = []
            for client in clients:
                config_name = None
                if client.config_id:
                    config = (
                        db(db.client_configs.id == client.config_id).select().first()
                    )
                    if config:
                        config_name = config.name

                result.append(
                    {
                        "client_id": client.client_id,
                        "hostname": client.hostname,
                        "ip_address": client.ip_address,
                        "last_checkin": (
                            client.last_checkin.isoformat()
                            if client.last_checkin
                            else None
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
                    }
                )

            return result

        except Exception as e:
            logger.error(f"Failed to get domain clients: {e}")
            return []
        finally:
            db.close()

    def get_client_stats(self) -> Dict:
        """Get client configuration statistics"""
        db = DAL(self.db_url)

        try:
            # Domain statistics
            total_domains = db(db.deployment_domains).count()
            active_domains = db(db.deployment_domains.active == True).count()

            # Client statistics
            total_clients = db(db.client_instances).count()
            active_clients = db(db.client_instances.status == "active").count()

            # Recent activity
            recent_checkins = db(
                db.client_instances.last_checkin
                >= (datetime.now() - timedelta(hours=24))
            ).count()

            recent_config_pulls = db(
                db.client_instances.last_config_pull
                >= (datetime.now() - timedelta(hours=24))
            ).count()

            # Configuration statistics
            total_configs = db(db.client_configs).count()
            active_configs = db(db.client_configs.active == True).count()

            return {
                "domains": {"total": total_domains, "active": active_domains},
                "clients": {
                    "total": total_clients,
                    "active": active_clients,
                    "recent_checkins_24h": recent_checkins,
                    "recent_config_pulls_24h": recent_config_pulls,
                },
                "configurations": {"total": total_configs, "active": active_configs},
                "timestamp": datetime.now().isoformat(),
            }

        except Exception as e:
            logger.error(f"Failed to get client stats: {e}")
            return {}
        finally:
            db.close()

    def cleanup_inactive_clients(self, inactive_days: int = 30) -> int:
        """Remove clients that haven't checked in for specified days"""
        db = DAL(self.db_url)

        try:
            cutoff_time = datetime.now() - timedelta(days=inactive_days)

            deleted = db(
                (db.client_instances.last_checkin < cutoff_time)
                | (db.client_instances.last_checkin == None)
            ).delete()

            db.commit()

            logger.info(f"Cleaned up {deleted} inactive clients")
            return deleted

        except Exception as e:
            logger.error(f"Failed to cleanup inactive clients: {e}")
            return 0
        finally:
            db.close()
