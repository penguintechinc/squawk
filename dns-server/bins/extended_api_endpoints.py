#!/usr/bin/env python3
"""
Extended API Endpoints for Squawk DNS
Integrates all missing features with proper authentication and security.
"""

import json
import logging
from datetime import datetime
from quart import request, jsonify
from typing import Dict, Optional
from whois_manager import WHOISManager
from ioc_manager import IOCManager
from client_config_api import ClientConfigManager
from prometheus_metrics import get_metrics_instance
import hashlib

logger = logging.getLogger(__name__)


class ExtendedAPIHandler:
    """
    Handles extended API endpoints for missing GitHub issue features.
    Integrates with existing authentication and security systems.
    """

    def __init__(self, db_url: str, jwt_secret: str = None):
        self.db_url = db_url

        # Initialize feature managers
        self.whois_manager = WHOISManager(db_url)
        self.ioc_manager = IOCManager(db_url)
        self.config_manager = ClientConfigManager(db_url, jwt_secret)

        # Initialize as None, will be set by main server
        self.cert_manager = None
        self.enable_mtls = False

    def set_security_context(self, cert_manager=None, enable_mtls: bool = False):
        """Set security context from main server"""
        self.cert_manager = cert_manager
        self.enable_mtls = enable_mtls

    async def _authenticate_request(self) -> Dict:
        """
        Authenticate API request using existing server authentication system.
        Returns authentication result with token info and client certificate.
        """
        result = {
            "authenticated": False,
            "token": None,
            "token_id": None,
            "client_cert_subject": None,
            "error": None,
        }

        try:
            # Get authentication token
            auth_header = request.headers.get("X-Auth-Token") or request.headers.get(
                "Authorization"
            )
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header[7:]
            else:
                token = auth_header

            if not token:
                result["error"] = "Authentication token required"
                return result

            # Get client certificate if mTLS is enabled
            client_cert_subject = None
            if self.enable_mtls and self.cert_manager:
                client_cert_pem = request.headers.get("X-SSL-CERT")
                if client_cert_pem:
                    # Would parse certificate here in production
                    # For now, extract from header if available
                    client_cert_subject = request.headers.get("X-SSL-CERT-SUBJECT")
                elif request.headers.get("X-SSL-Client-Verify") == "SUCCESS":
                    client_cert_subject = request.headers.get("X-SSL-Client-S-DN")

            # Use existing token validation from server
            from pydal import DAL

            db = DAL(self.db_url)

            try:
                # Define tokens table
                if "tokens" not in db.tables:
                    db.define_table(
                        "tokens",
                        Field("token", "string"),
                        Field("name", "string"),
                        Field("active", "boolean"),
                        Field("last_used", "datetime"),
                        migrate=False,
                    )

                # Validate token
                token_record = (
                    db((db.tokens.token == token) & (db.tokens.active == True))
                    .select()
                    .first()
                )

                if token_record:
                    # Update last used
                    token_record.update_record(last_used=datetime.now())
                    db.commit()

                    result.update(
                        {
                            "authenticated": True,
                            "token": token,
                            "token_id": token_record.id,
                            "token_name": token_record.name,
                            "client_cert_subject": client_cert_subject,
                        }
                    )
                else:
                    result["error"] = "Invalid or inactive token"

            finally:
                db.close()

        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            result["error"] = "Authentication system error"

        return result

    async def whois_lookup(self) -> tuple:
        """WHOIS lookup endpoint (Issue #17)"""
        try:
            # Authenticate request
            auth = await self._authenticate_request()
            if not auth["authenticated"]:
                return jsonify({"error": auth["error"]}), 401

            # Get query parameters
            if request.method == "GET":
                query = request.args.get("domain") or request.args.get("ip")
                query_type = "domain" if request.args.get("domain") else "ip"
                force_refresh = request.args.get("force", "false").lower() == "true"
            else:
                data = await request.get_json()
                query = data.get("query")
                query_type = data.get("type", "domain")
                force_refresh = data.get("force_refresh", False)

            if not query:
                return (
                    jsonify({"error": "Query parameter required (domain or ip)"}),
                    400,
                )

            # Get client IP for logging
            client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)

            # Perform WHOIS lookup
            if query_type == "domain":
                result = await self.whois_manager.lookup_domain(
                    query, client_ip, force_refresh
                )
            elif query_type == "ip":
                result = await self.whois_manager.lookup_ip(
                    query, client_ip, force_refresh
                )
            else:
                return (
                    jsonify({"error": "Invalid query type. Must be domain or ip"}),
                    400,
                )

            return jsonify(result), 200

        except Exception as e:
            logger.error(f"WHOIS lookup failed: {e}")
            return jsonify({"error": "WHOIS lookup failed"}), 500

    async def whois_search(self) -> tuple:
        """WHOIS search endpoint"""
        try:
            auth = await self._authenticate_request()
            if not auth["authenticated"]:
                return jsonify({"error": auth["error"]}), 401

            search_term = request.args.get("q")
            search_field = request.args.get(
                "field"
            )  # registrar, organization, nameserver, etc.
            limit = int(request.args.get("limit", "50"))

            if not search_term:
                return jsonify({"error": "Search term required (q parameter)"}), 400

            results = await self.whois_manager.search_whois(
                search_term, search_field, limit
            )

            return (
                jsonify(
                    {
                        "results": results,
                        "count": len(results),
                        "search_term": search_term,
                        "search_field": search_field,
                    }
                ),
                200,
            )

        except Exception as e:
            logger.error(f"WHOIS search failed: {e}")
            return jsonify({"error": "WHOIS search failed"}), 500

    async def ioc_check(self) -> tuple:
        """IOC check endpoint"""
        try:
            auth = await self._authenticate_request()
            if not auth["authenticated"]:
                return jsonify({"error": auth["error"]}), 401

            if request.method == "GET":
                query = request.args.get("domain") or request.args.get("ip")
                query_type = "domain" if request.args.get("domain") else "ip"
            else:
                data = await request.get_json()
                query = data.get("query")
                query_type = data.get("type", "domain")

            if not query:
                return (
                    jsonify({"error": "Query parameter required (domain or ip)"}),
                    400,
                )

            # Check IOC status
            if query_type == "domain":
                should_block, reason = await self.ioc_manager.check_domain(
                    query, auth["token_id"]
                )
            elif query_type == "ip":
                should_block, reason = await self.ioc_manager.check_ip(
                    query, auth["token_id"]
                )
            else:
                return jsonify({"error": "Invalid query type"}), 400

            return (
                jsonify(
                    {
                        "query": query,
                        "type": query_type,
                        "blocked": should_block,
                        "reason": reason,
                        "timestamp": datetime.now().isoformat(),
                    }
                ),
                200,
            )

        except Exception as e:
            logger.error(f"IOC check failed: {e}")
            return jsonify({"error": "IOC check failed"}), 500

    async def ioc_override(self) -> tuple:
        """IOC override management endpoint (Issue #16)"""
        try:
            auth = await self._authenticate_request()
            if not auth["authenticated"]:
                return jsonify({"error": auth["error"]}), 401

            if request.method == "GET":
                # Get overrides for this token
                overrides = await self.ioc_manager.get_overrides(auth["token_id"])
                return jsonify({"overrides": overrides}), 200

            elif request.method == "POST":
                # Add new override
                data = await request.get_json()

                indicator = data.get("indicator")
                indicator_type = data.get("type")  # domain, ip
                override_type = data.get("override")  # allow, block
                reason = data.get("reason", "")
                expires_at = data.get("expires_at")  # Optional expiration

                if not all([indicator, indicator_type, override_type]):
                    return (
                        jsonify(
                            {"error": "indicator, type, and override are required"}
                        ),
                        400,
                    )

                if expires_at:
                    expires_at = datetime.fromisoformat(
                        expires_at.replace("Z", "+00:00")
                    )

                success = await self.ioc_manager.add_override(
                    auth["token_id"],
                    indicator,
                    indicator_type,
                    override_type,
                    reason,
                    auth["token_name"],
                    expires_at,
                )

                if success:
                    return jsonify({"success": True, "message": "Override added"}), 200
                else:
                    return jsonify({"error": "Failed to add override"}), 500

            elif request.method == "DELETE":
                # Remove override
                data = await request.get_json()
                indicator = data.get("indicator")
                indicator_type = data.get("type")

                if not all([indicator, indicator_type]):
                    return jsonify({"error": "indicator and type are required"}), 400

                success = await self.ioc_manager.remove_override(
                    auth["token_id"], indicator, indicator_type
                )

                if success:
                    return (
                        jsonify({"success": True, "message": "Override removed"}),
                        200,
                    )
                else:
                    return (
                        jsonify({"error": "Override not found or removal failed"}),
                        500,
                    )

        except Exception as e:
            logger.error(f"IOC override operation failed: {e}")
            return jsonify({"error": "IOC override operation failed"}), 500

    async def client_config_pull(self) -> tuple:
        """Client configuration pull endpoint (Issue #10)"""
        try:
            auth = await self._authenticate_request()
            if not auth["authenticated"]:
                return jsonify({"error": auth["error"]}), 401

            # Get parameters
            client_id = request.args.get("client_id")
            domain_jwt = request.args.get("domain_jwt") or request.headers.get(
                "X-Domain-JWT"
            )

            if not all([client_id, domain_jwt]):
                return jsonify({"error": "client_id and domain_jwt are required"}), 400

            # Pull configuration with authentication
            result = self.config_manager.pull_client_config(
                client_id, domain_jwt, auth["token"], auth["client_cert_subject"]
            )

            if result["success"]:
                return jsonify(result), 200
            else:
                return jsonify(result), 400

        except Exception as e:
            logger.error(f"Client config pull failed: {e}")
            return jsonify({"error": "Configuration pull failed"}), 500

    async def client_register(self) -> tuple:
        """Client registration endpoint"""
        try:
            auth = await self._authenticate_request()
            if not auth["authenticated"]:
                return jsonify({"error": auth["error"]}), 401

            data = await request.get_json()

            client_id = data.get("client_id")
            domain_jwt = data.get("domain_jwt")
            hostname = data.get("hostname")
            ip_address = data.get("ip_address")
            client_version = data.get("client_version", "")
            os_info = data.get("os_info", "")

            if not all([client_id, domain_jwt, hostname, ip_address]):
                return (
                    jsonify(
                        {
                            "error": "client_id, domain_jwt, hostname, and ip_address are required"
                        }
                    ),
                    400,
                )

            result = self.config_manager.register_client(
                client_id,
                domain_jwt,
                hostname,
                ip_address,
                client_version,
                os_info,
                auth["token"],
                auth["client_cert_subject"],
            )

            return jsonify(result), 200 if result["success"] else 400

        except Exception as e:
            logger.error(f"Client registration failed: {e}")
            return jsonify({"error": "Client registration failed"}), 500

    async def prometheus_metrics(self) -> tuple:
        """Prometheus metrics endpoint (Issue #14)"""
        try:
            # Optional authentication for metrics (might want to allow monitoring systems)
            metrics_auth = request.headers.get("X-Metrics-Token")
            if metrics_auth:  # If provided, validate it
                auth = await self._authenticate_request()
                if not auth["authenticated"]:
                    return jsonify({"error": "Invalid metrics token"}), 401

            # Get metrics instance
            prometheus = get_metrics_instance()
            if not prometheus:
                return "# Prometheus metrics not initialized\n", "text/plain"

            # Generate metrics
            metrics_output, content_type = prometheus.get_metrics_endpoint()
            return metrics_output, content_type

        except Exception as e:
            logger.error(f"Metrics generation failed: {e}")
            return "# Error generating metrics\n", "text/plain"

    async def service_stats(self) -> tuple:
        """Combined service statistics endpoint"""
        try:
            auth = await self._authenticate_request()
            if not auth["authenticated"]:
                return jsonify({"error": auth["error"]}), 401

            # Collect stats from all services
            stats = {"timestamp": datetime.now().isoformat(), "services": {}}

            # WHOIS stats
            try:
                whois_stats = await self.whois_manager.get_stats()
                stats["services"]["whois"] = whois_stats
            except Exception as e:
                logger.error(f"Failed to get WHOIS stats: {e}")
                stats["services"]["whois"] = {"error": "Stats unavailable"}

            # IOC stats
            try:
                ioc_stats = await self.ioc_manager.get_stats()
                stats["services"]["ioc"] = ioc_stats
            except Exception as e:
                logger.error(f"Failed to get IOC stats: {e}")
                stats["services"]["ioc"] = {"error": "Stats unavailable"}

            # Client config stats
            try:
                config_stats = self.config_manager.get_client_stats()
                stats["services"]["client_config"] = config_stats
            except Exception as e:
                logger.error(f"Failed to get client config stats: {e}")
                stats["services"]["client_config"] = {"error": "Stats unavailable"}

            # Prometheus metrics summary
            try:
                prometheus = get_metrics_instance()
                if prometheus:
                    prometheus_stats = prometheus.get_current_stats()
                    stats["services"]["dns_metrics"] = prometheus_stats
            except Exception as e:
                logger.error(f"Failed to get Prometheus stats: {e}")
                stats["services"]["dns_metrics"] = {"error": "Stats unavailable"}

            return jsonify(stats), 200

        except Exception as e:
            logger.error(f"Service stats failed: {e}")
            return jsonify({"error": "Service statistics unavailable"}), 500


# Global instance
extended_api = None


def init_extended_api(db_url: str, jwt_secret: str = None) -> ExtendedAPIHandler:
    """Initialize extended API handler"""
    global extended_api
    extended_api = ExtendedAPIHandler(db_url, jwt_secret)
    return extended_api


def get_extended_api() -> Optional[ExtendedAPIHandler]:
    """Get the global extended API instance"""
    return extended_api
