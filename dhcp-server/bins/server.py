#!/usr/bin/env python3
"""
DHCP-over-HTTPS Server (Production-Grade)

Provides DHCP lease management over secure HTTPS connections.
Uses penguin-dal for persistent storage, JWT HS256 for auth, PostHog for feature flags.
Part of the Squawk project.
"""

import asyncio
import logging
import sys
import structlog
from datetime import datetime, timedelta
from typing import Tuple, Dict, Any

from quart import Quart, request, jsonify
from hypercorn.asyncio import serve
from hypercorn.config import Config

from app.config import (
    DHCP_PORT,
    DATABASE_URL,
    JWT_SECRET_KEY,
    POOL_START,
    POOL_END,
    GATEWAY,
    DNS_SERVERS,
    LEASE_TIME,
    LOG_LEVEL,
    POSTHOG_KEY,
    POSTHOG_HOST,
    validate_config,
)
from app.auth import check_auth
from app.db import DHCPDatabase
from app.models import DHCPOffer, DHCPAck


# Configure structured logging
def _configure_logging() -> None:
    """Configure structlog for structured logging."""
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL), format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


_configure_logging()
logger = structlog.get_logger(__name__)

# Validate config at module load time
validate_config()

# Initialize Quart app
app = Quart(__name__)

# Initialize database
db = DHCPDatabase()

# PostHog client (lazy-loaded)
posthog_client = None


def get_posthog_client():
    """Get or create PostHog client. Returns None if not configured."""
    global posthog_client
    if posthog_client is None and POSTHOG_KEY:
        try:
            from posthog import Posthog

            posthog_client = Posthog(api_key=POSTHOG_KEY, host=POSTHOG_HOST)
        except Exception as e:
            logger.error("posthog_init_failed", error=str(e))
            return None
    return posthog_client


def is_feature_enabled(flag_key: str, user_id: str = "dhcp-server") -> bool:
    """
    Check if feature flag is enabled via PostHog.
    Graceful degradation: defaults to False if PostHog unavailable.

    Args:
        flag_key: Feature flag key (e.g., 'squawkdns.dhcp-server')
        user_id: User/context ID for flag evaluation

    Returns:
        True if flag enabled, False otherwise (default OFF)
    """
    try:
        ph = get_posthog_client()
        if not ph:
            logger.warning("posthog_not_configured", flag=flag_key)
            return False

        enabled = ph.feature_enabled(flag_key, user_id)
        logger.info("feature_flag_evaluated", flag=flag_key, enabled=enabled)
        return enabled
    except Exception as e:
        logger.error("feature_flag_error", flag=flag_key, error=str(e))
        return False


async def expire_leases_task() -> None:
    """Background task to expire old leases periodically."""
    while True:
        try:
            await asyncio.sleep(60)  # Run every 60 seconds

            # For now, use default pool_id=1
            # In production, would query all pools
            count = db.expire_old_leases(pool_id=1)
            if count > 0:
                logger.info("leases_expired", count=count)
        except Exception as e:
            logger.error("expire_leases_task_error", error=str(e))


@app.before_serving
async def startup() -> None:
    """Initialize DHCP server on startup."""
    logger.info(
        "dhcp_server_starting",
        port=DHCP_PORT,
        pool_start=POOL_START,
        pool_end=POOL_END,
        gateway=GATEWAY,
        database=DATABASE_URL,
    )

    if not JWT_SECRET_KEY:
        logger.critical("jwt_secret_key_missing")
        # Server will return 500 on all protected endpoints

    # Start background tasks
    app.add_background_task(expire_leases_task)

    logger.info("dhcp_server_started")


@app.after_serving
async def shutdown() -> None:
    """Cleanup on shutdown."""
    db.close()
    ph = get_posthog_client()
    if ph:
        ph.shutdown()
    logger.info("dhcp_server_shutdown")


def _error_response(status_code: int, message: str) -> Tuple[Dict[str, Any], int]:
    """Create error response."""
    return jsonify({"status": "error", "message": message}), status_code


def _jwt_error_response(status_code: int) -> Tuple[Dict[str, Any], int]:
    """Create JWT error response."""
    if not JWT_SECRET_KEY:
        logger.error("jwt_auth_disabled")
        return jsonify({"status": "error", "message": "Server misconfigured"}), 500

    msg = "Unauthorized" if status_code == 403 else "Invalid or expired token"
    return jsonify({"status": "error", "message": msg}), status_code


@app.route("/dhcp/discover", methods=["POST"])
async def dhcp_discover() -> Tuple[Dict[str, Any], int]:
    """
    Handle DHCP Discover request.
    Requires dhcp:read scope.
    """
    # Feature flag check
    if not is_feature_enabled("squawkdns.dhcp-server"):
        logger.warning("dhcp_service_disabled")
        return jsonify({"status": "error", "message": "Service unavailable"}), 503

    # Auth check
    auth_header = request.headers.get("Authorization", "")
    status_code, payload = check_auth(auth_header, "dhcp:read")
    if status_code != 200:
        return _jwt_error_response(status_code)

    # Parse request
    data = await request.get_json()
    if not data:
        return _error_response(400, "Invalid request body")

    mac = data.get("mac_address")
    if not mac:
        return _error_response(400, "MAC address required")

    hostname = data.get("hostname")
    requested_ip = data.get("requested_ip")

    # Get available IP (pool_id=1 for now)
    pool_id = 1
    offered_ip = db.get_offer(pool_id, mac, requested_ip)

    if not offered_ip:
        logger.warning("no_ips_available", mac=mac)
        return jsonify({"status": "error", "message": "No IP addresses available"}), 503

    # Create offer
    import uuid

    offer = DHCPOffer(
        status="offer",
        offered_ip=offered_ip,
        subnet_mask="255.255.255.0",
        gateway=GATEWAY,
        dns_servers=DNS_SERVERS,
        lease_time=LEASE_TIME,
        server_id=GATEWAY,
        transaction_id=str(uuid.uuid4())[:8],
    )

    logger.info("dhcp_offer_created", mac=mac, offered_ip=offered_ip)
    return jsonify(
        {
            "status": offer.status,
            "offered_ip": offer.offered_ip,
            "subnet_mask": offer.subnet_mask,
            "gateway": offer.gateway,
            "dns_servers": offer.dns_servers,
            "lease_time": offer.lease_time,
            "server_id": offer.server_id,
            "transaction_id": offer.transaction_id,
        }
    )


@app.route("/dhcp/request", methods=["POST"])
async def dhcp_request() -> Tuple[Dict[str, Any], int]:
    """
    Handle DHCP Request.
    Requires dhcp:read scope.
    """
    # Feature flag check
    if not is_feature_enabled("squawkdns.dhcp-server"):
        return jsonify({"status": "error", "message": "Service unavailable"}), 503

    # Auth check
    auth_header = request.headers.get("Authorization", "")
    status_code, payload = check_auth(auth_header, "dhcp:read")
    if status_code != 200:
        return _jwt_error_response(status_code)

    # Parse request
    data = await request.get_json()
    if not data:
        return _error_response(400, "Invalid request body")

    mac = data.get("mac_address")
    requested_ip = data.get("requested_ip")

    if not mac or not requested_ip:
        return _error_response(400, "MAC address and requested IP required")

    # Create/renew lease
    pool_id = 1
    lease = db.create_lease(pool_id, mac, requested_ip, data.get("hostname"))

    ack = DHCPAck(
        status="ack",
        assigned_ip=lease.ip_address,
        subnet_mask=lease.subnet_mask,
        gateway=lease.gateway,
        dns_servers=lease.dns_servers,
        lease_time=lease.lease_time,
        renewal_time=lease.renewal_time,
        rebinding_time=lease.rebinding_time,
    )

    logger.info("dhcp_lease_created", mac=mac, ip=requested_ip)
    return jsonify(
        {
            "status": ack.status,
            "assigned_ip": ack.assigned_ip,
            "subnet_mask": ack.subnet_mask,
            "gateway": ack.gateway,
            "dns_servers": ack.dns_servers,
            "lease_time": ack.lease_time,
            "renewal_time": ack.renewal_time,
            "rebinding_time": ack.rebinding_time,
        }
    )


@app.route("/dhcp/release", methods=["POST"])
async def dhcp_release() -> Tuple[Dict[str, Any], int]:
    """
    Handle DHCP Release.
    Requires dhcp:read scope.
    """
    # Feature flag check
    if not is_feature_enabled("squawkdns.dhcp-server"):
        return jsonify({"status": "error", "message": "Service unavailable"}), 503

    # Auth check
    auth_header = request.headers.get("Authorization", "")
    status_code, payload = check_auth(auth_header, "dhcp:read")
    if status_code != 200:
        return _jwt_error_response(status_code)

    # Parse request
    data = await request.get_json()
    if not data:
        return _error_response(400, "Invalid request body")

    mac = data.get("mac_address")
    if not mac:
        return _error_response(400, "MAC address required")

    # Release lease
    pool_id = 1
    success = db.release_lease(pool_id, mac)

    logger.info("dhcp_lease_released", mac=mac, success=success)
    return jsonify({"success": success, "message": "Lease released" if success else "Lease not found"})


@app.route("/dhcp/config", methods=["GET"])
async def dhcp_config() -> Tuple[Dict[str, Any], int]:
    """
    Get DHCP configuration for a client (REST API config pull).
    Requires dhcp:read scope.
    """
    # Feature flag check
    if not is_feature_enabled("squawkdns.dhcp-server"):
        return jsonify({"status": "error", "message": "Service unavailable"}), 503

    # Auth check
    auth_header = request.headers.get("Authorization", "")
    status_code, payload = check_auth(auth_header, "dhcp:read")
    if status_code != 200:
        return _jwt_error_response(status_code)

    # Get MAC from query params
    mac = request.args.get("mac")
    if not mac:
        return _error_response(400, "MAC address required")

    # Get lease
    pool_id = 1
    lease = db.get_lease(pool_id, mac)
    if not lease:
        return jsonify({"status": "not_found"}), 404

    logger.info("dhcp_config_requested", mac=mac)
    return jsonify(
        {
            "assigned_ip": lease.ip_address,
            "subnet_mask": lease.subnet_mask,
            "gateway": lease.gateway,
            "dns_servers": lease.dns_servers,
            "lease_time": lease.lease_time,
            "renewal_time": lease.renewal_time,
            "rebinding_time": lease.rebinding_time,
            "lease_start": int(lease.lease_start.timestamp()),
            "lease_end": int(lease.lease_end.timestamp()),
            "status": lease.status,
        }
    )


@app.route("/dhcp/lease/<mac>", methods=["GET"])
async def get_lease(mac: str) -> Tuple[Dict[str, Any], int]:
    """
    Get current lease for MAC address.
    Requires dhcp:read scope.
    """
    # Feature flag check
    if not is_feature_enabled("squawkdns.dhcp-server"):
        return jsonify({"status": "error", "message": "Service unavailable"}), 503

    # Auth check
    auth_header = request.headers.get("Authorization", "")
    status_code, payload = check_auth(auth_header, "dhcp:read")
    if status_code != 200:
        return _jwt_error_response(status_code)

    # Get lease
    pool_id = 1
    lease = db.get_lease(pool_id, mac)
    if not lease:
        return jsonify({"status": "not_found"}), 404

    logger.info("dhcp_lease_queried", mac=mac)
    return jsonify(
        {
            "mac_address": lease.mac_address,
            "ip_address": lease.ip_address,
            "hostname": lease.hostname,
            "lease_start": int(lease.lease_start.timestamp()),
            "lease_end": int(lease.lease_end.timestamp()),
            "status": lease.status,
            "subnet_mask": lease.subnet_mask,
            "gateway": lease.gateway,
            "dns_servers": lease.dns_servers,
        }
    )


@app.route("/dhcp/leases", methods=["GET"])
async def list_leases() -> Tuple[Dict[str, Any], int]:
    """
    List all active leases (admin only).
    Requires dhcp:admin scope.
    """
    # Feature flag check
    if not is_feature_enabled("squawkdns.dhcp-server"):
        return jsonify({"status": "error", "message": "Service unavailable"}), 503

    # Auth check (requires admin scope)
    auth_header = request.headers.get("Authorization", "")
    status_code, payload = check_auth(auth_header, "dhcp:admin")
    if status_code != 200:
        return _jwt_error_response(status_code)

    # Get pool stats
    pool_id = 1
    active, available, total = db.get_pool_stats(pool_id)

    logger.info("dhcp_leases_listed", active=active, available=available, total=total)
    return jsonify({"active_leases": active, "available_ips": available, "total_ips": total})


@app.route("/health", methods=["GET"])
async def health() -> Tuple[Dict[str, Any], int]:
    """Health check endpoint (no auth required)."""
    pool_id = 1
    active, available, total = db.get_pool_stats(pool_id)

    return jsonify(
        {
            "status": "healthy",
            "service": "dhcp",
            "active_leases": active,
            "available_ips": available,
            "total_ips": total,
        }
    )


@app.route("/", methods=["GET"])
async def root() -> Tuple[Dict[str, Any], int]:
    """Root endpoint (no auth required)."""
    return jsonify(
        {
            "service": "Squawk DHCP-over-HTTPS Server",
            "version": "2.0.0",
            "endpoints": [
                "POST /dhcp/discover (requires dhcp:read)",
                "POST /dhcp/request (requires dhcp:read)",
                "POST /dhcp/release (requires dhcp:read)",
                "GET /dhcp/config?mac= (requires dhcp:read)",
                "GET /dhcp/lease/<mac> (requires dhcp:read)",
                "GET /dhcp/leases (requires dhcp:admin)",
                "GET /health",
                "GET /",
            ],
        }
    )


async def main() -> None:
    """Main entry point."""
    config = Config()
    config.bind = [f"0.0.0.0:{DHCP_PORT}"]
    config.accesslog = "-"
    config.errorlog = "-"

    logger.info("dhcp_server_main", port=DHCP_PORT)

    try:
        await serve(app, config)
    except KeyboardInterrupt:
        logger.info("dhcp_server_interrupted")
    finally:
        db.close()
        logger.info("dhcp_server_stopped")


if __name__ == "__main__":
    asyncio.run(main())
