#!/usr/bin/env python3
"""
DHCP-over-HTTPS Server

Provides DHCP lease management over secure HTTPS connections.
Part of the Squawk project.
"""

import asyncio
import os
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional

from quart import Quart, request, jsonify
from hypercorn.asyncio import serve
from hypercorn.config import Config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Quart(__name__)

# Configuration from environment
PORT = int(os.getenv("DHCP_PORT", "8081"))
AUTH_REQUIRED = os.getenv("AUTH_REQUIRED", "true").lower() == "true"
SHARED_AUTH_URL = os.getenv("SHARED_AUTH_URL", "http://localhost:8080")

# DHCP Pool configuration
POOL_SUBNET = os.getenv("DHCP_POOL_SUBNET", "192.168.1.0/24")
POOL_START = os.getenv("DHCP_POOL_START", "192.168.1.100")
POOL_END = os.getenv("DHCP_POOL_END", "192.168.1.200")
GATEWAY = os.getenv("DHCP_GATEWAY", "192.168.1.1")
DNS_SERVERS = os.getenv("DHCP_DNS_SERVERS", "8.8.8.8,8.8.4.4").split(",")
LEASE_TIME = int(os.getenv("DHCP_LEASE_TIME", "86400"))  # seconds


class DHCPPool:
    """Manages DHCP IP address pool."""

    def __init__(self, start_ip: str, end_ip: str, gateway: str,
                 dns_servers: list, subnet_mask: str = "255.255.255.0"):
        self.start_ip = start_ip
        self.end_ip = end_ip
        self.gateway = gateway
        self.dns_servers = dns_servers
        self.subnet_mask = subnet_mask
        self.available_ips = self._generate_ip_range(start_ip, end_ip)
        self.leases: Dict[str, dict] = {}  # MAC -> lease
        self.ip_to_mac: Dict[str, str] = {}  # IP -> MAC

    def _generate_ip_range(self, start: str, end: str) -> list:
        """Generate list of available IP addresses."""
        import ipaddress
        start_int = int(ipaddress.IPv4Address(start))
        end_int = int(ipaddress.IPv4Address(end))
        return [str(ipaddress.IPv4Address(ip)) for ip in range(start_int, end_int + 1)]

    def get_offer(self, mac: str, hostname: str = None,
                  requested_ip: str = None) -> Optional[dict]:
        """Create a DHCP offer for a client."""
        # Check if client already has a lease
        if mac in self.leases:
            lease = self.leases[mac]
            if not self._is_expired(lease):
                return self._create_offer(lease["ip"], mac)

        # Check if requested IP is available
        if requested_ip and requested_ip in self.available_ips:
            return self._create_offer(requested_ip, mac)

        # Find an available IP
        for ip in self.available_ips:
            if ip not in self.ip_to_mac:
                return self._create_offer(ip, mac)

        return None  # No IPs available

    def _create_offer(self, ip: str, mac: str) -> dict:
        """Create an offer response."""
        import uuid
        return {
            "status": "offer",
            "offered_ip": ip,
            "subnet_mask": self.subnet_mask,
            "gateway": self.gateway,
            "dns_servers": self.dns_servers,
            "lease_time": LEASE_TIME,
            "server_id": self.gateway,
            "transaction_id": str(uuid.uuid4())[:8]
        }

    def create_lease(self, mac: str, ip: str, hostname: str = None) -> dict:
        """Create or renew a lease."""
        now = datetime.utcnow()
        lease = {
            "mac_address": mac,
            "ip": ip,
            "hostname": hostname,
            "subnet_mask": self.subnet_mask,
            "gateway": self.gateway,
            "dns_servers": self.dns_servers,
            "lease_time": LEASE_TIME,
            "renewal_time": LEASE_TIME // 2,
            "rebinding_time": int(LEASE_TIME * 0.875),
            "lease_start": now.isoformat(),
            "lease_end": (now + timedelta(seconds=LEASE_TIME)).isoformat(),
            "status": "active"
        }

        # Clean up old lease if exists
        if mac in self.leases:
            old_ip = self.leases[mac]["ip"]
            if old_ip in self.ip_to_mac:
                del self.ip_to_mac[old_ip]

        self.leases[mac] = lease
        self.ip_to_mac[ip] = mac

        return {
            "status": "ack",
            "assigned_ip": ip,
            "subnet_mask": self.subnet_mask,
            "gateway": self.gateway,
            "dns_servers": self.dns_servers,
            "lease_time": LEASE_TIME,
            "renewal_time": LEASE_TIME // 2,
            "rebinding_time": int(LEASE_TIME * 0.875)
        }

    def release_lease(self, mac: str, ip: str = None) -> bool:
        """Release a lease."""
        if mac not in self.leases:
            return False

        lease = self.leases[mac]
        if ip and lease["ip"] != ip:
            return False

        lease_ip = lease["ip"]
        del self.leases[mac]
        if lease_ip in self.ip_to_mac:
            del self.ip_to_mac[lease_ip]

        return True

    def get_lease(self, mac: str) -> Optional[dict]:
        """Get lease for a MAC address."""
        if mac not in self.leases:
            return None

        lease = self.leases[mac]
        if self._is_expired(lease):
            self.release_lease(mac)
            return None

        return lease

    def _is_expired(self, lease: dict) -> bool:
        """Check if a lease is expired."""
        lease_end = datetime.fromisoformat(lease["lease_end"])
        return datetime.utcnow() > lease_end

    def get_stats(self) -> dict:
        """Get pool statistics."""
        active = sum(1 for l in self.leases.values() if not self._is_expired(l))
        total = len(self.available_ips)
        return {
            "active": active,
            "available": total - active,
            "total": total
        }


# Initialize DHCP pool
dhcp_pool = DHCPPool(
    start_ip=POOL_START,
    end_ip=POOL_END,
    gateway=GATEWAY,
    dns_servers=DNS_SERVERS
)


async def verify_token(token: str) -> bool:
    """Verify authentication token."""
    if not AUTH_REQUIRED:
        return True

    if not token:
        return False

    # For now, accept any non-empty token
    # In production, validate against shared auth service
    return len(token) > 0


@app.route("/dhcp/discover", methods=["POST"])
async def dhcp_discover():
    """Handle DHCP Discover request."""
    # Verify authentication
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "") if auth_header.startswith("Bearer ") else ""

    if not await verify_token(token):
        return jsonify({"status": "error", "message": "Unauthorized"}), 403

    data = await request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "Invalid request body"}), 400

    mac = data.get("mac_address")
    if not mac:
        return jsonify({"status": "error", "message": "MAC address required"}), 400

    hostname = data.get("hostname")
    requested_ip = data.get("requested_ip")

    offer = dhcp_pool.get_offer(mac, hostname, requested_ip)
    if not offer:
        return jsonify({
            "status": "error",
            "message": "No IP addresses available"
        }), 503

    logger.info(f"DHCP Discover from {mac}: offering {offer['offered_ip']}")
    return jsonify(offer)


@app.route("/dhcp/request", methods=["POST"])
async def dhcp_request():
    """Handle DHCP Request."""
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "") if auth_header.startswith("Bearer ") else ""

    if not await verify_token(token):
        return jsonify({"status": "error", "message": "Unauthorized"}), 403

    data = await request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "Invalid request body"}), 400

    mac = data.get("mac_address")
    requested_ip = data.get("requested_ip")

    if not mac or not requested_ip:
        return jsonify({
            "status": "nak",
            "error_message": "MAC address and requested IP required"
        }), 400

    # Validate the requested IP is available or already assigned to this client
    existing = dhcp_pool.get_lease(mac)
    if existing and existing["ip"] != requested_ip:
        # Client is requesting different IP
        return jsonify({
            "status": "nak",
            "error_message": "Requested IP not available"
        })

    ack = dhcp_pool.create_lease(mac, requested_ip, data.get("hostname"))
    logger.info(f"DHCP Request from {mac}: assigned {requested_ip}")
    return jsonify(ack)


@app.route("/dhcp/release", methods=["POST"])
async def dhcp_release():
    """Handle DHCP Release."""
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "") if auth_header.startswith("Bearer ") else ""

    if not await verify_token(token):
        return jsonify({"status": "error", "message": "Unauthorized"}), 403

    data = await request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "Invalid request body"}), 400

    mac = data.get("mac_address")
    client_ip = data.get("client_ip")

    if not mac:
        return jsonify({"success": False, "message": "MAC address required"}), 400

    success = dhcp_pool.release_lease(mac, client_ip)
    logger.info(f"DHCP Release from {mac}: {'success' if success else 'not found'}")

    return jsonify({
        "success": success,
        "message": "Lease released" if success else "Lease not found"
    })


@app.route("/dhcp/config", methods=["GET"])
async def dhcp_config():
    """Get DHCP configuration for a client (REST API config pull)."""
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "") if auth_header.startswith("Bearer ") else ""

    if not await verify_token(token):
        return jsonify({"status": "error", "message": "Unauthorized"}), 403

    mac = request.args.get("mac")
    if not mac:
        return jsonify({"status": "error", "message": "MAC address required"}), 400

    lease = dhcp_pool.get_lease(mac)
    if not lease:
        return jsonify({"status": "not_found"}), 404

    return jsonify({
        "assigned_ip": lease["ip"],
        "subnet_mask": lease["subnet_mask"],
        "gateway": lease["gateway"],
        "dns_servers": lease["dns_servers"],
        "lease_time": lease["lease_time"],
        "renewal_time": lease["renewal_time"],
        "lease_start": int(datetime.fromisoformat(lease["lease_start"]).timestamp()),
        "lease_end": int(datetime.fromisoformat(lease["lease_end"]).timestamp()),
        "status": lease["status"]
    })


@app.route("/dhcp/lease/<mac>", methods=["GET"])
async def get_lease(mac: str):
    """Get current lease for MAC address."""
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "") if auth_header.startswith("Bearer ") else ""

    if not await verify_token(token):
        return jsonify({"status": "error", "message": "Unauthorized"}), 403

    lease = dhcp_pool.get_lease(mac)
    if not lease:
        return jsonify({"status": "not_found"}), 404

    return jsonify(lease)


@app.route("/dhcp/leases", methods=["GET"])
async def list_leases():
    """List all active leases (admin only)."""
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "") if auth_header.startswith("Bearer ") else ""

    if not await verify_token(token):
        return jsonify({"status": "error", "message": "Unauthorized"}), 403

    leases = list(dhcp_pool.leases.values())
    return jsonify({"leases": leases, "count": len(leases)})


@app.route("/health", methods=["GET"])
async def health():
    """Health check endpoint."""
    stats = dhcp_pool.get_stats()
    return jsonify({
        "status": "healthy",
        "service": "dhcp",
        "active_leases": stats["active"],
        "available_ips": stats["available"],
        "total_ips": stats["total"]
    })


@app.route("/", methods=["GET"])
async def root():
    """Root endpoint."""
    return jsonify({
        "service": "Squawk DHCP-over-HTTPS Server",
        "version": "1.0.0",
        "endpoints": [
            "POST /dhcp/discover",
            "POST /dhcp/request",
            "POST /dhcp/release",
            "GET /dhcp/config",
            "GET /dhcp/lease/<mac>",
            "GET /dhcp/leases",
            "GET /health"
        ]
    })


async def main():
    """Main entry point."""
    config = Config()
    config.bind = [f"0.0.0.0:{PORT}"]
    config.accesslog = "-"
    config.errorlog = "-"

    logger.info(f"Starting DHCP-over-HTTPS server on port {PORT}")
    logger.info(f"Pool: {POOL_START} - {POOL_END}, Gateway: {GATEWAY}")

    await serve(app, config)


if __name__ == "__main__":
    asyncio.run(main())
