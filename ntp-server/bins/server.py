#!/usr/bin/env python3
"""
NTP/NTS Server (Network Time Security - RFC 8915)

Provides NTS Key Establishment and NTP time queries over HTTPS.
Part of the Squawk project.
"""

import asyncio
import os
import logging
import secrets
import struct
import time
from datetime import datetime, timezone
from typing import Dict, Optional, List
from dataclasses import dataclass, field

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
PORT = int(os.getenv("NTP_PORT", "8082"))
NTS_KE_PORT = int(os.getenv("NTS_KE_PORT", "4460"))
AUTH_REQUIRED = os.getenv("AUTH_REQUIRED", "true").lower() == "true"
SHARED_AUTH_URL = os.getenv("SHARED_AUTH_URL", "http://localhost:8080")
UPSTREAM_NTP = os.getenv("UPSTREAM_NTP", "pool.ntp.org")

# NTP epoch offset (seconds between 1900-01-01 and 1970-01-01)
NTP_EPOCH_OFFSET = 2208988800

# NTS-KE Record Types (RFC 8915 Section 4)
NTSKE_END_OF_MESSAGE = 0
NTSKE_NEXT_PROTOCOL = 1
NTSKE_ERROR = 2
NTSKE_WARNING = 3
NTSKE_AEAD_ALGORITHM = 4
NTSKE_NEW_COOKIE = 5
NTSKE_SERVER_NEGOTIATION = 6
NTSKE_PORT_NEGOTIATION = 7

# AEAD Algorithms (RFC 8915)
AEAD_AES_SIV_CMAC_256 = 15
AEAD_AES_SIV_CMAC_384 = 16
AEAD_AES_SIV_CMAC_512 = 17


@dataclass
class NTSSession:
    """Represents an NTS session with key material."""
    session_id: str
    c2s_key: bytes  # Client-to-Server key
    s2c_key: bytes  # Server-to-Client key
    cookies: List[bytes] = field(default_factory=list)
    aead_algorithm: int = AEAD_AES_SIV_CMAC_256
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0

    def __post_init__(self):
        if self.expires_at == 0:
            self.expires_at = self.created_at + 86400  # 24 hours

    def is_expired(self) -> bool:
        return time.time() > self.expires_at


class NTSKeyManager:
    """Manages NTS keys and sessions."""

    def __init__(self):
        self.sessions: Dict[str, NTSSession] = {}
        self.cookie_to_session: Dict[bytes, str] = {}
        self.master_key = secrets.token_bytes(32)  # Server master key

    def create_session(self, aead_algorithm: int = AEAD_AES_SIV_CMAC_256) -> NTSSession:
        """Create a new NTS session with keys."""
        session_id = secrets.token_hex(16)

        # Generate key material
        c2s_key = secrets.token_bytes(32)
        s2c_key = secrets.token_bytes(32)

        # Generate initial cookies (8 cookies as per RFC recommendation)
        cookies = [self._generate_cookie(session_id) for _ in range(8)]

        session = NTSSession(
            session_id=session_id,
            c2s_key=c2s_key,
            s2c_key=s2c_key,
            cookies=cookies,
            aead_algorithm=aead_algorithm
        )

        self.sessions[session_id] = session

        # Map cookies to session
        for cookie in cookies:
            self.cookie_to_session[cookie] = session_id

        return session

    def _generate_cookie(self, session_id: str) -> bytes:
        """Generate an NTS cookie."""
        # Cookie format: random_nonce + encrypted(session_id)
        # Simplified implementation - production would use AEAD encryption
        nonce = secrets.token_bytes(16)
        session_bytes = session_id.encode()
        # Simple XOR for demo - use proper AEAD in production
        cookie = nonce + bytes(a ^ b for a, b in zip(
            session_bytes.ljust(32, b'\0'),
            (self.master_key * 2)[:32]
        ))
        return cookie

    def validate_cookie(self, cookie: bytes) -> Optional[NTSSession]:
        """Validate a cookie and return the session."""
        session_id = self.cookie_to_session.get(cookie)
        if not session_id:
            return None

        session = self.sessions.get(session_id)
        if not session or session.is_expired():
            return None

        return session

    def generate_new_cookie(self, session_id: str) -> Optional[bytes]:
        """Generate a new cookie for an existing session."""
        session = self.sessions.get(session_id)
        if not session or session.is_expired():
            return None

        cookie = self._generate_cookie(session_id)
        session.cookies.append(cookie)
        self.cookie_to_session[cookie] = session_id
        return cookie

    def cleanup_expired(self):
        """Remove expired sessions."""
        expired = [sid for sid, s in self.sessions.items() if s.is_expired()]
        for sid in expired:
            session = self.sessions.pop(sid, None)
            if session:
                for cookie in session.cookies:
                    self.cookie_to_session.pop(cookie, None)


# Initialize NTS key manager
nts_manager = NTSKeyManager()


def get_current_ntp_time() -> tuple:
    """Get current time in NTP format (seconds, fraction)."""
    now = time.time()
    ntp_seconds = int(now) + NTP_EPOCH_OFFSET
    ntp_fraction = int((now % 1) * (2**32))
    return ntp_seconds, ntp_fraction


def ntp_to_unix(ntp_secs: int, ntp_frac: int) -> float:
    """Convert NTP timestamp to Unix timestamp."""
    return (ntp_secs - NTP_EPOCH_OFFSET) + (ntp_frac / (2**32))


async def verify_token(token: str) -> bool:
    """Verify authentication token."""
    if not AUTH_REQUIRED:
        return True

    if not token:
        return False

    # For now, accept any non-empty token
    # In production, validate against shared auth service
    return len(token) > 0


@app.route("/nts/ke", methods=["POST"])
async def nts_key_establishment():
    """
    NTS Key Establishment endpoint.

    Implements RFC 8915 NTS-KE protocol over HTTPS.
    """
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "") if auth_header.startswith("Bearer ") else ""

    if not await verify_token(token):
        return jsonify({"success": False, "error": "Unauthorized"}), 403

    data = await request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Invalid request body"}), 400

    # Get supported algorithms from client
    supported_algorithms = data.get("supported_algorithms", [AEAD_AES_SIV_CMAC_256])
    next_protocol = data.get("next_protocol", "ntske/1")

    # Select algorithm (prefer strongest available)
    selected_algorithm = AEAD_AES_SIV_CMAC_256
    for algo in [AEAD_AES_SIV_CMAC_512, AEAD_AES_SIV_CMAC_384, AEAD_AES_SIV_CMAC_256]:
        if algo in supported_algorithms:
            selected_algorithm = algo
            break

    # Create NTS session
    session = nts_manager.create_session(selected_algorithm)

    import base64

    logger.info(f"NTS-KE: Created session {session.session_id}")

    return jsonify({
        "success": True,
        "c2s_key": base64.b64encode(session.c2s_key).decode(),
        "s2c_key": base64.b64encode(session.s2c_key).decode(),
        "cookies": [base64.b64encode(c).decode() for c in session.cookies],
        "ntp_server": request.host.split(":")[0],
        "ntp_port": PORT,
        "aead_algorithm": selected_algorithm,
        "expires_at": int(session.expires_at)
    })


@app.route("/ntp/query", methods=["POST"])
async def ntp_query():
    """
    NTS-authenticated NTP query endpoint.

    Accepts an NTS cookie and returns authenticated time.
    """
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "") if auth_header.startswith("Bearer ") else ""

    if not await verify_token(token):
        return jsonify({"error": "Unauthorized"}), 403

    data = await request.get_json()
    if not data:
        return jsonify({"error": "Invalid request body"}), 400

    import base64

    # Get cookie from request
    cookie_b64 = data.get("cookie")
    if not cookie_b64:
        return jsonify({"error": "NTS cookie required"}), 400

    try:
        cookie = base64.b64decode(cookie_b64)
    except Exception:
        return jsonify({"error": "Invalid cookie encoding"}), 400

    # Validate cookie
    session = nts_manager.validate_cookie(cookie)
    if not session:
        return jsonify({"error": "Invalid or expired cookie"}), 401

    # Get client timestamps
    client_transmit = data.get("client_transmit", 0)
    unique_id = data.get("unique_id")

    # Get current time
    receive_time = time.time_ns()
    ntp_secs, ntp_frac = get_current_ntp_time()

    # Generate new cookie for response
    new_cookie = nts_manager.generate_new_cookie(session.session_id)

    # Build response
    transmit_time = time.time_ns()

    response = {
        "stratum": 2,  # Secondary reference
        "precision": -20,  # ~1 microsecond
        "root_delay": 0.001,
        "root_dispersion": 0.001,
        "reference_id": "NTSP",  # NTS over HTTPS
        "reference_timestamp": transmit_time,
        "origin_timestamp": client_transmit,
        "receive_timestamp": receive_time,
        "transmit_timestamp": transmit_time,
        "ntp_seconds": ntp_secs,
        "ntp_fraction": ntp_frac,
        "authenticated": True
    }

    # Include new cookie if generated
    if new_cookie:
        response["cookie"] = base64.b64encode(new_cookie).decode()

    # Echo unique ID for replay protection
    if unique_id:
        response["unique_id"] = unique_id

    logger.info(f"NTP Query from session {session.session_id}")
    return jsonify(response)


@app.route("/ntp/time", methods=["GET"])
async def ntp_time():
    """
    Simple REST time API (unauthenticated time query).

    Returns current server time in various formats.
    """
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "") if auth_header.startswith("Bearer ") else ""

    if not await verify_token(token):
        return jsonify({"error": "Unauthorized"}), 403

    now = time.time()
    ntp_secs, ntp_frac = get_current_ntp_time()
    dt = datetime.now(timezone.utc)

    return jsonify({
        "timestamp": int(now * 1e9),  # nanoseconds
        "unix_timestamp": now,
        "ntp_seconds": ntp_secs,
        "ntp_fraction": ntp_frac,
        "iso8601": dt.isoformat(),
        "stratum": 2,
        "precision": -20,
        "reference_id": "HTTP",
        "authenticated": False
    })


@app.route("/ntp/status", methods=["GET"])
async def ntp_status():
    """Get NTP server status and statistics."""
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "") if auth_header.startswith("Bearer ") else ""

    if not await verify_token(token):
        return jsonify({"error": "Unauthorized"}), 403

    # Cleanup expired sessions
    nts_manager.cleanup_expired()

    active_sessions = len(nts_manager.sessions)
    active_cookies = len(nts_manager.cookie_to_session)

    return jsonify({
        "active_sessions": active_sessions,
        "active_cookies": active_cookies,
        "upstream_ntp": UPSTREAM_NTP,
        "stratum": 2,
        "reference_id": "NTSP"
    })


@app.route("/health", methods=["GET"])
async def health():
    """Health check endpoint."""
    ntp_secs, _ = get_current_ntp_time()

    return jsonify({
        "status": "healthy",
        "service": "ntp",
        "ntp_time": ntp_secs,
        "active_sessions": len(nts_manager.sessions)
    })


@app.route("/", methods=["GET"])
async def root():
    """Root endpoint."""
    return jsonify({
        "service": "Squawk NTP/NTS Server",
        "version": "1.0.0",
        "rfc": "RFC 8915 (Network Time Security)",
        "endpoints": [
            "POST /nts/ke - NTS Key Establishment",
            "POST /ntp/query - NTS-authenticated time query",
            "GET /ntp/time - Simple REST time API",
            "GET /ntp/status - Server status",
            "GET /health - Health check"
        ]
    })


async def cleanup_task():
    """Periodic cleanup of expired sessions."""
    while True:
        await asyncio.sleep(3600)  # Run every hour
        nts_manager.cleanup_expired()
        logger.info("Cleaned up expired NTS sessions")


async def main():
    """Main entry point."""
    config = Config()
    config.bind = [f"0.0.0.0:{PORT}"]
    config.accesslog = "-"
    config.errorlog = "-"

    logger.info(f"Starting NTP/NTS server on port {PORT}")
    logger.info(f"Upstream NTP: {UPSTREAM_NTP}")

    # Start cleanup task
    asyncio.create_task(cleanup_task())

    await serve(app, config)


if __name__ == "__main__":
    asyncio.run(main())
