#!/usr/bin/env python3
"""
Production-Grade NTP/NTS Server (RFC 8915 Compliant)

Provides RFC 8915 Network Time Security with:
- NTS-KE (Key Establishment) server using RFC 5705 TLS exporter
- Real AEAD-sealed cookies using AES-SIV-CMAC-256
- Authenticated NTPv4 queries over UDP with NTS extension fields
- JWT-based access control (HS256)
- Feature flag integration (PostHog)

Part of the Squawk project.
"""

from __future__ import annotations

import asyncio
import os
import struct
import time
import secrets
import socket
import logging
import hmac
import jwt
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Dict, List, Tuple
from enum import IntEnum

from quart import Quart, request, jsonify
from hypercorn.asyncio import serve
from hypercorn.config import Config
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from OpenSSL import SSL
import posthog

# Structured logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# ============================================================================
# Configuration
# ============================================================================

PORT = int(os.getenv("NTP_PORT", "8082"))
NTS_KE_PORT = int(os.getenv("NTS_KE_PORT", "4460"))
UDP_PORT = int(os.getenv("NTP_UDP_PORT", "123"))

TLS_CERT_FILE = os.getenv("TLS_CERT_FILE")
TLS_KEY_FILE = os.getenv("TLS_KEY_FILE")
# TLS cert/key optional for testing; required at startup
if TLS_CERT_FILE and TLS_KEY_FILE:
    TLS_ENABLED = True
else:
    TLS_ENABLED = False

# JWT configuration (asymmetric: ES256 default, RS256 fallback)
def _load_jwt_public_key() -> Optional[str]:
    """Load JWT public key from env var or file."""
    key = os.getenv("JWT_PUBLIC_KEY")
    if key:
        return key
    key_file = os.getenv("JWT_PUBLIC_KEY_FILE")
    if key_file and os.path.isfile(key_file):
        with open(key_file, 'r') as f:
            return f.read().strip()
    return None


def _compute_kid_from_public_pem(public_pem: str) -> str:
    """Compute kid (key ID) as first 16 hex chars of SHA-256 over DER SubjectPublicKeyInfo."""
    import hashlib
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    public_key = serialization.load_pem_public_key(public_pem.encode(), default_backend())
    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    sha256_hash = hashlib.sha256(der_bytes).digest()
    return sha256_hash.hex()[:16]


def _load_jwt_public_keys_from_directory() -> Dict[str, str]:
    """Load multiple PEM keys from a directory (for key rotation overlap)."""
    keys: Dict[str, str] = {}
    dir_path = os.getenv("JWT_PUBLIC_KEYS_DIR")
    if not dir_path or not os.path.isdir(dir_path):
        return keys
    try:
        for filename in os.listdir(dir_path):
            if filename.endswith('.pem'):
                filepath = os.path.join(dir_path, filename)
                if os.path.isfile(filepath):
                    with open(filepath, 'r') as f:
                        pem_content = f.read().strip()
                        if pem_content:
                            try:
                                kid = _compute_kid_from_public_pem(pem_content)
                                keys[kid] = pem_content
                            except Exception:
                                pass
    except Exception:
        pass
    return keys


JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "ES256")
JWT_ISSUER = os.getenv("JWT_ISSUER", "squawk-manager")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "squawk")
JWT_PUBLIC_KEY = _load_jwt_public_key()
JWT_PUBLIC_KEYS = _load_jwt_public_keys_from_directory()

POSTHOG_KEY = os.getenv("POSTHOG_KEY", "")
POSTHOG_HOST = os.getenv("POSTHOG_HOST", "")

# Initialize PostHog (optional)
if POSTHOG_KEY and POSTHOG_HOST:
    posthog.api_key = POSTHOG_KEY
    posthog.host = POSTHOG_HOST
else:
    posthog.disabled = True

# NTP epoch offset
NTP_EPOCH_OFFSET = 2208988800

# ============================================================================
# RFC 8915 Constants
# ============================================================================


class NTSKERecordType(IntEnum):
    """NTS-KE record types (RFC 8915 §4.1.1)."""

    END_OF_MESSAGE = 0
    NEXT_PROTOCOL = 1
    ERROR = 2
    WARNING = 3
    AEAD_ALGORITHM = 4
    NEW_COOKIE = 5
    SERVER_NEGOTIATION = 6
    PORT_NEGOTIATION = 7
    # Private/experimental range (RFC 8915 §4.1.1 / IANA registry: 16384-32767).
    # Squawk-specific: carries a Bearer JWT so NTS-KE can enforce the
    # ntp:client scope before issuing cookies -- RFC 8915 has no native
    # per-client auth concept beyond the TLS channel itself.
    SQUAWK_AUTH_TOKEN = 16384


class AEADAlgorithm(IntEnum):
    """AEAD algorithms (RFC 8915 §4.1.3)."""

    AEAD_AES_SIV_CMAC_256 = 15
    AEAD_AES_SIV_CMAC_384 = 16
    AEAD_AES_SIV_CMAC_512 = 17


class NTPExtensionField(IntEnum):
    """NTP extension field types (RFC 8915 §5.7)."""

    UNIQUE_IDENTIFIER = 0x0104
    NTS_COOKIE = 0x0204
    COOKIE_PLACEHOLDER = 0x0304
    NTS_AUTHENTICATOR = 0x0404
    NTS_EF_ENCRYPTED = 0x0504


# ============================================================================
# Data Classes
# ============================================================================


@dataclass(slots=True, frozen=True)
class KeyMaterial:
    """Derived key material from TLS exporter."""

    c2s_key: bytes
    s2c_key: bytes
    aead_id: int
    expiry: float


@dataclass(slots=True)
class NTSCookie:
    """Sealed NTS cookie with plaintext metadata."""

    sealed: bytes  # AEAD-encrypted key material
    version: int  # Master key version for rotation
    created_at: float = field(default_factory=time.time)
    expiry: float = field(default_factory=lambda: time.time() + 86400)

    def is_expired(self) -> bool:
        return time.time() > self.expiry


@dataclass(slots=True)
class NTSSession:
    """In-memory NTS session (temporary, ephemeral)."""

    c2s_key: bytes
    s2c_key: bytes
    aead_id: int
    created_at: float = field(default_factory=time.time)
    expiry: float = field(default_factory=lambda: time.time() + 3600)

    def is_expired(self) -> bool:
        return time.time() > self.expiry


@dataclass(slots=True)
class NTPPacket:
    """Parsed NTP packet with extension fields."""

    version: int
    mode: int
    stratum: int
    poll: int
    precision: int
    root_delay: float
    root_dispersion: float
    reference_id: int
    reference_timestamp: float
    origin_timestamp: float
    receive_timestamp: float
    transmit_timestamp: float
    extension_fields: Dict[int, bytes] = field(default_factory=dict)


# ============================================================================
# NTS-KE Record Encoding/Decoding (RFC 8915 §4.1.2)
# ============================================================================


class NTSKERecord:
    """RFC 8915 NTS-KE record encoding/decoding."""

    @staticmethod
    def encode(record_type: int, body: bytes, critical: bool = False) -> bytes:
        """
        Encode a single NTS-KE record.

        Format: 16-bit (Critical|Type) + 16-bit Body Length + Body (padded to 4 bytes)
        Critical bit is MSB of the Type field.

        Args:
            record_type: Record type (0-32767)
            body: Record body
            critical: If True, set the critical bit (MSB of type field)

        Returns:
            Encoded record (with padding to 4-byte boundary)
        """
        # Critical bit (1) + Record Type (15 bits)
        if critical:
            type_field = (1 << 15) | record_type
        else:
            type_field = record_type

        # Body length (not including header, not including padding)
        body_len = len(body)

        # Total length including 4-byte header, padded to 4-byte boundary
        total_len = 4 + body_len
        if total_len % 4 != 0:
            total_len += 4 - (total_len % 4)

        # Padding
        padding = total_len - 4 - body_len

        record = struct.pack("!HH", type_field, body_len)
        record += body
        if padding:
            record += b"\x00" * padding

        return record

    @staticmethod
    def decode(data: bytes, offset: int = 0) -> Optional[Tuple[int, bytes, int, bool]]:
        """
        Decode a single NTS-KE record from data stream.

        Returns: (record_type, body, next_offset, critical_bit) or None if invalid
        """
        if offset + 4 > len(data):
            return None

        type_field, body_len = struct.unpack("!HH", data[offset : offset + 4])
        critical = bool(type_field & (1 << 15))
        record_type = type_field & 0x7FFF

        if offset + 4 + body_len > len(data):
            return None

        body = data[offset + 4 : offset + 4 + body_len]

        # Calculate padded length
        total_len = 4 + body_len
        if total_len % 4 != 0:
            total_len += 4 - (total_len % 4)

        return (record_type, body, offset + total_len, critical)

    @staticmethod
    def parse_all(data: bytes) -> List[Tuple[int, bytes, bool]]:
        """Parse all records from NTS-KE message stream."""
        records = []
        offset = 0
        while offset < len(data):
            result = NTSKERecord.decode(data, offset)
            if result is None:
                break
            record_type, body, next_offset, critical = result
            records.append((record_type, body, critical))
            offset = next_offset
        return records


# ============================================================================
# Cookie Manager (Real AEAD)
# ============================================================================


class CookieManager:
    """
    Manages NTS cookies with real AEAD encryption.

    Master key rotation: holds current and previous key version for grace period.
    """

    def __init__(self):
        self.master_key_version = 0
        self.master_keys: Dict[int, bytes] = {0: secrets.token_bytes(32)}  # Current AES-SIV key (32 bytes)
        self.previous_key_expires_at = time.time() + 3600  # Grace period: 1 hour

    def seal_cookie(self, c2s_key: bytes, s2c_key: bytes, aead_id: int) -> NTSCookie:
        """
        Seal key material into a cookie using AES-SIV.

        Plaintext format: c2s_key || s2c_key || aead_id (2 bytes) || expiry (8 bytes, unix timestamp)
        AAD (authenticated, not encrypted): version byte
        """
        expiry = int(time.time() + 86400)
        plaintext = c2s_key + s2c_key + struct.pack("!HQ", int(aead_id), expiry)
        aad = struct.pack("!B", self.master_key_version)

        cipher = AESSIV(self.master_keys[self.master_key_version])
        # Note: AESSIV.encrypt(plaintext, associated_data) - AAD is required for the tag
        sealed = cipher.encrypt(plaintext, [aad])

        return NTSCookie(sealed=sealed, version=self.master_key_version, expiry=float(expiry))

    def unseal_cookie(self, cookie: NTSCookie) -> Optional[Tuple[bytes, bytes, int]]:
        """
        Unseal a cookie to recover key material.

        Returns: (c2s_key, s2c_key, aead_id) or None if decryption fails.
        """
        # Try current key version
        if cookie.version in self.master_keys:
            try:
                aad = struct.pack("!B", cookie.version)
                cipher = AESSIV(self.master_keys[cookie.version])
                plaintext = cipher.decrypt(cookie.sealed, [aad])

                # Parse plaintext: 32 bytes c2s + 32 bytes s2c + 2 bytes aead_id + 8 bytes expiry
                c2s_key = plaintext[:32]
                s2c_key = plaintext[32:64]
                aead_id, expiry = struct.unpack("!HQ", plaintext[64:74])

                # Check expiry
                if time.time() > expiry:
                    logger.warning("Cookie unsealing: expired cookie")
                    return None

                return (c2s_key, s2c_key, aead_id)
            except Exception as e:
                logger.warning(f"Cookie unsealing failed: {e}")
                return None

        return None

    def wire_encode(self, cookie: NTSCookie) -> bytes:
        """
        Encode a cookie for the wire: 2-byte length prefix || version byte
        || AEAD ciphertext.

        Two problems this fixes at once:
        1. The master-key version is never part of the AEAD ciphertext, so
           without carrying it a returned cookie can't be matched back to
           the key generation it was sealed under once ``rotate_key`` runs.
        2. NTP extension-field framing (RFC 7822) zero-pads the EF body to a
           4-byte boundary. AES-SIV-CMAC-256 cookies seal to a length that
           is *never* 4-aligned (74-byte plaintext -> 90-byte ciphertext),
           so every cookie sent in an EF picks up 2 bytes of trailing zero
           padding. AES-SIV authenticates the exact ciphertext bytes, so
           that padding makes ``unseal_cookie`` fail unconditionally unless
           the receiver knows the true (unpadded) length to strip it.
        """
        body = struct.pack("!B", cookie.version) + cookie.sealed
        return struct.pack("!H", len(body)) + body

    def wire_decode(self, data: bytes) -> Optional[NTSCookie]:
        """Recover version + sealed ciphertext from wire-format cookie bytes,
        stripping any EF-alignment padding via the embedded length prefix."""
        if len(data) < 3:
            return None
        (body_len,) = struct.unpack("!H", data[:2])
        body = data[2 : 2 + body_len]
        if len(body) != body_len:
            return None
        return NTSCookie(sealed=body[1:], version=body[0])

    def rotate_key(self) -> None:
        """Rotate master key (deprecate old key after grace period)."""
        # Deprecate old version after grace period
        if time.time() > self.previous_key_expires_at:
            old_version = self.master_key_version - 1
            if old_version in self.master_keys and old_version >= 0:
                del self.master_keys[old_version]
                logger.info(f"Deprecated old master key version {old_version}")

        # Create new current key
        self.master_key_version += 1
        self.master_keys[self.master_key_version] = secrets.token_bytes(32)
        self.previous_key_expires_at = time.time() + 3600
        logger.info(f"Rotated master key to version {self.master_key_version}")


# ============================================================================
# JWT Validation
# ============================================================================


def verify_jwt(token: str, required_scope: Optional[str] = None) -> bool:
    """
    Verify ES256/RS256 JWT and optionally check scope.
    Supports kid-based key selection for rotation overlap.

    Args:
        token: Bearer token
        required_scope: Optional scope (e.g., "ntp:client", "ntp:admin")

    Returns:
        True if valid, False otherwise. Fail closed if no public key configured.
    """
    if not token:
        return False

    # Decode header to extract kid (without verifying signature yet)
    try:
        header = jwt.get_unverified_header(token)
    except Exception:
        logger.warning("JWT verification: failed to extract header")
        return False

    kid = header.get('kid')

    # Determine which key(s) to try
    keys_to_try: Dict[Optional[str], str] = {}

    if kid:
        # Token has kid: must match in JWT_PUBLIC_KEYS (if provided)
        if JWT_PUBLIC_KEYS and kid in JWT_PUBLIC_KEYS:
            keys_to_try[kid] = JWT_PUBLIC_KEYS[kid]
        else:
            # Kid present but not found: reject (unknown key)
            logger.warning(f"JWT verification: unknown kid '{kid}'")
            return False
    else:
        # Token has no kid: try all keys (backward compat during rotation)
        if JWT_PUBLIC_KEYS:
            keys_to_try = JWT_PUBLIC_KEYS.copy()
        else:
            # Fall back to single JWT_PUBLIC_KEY
            public_key = os.getenv("JWT_PUBLIC_KEY")
            if not public_key:
                # Try loading from file
                key_file = os.getenv("JWT_PUBLIC_KEY_FILE")
                if key_file and os.path.isfile(key_file):
                    with open(key_file, 'r') as f:
                        public_key = f.read().strip()
            if not public_key:
                logger.warning("JWT verification: JWT_PUBLIC_KEY not configured")
                return False
            keys_to_try[None] = public_key

    # Try each key until one succeeds
    for _kid_val, key in keys_to_try.items():
        if not key:
            continue
        try:
            payload = jwt.decode(
                token,
                key,
                algorithms=["ES256", "RS256"],
                audience=JWT_AUDIENCE,
                issuer=JWT_ISSUER,
                options={"require": ["exp", "iat", "tenant"]}
            )

            # Fail closed: tenant claim must be present and non-empty
            if not payload.get('tenant'):
                logger.warning("JWT verification: token missing or empty tenant claim")
                return False

            # Check scope if required
            if required_scope:
                scopes = payload.get("scope", "").split()
                if required_scope not in scopes:
                    logger.warning(f"JWT verification: missing scope {required_scope}")
                    return False

            return True
        except (jwt.InvalidSignatureError, jwt.DecodeError):
            # Signature mismatch is expected when trying multiple keys
            if kid:
                logger.warning(f"JWT verification: signature verification failed for kid '{kid}'")
                return False
            # For no-kid tokens, continue to try other keys
            continue
        except jwt.ExpiredSignatureError:
            logger.warning("JWT verification: token expired")
            return False
        except Exception as e:
            logger.warning(f"JWT verification failed: {e}")
            return False

    # No keys succeeded
    if kid:
        logger.warning(f"JWT verification: token signature verification failed for kid '{kid}'")
    else:
        logger.warning("JWT verification: token signature verification failed with all available keys")
    return False


def _extract_nts_ke_auth_token(client_request: bytes) -> Optional[str]:
    """
    Extract the Squawk Bearer-JWT auth record from an NTS-KE client request.

    Returns the decoded token string, or None if no SQUAWK_AUTH_TOKEN record
    is present or its body isn't valid UTF-8.
    """
    try:
        records = NTSKERecord.parse_all(client_request)
    except Exception:
        return None
    for record_type, body, _critical in records:
        if record_type == NTSKERecordType.SQUAWK_AUTH_TOKEN:
            try:
                token = body.decode("utf-8").strip()
            except UnicodeDecodeError:
                return None
            return token or None
    return None


# ============================================================================
# NTS-KE Server (RFC 8915 §4)
# ============================================================================


class NTSKEServer:
    """
    RFC 8915 NTS Key Establishment server.

    Runs a standalone TLS server on port 4460 using pyOpenSSL.
    Uses RFC 5705 TLS exporter to derive AEAD keys.
    """

    def __init__(self, cert_file: str, key_file: str, port: int = 4460):
        self.cert_file = cert_file
        self.key_file = key_file
        self.port = port
        self.cookie_manager = CookieManager()

    def create_tls_context(self) -> SSL.Context:
        """Create OpenSSL TLS context with ALPN."""
        ctx = SSL.Context(SSL.TLS_SERVER_METHOD)
        ctx.set_verify(SSL.VERIFY_NONE, lambda *_: True)  # Don't verify client certs
        ctx.use_certificate_file(self.cert_file)
        ctx.use_privatekey_file(self.key_file)
        # RFC 8915 §3 mandates TLS 1.3+ for NTS-KE; OP_NO_TLSv1/1_1 alone
        # still permitted TLS 1.2 negotiation.
        ctx.set_min_proto_version(SSL.TLS1_3_VERSION)

        # Set ALPN protocol
        try:
            ctx.set_alpn_protos([b"ntske/1"])
        except AttributeError:
            logger.warning("ALPN not supported; proceeding without it")

        return ctx

    async def handle_client(self, conn: SSL.Connection, addr: Tuple) -> None:
        """
        Handle NTS-KE client connection.

        Implements NTS-KE protocol:
        1. Receive NTS-KE request records (client capabilities)
        2. Perform TLS exporter key derivation (RFC 5705)
        3. Send NTS-KE response records (selected algorithm, cookies, server address)
        """
        try:
            logger.info(f"NTS-KE client connected: {addr}")

            # Receive client request (NTS-KE records)
            client_request = conn.recv(4096)
            if not client_request:
                logger.warning("Empty NTS-KE client request")
                return

            # Parse NTS-KE client request (simplified: assume raw record stream)
            # Production: proper record parsing
            logger.debug(f"NTS-KE client request size: {len(client_request)} bytes")

            # RFC 8915 has no native per-client auth beyond the TLS channel;
            # Squawk requires an ntp:client-scoped JWT (carried in a private
            # SQUAWK_AUTH_TOKEN record) before issuing any cookies. Reject
            # and close rather than fail open.
            token = _extract_nts_ke_auth_token(client_request)
            if not token or not verify_jwt(token, required_scope="ntp:client"):
                logger.warning(f"NTS-KE rejected: missing/invalid ntp:client JWT from {addr}")
                error_response = NTSKERecord.encode(NTSKERecordType.ERROR, struct.pack("!H", 1), critical=True)
                error_response += NTSKERecord.encode(NTSKERecordType.END_OF_MESSAGE, b"", critical=True)
                try:
                    conn.send(error_response)
                except OSError:
                    pass
                return

            # For now, assume client sends supported AEAD algorithms
            # Production: parse NTS-KE request records
            selected_aead = AEADAlgorithm.AEAD_AES_SIV_CMAC_256

            # ========================================================================
            # RFC 5705 Key Exporter (CRITICAL)
            # ========================================================================
            # Label: "EXPORTER-network-time-security"
            # Context per key:
            #   [Next Protocol=0x0000 (2 bytes, NTPv4)]
            #   [AEAD ID (2 bytes, e.g., 0x000F for AES-SIV-CMAC-256)]
            #   [C2S=0x00 / S2C=0x01 (1 byte)]
            # Key length: 32 bytes for AES-SIV-CMAC-256
            # ========================================================================

            label = b"EXPORTER-network-time-security"
            keylen = 32  # AES-SIV-CMAC-256

            # C2S context: Next Proto (0x0000) + AEAD ID + 0x00
            c2s_context = struct.pack("!HHB", 0x0000, selected_aead, 0x00)
            # S2C context: Next Proto (0x0000) + AEAD ID + 0x01
            s2c_context = struct.pack("!HHB", 0x0000, selected_aead, 0x01)

            try:
                c2s_key = conn.export_keying_material(label, keylen, c2s_context)
                s2c_key = conn.export_keying_material(label, keylen, s2c_context)

                if not c2s_key or not s2c_key or len(c2s_key) != keylen or len(s2c_key) != keylen:
                    logger.error(
                        f"Key exporter returned invalid key length: c2s={len(c2s_key) if c2s_key else 0}, s2c={len(s2c_key) if s2c_key else 0}"
                    )
                    conn.send(b"ERROR: Key export failed")
                    return

                logger.info(f"NTS-KE derived keys: c2s={len(c2s_key)} bytes, s2c={len(s2c_key)} bytes")

                # Generate 8 cookies (RFC 8915 recommendation)
                cookies = []
                for _ in range(8):
                    cookie = self.cookie_manager.seal_cookie(c2s_key, s2c_key, selected_aead)
                    cookies.append(cookie)

                # Build NTS-KE response (simplified)
                response = self._build_nts_ke_response(selected_aead, cookies)

                conn.send(response)
                logger.info(f"NTS-KE response sent to {addr}")

            except Exception as e:
                logger.error(f"TLS exporter failed: {e}")
                conn.send(b"ERROR: Key export failed")
                return

        except Exception as e:
            logger.error(f"NTS-KE client handling failed: {e}")
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _build_nts_ke_response(self, aead_id: int, cookies: List[NTSCookie]) -> bytes:
        """
        Build NTS-KE response per RFC 8915 §4.1.2.

        Response contains:
        1. NTS Next Protocol Negotiation (type 1): protocol 0 = NTPv4
        2. AEAD Algorithm Negotiation (type 4): algorithm ID (15 = AES-SIV-CMAC-256)
        3. New Cookie for NTPv4 (type 5): one per cookie
        4. End of Message (type 0, critical)
        """
        response = b""

        # Record 1: NTS Next Protocol Negotiation (type 1, CRITICAL).
        # RFC 8915 §4.1.5: the Critical Bit of this record MUST be set. Strict
        # clients (ntpsec, chrony) reject a response whose Next Protocol record
        # is non-critical, so this bit is required for wire interop.
        # Body: 16-bit protocol ID (0 = NTPv4)
        next_proto_body = struct.pack("!H", 0)  # NTPv4
        response += NTSKERecord.encode(NTSKERecordType.NEXT_PROTOCOL, next_proto_body, critical=True)

        # Record 2: AEAD Algorithm Negotiation (type 4, not critical)
        # Body: 16-bit algorithm ID
        aead_body = struct.pack("!H", aead_id)
        response += NTSKERecord.encode(NTSKERecordType.AEAD_ALGORITHM, aead_body, critical=False)

        # Record 3: New Cookies (type 5, not critical) - one per cookie
        # Wire-encoded (version byte || sealed) so a returned cookie can be
        # unsealed against the correct master-key generation after rotation.
        for cookie in cookies:
            response += NTSKERecord.encode(
                NTSKERecordType.NEW_COOKIE, self.cookie_manager.wire_encode(cookie), critical=False
            )

        # Record 4: End of Message (type 0, CRITICAL per RFC 8915 §4.1.1)
        response += NTSKERecord.encode(NTSKERecordType.END_OF_MESSAGE, b"", critical=True)

        return response

    async def run(self) -> None:
        """Run NTS-KE TLS server."""
        ctx = self.create_tls_context()
        loop = asyncio.get_event_loop()

        # Create server socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("0.0.0.0", self.port))
        server_socket.listen(5)
        server_socket.setblocking(False)

        logger.info(f"NTS-KE server listening on port {self.port}")

        try:
            while True:
                try:
                    client_socket, addr = await loop.sock_accept(server_socket)
                    conn = SSL.Connection(ctx, client_socket)
                    conn.set_accept_state()

                    # Handle client in background
                    asyncio.create_task(self.handle_client(conn, addr))
                except BlockingIOError:
                    await asyncio.sleep(0.1)
        except Exception as e:
            logger.error(f"NTS-KE server error: {e}")
        finally:
            server_socket.close()


# ============================================================================
# NTP/UDP Server (RFC 5905 with NTS Extensions)
# ============================================================================


class NTPUDPServer:
    """
    UDP NTP server with NTS authentication (RFC 5905 + RFC 8915 §5).

    Parses NTP packets, validates NTS cookies, and signs responses.
    """

    _RATE_LIMIT_MAX_TRACKED = 50_000

    def __init__(self, cookie_manager: CookieManager, port: int = 123):
        self.cookie_manager = cookie_manager
        self.port = port
        self._rate_limit_window = 1.0  # seconds
        self._rate_limit_max = int(os.getenv("NTP_RATE_LIMIT_PER_SEC", "20"))
        self._rate_limit_state: Dict[str, Tuple[float, int]] = {}

    def _rate_limited(self, source_ip: str) -> bool:
        """
        Per-source-IP fixed-window rate limit for the UDP responder.

        Blunts spoofed-source floods against the parsing/AEAD-verification
        path (RFC 8915 §5.7 requires per-packet crypto work even to reject
        a forged request). Not a substitute for network-level filtering.
        """
        now = time.time()
        entry = self._rate_limit_state.get(source_ip)
        if entry is None or now - entry[0] >= self._rate_limit_window:
            self._rate_limit_state[source_ip] = (now, 1)
            if len(self._rate_limit_state) > self._RATE_LIMIT_MAX_TRACKED:
                self._prune_rate_limit_state(now)
            return False
        window_start, count = entry
        if count >= self._rate_limit_max:
            return True
        self._rate_limit_state[source_ip] = (window_start, count + 1)
        return False

    def _prune_rate_limit_state(self, now: float) -> None:
        """Evict stale rate-limit windows so a spoofed-source flood can't grow this dict unboundedly."""
        stale_before = now - (self._rate_limit_window * 10)
        stale_ips = [ip for ip, (start, _count) in self._rate_limit_state.items() if start < stale_before]
        for ip in stale_ips:
            del self._rate_limit_state[ip]

    def _extract_authenticator(self, data: bytes) -> Optional[Tuple[bytes, bytes]]:
        """
        Locate the NTS Authenticator extension field in a raw request.

        Returns (aad, tag): aad is every byte of the packet before the
        Authenticator EF header (RFC 8915 §5.7 associated data) and tag is
        the EF body (the AES-SIV authentication tag). Returns None if the
        packet is too short or no well-formed Authenticator EF is present.
        """
        if len(data) < 48:
            return None
        offset = 48
        while offset + 4 <= len(data):
            ef_type, ef_len = struct.unpack("!HH", data[offset : offset + 4])
            if ef_len < 4 or ef_len % 4 != 0 or offset + ef_len > len(data):
                return None
            if ef_type == NTPExtensionField.NTS_AUTHENTICATOR:
                return data[:offset], data[offset + 4 : offset + ef_len]
            offset += ef_len
        return None

    def parse_ntp_packet(self, data: bytes) -> Optional[NTPPacket]:
        """Parse RFC 5905 NTP packet."""
        if len(data) < 48:
            return None

        try:
            # RFC 5905 format: 1B(LI+VN+Mode) + 1B(Stratum) + 1B(Poll) + 1b(Precision-signed) +
            # 4B(RootDelay) + 4B(RootDisp) + 4B(RefID) + 8B(RefTS) + 8B(OriginTS) + 8B(ReceiveTS) + 8B(TransmitTS)
            header = struct.unpack("!BBBbIIIQQQQ", data[:48])
            (
                byte0,
                stratum,
                poll,
                precision,
                root_delay_int,
                root_dispersion_int,
                reference_id,
                reference_ts,
                origin_ts,
                receive_ts,
                transmit_ts,
            ) = header

            version = (byte0 >> 3) & 0x07
            mode = byte0 & 0x07

            # Convert NTP timestamps
            def ntp_to_float(ts: int) -> float:
                return (ts >> 32) + ((ts & 0xFFFFFFFF) / (2**32))

            packet = NTPPacket(
                version=version,
                mode=mode,
                stratum=stratum,
                poll=poll,
                precision=precision,
                root_delay=root_delay_int / (2**16),
                root_dispersion=root_dispersion_int / (2**16),
                reference_id=reference_id,
                reference_timestamp=ntp_to_float(reference_ts),
                origin_timestamp=ntp_to_float(origin_ts),
                receive_timestamp=ntp_to_float(receive_ts),
                transmit_timestamp=ntp_to_float(transmit_ts),
            )

            # Parse extension fields (RFC 5905 §7.5)
            # Format: Type (2B) | Length (2B) | Data
            # Length includes the 4-byte header and is padded to 4-byte boundary
            offset = 48
            while offset < len(data):
                if offset + 4 > len(data):
                    break

                ef_header = struct.unpack("!HH", data[offset : offset + 4])
                ef_type, ef_len = ef_header

                if ef_len < 4 or ef_len % 4 != 0:
                    # Invalid extension field
                    break

                if offset + ef_len > len(data):
                    break

                ef_data = data[offset + 4 : offset + ef_len]
                packet.extension_fields[ef_type] = ef_data

                offset += ef_len

            return packet

        except Exception as e:
            logger.warning(f"NTP packet parsing failed: {e}")
            return None

    def build_ntp_response(
        self,
        request_packet: NTPPacket,
        c2s_key: bytes,
        s2c_key: bytes,
        aead_id: int,
        unique_id: Optional[bytes] = None,
    ) -> bytes:
        """
        Build NTP response with NTS authentication.

        Implements RFC 8915 §5.7: NTS extension fields.
        """
        # Get current time
        now = time.time()
        ntp_now_int = int(now) + NTP_EPOCH_OFFSET
        ntp_frac = int((now % 1) * (2**32))
        transmit_ts = (ntp_now_int << 32) | ntp_frac

        # Build NTP header (RFC 5905 format)
        byte0 = (4 << 3) | 4  # Version 4, mode 4 (server)
        root_delay_int = int(0.001 * (2**16))
        root_dispersion_int = int(0.001 * (2**16))

        header = struct.pack(
            "!BBBbIIIQQQQ",
            byte0,
            2,  # stratum
            3,  # poll
            -20,  # precision (signed)
            root_delay_int,  # root_delay
            root_dispersion_int,  # root_dispersion
            0,  # reference_id
            transmit_ts,  # reference_ts (64-bit timestamp)
            int(request_packet.origin_timestamp * (2**32)) if request_packet.origin_timestamp else 0,  # origin
            int(now * (2**32)),  # receive_ts
            transmit_ts,  # transmit_ts
        )

        response = header

        # Add NTS extension fields (RFC 8915 §5.7)
        if unique_id:
            # Unique Identifier EF
            response += self._build_ef(NTPExtensionField.UNIQUE_IDENTIFIER, unique_id)

        # New NTS Cookie EF (wire-encoded: version byte || sealed ciphertext,
        # so it can be unsealed against the right key generation after rotation)
        new_cookie = self.cookie_manager.seal_cookie(c2s_key, s2c_key, aead_id)
        response += self._build_ef(NTPExtensionField.NTS_COOKIE, self.cookie_manager.wire_encode(new_cookie))

        # NTS Authenticator EF (AEAD tag over the response)
        # AAD: entire packet up to this point
        authenticator = self._compute_authenticator(response, s2c_key, aead_id, aad=response)
        response += self._build_ef(NTPExtensionField.NTS_AUTHENTICATOR, authenticator)

        return response

    def _build_ef(self, ef_type: int, data: bytes) -> bytes:
        """Build NTP extension field."""
        # Pad data to 4-byte boundary
        padded_len = len(data)
        if padded_len % 4:
            padded_len += 4 - (padded_len % 4)
            data = data + b"\x00" * (padded_len - len(data))

        ef_len = 4 + len(data)  # Header + data
        return struct.pack("!HH", ef_type, ef_len) + data

    def _compute_authenticator(self, packet: bytes, key: bytes, aead_id: int, aad: bytes) -> bytes:
        """
        Compute AES-SIV authenticator for NTS (RFC 8915 §5.7).

        Uses AES-SIV-CMAC-256 to create an authentication tag over the packet.
        The associated data (aad) is the entire packet up to this point.
        Returns: AES-SIV tag (16 bytes)
        """
        if aead_id != AEADAlgorithm.AEAD_AES_SIV_CMAC_256:
            # Only AES-SIV-CMAC-256 is negotiated by NTS-KE (RFC 8915). Never
            # silently downgrade to a weaker MAC — fail closed instead.
            raise ValueError(f"Unsupported AEAD algorithm {aead_id}; only AES-SIV-CMAC-256 supported")

        # AES-SIV MAC: encrypt empty plaintext with the packet bytes as the sole
        # associated-data element; AES-SIV returns the 16-byte SIV as the tag.
        # Any crypto failure propagates (fail closed) rather than downgrading.
        cipher = AESSIV(key)
        sealed = cipher.encrypt(b"", [aad])
        return sealed[:16]

    def verify_authenticator(self, packet: bytes, key: bytes, aead_id: int, aad: bytes, tag: bytes) -> bool:
        """
        Verify AES-SIV authenticator.

        Returns: True if tag is valid, False otherwise
        """
        if aead_id != AEADAlgorithm.AEAD_AES_SIV_CMAC_256:
            # Unsupported algorithm — reject rather than verify with a weaker MAC.
            logger.warning(f"Rejecting authenticator: unsupported AEAD {aead_id}")
            return False

        try:
            # Verify by recomputing and comparing
            computed_tag = self._compute_authenticator(packet, key, aead_id, aad)
            return hmac.compare_digest(tag, computed_tag)
        except Exception as e:
            logger.warning(f"AES-SIV authenticator verification failed: {e}")
            return False

    def handle_request(self, data: bytes, addr: Tuple[str, int]) -> Optional[bytes]:
        """
        Process one inbound UDP datagram and decide the response.

        Returns the response bytes to send, or None if the packet must be
        dropped silently (rate-limited, malformed, missing/invalid cookie,
        or failing NTS Authenticator verification). Extracted from ``run``
        so the drop-vs-respond decision is unit-testable without a live
        socket loop.
        """
        # Per-source-IP rate limit -- blunt spoofed-source floods before
        # doing any parsing/crypto work.
        if self._rate_limited(addr[0]):
            logger.warning(f"NTP request rate-limited from {addr}")
            return None

        # Parse NTP request
        packet = self.parse_ntp_packet(data)
        if not packet:
            logger.warning(f"Invalid NTP packet from {addr}")
            return None

        # Check for NTS cookie EF
        cookie_ef = packet.extension_fields.get(NTPExtensionField.NTS_COOKIE)
        if not cookie_ef:
            logger.warning(f"NTP request without NTS cookie from {addr}")
            return None

        # RFC 8915 §5.7: an NTS-protected request MUST carry an Authenticator
        # EF. Locate it (and its AAD) before trusting anything else about
        # this packet.
        authenticator = self._extract_authenticator(data)
        if not authenticator:
            logger.warning(f"NTP request without NTS Authenticator from {addr}")
            return None
        aad, tag = authenticator

        # Unseal cookie (wire-encoded: version byte || AEAD ciphertext)
        sealed_cookie = self.cookie_manager.wire_decode(cookie_ef)
        if not sealed_cookie:
            logger.warning(f"Malformed NTS cookie from {addr}")
            return None
        result = self.cookie_manager.unseal_cookie(sealed_cookie)
        if not result:
            logger.warning(f"Invalid NTS cookie from {addr}")
            return None

        c2s_key, s2c_key, aead_id = result

        # RFC 8915 §5.7 (CRITICAL): verify the request's Authenticator with
        # the client's C2S key BEFORE building or sending any response.
        # Never respond to an unauthenticated/forged request -- doing so
        # turns this server into an off-path reflector.
        if not self.verify_authenticator(aad, c2s_key, aead_id, aad, tag):
            logger.warning(f"NTS Authenticator verification failed from {addr}")
            return None

        # Get unique ID if present
        unique_id = packet.extension_fields.get(NTPExtensionField.UNIQUE_IDENTIFIER)

        return self.build_ntp_response(packet, c2s_key, s2c_key, aead_id, unique_id)

    async def run(self) -> None:
        """Run UDP NTP server."""
        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", self.port))
        sock.setblocking(False)

        logger.info(f"UDP NTP server listening on port {self.port}")

        try:
            while True:
                try:
                    data, addr = await loop.sock_recvfrom(sock, 4096)

                    response = self.handle_request(data, addr)
                    if response is not None:
                        await loop.sock_sendto(sock, response, addr)
                        logger.info(f"NTP response sent to {addr}")

                except BlockingIOError:
                    await asyncio.sleep(0.01)
        except Exception as e:
            logger.error(f"UDP NTP server error: {e}")
        finally:
            sock.close()


# ============================================================================
# Quart HTTP API (Plain Endpoints)
# ============================================================================

app = Quart(__name__)


def _feature_enabled(flag_key: str, distinct_id: str = "ntp-server") -> bool:
    """
    Check a PostHog feature flag. Fails SAFE (deny) if PostHog is
    unconfigured or unreachable -- never fails open, consistent with the
    other Squawk services.
    """
    if not (POSTHOG_KEY and POSTHOG_HOST):
        logger.warning(f"posthog not configured; denying flag {flag_key}")
        return False
    try:
        return bool(posthog.feature_enabled(flag_key, distinct_id))
    except Exception as e:
        logger.error(f"feature flag check failed for {flag_key}: {e}")
        return False


@app.route("/ntp/time", methods=["GET"])
async def ntp_time():
    """
    GET /ntp/time: Simple REST time API.

    No authentication required. Returns current server time in NTP and Unix formats.
    """
    if not _feature_enabled("squawkdns.ntp-server", "server"):
        return jsonify({"error": "NTP service disabled"}), 503

    now = time.time()
    ntp_secs = int(now) + NTP_EPOCH_OFFSET
    ntp_frac = int((now % 1) * (2**32))

    return jsonify(
        {
            "unix_timestamp": now,
            "ntp_seconds": ntp_secs,
            "ntp_fraction": ntp_frac,
            "iso8601": datetime.now(timezone.utc).isoformat(),
        }
    )


@app.route("/ntp/status", methods=["GET"])
async def ntp_status():
    """
    GET /ntp/status: Server status and statistics.

    Requires scope: ntp:admin
    """
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "") if auth_header.startswith("Bearer ") else ""

    if not verify_jwt(token, required_scope="ntp:admin"):
        return jsonify({"error": "Unauthorized"}), 403

    return jsonify(
        {
            "service": "NTP/NTS",
            "version": "2.0.0",
            "rfc": "RFC 8915",
            "master_key_version": (
                getattr(nts_ke_server, "cookie_manager", None).master_key_version if nts_ke_server else None
            ),
        }
    )


@app.route("/health", methods=["GET"])
async def health():
    """GET /health: Health check endpoint (no auth)."""
    ntp_secs = int(time.time()) + NTP_EPOCH_OFFSET
    return jsonify(
        {
            "status": "healthy",
            "service": "ntp",
            "ntp_time": ntp_secs,
        }
    )


@app.route("/", methods=["GET"])
async def root():
    """Root endpoint."""
    return jsonify(
        {
            "service": "Squawk NTP/NTS Server (RFC 8915)",
            "version": "2.0.0",
            "endpoints": {
                "plain": [
                    "GET /ntp/time - Current server time",
                    "GET /ntp/status - Server status (requires ntp:admin scope)",
                    "GET /health - Health check",
                ],
                "nts-ke": "TLS on port 4460 (RFC 5705 exporter, requires ntp:client scope)",
                "ntp-udp": "UDP port 123 (NTS-authenticated queries)",
            },
        }
    )


# ============================================================================
# Periodic Tasks
# ============================================================================


async def master_key_rotation_task(cookie_manager: CookieManager):
    """Rotate master key daily (grace period: 1 hour)."""
    while True:
        await asyncio.sleep(86400)  # Daily
        cookie_manager.rotate_key()
        logger.info("Master key rotation task executed")


# ============================================================================
# Main Entry Point
# ============================================================================

nts_ke_server: Optional[NTSKEServer] = None
ntp_udp_server: Optional[NTPUDPServer] = None


async def main():
    """Start NTP/NTS server."""
    global nts_ke_server, ntp_udp_server

    logger.info("Starting NTP/NTS Server (RFC 8915)")

    # Initialize NTS-KE server (TLS certs optional for testing)
    if TLS_ENABLED:
        nts_ke_server = NTSKEServer(TLS_CERT_FILE, TLS_KEY_FILE, NTS_KE_PORT)
        asyncio.create_task(nts_ke_server.run())
        logger.info(f"NTS-KE TLS server listening on port {NTS_KE_PORT}")
    else:
        # Create a minimal cookie manager for testing without TLS
        cookie_manager = CookieManager()
        logger.warning("TLS certs not configured; NTS-KE server disabled")

    # Initialize UDP NTP server
    cookie_mgr = nts_ke_server.cookie_manager if nts_ke_server else cookie_manager
    ntp_udp_server = NTPUDPServer(cookie_mgr, UDP_PORT)
    asyncio.create_task(ntp_udp_server.run())
    logger.info(f"UDP NTP server listening on port {UDP_PORT}")

    # Master key rotation
    asyncio.create_task(master_key_rotation_task(cookie_mgr))

    # Start Quart HTTP API
    config = Config()
    config.bind = [f"0.0.0.0:{PORT}"]
    config.accesslog = "-"
    config.errorlog = "-"

    logger.info(f"HTTP API listening on port {PORT}")

    await serve(app, config)


if __name__ == "__main__":
    asyncio.run(main())
