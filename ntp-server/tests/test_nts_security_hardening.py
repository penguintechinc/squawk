"""
Regression tests for NTP/NTS security hardening fixes.

Covers:
- (a) NTS Authenticator verification is required before responding
  (RFC 8915 §5.7) -- a bad/missing authenticator gets no response.
- Per-source-IP rate limiting on the UDP responder.
- Cookie wire format carries the real master-key version so cookies
  survive key rotation (and survive NTP extension-field 4-byte padding).
- (b) NTS-KE requires an ntp:client-scoped JWT before issuing cookies.
"""

from __future__ import annotations

import secrets
import struct
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESSIV

sys.path.insert(0, str(Path(__file__).parent.parent / "bins"))

from server import (  # noqa: E402
    AEADAlgorithm,
    CookieManager,
    NTPExtensionField,
    NTPUDPServer,
    NTSKERecord,
    NTSKERecordType,
    _extract_nts_ke_auth_token,
    verify_jwt,
)

AES_SIV_CMAC_256 = int(AEADAlgorithm.AEAD_AES_SIV_CMAC_256)


def _build_ntp_header() -> bytes:
    """Minimal RFC 5905 client-mode header (version 4, mode 3)."""
    byte0 = (4 << 3) | 3
    return struct.pack("!BBBbIIIQQQQ", byte0, 2, 3, -20, 0, 0, 0, 0, 0, 0, 0)


def _build_authenticated_request(
    server: NTPUDPServer,
    cookie_manager: CookieManager,
    c2s_key: bytes,
    s2c_key: bytes,
    aead_id: int,
    *,
    tamper_tag: bool = False,
    omit_authenticator: bool = False,
) -> bytes:
    """Build a wire-accurate NTS-protected NTP request via the server's own EF builder."""
    header = _build_ntp_header()
    cookie = cookie_manager.seal_cookie(c2s_key, s2c_key, aead_id)
    cookie_ef = server._build_ef(NTPExtensionField.NTS_COOKIE, cookie_manager.wire_encode(cookie))
    packet_prefix = header + cookie_ef

    if omit_authenticator:
        return packet_prefix

    tag = AESSIV(c2s_key).encrypt(b"", [packet_prefix])[:16]
    if tamper_tag:
        tag = bytes([tag[0] ^ 0x01]) + tag[1:]

    auth_ef = server._build_ef(NTPExtensionField.NTS_AUTHENTICATOR, tag)
    return packet_prefix + auth_ef


class TestUDPAuthenticatorEnforcement:
    """(a) Regression: bad/missing NTS Authenticator gets no response."""

    def test_valid_authenticator_gets_response(self):
        cm = CookieManager()
        c2s, s2c = secrets.token_bytes(32), secrets.token_bytes(32)
        server = NTPUDPServer(cm)
        request = _build_authenticated_request(server, cm, c2s, s2c, AES_SIV_CMAC_256)

        response = server.handle_request(request, ("203.0.113.10", 12345))

        assert response is not None

    def test_missing_authenticator_gets_no_response(self):
        cm = CookieManager()
        c2s, s2c = secrets.token_bytes(32), secrets.token_bytes(32)
        server = NTPUDPServer(cm)
        request = _build_authenticated_request(
            server, cm, c2s, s2c, AES_SIV_CMAC_256, omit_authenticator=True
        )

        response = server.handle_request(request, ("203.0.113.11", 12345))

        assert response is None

    def test_tampered_authenticator_gets_no_response(self):
        cm = CookieManager()
        c2s, s2c = secrets.token_bytes(32), secrets.token_bytes(32)
        server = NTPUDPServer(cm)
        request = _build_authenticated_request(server, cm, c2s, s2c, AES_SIV_CMAC_256, tamper_tag=True)

        response = server.handle_request(request, ("203.0.113.12", 12345))

        assert response is None

    def test_authenticator_signed_with_wrong_key_gets_no_response(self):
        """A tag computed with a different C2S key (e.g. replayed against
        another session, or a spoofed request) must be rejected."""
        cm = CookieManager()
        c2s, s2c = secrets.token_bytes(32), secrets.token_bytes(32)
        wrong_c2s = secrets.token_bytes(32)
        server = NTPUDPServer(cm)

        header = _build_ntp_header()
        cookie = cm.seal_cookie(c2s, s2c, AES_SIV_CMAC_256)
        cookie_ef = server._build_ef(NTPExtensionField.NTS_COOKIE, cm.wire_encode(cookie))
        packet_prefix = header + cookie_ef
        forged_tag = AESSIV(wrong_c2s).encrypt(b"", [packet_prefix])[:16]
        request = packet_prefix + server._build_ef(NTPExtensionField.NTS_AUTHENTICATOR, forged_tag)

        response = server.handle_request(request, ("203.0.113.13", 12345))

        assert response is None

    def test_missing_cookie_gets_no_response(self):
        cm = CookieManager()
        server = NTPUDPServer(cm)
        request = _build_ntp_header()  # no extension fields at all

        response = server.handle_request(request, ("203.0.113.14", 12345))

        assert response is None


class TestUDPRateLimiting:
    """Per-source-IP rate limiting blunts spoofed-source floods."""

    def test_requests_within_limit_are_not_rate_limited(self):
        server = NTPUDPServer(CookieManager())
        server._rate_limit_max = 5

        for _ in range(5):
            assert server._rate_limited("198.51.100.1") is False

    def test_requests_over_limit_are_rate_limited(self):
        server = NTPUDPServer(CookieManager())
        server._rate_limit_max = 3

        for _ in range(3):
            assert server._rate_limited("198.51.100.2") is False
        assert server._rate_limited("198.51.100.2") is True

    def test_rate_limit_is_per_source_ip(self):
        server = NTPUDPServer(CookieManager())
        server._rate_limit_max = 1

        assert server._rate_limited("198.51.100.3") is False
        assert server._rate_limited("198.51.100.4") is False  # separate bucket
        assert server._rate_limited("198.51.100.3") is True  # first IP now over its limit

    def test_rate_limited_request_via_handle_request_gets_no_response(self):
        cm = CookieManager()
        c2s, s2c = secrets.token_bytes(32), secrets.token_bytes(32)
        server = NTPUDPServer(cm)
        server._rate_limit_max = 1
        request = _build_authenticated_request(server, cm, c2s, s2c, AES_SIV_CMAC_256)

        first = server.handle_request(request, ("198.51.100.5", 12345))
        second = server.handle_request(request, ("198.51.100.5", 12345))

        assert first is not None
        assert second is None


class TestCookieWireVersioning:
    """Cookie wire format carries the real master-key version (rotation-safe)."""

    def test_cookie_survives_key_rotation(self):
        cm = CookieManager()
        c2s, s2c = secrets.token_bytes(32), secrets.token_bytes(32)
        server = NTPUDPServer(cm)

        cookie = cm.seal_cookie(c2s, s2c, AES_SIV_CMAC_256)
        wire_bytes = cm.wire_encode(cookie)
        # Round-trip through actual EF framing so 4-byte padding is exercised.
        ef = server._build_ef(NTPExtensionField.NTS_COOKIE, wire_bytes)
        ef_type, ef_len = struct.unpack("!HH", ef[:4])
        ef_data = ef[4:ef_len]

        cm.rotate_key()
        assert cm.master_key_version == 1

        decoded = cm.wire_decode(ef_data)
        assert decoded is not None
        assert decoded.version == 0  # carried on the wire, not hardcoded

        result = cm.unseal_cookie(decoded)
        assert result is not None
        assert result[0] == c2s
        assert result[1] == s2c

    def test_udp_request_with_pre_rotation_cookie_still_works(self):
        """End-to-end via handle_request: a session established before
        rotation keeps working during the grace period."""
        cm = CookieManager()
        c2s, s2c = secrets.token_bytes(32), secrets.token_bytes(32)
        server = NTPUDPServer(cm)

        request = _build_authenticated_request(server, cm, c2s, s2c, AES_SIV_CMAC_256)
        cm.rotate_key()

        response = server.handle_request(request, ("198.51.100.6", 12345))

        assert response is not None

    def test_wire_decode_rejects_truncated_input(self):
        cm = CookieManager()
        assert cm.wire_decode(b"") is None
        assert cm.wire_decode(b"\x00\x05ab") is None  # declared length exceeds actual data


class TestNTSKEAuthTokenExtraction:
    """(b) NTS-KE without a valid ntp:client JWT is rejected."""

    def test_extract_auth_token_present(self):
        token = "some.jwt.token"
        request = NTSKERecord.encode(NTSKERecordType.SQUAWK_AUTH_TOKEN, token.encode(), critical=False)

        assert _extract_nts_ke_auth_token(request) == token

    def test_extract_auth_token_absent(self):
        request = NTSKERecord.encode(NTSKERecordType.AEAD_ALGORITHM, struct.pack("!H", 15), critical=False)

        assert _extract_nts_ke_auth_token(request) is None

    def test_extract_auth_token_empty_body(self):
        request = NTSKERecord.encode(NTSKERecordType.SQUAWK_AUTH_TOKEN, b"", critical=False)

        assert _extract_nts_ke_auth_token(request) is None

    def test_nts_ke_rejects_missing_token(self):
        """No SQUAWK_AUTH_TOKEN record at all -> auth must fail closed."""
        client_request = NTSKERecord.encode(NTSKERecordType.AEAD_ALGORITHM, struct.pack("!H", 15), critical=False)

        token = _extract_nts_ke_auth_token(client_request)

        assert token is None
        assert verify_jwt(token or "", required_scope="ntp:client") is False

    def test_nts_ke_rejects_wrong_scope_token(self, jwt_keypair, monkeypatch):
        """A validly-signed token WITHOUT ntp:client scope must be rejected."""
        monkeypatch.setenv("JWT_PUBLIC_KEY", jwt_keypair["public"])
        now = datetime.now(timezone.utc)
        payload = {
            "sub": "test",
            "iss": "squawk-manager",
            "aud": "squawk",
            "tenant": "default",
            "scope": "ntp:admin",
            "iat": now,
            "exp": now + timedelta(hours=1),
        }
        token = jwt.encode(payload, jwt_keypair["private"], algorithm="ES256")
        client_request = NTSKERecord.encode(NTSKERecordType.SQUAWK_AUTH_TOKEN, token.encode(), critical=False)

        extracted = _extract_nts_ke_auth_token(client_request)

        assert extracted == token
        assert verify_jwt(extracted, required_scope="ntp:client") is False

    def test_nts_ke_accepts_valid_ntp_client_token(self, jwt_keypair, monkeypatch):
        """A validly-signed ntp:client-scoped token is accepted."""
        monkeypatch.setenv("JWT_PUBLIC_KEY", jwt_keypair["public"])
        now = datetime.now(timezone.utc)
        payload = {
            "sub": "test",
            "iss": "squawk-manager",
            "aud": "squawk",
            "tenant": "default",
            "scope": "ntp:client",
            "iat": now,
            "exp": now + timedelta(hours=1),
        }
        token = jwt.encode(payload, jwt_keypair["private"], algorithm="ES256")
        client_request = NTSKERecord.encode(NTSKERecordType.SQUAWK_AUTH_TOKEN, token.encode(), critical=False)

        extracted = _extract_nts_ke_auth_token(client_request)

        assert extracted == token
        assert verify_jwt(extracted, required_scope="ntp:client") is True


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
