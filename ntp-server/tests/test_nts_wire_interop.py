"""NTS wire-format interop tests (RFC 8915 / RFC 7822 / RFC 5297).

These tests validate that the server emits and consumes the *exact* bytes a
third-party NTS implementation (chrony, ntpsec) would produce/expect. Unlike the
self-consistency tests in ``test_nts_server.py`` (which encode then decode with
the same code), these cross-check against:

- an **independent, spec-faithful codec** written straight from the RFCs and
  sharing no code with ``server.py``;
- the **RFC 5297 AES-SIV known-answer vector** — the same primitive chrony and
  ntpsec implement — so a mismatch in our AEAD would be caught; and
- a **client-side authenticator recomputation**, proving a peer holding the S2C
  key can authenticate our NTP response.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path
from typing import List, Tuple

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESSIV

sys.path.insert(0, str(Path(__file__).parent.parent / "bins"))

from server import (  # noqa: E402
    AEADAlgorithm,
    CookieManager,
    NTPExtensionField,
    NTPPacket,
    NTPUDPServer,
    NTSKERecord,
    NTSKERecordType,
    NTSKEServer,
)

AES_SIV_CMAC_256 = int(AEADAlgorithm.AEAD_AES_SIV_CMAC_256)  # 15


# ---------------------------------------------------------------------------
# Independent, spec-faithful reference codec (shares no code with server.py)
# ---------------------------------------------------------------------------
def _ref_encode_record(critical: bool, rtype: int, body: bytes) -> bytes:
    """RFC 8915 §4.1.1 record: (C|Type):16, BodyLength:16, Body, pad to 4B."""
    type_field = (0x8000 if critical else 0) | (rtype & 0x7FFF)
    rec = struct.pack("!HH", type_field, len(body)) + body
    if len(rec) % 4:
        rec += b"\x00" * (4 - len(rec) % 4)
    return rec


def _ref_parse_records(data: bytes) -> List[Tuple[bool, int, bytes]]:
    """Independent parser → list of (critical, record_type, body)."""
    out: List[Tuple[bool, int, bytes]] = []
    off = 0
    while off + 4 <= len(data):
        type_field, body_len = struct.unpack("!HH", data[off : off + 4])
        critical = bool(type_field & 0x8000)
        rtype = type_field & 0x7FFF
        body = data[off + 4 : off + 4 + body_len]
        total = 4 + body_len
        if total % 4:
            total += 4 - total % 4
        out.append((critical, rtype, body))
        off += total
    return out


def _ref_parse_extension_fields(data: bytes) -> List[Tuple[int, bytes]]:
    """RFC 7822 EF: Type:16, Length:16 (incl. 4B header, 4B-aligned), Value."""
    out: List[Tuple[int, bytes]] = []
    off = 0
    while off + 4 <= len(data):
        ef_type, ef_len = struct.unpack("!HH", data[off : off + 4])
        if ef_len < 4 or ef_len % 4 or off + ef_len > len(data):
            break
        out.append((ef_type, data[off + 4 : off + ef_len]))
        off += ef_len
    return out


# ---------------------------------------------------------------------------
# NTS-KE response: byte layout & critical bits as a real client would read them
# ---------------------------------------------------------------------------
class TestNTSKEResponseInterop:
    def _response(self, n_cookies: int = 2) -> bytes:
        cm = CookieManager()
        cookies = [
            cm.seal_cookie(b"\x11" * 32, b"\x22" * 32, AES_SIV_CMAC_256)
            for _ in range(n_cookies)
        ]
        server = NTSKEServer("unused-cert.pem", "unused-key.pem")
        return server._build_nts_ke_response(AES_SIV_CMAC_256, cookies)

    def test_response_record_sequence(self):
        recs = _ref_parse_records(self._response(n_cookies=2))
        types = [(c, t) for (c, t, _b) in recs]

        # RFC 8915 §4.1.2 ordering: Next Protocol, AEAD, cookies…, End of Message
        assert types[0] == (True, int(NTSKERecordType.NEXT_PROTOCOL))
        assert types[1] == (False, int(NTSKERecordType.AEAD_ALGORITHM))
        assert types[2] == (False, int(NTSKERecordType.NEW_COOKIE))
        assert types[3] == (False, int(NTSKERecordType.NEW_COOKIE))
        assert types[-1] == (True, int(NTSKERecordType.END_OF_MESSAGE))

    def test_next_protocol_is_ntpv4_and_critical(self):
        """RFC 8915 §4.1.5: Next Protocol record MUST be critical; body = 0 (NTPv4).

        Regression: strict clients (ntpsec) reject a non-critical Next Protocol.
        """
        recs = _ref_parse_records(self._response())
        crit, rtype, body = recs[0]
        assert rtype == int(NTSKERecordType.NEXT_PROTOCOL)
        assert crit is True
        assert struct.unpack("!H", body)[0] == 0  # NTPv4

    def test_aead_negotiation_advertises_aes_siv_cmac_256(self):
        recs = _ref_parse_records(self._response())
        aead = next(b for (_c, t, b) in recs if t == int(NTSKERecordType.AEAD_ALGORITHM))
        assert struct.unpack("!H", aead)[0] == 15  # chrony/ntpsec expect ID 15

    def test_end_of_message_is_empty_and_critical(self):
        recs = _ref_parse_records(self._response())
        crit, rtype, body = recs[-1]
        assert rtype == int(NTSKERecordType.END_OF_MESSAGE)
        assert crit is True
        assert body == b""

    def test_server_parses_independently_encoded_client_request(self):
        """A chrony-style request (independent encoder) is parsed correctly."""
        req = (
            _ref_encode_record(True, int(NTSKERecordType.NEXT_PROTOCOL), struct.pack("!H", 0))
            + _ref_encode_record(True, int(NTSKERecordType.AEAD_ALGORITHM), struct.pack("!H", 15))
            + _ref_encode_record(True, int(NTSKERecordType.END_OF_MESSAGE), b"")
        )
        parsed = NTSKERecord.parse_all(req)
        assert parsed[0] == (int(NTSKERecordType.NEXT_PROTOCOL), struct.pack("!H", 0), True)
        assert parsed[1] == (int(NTSKERecordType.AEAD_ALGORITHM), struct.pack("!H", 15), True)
        assert parsed[2] == (int(NTSKERecordType.END_OF_MESSAGE), b"", True)


@pytest.mark.parametrize("body_len", [0, 1, 2, 3, 4, 5, 7, 8, 33])
def test_record_encoding_is_byte_identical_to_reference(body_len):
    """server encode == independent reference encode (4-byte alignment interop)."""
    body = bytes(range(body_len))
    assert NTSKERecord.encode(7, body, critical=False) == _ref_encode_record(False, 7, body)
    assert NTSKERecord.encode(7, body, critical=True) == _ref_encode_record(True, 7, body)


# ---------------------------------------------------------------------------
# AES-SIV primitive: RFC 5297 known-answer vector (cross-implementation anchor)
# ---------------------------------------------------------------------------
def test_aes_siv_rfc5297_deterministic_vector():
    """cryptography's AES-SIV matches the RFC 5297 A.1 vector byte-for-byte."""
    key = bytes.fromhex(
        "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    )
    ad = bytes.fromhex("101112131415161718191a1b1c1d1e1f2021222324252627")
    pt = bytes.fromhex("112233445566778899aabbccddee")
    out = AESSIV(key).encrypt(pt, [ad])
    # RFC 5297 output = SIV(16) || ciphertext; the SIV is the authentication tag.
    assert out[:16].hex() == "85632d07c6e8f37f950acd320a2ecc93"
    assert out.hex() == "85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c"


def test_authenticator_is_aes_siv_tag_over_aad():
    """NTS authenticator == AES-SIV(S2C).encrypt(empty, [AAD])[:16] (RFC 8915 §5.7)."""
    server = NTPUDPServer(CookieManager())
    s2c = b"\x33" * 32
    aad = b"the-quick-brown-fox-jumps-over-the-lazy-dog!!"
    tag = server._compute_authenticator(aad, s2c, AES_SIV_CMAC_256, aad=aad)
    independent = AESSIV(s2c).encrypt(b"", [aad])[:16]
    assert tag == independent
    assert len(tag) == 16


def test_authenticator_rejects_non_aes_siv_algorithm():
    """No silent MAC downgrade: unsupported AEAD IDs are rejected, not weakened."""
    server = NTPUDPServer(CookieManager())
    with pytest.raises(ValueError):
        server._compute_authenticator(b"x", b"\x00" * 32, 999, aad=b"x")
    assert server.verify_authenticator(b"x", b"\x00" * 32, 999, b"x", b"\x00" * 16) is False


# ---------------------------------------------------------------------------
# NTP extension-field framing (RFC 7822) — independent cross-check
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("data_len", [1, 4, 16, 20, 30, 90])
def test_extension_field_framing_matches_rfc7822(data_len):
    server = NTPUDPServer(CookieManager())
    payload = bytes(range(256))[:data_len]
    ef = server._build_ef(NTPExtensionField.NTS_COOKIE, payload)

    # Length field: 4-byte header + 4-byte-aligned data.
    ef_type, ef_len = struct.unpack("!HH", ef[:4])
    assert ef_type == int(NTPExtensionField.NTS_COOKIE)
    assert ef_len % 4 == 0 and ef_len >= 4
    assert len(ef) == ef_len

    parsed = _ref_parse_extension_fields(ef)
    assert len(parsed) == 1
    p_type, p_value = parsed[0]
    assert p_type == int(NTPExtensionField.NTS_COOKIE)
    assert p_value[:data_len] == payload  # original data preserved (plus zero pad)


# ---------------------------------------------------------------------------
# End-to-end: a client holding the S2C key can authenticate our response
# ---------------------------------------------------------------------------
def test_response_authenticator_verifiable_by_client():
    server = NTPUDPServer(CookieManager())
    c2s, s2c = b"\xaa" * 32, b"\xbb" * 32
    unique_id = b"\xcd" * 32

    req = NTPPacket(
        version=4, mode=3, stratum=0, poll=0, precision=0,
        root_delay=0.0, root_dispersion=0.0, reference_id=0,
        reference_timestamp=0.0, origin_timestamp=1.0,
        receive_timestamp=0.0, transmit_timestamp=1.0,
    )
    resp = server.build_ntp_response(req, c2s, s2c, AES_SIV_CMAC_256, unique_id=unique_id)

    # Client parses: 48-byte header then extension fields, tracking byte offsets
    # (positional walk — never search for the 0x0404 type bytes, which could
    # collide with bytes inside the authenticator tag or a sealed cookie).
    assert len(resp) >= 48
    offset = 48
    efs: List[Tuple[int, bytes, int]] = []  # (type, value, ef_start_offset)
    while offset + 4 <= len(resp):
        ef_type, ef_len = struct.unpack("!HH", resp[offset : offset + 4])
        assert ef_len >= 4 and ef_len % 4 == 0
        efs.append((ef_type, resp[offset + 4 : offset + ef_len], offset))
        offset += ef_len
    assert offset == len(resp)  # EFs tile the packet exactly

    ef_types = [t for (t, _v, _o) in efs]
    assert int(NTPExtensionField.UNIQUE_IDENTIFIER) in ef_types
    assert int(NTPExtensionField.NTS_COOKIE) in ef_types
    assert ef_types[-1] == int(NTPExtensionField.NTS_AUTHENTICATOR)

    # Echoed Unique Identifier must match the request (replay binding).
    uid_value = next(v for (t, v, _o) in efs if t == int(NTPExtensionField.UNIQUE_IDENTIFIER))
    assert uid_value[: len(unique_id)] == unique_id

    # AAD = everything before the authenticator EF; recompute the tag independently.
    _auth_type, auth_value, auth_ef_start = efs[-1]
    aad = resp[:auth_ef_start]
    expected = AESSIV(s2c).encrypt(b"", [aad])[:16]
    assert auth_value[:16] == expected
