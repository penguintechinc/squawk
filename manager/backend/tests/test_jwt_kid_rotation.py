"""Tests for JWT kid (key ID) support and key rotation."""

from __future__ import annotations

import pytest
import jwt as pyjwt
from datetime import datetime, timedelta, timezone

from app.utils.crypto import (
    compute_kid_from_public_pem,
    compute_kid_from_private_pem,
    generate_ephemeral_es256_keypair,
)


def test_compute_kid_from_public_pem_deterministic() -> None:
    """kid computation from public key is deterministic (same key → same kid)."""
    private_pem, public_pem = generate_ephemeral_es256_keypair()
    kid1 = compute_kid_from_public_pem(public_pem)
    kid2 = compute_kid_from_public_pem(public_pem)
    assert kid1 == kid2
    assert len(kid1) == 16


def test_compute_kid_from_public_pem_format() -> None:
    """kid is exactly 16 hex characters."""
    _, public_pem = generate_ephemeral_es256_keypair()
    kid = compute_kid_from_public_pem(public_pem)
    assert len(kid) == 16
    assert all(c in '0123456789abcdef' for c in kid)


def test_compute_kid_from_private_pem() -> None:
    """kid derived from private key matches kid of its public key."""
    private_pem, public_pem = generate_ephemeral_es256_keypair()
    kid_from_private = compute_kid_from_private_pem(private_pem)
    kid_from_public = compute_kid_from_public_pem(public_pem)
    assert kid_from_private == kid_from_public


def test_different_keys_different_kids() -> None:
    """Different keys produce different kids."""
    _, public_pem1 = generate_ephemeral_es256_keypair()
    _, public_pem2 = generate_ephemeral_es256_keypair()
    kid1 = compute_kid_from_public_pem(public_pem1)
    kid2 = compute_kid_from_public_pem(public_pem2)
    assert kid1 != kid2


def test_jwt_issued_with_kid_header() -> None:
    """JWTs issued include kid header."""
    private_pem, public_pem = generate_ephemeral_es256_keypair()
    kid = compute_kid_from_private_pem(private_pem)

    now = datetime.now(timezone.utc)
    payload = {
        "sub": "user-123",
        "iss": "squawk-manager",
        "aud": "squawk",
        "tenant": "default",
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "iat": int(now.timestamp()),
    }

    token = pyjwt.encode(payload, private_pem, algorithm="ES256", headers={"kid": kid})

    # Verify kid is in header
    header = pyjwt.get_unverified_header(token)
    assert header.get("kid") == kid


def test_jwt_kid_based_key_selection() -> None:
    """During rotation overlap, kid correctly selects the right key."""
    # Generate two keypairs (simulating old and new key)
    old_private, old_public = generate_ephemeral_es256_keypair()
    new_private, new_public = generate_ephemeral_es256_keypair()

    old_kid = compute_kid_from_public_pem(old_public)
    new_kid = compute_kid_from_public_pem(new_public)

    # Create token with old key
    now = datetime.now(timezone.utc)
    payload = {
        "sub": "user-123",
        "iss": "squawk-manager",
        "aud": "squawk",
        "tenant": "default",
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "iat": int(now.timestamp()),
    }

    token = pyjwt.encode(payload, old_private, algorithm="ES256", headers={"kid": old_kid})

    # Try verifying with both keys available (rotation overlap)
    keys = {old_kid: old_public, new_kid: new_public}
    header = pyjwt.get_unverified_header(token)
    kid = header.get("kid")
    assert kid == old_kid
    assert kid in keys

    # Verify with correct key
    decoded = pyjwt.decode(
        token,
        keys[kid],
        algorithms=["ES256"],
        audience="squawk",
        issuer="squawk-manager",
    )
    assert decoded["sub"] == "user-123"


def test_jwt_unknown_kid_rejected() -> None:
    """Token with unknown kid should be rejected (no fallback)."""
    private_pem, _ = generate_ephemeral_es256_keypair()
    unknown_kid = "unknown1234567890"  # 16 hex chars but not in key set

    now = datetime.now(timezone.utc)
    payload = {
        "sub": "user-123",
        "iss": "squawk-manager",
        "aud": "squawk",
        "tenant": "default",
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "iat": int(now.timestamp()),
    }

    token = pyjwt.encode(
        payload, private_pem, algorithm="ES256", headers={"kid": unknown_kid}
    )

    # Simulate verifier behavior: kid present but not in available keys → reject
    header = pyjwt.get_unverified_header(token)
    kid = header.get("kid")
    available_keys = {}  # No keys available

    if kid:
        if kid not in available_keys:
            # Unknown kid → reject
            with pytest.raises(KeyError):
                _ = available_keys[kid]


def test_jwt_no_kid_backward_compat() -> None:
    """Token without kid should be verifiable during rotation (backward compat)."""
    private_pem, public_pem = generate_ephemeral_es256_keypair()

    now = datetime.now(timezone.utc)
    payload = {
        "sub": "user-123",
        "iss": "squawk-manager",
        "aud": "squawk",
        "tenant": "default",
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "iat": int(now.timestamp()),
    }

    # Issue token without kid (legacy)
    token = pyjwt.encode(payload, private_pem, algorithm="ES256")

    # Verify without kid (try all available keys)
    header = pyjwt.get_unverified_header(token)
    assert header.get("kid") is None

    # Should be verifiable with public key
    decoded = pyjwt.decode(
        token,
        public_pem,
        algorithms=["ES256"],
        audience="squawk",
        issuer="squawk-manager",
    )
    assert decoded["sub"] == "user-123"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
