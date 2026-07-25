"""DNS-server cryptographic utilities for key rotation."""

from __future__ import annotations

import hashlib


def compute_kid_from_public_pem(public_pem: str) -> str:
    """Compute kid (key ID) as first 16 hex chars of SHA-256 over DER SubjectPublicKeyInfo.

    Args:
        public_pem: PEM-encoded public key (SubjectPublicKeyInfo format)

    Returns:
        Key ID (first 16 hex characters of SHA-256 hash)
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    public_key = serialization.load_pem_public_key(public_pem.encode(), default_backend())
    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    sha256_hash = hashlib.sha256(der_bytes).digest()
    hex_string = sha256_hash.hex()
    return hex_string[:16]
