"""Shared crypto helpers for the manager service."""

from __future__ import annotations

import hashlib
from typing import Optional, Tuple


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


def compute_kid_from_private_pem(private_pem: str) -> str:
    """Compute kid from private key by extracting public key and hashing it.

    Args:
        private_pem: PEM-encoded private key (PKCS8 format)

    Returns:
        Key ID (first 16 hex characters of SHA-256 hash)
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    private_key = serialization.load_pem_private_key(
        private_pem.encode(),
        password=None,
        backend=default_backend(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return compute_kid_from_public_pem(public_pem)


def generate_ephemeral_es256_keypair() -> Tuple[str, str]:
    """Generate an in-process ES256 (NIST P-256) keypair as PEM strings.

    Returns:
        (private_pem, public_pem)

    Used only where no configured keypair is supplied (dev/test/standalone).
    Production always supplies JWT_PRIVATE_KEY/JWT_PUBLIC_KEY — ProductionConfig
    fails fast without them.
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem
