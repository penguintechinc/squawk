"""Shared crypto helpers for the manager service."""

from __future__ import annotations

from typing import Tuple


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
