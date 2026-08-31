"""Shared crypto helpers for the manager service."""

from __future__ import annotations

import base64
import hashlib
from typing import Tuple


def sha256_hex(value: str) -> str:
    """Return the hex-encoded SHA-256 digest of a UTF-8 string.

    Used for fast, unique-indexed at-rest hashing of high-entropy secrets
    that are looked up by exact value on every request (DNS resolver
    tokens, DNS-server join keys, deployment-domain JWTs) -- a plain unique
    index on the hash gives O(1) lookup, unlike bcrypt which requires an
    unindexable per-row comparison. NOT for passwords/low-entropy secrets
    (see bcrypt in AuthService for those).
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def get_fernet_cipher(info: bytes):
    """Derive a Fernet cipher from the app's `SECRET_KEY` via HKDF-SHA256.

    `info` scopes the derived key to a single use case (e.g.
    ``b"dns-server-jwt-secret-encryption"``) so the same `SECRET_KEY` yields
    independent keys per secret type -- mirrors the pattern already used by
    MFAService/SSOService/SAMLService, centralized here for reuse.

    Returns:
        A `cryptography.fernet.Fernet` cipher instance.

    Raises:
        ValueError: if `SECRET_KEY` is not configured.
    """
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.backends import default_backend
    from flask import current_app

    secret_key = current_app.config.get("SECRET_KEY", "").encode("utf-8")
    if not secret_key:
        raise ValueError("SECRET_KEY not configured")

    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
        backend=default_backend(),
    )
    derived_key = kdf.derive(secret_key)
    b64_key = base64.urlsafe_b64encode(derived_key)
    return Fernet(b64_key)


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
