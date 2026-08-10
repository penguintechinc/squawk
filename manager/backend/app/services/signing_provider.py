"""
Pluggable JWT signing provider abstraction.

Supports local PEM files and AWS KMS-backed signing. Implementations handle
key material securely and produce JOSE-compatible signatures.
"""

from __future__ import annotations

import base64
import json
import logging
from abc import ABC, abstractmethod
from typing import Optional

logger = logging.getLogger(__name__)


class SigningProvider(ABC):
    """Abstract base for pluggable JWT signing providers."""

    @property
    @abstractmethod
    def algorithm(self) -> str:
        """JOSE algorithm name (ES256, RS256, etc.)."""
        pass

    @property
    @abstractmethod
    def kid(self) -> str:
        """Key ID (first 16 hex chars of SHA-256 over public key DER)."""
        pass

    @abstractmethod
    def public_key_pem(self) -> str:
        """Return the public key in PEM format (SubjectPublicKeyInfo)."""
        pass

    @abstractmethod
    def sign(self, signing_input: bytes) -> bytes:
        """Sign raw bytes and return JOSE-format signature.

        For ES256/RS256, this is the raw (r||s) format, not DER.

        Args:
            signing_input: The signing input (typically base64url-encoded
                          header + '.' + base64url-encoded payload)

        Returns:
            Raw JOSE signature bytes.
        """
        pass


class LocalPemProvider(SigningProvider):
    """JWT signing using a local PEM-encoded private key.

    This is the default provider. It wraps the current behavior (PyJWT-compatible
    signing) and enables zero-behavior-change when selected.
    """

    def __init__(self, private_key_pem: str, algorithm: str = "ES256"):
        """Initialize with a PEM-encoded private key.

        Args:
            private_key_pem: Private key in PEM format (PKCS8)
            algorithm: Algorithm name (ES256 or RS256)
        """
        self._private_key_pem = private_key_pem
        self._algorithm = algorithm
        self._kid: Optional[str] = None
        self._public_key_pem: Optional[str] = None
        self._compute_kid_and_public_key()

    def _compute_kid_and_public_key(self) -> None:
        """Extract public key and compute kid from the private key."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        from app.utils.crypto import compute_kid_from_public_pem

        private_key = serialization.load_pem_private_key(
            self._private_key_pem.encode(),
            password=None,
            backend=default_backend(),
        )
        public_key_obj = private_key.public_key()
        self._public_key_pem = public_key_obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        self._kid = compute_kid_from_public_pem(self._public_key_pem)

    @property
    def algorithm(self) -> str:
        """Return the algorithm (ES256 or RS256)."""
        return self._algorithm

    @property
    def kid(self) -> str:
        """Return the key ID."""
        return self._kid

    def public_key_pem(self) -> str:
        """Return the public key in PEM format."""
        return self._public_key_pem

    def sign(self, signing_input: bytes) -> bytes:
        """Sign using the private key, producing JOSE-format signature.

        Args:
            signing_input: Either the raw message (will be hashed) or pre-hashed
                          digest (32 bytes for SHA256). If exactly 32 bytes,
                          treated as pre-hashed SHA-256.

        Returns:
            Raw JOSE signature (r||s for ES256, raw for RS256).
        """
        import hashlib
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import ec, padding, utils

        private_key = serialization.load_pem_private_key(
            self._private_key_pem.encode(),
            password=None,
            backend=default_backend(),
        )

        # Determine if input is pre-hashed (32 bytes = SHA-256 digest)
        if len(signing_input) == 32:
            # Assume pre-hashed SHA-256
            message_digest = signing_input
        else:
            # Raw message, hash it
            message_digest = hashlib.sha256(signing_input).digest()

        if self._algorithm == "ES256":
            # ECDSA with SHA-256
            # For pre-hashed input, use Prehashed
            signature_der = private_key.sign(
                message_digest,
                ec.ECDSA(utils.Prehashed(hashes.SHA256())),
            )
            # Convert DER to raw (r||s) JOSE format
            from cryptography.hazmat.primitives.asymmetric.utils import (
                decode_dss_signature,
            )

            r, s = decode_dss_signature(signature_der)
            # P-256 curve produces 256-bit (32-byte) r and s
            return r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")

        elif self._algorithm == "RS256":
            # RSA with SHA-256 (PKCS#1 v1.5)
            return private_key.sign(
                message_digest,
                padding.PKCS1v15(),
                utils.Prehashed(hashes.SHA256()),
            )

        else:
            raise ValueError(f"Unsupported algorithm: {self._algorithm}")


class AwsKmsProvider(SigningProvider):
    """JWT signing using AWS KMS (Key Management Service).

    This provider requires:
    - `AWS_KMS_KEY_ID` env var (ARN or alias)
    - AWS credentials (env vars or IRSA)
    - boto3 package installed
    - Enterprise license tier

    The public key is fetched once and cached. Signatures are computed via
    KMS Sign API and converted from DER to JOSE raw format.
    """

    def __init__(self, key_id: str, algorithm: str = "ES256"):
        """Initialize with an AWS KMS key ID.

        Args:
            key_id: KMS key ID (ARN or alias)
            algorithm: Algorithm name (ES256 or RS256)
        """
        self._key_id = key_id
        self._algorithm = algorithm
        self._kms_client: Optional[object] = None
        self._public_key_pem: Optional[str] = None
        self._kid: Optional[str] = None

        # Lazy-initialize KMS client and fetch public key
        self._initialize()

    def _initialize(self) -> None:
        """Lazy-initialize KMS client and fetch public key."""
        try:
            import boto3
        except ImportError:
            raise ImportError(
                "boto3 is required for AwsKmsProvider. "
                "Install it with: pip install boto3"
            ) from None

        self._kms_client = boto3.client("kms", region_name=None)
        self._fetch_public_key()

    def _fetch_public_key(self) -> None:
        """Fetch the public key from KMS and compute kid."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        from app.utils.crypto import compute_kid_from_public_pem

        try:
            response = self._kms_client.get_public_key(KeyId=self._key_id)
        except Exception as e:
            logger.error(f"Failed to fetch public key from KMS: {e}")
            raise

        # KMS returns DER-encoded public key
        public_key_der = response["PublicKey"]

        # Convert DER to PEM
        public_key_obj = serialization.load_der_public_key(
            public_key_der, backend=default_backend()
        )
        self._public_key_pem = public_key_obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        # Compute kid from the public key
        self._kid = compute_kid_from_public_pem(self._public_key_pem)
        logger.info(f"AwsKmsProvider initialized with kid={self._kid}")

    @property
    def algorithm(self) -> str:
        """Return the algorithm (ES256 or RS256)."""
        return self._algorithm

    @property
    def kid(self) -> str:
        """Return the key ID."""
        return self._kid

    def public_key_pem(self) -> str:
        """Return the public key in PEM format."""
        return self._public_key_pem

    def sign(self, signing_input: bytes) -> bytes:
        """Sign using AWS KMS.

        KMS Sign API returns a DER-encoded ECDSA signature. We convert it
        to raw JOSE format (r||s).

        Args:
            signing_input: The signing input (pre-hashed header.payload)

        Returns:
            Raw JOSE signature bytes (r||s for ECDSA, raw for RSA).
        """
        import hashlib

        try:
            # KMS expects the MessageDigest (pre-hashed) for ECDSA_SHA_256
            message_digest = hashlib.sha256(signing_input).digest()

            response = self._kms_client.sign(
                KeyId=self._key_id,
                Message=message_digest,
                MessageDigest="SHA_256",
                SigningAlgorithm="ECDSA_SHA_256" if self._algorithm == "ES256" else "RSASSA_PKCS1_V1_5_SHA_256",
            )
        except Exception as e:
            logger.error(f"KMS sign operation failed: {e}")
            raise

        signature_der = response["Signature"]

        if self._algorithm == "ES256":
            # Convert DER to raw (r||s) JOSE format
            from cryptography.hazmat.primitives.asymmetric.utils import (
                decode_dss_signature,
            )

            r, s = decode_dss_signature(signature_der)
            # P-256 curve produces 256-bit (32-byte) r and s
            return r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")

        elif self._algorithm == "RS256":
            # RSA signatures are already in raw format
            return signature_der

        else:
            raise ValueError(f"Unsupported algorithm: {self._algorithm}")


def create_signing_provider(
    provider_type: str,
    private_key_pem: Optional[str] = None,
    algorithm: str = "ES256",
) -> SigningProvider:
    """Factory function to create the appropriate signing provider.

    Args:
        provider_type: 'local' (default) or 'aws_kms'
        private_key_pem: PEM private key (required for local provider)
        algorithm: Algorithm name (ES256 or RS256)

    Returns:
        A SigningProvider instance

    Raises:
        ValueError: If config is invalid
    """
    import os

    provider_type = provider_type.lower().strip()

    if provider_type == "local":
        if not private_key_pem:
            raise ValueError("private_key_pem is required for local provider")
        return LocalPemProvider(private_key_pem, algorithm)

    elif provider_type == "aws_kms":
        # Check enterprise license
        from app.services.license_service import LicenseService

        license_service = LicenseService()
        validation = license_service.validate_license()
        tier = validation.get("tier", "community")

        if tier not in ["enterprise", "enterprise_self_hosted", "enterprise_cloud"]:
            raise ValueError(
                f"AWS KMS signing requires Enterprise license (current: {tier}). "
                "Set JWT_SIGNING_PROVIDER=local or upgrade your license."
            )

        key_id = os.getenv("AWS_KMS_KEY_ID")
        if not key_id:
            raise ValueError(
                "AWS_KMS_KEY_ID env var is required for aws_kms provider"
            )

        return AwsKmsProvider(key_id, algorithm)

    else:
        raise ValueError(
            f"Unknown JWT signing provider: {provider_type}. "
            "Supported: 'local', 'aws_kms'"
        )


def build_jws_manually(
    claims: dict,
    provider: SigningProvider,
    headers: Optional[dict] = None,
) -> str:
    """Manually construct a JWS (JSON Web Signature) with a custom signing provider.

    This bypasses PyJWT's internal signing to allow external KMS signing.

    Args:
        claims: JWT payload claims (datetime values are converted to Unix timestamps)
        provider: SigningProvider instance (local or KMS)
        headers: Optional additional headers (typ, kid, etc.)

    Returns:
        Signed JWT string (header.payload.signature in base64url format)
    """
    from datetime import datetime

    # Build the header
    header = {
        "alg": provider.algorithm,
        "typ": "JWT",
    }
    if headers:
        header.update(headers)
    header["kid"] = provider.kid

    # Convert datetime objects to Unix timestamps (JWT standard)
    claims_json_ready = {}
    for key, value in claims.items():
        if isinstance(value, datetime):
            claims_json_ready[key] = int(value.timestamp())
        else:
            claims_json_ready[key] = value

    # Encode header and payload
    header_json = json.dumps(header, separators=(",", ":"), sort_keys=True)
    header_b64 = base64.urlsafe_b64encode(header_json.encode()).rstrip(b"=").decode()

    payload_json = json.dumps(claims_json_ready, separators=(",", ":"), sort_keys=True)
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).rstrip(b"=").decode()

    # Build the signing input
    signing_input = f"{header_b64}.{payload_b64}".encode()

    # Hash the signing input and sign
    import hashlib
    message_hash = hashlib.sha256(signing_input).digest()

    # Sign
    signature_raw = provider.sign(message_hash)

    # Encode signature as base64url
    signature_b64 = base64.urlsafe_b64encode(signature_raw).rstrip(b"=").decode()

    return f"{header_b64}.{payload_b64}.{signature_b64}"
