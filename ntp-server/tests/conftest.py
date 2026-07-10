"""
Test configuration for NTP server tests.
Includes ES256 JWT keypair fixtures for asymmetric token verification.
"""

import pytest
import jwt
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


@pytest.fixture(scope="session")
def jwt_keypair():
    """Generate an ephemeral ES256 keypair for testing."""
    # Generate EC private key (P-256)
    private_key = ec.generate_private_key(
        ec.SECP256R1(), default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    # Extract public key
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return {
        'private': private_pem,
        'public': public_pem
    }


@pytest.fixture
def jwt_token_factory(jwt_keypair):
    """Factory to create valid ES256 JWT tokens for testing."""
    def _make_token(user_id: str = "test-user",
                    global_role: str = "Viewer",
                    scope: str = "ntp:client",
                    tenant: str = "default",
                    issuer: str = "squawk-manager",
                    audience: str = "squawk",
                    expired: bool = False) -> str:
        """Create a valid JWT token with ES256 signature."""
        now = datetime.utcnow()
        if expired:
            exp = now - timedelta(hours=1)
        else:
            exp = now + timedelta(hours=1)

        payload = {
            'sub': user_id,
            'iss': issuer,
            'aud': audience,
            'tenant': tenant,
            'global_role': global_role,
            'scope': scope,
            'exp': exp,
            'iat': now
        }
        return jwt.encode(payload, jwt_keypair['private'], algorithm='ES256')

    return _make_token
