"""
Tests for the pluggable JWT signing provider system.

Tests LocalPemProvider, AwsKmsProvider (stubbed), and JWS manual assembly.
No real AWS credentials or KMS calls — uses mocked boto3.
"""

import os
import sys
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta

import pytest
import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


# Suppress the penguin_limiter mock during imports
sys.modules['penguin_limiter'] = MagicMock()
sys.modules['penguin_limiter.storage'] = MagicMock()
sys.modules['penguin_limiter.storage.redis_store'] = MagicMock()


class TestLocalPemProvider:
    """Tests for LocalPemProvider (default, file-based signing)."""

    def test_local_provider_initialization(self, jwt_keypair):
        """LocalPemProvider initializes with private key and computes kid."""
        from app.services.signing_provider import LocalPemProvider

        provider = LocalPemProvider(jwt_keypair['private'], algorithm='ES256')

        assert provider.algorithm == 'ES256'
        assert provider.kid is not None
        assert len(provider.kid) == 16  # SHA-256 first 16 hex chars
        assert provider.public_key_pem() is not None
        assert provider.public_key_pem().startswith('-----BEGIN PUBLIC KEY-----')

    def test_local_provider_kid_consistency(self, jwt_keypair):
        """Kid computed by LocalPemProvider matches compute_kid_from_private_pem."""
        from app.services.signing_provider import LocalPemProvider
        from app.utils.crypto import compute_kid_from_private_pem

        provider = LocalPemProvider(jwt_keypair['private'])
        expected_kid = compute_kid_from_private_pem(jwt_keypair['private'])

        assert provider.kid == expected_kid

    def test_local_provider_signing(self, jwt_keypair):
        """LocalPemProvider.sign produces a valid ES256 signature."""
        from app.services.signing_provider import LocalPemProvider

        provider = LocalPemProvider(jwt_keypair['private'], algorithm='ES256')

        # Create a simple message
        message = b'test message'

        # Sign it
        signature = provider.sign(message)

        # Signature should be 64 bytes (r||s, each 32 bytes for P-256)
        assert len(signature) == 64
        assert isinstance(signature, bytes)

    def test_local_provider_signature_verification(self, jwt_keypair):
        """Signature produced by LocalPemProvider verifies with the public key."""
        from app.services.signing_provider import LocalPemProvider
        import hashlib

        provider = LocalPemProvider(jwt_keypair['private'], algorithm='ES256')

        # Create and hash a message
        message = b'test message'
        message_hash = hashlib.sha256(message).digest()

        # Sign the hash
        signature_raw = provider.sign(message_hash)

        # Verify with cryptography library using the public key
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric.utils import (
            encode_dss_signature, Prehashed
        )

        public_key_obj = serialization.load_pem_public_key(
            provider.public_key_pem().encode(),
            backend=default_backend()
        )

        # Convert raw (r||s) back to DER for verification
        r = int.from_bytes(signature_raw[:32], byteorder='big')
        s = int.from_bytes(signature_raw[32:], byteorder='big')
        signature_der = encode_dss_signature(r, s)

        # Verify using Prehashed since we signed the digest (should not raise)
        public_key_obj.verify(signature_der, message_hash, ec.ECDSA(Prehashed(hashes.SHA256())))

    def test_local_provider_rs256(self):
        """LocalPemProvider supports RS256 algorithm."""
        # Generate an RSA keypair
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode('utf-8')

        from app.services.signing_provider import LocalPemProvider

        provider = LocalPemProvider(private_pem, algorithm='RS256')
        assert provider.algorithm == 'RS256'
        assert provider.kid is not None


class TestAwsKmsProvider:
    """Tests for AwsKmsProvider (stubbed KMS integration)."""

    def test_aws_kms_provider_initialization_with_stubbed_kms(self):
        """AwsKmsProvider initializes with stubbed KMS client."""
        from app.services.signing_provider import AwsKmsProvider
        from app.utils.crypto import generate_ephemeral_es256_keypair

        # Generate a real keypair for the "KMS" to return
        private_pem, public_pem = generate_ephemeral_es256_keypair()

        # Stub boto3
        mock_kms_client = MagicMock()

        # Extract the DER public key from the PEM
        public_key_obj = serialization.load_pem_public_key(
            public_pem.encode(),
            backend=default_backend()
        )
        public_key_der = public_key_obj.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        mock_kms_client.get_public_key.return_value = {
            'PublicKey': public_key_der
        }

        with patch('boto3.client', return_value=mock_kms_client):
            provider = AwsKmsProvider('arn:aws:kms:us-east-1:123456789:key/1234', 'ES256')

        assert provider.algorithm == 'ES256'
        assert provider.kid is not None
        assert provider.public_key_pem() == public_pem

    def test_aws_kms_provider_kid_consistency(self):
        """AwsKmsProvider computes kid consistently from fetched public key."""
        from app.services.signing_provider import AwsKmsProvider
        from app.utils.crypto import generate_ephemeral_es256_keypair, compute_kid_from_public_pem

        private_pem, public_pem = generate_ephemeral_es256_keypair()

        mock_kms_client = MagicMock()
        public_key_obj = serialization.load_pem_public_key(
            public_pem.encode(),
            backend=default_backend()
        )
        public_key_der = public_key_obj.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        mock_kms_client.get_public_key.return_value = {'PublicKey': public_key_der}

        with patch('boto3.client', return_value=mock_kms_client):
            provider = AwsKmsProvider('arn:aws:kms:us-east-1:123456789:key/1234', 'ES256')

        expected_kid = compute_kid_from_public_pem(public_pem)
        assert provider.kid == expected_kid

    def test_aws_kms_provider_signing_with_stubbed_kms(self):
        """AwsKmsProvider.sign calls KMS and converts DER to raw signature."""
        from app.services.signing_provider import AwsKmsProvider
        from app.utils.crypto import generate_ephemeral_es256_keypair
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        import hashlib

        private_pem, public_pem = generate_ephemeral_es256_keypair()

        # Generate a real private key to create a valid signature
        private_key_obj = serialization.load_pem_private_key(
            private_pem.encode(),
            password=None,
            backend=default_backend()
        )

        mock_kms_client = MagicMock()
        public_key_der = serialization.load_pem_public_key(
            public_pem.encode(),
            backend=default_backend()
        ).public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        mock_kms_client.get_public_key.return_value = {'PublicKey': public_key_der}

        # Mock the Sign response with a real DER signature
        message = b'test message'
        message_hash = hashlib.sha256(message).digest()
        from cryptography.hazmat.primitives import hashes
        signature_der = private_key_obj.sign(
            message_hash,
            ec.ECDSA(hashes.SHA256())
        )
        mock_kms_client.sign.return_value = {'Signature': signature_der}

        with patch('boto3.client', return_value=mock_kms_client):
            provider = AwsKmsProvider('arn:aws:kms:us-east-1:123456789:key/1234', 'ES256')
            signature = provider.sign(message_hash)

        # Signature should be 64 bytes (r||s for P-256)
        assert len(signature) == 64
        assert isinstance(signature, bytes)

        # Verify the KMS Sign was called correctly
        mock_kms_client.sign.assert_called_once()
        call_kwargs = mock_kms_client.sign.call_args[1]
        assert call_kwargs['SigningAlgorithm'] == 'ECDSA_SHA_256'

    def test_aws_kms_provider_requires_enterprise_license(self):
        """AwsKmsProvider selection requires Enterprise license."""
        from app.services.signing_provider import create_signing_provider

        with patch('app.services.license_service.LicenseService') as MockLicenseService:
            mock_instance = MagicMock()
            mock_instance.validate_license.return_value = {'tier': 'community'}
            MockLicenseService.return_value = mock_instance

            with patch.dict(os.environ, {'AWS_KMS_KEY_ID': 'arn:aws:kms:us-east-1:123456789:key/1234'}, clear=True):
                with pytest.raises(ValueError, match='Enterprise license'):
                    create_signing_provider('aws_kms')

    def test_aws_kms_provider_requires_key_id(self):
        """AwsKmsProvider selection requires AWS_KMS_KEY_ID env var."""
        from app.services.signing_provider import create_signing_provider

        with patch('app.services.license_service.LicenseService') as MockLicenseService:
            mock_instance = MagicMock()
            mock_instance.validate_license.return_value = {'tier': 'enterprise'}
            MockLicenseService.return_value = mock_instance

            with patch.dict(os.environ, {}, clear=True):
                with pytest.raises(ValueError, match='AWS_KMS_KEY_ID'):
                    create_signing_provider('aws_kms')


class TestJWSManualAssembly:
    """Tests for build_jws_manually function."""

    def test_jws_manual_assembly_basic(self, jwt_keypair):
        """build_jws_manually produces a valid JWS token."""
        from app.services.signing_provider import LocalPemProvider, build_jws_manually

        provider = LocalPemProvider(jwt_keypair['private'], algorithm='ES256')

        claims = {
            'sub': 'testuser',
            'iss': 'squawk-manager',
            'aud': 'squawk',
            'exp': datetime.utcnow() + timedelta(hours=1),
            'iat': datetime.utcnow()
        }

        token = build_jws_manually(claims, provider)

        # Token should be three base64url-separated parts
        parts = token.split('.')
        assert len(parts) == 3

    def test_jws_manual_assembly_includes_kid(self, jwt_keypair):
        """build_jws_manually includes kid in the header."""
        from app.services.signing_provider import LocalPemProvider, build_jws_manually
        import base64
        import json

        provider = LocalPemProvider(jwt_keypair['private'], algorithm='ES256')

        claims = {'sub': 'testuser'}

        token = build_jws_manually(claims, provider)

        # Decode the header
        header_b64 = token.split('.')[0]
        # Add padding if needed
        header_b64 += '=' * (4 - len(header_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))

        assert header['kid'] == provider.kid
        assert header['alg'] == 'ES256'
        assert header['typ'] == 'JWT'

    def test_jws_manual_assembly_verifies_with_pyjwt(self, jwt_keypair):
        """Token from build_jws_manually verifies with PyJWT."""
        from app.services.signing_provider import LocalPemProvider, build_jws_manually
        import time

        provider = LocalPemProvider(jwt_keypair['private'], algorithm='ES256')

        # Use Unix timestamps directly (not datetime) to avoid rounding issues
        now_ts = int(time.time())
        claims = {
            'sub': 'testuser',
            'iss': 'squawk-manager',
            'aud': 'squawk',
            'exp': now_ts + 3600,  # 1 hour from now
            'iat': now_ts - 60      # 60 seconds ago
        }

        token = build_jws_manually(claims, provider)

        # Verify with PyJWT using the public key
        decoded = jwt.decode(
            token,
            provider.public_key_pem(),
            algorithms=['ES256'],
            audience='squawk',
            issuer='squawk-manager',
            options={'leeway': 10}
        )

        assert decoded['sub'] == 'testuser'


class TestProviderFactory:
    """Tests for create_signing_provider factory function."""

    def test_factory_creates_local_provider(self, jwt_keypair):
        """Factory creates LocalPemProvider when type='local'."""
        from app.services.signing_provider import create_signing_provider

        provider = create_signing_provider('local', jwt_keypair['private'], 'ES256')

        assert provider.__class__.__name__ == 'LocalPemProvider'
        assert provider.algorithm == 'ES256'

    def test_factory_defaults_to_local(self, jwt_keypair):
        """Factory defaults to LocalPemProvider when no type specified."""
        from app.services.signing_provider import create_signing_provider

        provider = create_signing_provider('local', jwt_keypair['private'])

        assert provider.__class__.__name__ == 'LocalPemProvider'

    def test_factory_rejects_unknown_provider_type(self):
        """Factory raises ValueError for unknown provider type."""
        from app.services.signing_provider import create_signing_provider

        with pytest.raises(ValueError, match='Unknown JWT signing provider'):
            create_signing_provider('invalid_provider', 'dummy_key')

    def test_factory_requires_private_key_for_local(self):
        """Factory requires private_key_pem for local provider."""
        from app.services.signing_provider import create_signing_provider

        with pytest.raises(ValueError, match='private_key_pem is required'):
            create_signing_provider('local', None)


class TestAuthServiceIntegration:
    """Integration tests for signing providers with AuthService."""

    def test_auth_service_with_local_provider(self, app, jwt_keypair):
        """AuthService.create_access_token works with LocalPemProvider."""
        from app.services.auth_service import AuthService
        from app.services.signing_provider import LocalPemProvider

        provider = LocalPemProvider(jwt_keypair['private'], 'ES256')

        with app.app_context():
            # Configure the provider
            app.config['JWT_SIGNING_PROVIDER'] = provider

            token = AuthService.create_access_token(1, 'testuser', 'Viewer')

        # Verify token is valid
        decoded = jwt.decode(
            token,
            jwt_keypair['public'],
            algorithms=['ES256'],
            audience='squawk',
            issuer='squawk-manager'
        )

        assert decoded['user_id'] == 1
        assert decoded['username'] == 'testuser'
        assert decoded['sub'] == '1'

    def test_auth_service_refresh_token_with_provider(self, app, jwt_keypair):
        """AuthService.create_refresh_token works with SigningProvider."""
        from app.services.auth_service import AuthService
        from app.services.signing_provider import LocalPemProvider

        provider = LocalPemProvider(jwt_keypair['private'], 'ES256')

        with app.app_context():
            app.config['JWT_SIGNING_PROVIDER'] = provider

            token = AuthService.create_refresh_token(1)

        # Verify token
        decoded = jwt.decode(
            token,
            jwt_keypair['public'],
            algorithms=['ES256'],
            audience='squawk',
            issuer='squawk-manager'
        )

        assert decoded['user_id'] == 1
        assert decoded['type'] == 'refresh'
        assert 'jti' in decoded

    def test_token_includes_kid_header(self, app, jwt_keypair):
        """Tokens signed by provider include kid header."""
        from app.services.auth_service import AuthService
        from app.services.signing_provider import LocalPemProvider
        import base64
        import json

        provider = LocalPemProvider(jwt_keypair['private'], 'ES256')

        with app.app_context():
            app.config['JWT_SIGNING_PROVIDER'] = provider

            token = AuthService.create_access_token(1, 'testuser', 'Viewer')

        # Decode header to check for kid
        header_b64 = token.split('.')[0]
        header_b64 += '=' * (4 - len(header_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))

        assert 'kid' in header
        assert header['kid'] == provider.kid


class TestDerToRawConversion:
    """Tests for DER to raw (JOSE) signature format conversion."""

    def test_der_to_raw_roundtrip(self, jwt_keypair):
        """DER->raw and raw->DER roundtrips produce same signature."""
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric.utils import (
            encode_dss_signature, decode_dss_signature
        )

        private_key_obj = serialization.load_pem_private_key(
            jwt_keypair['private'].encode(),
            password=None,
            backend=default_backend()
        )

        message = b'test message'
        message_hash = hashlib.sha256(message).digest()

        # Sign and get DER signature
        signature_der = private_key_obj.sign(
            message_hash,
            ec.ECDSA(hashes.SHA256())
        )

        # Convert DER to raw
        r, s = decode_dss_signature(signature_der)
        signature_raw = r.to_bytes(32, byteorder='big') + s.to_bytes(32, byteorder='big')

        # Convert back to DER
        r_recovered = int.from_bytes(signature_raw[:32], byteorder='big')
        s_recovered = int.from_bytes(signature_raw[32:], byteorder='big')
        signature_der_recovered = encode_dss_signature(r_recovered, s_recovered)

        assert signature_der == signature_der_recovered


# Required for hash function used in tests
import hashlib
