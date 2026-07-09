"""
Comprehensive tests for mTLS Certificate Manager.
Tests CA creation, server/client cert lifecycle, verification, rotation, and revocation.
"""

import pytest
import tempfile
import datetime
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# Import the CertManager service
from cert_manager import CertManager, CertificateInfo, VerificationResult


@pytest.fixture
def temp_cert_dir():
    """Create a temporary certificate directory."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        yield tmp_dir


@pytest.fixture
def temp_db_url(temp_cert_dir):
    """Create a temporary SQLite database for certificate persistence."""
    import tempfile
    import sqlite3

    db_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    db_path = db_file.name
    db_file.close()

    # Create minimal schema for mtls tables
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mtls_certificate (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cert_type VARCHAR(20) NOT NULL,
            common_name VARCHAR(255) NOT NULL,
            serial_number VARCHAR(255) NOT NULL UNIQUE,
            fingerprint_sha256 VARCHAR(64) NOT NULL UNIQUE,
            pem_certificate TEXT NOT NULL,
            issued_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            not_valid_before DATETIME NOT NULL,
            not_valid_after DATETIME NOT NULL,
            is_revoked BOOLEAN NOT NULL DEFAULT 0,
            revoked_at DATETIME,
            revocation_reason VARCHAR(255),
            subject_dn VARCHAR(512) NOT NULL,
            issuer_dn VARCHAR(512) NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mtls_revocation (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            serial_number VARCHAR(255) NOT NULL UNIQUE,
            common_name VARCHAR(255) NOT NULL,
            revoked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            revocation_reason VARCHAR(255),
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()

    yield f"sqlite:///{db_path}"

    # Cleanup
    import os
    try:
        os.unlink(db_path)
    except Exception:
        pass


@pytest.fixture
def cert_manager(temp_cert_dir, temp_db_url):
    """Create a CertManager instance with mTLS enabled and database for testing."""
    return CertManager(cert_dir=temp_cert_dir, db_url=temp_db_url, mtls_enabled=True)


class TestCACreation:
    """Test CA certificate creation and loading."""

    def test_create_ca_success(self, cert_manager):
        """Test successful CA certificate creation."""
        result = cert_manager.create_ca()
        assert result is True
        assert cert_manager.ca_cert_path.exists()
        assert cert_manager.ca_key_path.exists()

    def test_create_ca_twice_no_force(self, cert_manager):
        """Test that creating CA twice without force returns False."""
        result1 = cert_manager.create_ca()
        assert result1 is True

        result2 = cert_manager.create_ca(force=False)
        assert result2 is False

    def test_create_ca_force_regeneration(self, cert_manager):
        """Test force regeneration of CA."""
        result1 = cert_manager.create_ca()
        assert result1 is True

        original_cert = cert_manager._load_certificate(cert_manager.ca_cert_path)
        original_serial = original_cert.serial_number

        # Force regeneration
        result2 = cert_manager.create_ca(force=True)
        assert result2 is True

        new_cert = cert_manager._load_certificate(cert_manager.ca_cert_path)
        new_serial = new_cert.serial_number

        # Serial numbers should be different
        assert original_serial != new_serial

    def test_ca_certificate_properties(self, cert_manager):
        """Test CA certificate has correct properties."""
        cert_manager.create_ca()

        ca_cert = cert_manager._load_certificate(cert_manager.ca_cert_path)

        # Check basic properties
        assert ca_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[
            0
        ].value == "Squawk DNS CA"
        assert ca_cert.issuer == ca_cert.subject  # Self-signed

        # Check CA constraints
        ca_constraints = ca_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        assert ca_constraints.value.ca is True
        assert ca_constraints.critical is True

    def test_ca_certificate_validity(self, cert_manager):
        """Test CA certificate has correct validity period."""
        cert_manager.create_ca()

        ca_cert = cert_manager._load_certificate(cert_manager.ca_cert_path)
        now = datetime.datetime.utcnow()

        # Should be valid immediately
        assert ca_cert.not_valid_before <= now
        # Should be valid for approximately CA_VALIDITY_DAYS
        expected_expiry = now + datetime.timedelta(
            days=cert_manager.ca_validity_days
        )
        # Allow 1 minute tolerance
        delta = abs((ca_cert.not_valid_after - expected_expiry).total_seconds())
        assert delta < 60


class TestServerCertificate:
    """Test server certificate creation and properties."""

    def test_create_server_cert_without_ca(self, cert_manager):
        """Test server cert creation auto-creates CA if needed."""
        result = cert_manager.create_server_cert()
        assert result is True
        assert cert_manager.ca_cert_path.exists()
        assert cert_manager.server_cert_path.exists()
        assert cert_manager.server_key_path.exists()

    def test_create_server_cert_with_hostname(self, cert_manager):
        """Test server cert creation with specific hostname."""
        cert_manager.create_ca()
        result = cert_manager.create_server_cert(hostname="dns.example.com")
        assert result is True

        server_cert = cert_manager._load_certificate(cert_manager.server_cert_path)
        cn = server_cert.subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME
        )[0].value
        assert cn == "dns.example.com"

    def test_create_server_cert_with_sans(self, cert_manager):
        """Test server cert creation with SANs."""
        cert_manager.create_ca()
        ip_addresses = ["192.168.1.1", "10.0.0.1"]
        result = cert_manager.create_server_cert(
            hostname="dns.example.com", ip_addresses=ip_addresses
        )
        assert result is True

        server_cert = cert_manager._load_certificate(cert_manager.server_cert_path)

        # Check SANs
        san_ext = server_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        sans = san_ext.value

        # Should have hostname and IPs
        san_strings = [str(san) for san in sans]
        assert any("dns.example.com" in s for s in san_strings)
        assert any("192.168.1.1" in s for s in san_strings)
        assert any("10.0.0.1" in s for s in san_strings)

    def test_server_cert_signed_by_ca(self, cert_manager):
        """Test that server cert is signed by CA."""
        cert_manager.create_ca()
        cert_manager.create_server_cert()

        server_cert = cert_manager._load_certificate(cert_manager.server_cert_path)
        ca_cert = cert_manager._load_certificate(cert_manager.ca_cert_path)

        # Issuer should match CA subject
        assert server_cert.issuer == ca_cert.subject

    def test_server_cert_key_usage(self, cert_manager):
        """Test server cert has correct key usage."""
        cert_manager.create_ca()
        cert_manager.create_server_cert()

        server_cert = cert_manager._load_certificate(cert_manager.server_cert_path)

        key_usage = server_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.KEY_USAGE
        )
        assert key_usage.value.digital_signature is True
        assert key_usage.value.key_encipherment is True


class TestClientCertificate:
    """Test client certificate creation and identity extraction."""

    def test_create_client_cert_success(self, cert_manager):
        """Test successful client certificate creation."""
        cert_manager.create_ca()

        result = cert_manager.create_client_cert("client1")
        assert result is not None
        assert isinstance(result, str)
        assert "-----BEGIN CERTIFICATE-----" in result

    def test_create_client_cert_without_ca(self, cert_manager):
        """Test client cert creation auto-creates CA if needed."""
        result = cert_manager.create_client_cert("client1")
        assert result is not None
        assert cert_manager.ca_cert_path.exists()

    def test_client_cert_common_name(self, cert_manager):
        """Test client certificate has correct common name (identity)."""
        cert_manager.create_ca()
        result = cert_manager.create_client_cert("test-client-123")

        assert result is not None

        # Load the PEM and parse it
        from cryptography import x509 as x509_module
        from cryptography.hazmat.backends import default_backend

        cert = x509_module.load_pem_x509_certificate(
            result.encode(), default_backend()
        )

        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        assert cn == "test-client-123"

    def test_client_cert_file_creation(self, cert_manager):
        """Test client cert files are created."""
        cert_manager.create_ca()
        cert_manager.create_client_cert("client1")

        client_key = cert_manager.clients_dir / "client1.key"
        client_cert = cert_manager.clients_dir / "client1.crt"

        assert client_key.exists()
        assert client_cert.exists()

    def test_create_multiple_client_certs(self, cert_manager):
        """Test creating multiple client certificates."""
        cert_manager.create_ca()

        result1 = cert_manager.create_client_cert("client1")
        result2 = cert_manager.create_client_cert("client2")

        assert result1 is not None
        assert result2 is not None

        from cryptography import x509 as x509_module

        cert1 = x509_module.load_pem_x509_certificate(
            result1.encode(), default_backend()
        )
        cert2 = x509_module.load_pem_x509_certificate(
            result2.encode(), default_backend()
        )

        cn1 = cert1.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[
            0
        ].value
        cn2 = cert2.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[
            0
        ].value

        assert cn1 == "client1"
        assert cn2 == "client2"

    def test_client_cert_extended_key_usage(self, cert_manager):
        """Test client cert has CLIENT_AUTH extended key usage."""
        cert_manager.create_ca()
        result = cert_manager.create_client_cert("client1")

        from cryptography import x509 as x509_module

        cert = x509_module.load_pem_x509_certificate(
            result.encode(), default_backend()
        )

        eku_ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.EXTENDED_KEY_USAGE
        )
        assert x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in eku_ext.value


class TestVerification:
    """Test certificate verification against CA."""

    def test_verify_valid_client_cert(self, cert_manager):
        """Test verification of a valid client certificate."""
        cert_manager.create_ca()
        cert_pem = cert_manager.create_client_cert("client1")

        result = cert_manager.verify_client_cert(cert_pem)

        assert result.valid is True
        assert result.common_name == "client1"
        assert result.is_expired is False
        assert result.is_revoked is False

    def test_verify_with_wrong_ca(self, cert_manager):
        """Test verification fails with different CA."""
        cert_manager.create_ca()
        cert_pem = cert_manager.create_client_cert("client1")

        # Create new CA (different one)
        cert_manager.create_ca(force=True)

        # Original cert should not verify against new CA
        result = cert_manager.verify_client_cert(cert_pem)

        assert result.valid is False
        assert "Signature verification failed" in result.reason

    def test_verify_expired_cert(self, cert_manager):
        """Test verification rejects expired certificates."""
        cert_manager.create_ca()
        cert_pem = cert_manager.create_client_cert("client1")

        # Parse and modify to be expired
        from cryptography import x509 as x509_module
        from unittest.mock import patch

        # Mock datetime to return future date
        future_date = datetime.datetime.utcnow() + datetime.timedelta(days=400)

        with patch("datetime.datetime") as mock_datetime:
            mock_datetime.utcnow.return_value = future_date
            mock_datetime.side_effect = lambda *args, **kw: datetime.datetime(
                *args, **kw
            )

            result = cert_manager.verify_client_cert(cert_pem)

        # Should detect as expired
        assert result.valid is False
        assert result.is_expired is True

    def test_verify_tampered_cert(self, cert_manager):
        """Test verification rejects tampered certificates."""
        cert_manager.create_ca()
        cert_pem = cert_manager.create_client_cert("client1")

        # Tamper with the cert
        tampered_pem = cert_pem.replace("CERTIFICATE", "CORRUPTED")

        result = cert_manager.verify_client_cert(tampered_pem)

        assert result.valid is False
        assert result.reason is not None


class TestRevocation:
    """Test certificate revocation."""

    def test_revoke_client_cert(self, cert_manager):
        """Test revoking a client certificate."""
        cert_manager.create_ca()
        cert_pem = cert_manager.create_client_cert("client1")

        # Revoke it
        result = cert_manager.revoke_client_cert("client1", reason="Compromised")
        assert result is True

        # Verification should fail
        verify_result = cert_manager.verify_client_cert(cert_pem)
        assert verify_result.valid is False
        assert verify_result.is_revoked is True

    def test_revoke_nonexistent_cert(self, cert_manager):
        """Test revoking a nonexistent certificate."""
        result = cert_manager.revoke_client_cert("nonexistent")
        assert result is False

    def test_revoked_cert_appears_revoked(self, cert_manager):
        """Test that revoked cert is marked as revoked in revocation table."""
        cert_manager.create_ca()
        cert_pem = cert_manager.create_client_cert("client1")

        # Extract serial from cert
        from cryptography import x509 as x509_module

        cert = x509_module.load_pem_x509_certificate(
            cert_pem.encode(), default_backend()
        )
        serial = str(cert.serial_number)

        # Revoke
        cert_manager.revoke_client_cert("client1", reason="Test revocation")

        # Check revocation status
        is_revoked = cert_manager._is_revoked(serial)
        assert is_revoked is True


class TestRotation:
    """Test certificate rotation."""

    def test_rotate_server_cert(self, cert_manager):
        """Test rotating server certificate."""
        cert_manager.create_ca()
        cert_manager.create_server_cert(hostname="dns.example.com")

        original_cert = cert_manager._load_certificate(cert_manager.server_cert_path)
        original_serial = original_cert.serial_number

        # Rotate
        result = cert_manager.rotate_server_cert()
        assert result is True

        new_cert = cert_manager._load_certificate(cert_manager.server_cert_path)
        new_serial = new_cert.serial_number

        # Should have different serial
        assert original_serial != new_serial
        # Should have same CN
        assert (
            original_cert.subject.get_attributes_for_oid(
                x509.oid.NameOID.COMMON_NAME
            )[0].value
            == new_cert.subject.get_attributes_for_oid(
                x509.oid.NameOID.COMMON_NAME
            )[0].value
        )

    def test_rotate_nonexistent_server_cert(self, cert_manager):
        """Test rotating when server cert doesn't exist creates it."""
        cert_manager.create_ca()

        result = cert_manager.rotate_server_cert()
        assert result is True
        assert cert_manager.server_cert_path.exists()


class TestExpiryChecks:
    """Test certificate expiry detection."""

    def test_check_expiry_no_certs(self, cert_manager):
        """Test expiry check with no certificates."""
        result = cert_manager.check_cert_expiry(days_before=30)

        assert result["ca"] == []
        assert result["server"] == []
        assert result["clients"] == []

    def test_check_expiry_future_certs(self, cert_manager):
        """Test expiry check with non-expiring certs."""
        cert_manager.create_ca()
        cert_manager.create_server_cert()
        cert_manager.create_client_cert("client1")

        result = cert_manager.check_cert_expiry(days_before=30)

        # Should not be expiring soon
        assert result["ca"] == []
        assert result["server"] == []
        assert result["clients"] == []

    def test_check_expiry_soon_expiring(self, cert_manager):
        """Test expiry check detects soon-expiring certs."""
        cert_manager.create_ca()
        cert_manager.create_server_cert()

        # Check for expiry within 365 days (all new certs should match)
        result = cert_manager.check_cert_expiry(days_before=365)

        # Should detect server cert as soon-expiring
        assert len(result["server"]) > 0
        assert result["server"][0]["cn"] is not None


class TestFeatureGating:
    """Test PostHog feature flag integration."""

    def test_mtls_disabled_by_default(self, temp_cert_dir):
        """Test mTLS is disabled by default."""
        # Create manager without explicit mtls_enabled
        manager = CertManager(cert_dir=temp_cert_dir, db_url=None)
        assert manager.mtls_enabled is False

    def test_mtls_disabled_prevents_ca_creation(self, temp_cert_dir):
        """Test that CA creation fails when mTLS is disabled."""
        manager = CertManager(cert_dir=temp_cert_dir, db_url=None, mtls_enabled=False)
        result = manager.create_ca()
        assert result is False

    def test_mtls_disabled_prevents_server_cert(self, temp_cert_dir):
        """Test that server cert creation fails when mTLS is disabled."""
        manager = CertManager(cert_dir=temp_cert_dir, db_url=None, mtls_enabled=False)
        result = manager.create_server_cert()
        assert result is False

    def test_mtls_disabled_prevents_client_cert(self, temp_cert_dir):
        """Test that client cert creation fails when mTLS is disabled."""
        manager = CertManager(cert_dir=temp_cert_dir, db_url=None, mtls_enabled=False)
        result = manager.create_client_cert("client1")
        assert result is None

    def test_mtls_disabled_verification_fails(self, temp_cert_dir):
        """Test that verification fails when mTLS is disabled."""
        manager = CertManager(cert_dir=temp_cert_dir, db_url=None, mtls_enabled=False)
        result = manager.verify_client_cert("test-cert-pem")

        assert result.valid is False
        assert "mTLS not enabled" in result.reason


class TestCertificateInfo:
    """Test certificate info extraction."""

    def test_extract_cert_info(self, cert_manager):
        """Test extracting certificate information."""
        cert_manager.create_ca()
        ca_cert = cert_manager._load_certificate(cert_manager.ca_cert_path)

        info = cert_manager._extract_cert_info(ca_cert, "ca")

        assert info.cert_type == "ca"
        assert info.common_name == "Squawk DNS CA"
        assert len(info.serial_number) > 0
        assert len(info.fingerprint_sha256) == 64  # SHA256 hex = 64 chars
        assert info.subject_dn is not None
        assert info.issuer_dn is not None


class TestExtractCommonName:
    """Test Common Name extraction from certificates."""

    def test_extract_cn_from_ca(self, cert_manager):
        """Test extracting CN from CA certificate."""
        cert_manager.create_ca()
        ca_cert = cert_manager._load_certificate(cert_manager.ca_cert_path)

        cn = cert_manager._extract_common_name(ca_cert)
        assert cn == "Squawk DNS CA"

    def test_extract_cn_from_server_cert(self, cert_manager):
        """Test extracting CN from server certificate."""
        cert_manager.create_ca()
        cert_manager.create_server_cert(hostname="example.com")
        server_cert = cert_manager._load_certificate(cert_manager.server_cert_path)

        cn = cert_manager._extract_common_name(server_cert)
        assert cn == "example.com"

    def test_extract_cn_from_client_cert(self, cert_manager):
        """Test extracting CN from client certificate."""
        cert_manager.create_ca()
        cert_pem = cert_manager.create_client_cert("user@example.com")

        from cryptography import x509 as x509_module

        cert = x509_module.load_pem_x509_certificate(
            cert_pem.encode(), default_backend()
        )

        cn = cert_manager._extract_common_name(cert)
        assert cn == "user@example.com"


class TestIntegration:
    """Integration tests for full certificate lifecycle."""

    def test_full_lifecycle(self, cert_manager):
        """Test complete CA -> Server -> Client -> Verify -> Revoke lifecycle."""
        # Step 1: Create CA
        ca_result = cert_manager.create_ca()
        assert ca_result is True

        # Step 2: Create Server Cert
        server_result = cert_manager.create_server_cert(hostname="dns.example.com")
        assert server_result is True

        # Step 3: Create Client Cert
        client_pem = cert_manager.create_client_cert("admin@example.com")
        assert client_pem is not None

        # Step 4: Verify Client Cert
        verify_result = cert_manager.verify_client_cert(client_pem)
        assert verify_result.valid is True
        assert verify_result.common_name == "admin@example.com"

        # Step 5: Revoke Client Cert
        revoke_result = cert_manager.revoke_client_cert(
            "admin@example.com", reason="Removed from team"
        )
        assert revoke_result is True

        # Step 6: Verify Revoked Cert
        verify_result = cert_manager.verify_client_cert(client_pem)
        assert verify_result.valid is False
        assert verify_result.is_revoked is True

    def test_multiple_clients_independent(self, cert_manager):
        """Test multiple client certificates are independent."""
        cert_manager.create_ca()

        client1_pem = cert_manager.create_client_cert("client1")
        client2_pem = cert_manager.create_client_cert("client2")

        # Both should verify
        v1 = cert_manager.verify_client_cert(client1_pem)
        v2 = cert_manager.verify_client_cert(client2_pem)

        assert v1.valid is True
        assert v2.valid is True
        assert v1.common_name == "client1"
        assert v2.common_name == "client2"

        # Revoke client1
        cert_manager.revoke_client_cert("client1")

        # client1 should fail, client2 should still pass
        v1_after = cert_manager.verify_client_cert(client1_pem)
        v2_after = cert_manager.verify_client_cert(client2_pem)

        assert v1_after.valid is False
        assert v2_after.valid is True
