"""
mTLS Certificate Manager for Squawk DNS
Manages CA, server, and client certificate lifecycle with PostHog feature gating.
Persists certificate metadata to database via penguin-dal.
"""

from __future__ import annotations

import datetime
import ipaddress
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class CertificateInfo:
    """Certificate information extracted from an X.509 certificate."""
    cert_type: str
    common_name: str
    serial_number: str
    fingerprint_sha256: str
    not_valid_before: datetime.datetime
    not_valid_after: datetime.datetime
    subject_dn: str
    issuer_dn: str
    is_revoked: bool = False


@dataclass(slots=True)
class VerificationResult:
    """Result of certificate verification against CA."""
    valid: bool
    reason: Optional[str] = None
    common_name: Optional[str] = None
    is_expired: bool = False
    is_revoked: bool = False


class CertManager:
    """
    mTLS Certificate Manager with PostHog feature gating.
    Persists to database via penguin-dal.
    """

    def __init__(
        self,
        cert_dir: str = "/app/certs",
        db_url: Optional[str] = None,
        mtls_enabled: Optional[bool] = None,
    ) -> None:
        """
        Initialize certificate manager.

        Args:
            cert_dir: Directory for storing certificate files
            db_url: Database URL for penguin-dal persistence
            mtls_enabled: Override feature flag (for testing)
        """
        self.cert_dir = Path(cert_dir)
        self.cert_dir.mkdir(parents=True, exist_ok=True)

        self.db_url = db_url
        self._db = None

        # Certificate paths
        self.ca_key_path = self.cert_dir / "ca.key"
        self.ca_cert_path = self.cert_dir / "ca.crt"
        self.server_key_path = self.cert_dir / "server.key"
        self.server_cert_path = self.cert_dir / "server.crt"
        self.clients_dir = self.cert_dir / "clients"
        self.clients_dir.mkdir(exist_ok=True)

        # Certificate validity periods (days)
        self.ca_validity_days = int(os.getenv("CA_VALIDITY_DAYS", "3650"))  # 10 years
        self.cert_validity_days = int(os.getenv("CERT_VALIDITY_DAYS", "365"))  # 1 year

        # Feature gating: PostHog flag 'squawkdns.mtls' (default OFF)
        self.mtls_enabled = mtls_enabled
        if self.mtls_enabled is None:
            self.mtls_enabled = self._check_mtls_feature_flag()

        # Key algorithm: ECC preferred
        self.use_ecc = os.getenv("USE_ECC_KEYS", "true").lower() == "true"
        self.ecc_curve = getattr(ec, os.getenv("ECC_CURVE", "SECP384R1"))()

        if self.mtls_enabled:
            logger.info("mTLS certificate management enabled")
        else:
            logger.info("mTLS certificate management disabled")

    def _check_mtls_feature_flag(self) -> bool:
        """
        Check PostHog feature flag 'squawkdns.mtls' with graceful degradation.
        Returns False if flag server unreachable (safe fail).
        """
        try:
            # Try to import and use PostHog if available
            try:
                from manager.backend.app.services.posthog_client import PostHogClient
            except ImportError:
                logger.debug("PostHogClient not available, using default mTLS=False")
                return False

            client = PostHogClient()
            # Deployment-wide distinct_id for mTLS feature flag
            distinct_id = os.getenv("DEPLOYMENT_ID", "default")
            return client.feature_enabled("squawkdns.mtls", distinct_id, default=False)
        except Exception as e:
            logger.warning(
                f"Failed to check mTLS feature flag, defaulting to False: {e}"
            )
            return False

    def _get_db(self):
        """Get or create penguin-dal DB instance."""
        if not self.db_url:
            return None

        if not self._db:
            try:
                from penguin_dal import DB
                self._db = DB(self.db_url)
            except Exception as e:
                logger.error(f"Failed to create database connection: {e}")
                return None

        return self._db

    def _get_signing_algorithm(self):
        """Get appropriate signing algorithm based on key type."""
        if self.use_ecc:
            return hashes.SHA384()
        return hashes.SHA256()

    def _generate_private_key(self):
        """Generate a private key (ECC preferred, RSA fallback)."""
        if self.use_ecc:
            return ec.generate_private_key(self.ecc_curve, backend=default_backend())
        return rsa.generate_private_key(
            public_exponent=65537, key_size=4096, backend=default_backend()
        )

    def _save_private_key(
        self, key, filepath: Path, password: Optional[str] = None
    ) -> None:
        """Save private key to file with secure permissions.

        The file is created via os.open() with mode 0600 already applied at
        creation time, rather than written first and chmod'd afterward --
        that write-then-chmod ordering leaves a window at the process umask
        default (commonly 0644/0664) where the key is world/group readable.
        """
        encryption = serialization.NoEncryption()
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode())

        key_bytes = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption,
        )
        fd = os.open(filepath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key_bytes)

    def _load_private_key(
        self, filepath: Path, password: Optional[str] = None
    ):
        """Load private key from file."""
        with open(filepath, "rb") as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=password.encode() if password else None,
                backend=default_backend(),
            )

    def _save_certificate(self, cert, filepath: Path) -> None:
        """Save certificate to file with readable permissions."""
        with open(filepath, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        os.chmod(filepath, 0o644)

    def _load_certificate(self, filepath: Path):
        """Load certificate from file."""
        with open(filepath, "rb") as f:
            return x509.load_pem_x509_certificate(f.read(), default_backend())

    def _extract_cert_info(
        self, cert, cert_type: str
    ) -> CertificateInfo:
        """Extract structured information from X.509 certificate."""
        try:
            cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            common_name = cn_attr[0].value if cn_attr else "Unknown"
        except Exception:
            common_name = "Unknown"

        return CertificateInfo(
            cert_type=cert_type,
            common_name=common_name,
            serial_number=str(cert.serial_number),
            fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(),
            not_valid_before=cert.not_valid_before,
            not_valid_after=cert.not_valid_after,
            subject_dn=cert.subject.rfc4514_string(),
            issuer_dn=cert.issuer.rfc4514_string(),
        )

    def _persist_certificate(self, cert_info: CertificateInfo) -> None:
        """Persist certificate metadata to database if configured via penguin-dal."""
        if not self.db_url:
            logger.debug("No database URL configured, skipping persistence")
            return

        try:
            db = self._get_db()
            if not db:
                return

            # Check if already exists
            existing = db(
                db.mtls_certificate.serial_number == cert_info.serial_number
            ).select()
            if existing:
                logger.debug(
                    f"Certificate {cert_info.serial_number} already persisted"
                )
                return

            # Insert via penguin-dal
            db.mtls_certificate.insert(
                cert_type=cert_info.cert_type,
                common_name=cert_info.common_name,
                serial_number=cert_info.serial_number,
                fingerprint_sha256=cert_info.fingerprint_sha256,
                pem_certificate="",
                not_valid_before=cert_info.not_valid_before,
                not_valid_after=cert_info.not_valid_after,
                is_revoked=False,
                subject_dn=cert_info.subject_dn,
                issuer_dn=cert_info.issuer_dn,
            )
            db.commit()

            logger.info(
                f"Persisted certificate {cert_info.common_name} "
                f"({cert_info.serial_number}) to database"
            )
        except Exception as e:
            logger.error(f"Failed to persist certificate to database: {e}")

    def create_ca(self, force: bool = False) -> bool:
        """
        Create or load CA certificate and key.

        Args:
            force: Force regeneration if CA already exists

        Returns:
            True if CA created, False if already exists
        """
        if not self.mtls_enabled:
            logger.warning("mTLS not enabled, skipping CA creation")
            return False

        if not force and self.ca_cert_path.exists() and self.ca_key_path.exists():
            logger.info(f"CA certificate already exists at {self.ca_cert_path}")
            return False

        logger.info("Generating CA certificate...")

        # Generate CA private key
        ca_key = self._generate_private_key()

        # Build CA subject
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, os.getenv("CA_COUNTRY", "US")),
                x509.NameAttribute(
                    NameOID.STATE_OR_PROVINCE_NAME, os.getenv("CA_STATE", "State")
                ),
                x509.NameAttribute(
                    NameOID.LOCALITY_NAME, os.getenv("CA_LOCALITY", "City")
                ),
                x509.NameAttribute(
                    NameOID.ORGANIZATION_NAME, os.getenv("CA_ORG", "Squawk DNS")
                ),
                x509.NameAttribute(
                    NameOID.ORGANIZATIONAL_UNIT_NAME,
                    os.getenv("CA_OU", "Certificate Authority"),
                ),
                x509.NameAttribute(
                    NameOID.COMMON_NAME, os.getenv("CA_CN", "Squawk DNS CA")
                ),
            ]
        )

        # Generate self-signed CA certificate
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(
                datetime.datetime.utcnow()
                + datetime.timedelta(days=self.ca_validity_days)
            )
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                critical=False,
            )
            .sign(ca_key, self._get_signing_algorithm(), default_backend())
        )

        # Save CA certificate and key
        self._save_private_key(ca_key, self.ca_key_path)
        self._save_certificate(ca_cert, self.ca_cert_path)

        # Persist CA info to database
        ca_info = self._extract_cert_info(ca_cert, "ca")
        self._persist_certificate(ca_info)

        logger.info(
            f"CA certificate created: {self.ca_cert_path}, "
            f"valid until {ca_cert.not_valid_after}"
        )
        return True

    def create_server_cert(
        self,
        hostname: Optional[str] = None,
        ip_addresses: Optional[list[str]] = None,
        force: bool = False,
    ) -> bool:
        """
        Create server certificate signed by CA.

        Args:
            hostname: Server hostname (defaults to FQDN)
            ip_addresses: List of IP addresses for SAN
            force: Force regeneration if already exists

        Returns:
            True if created, False if already exists
        """
        if not self.mtls_enabled:
            logger.warning("mTLS not enabled, skipping server cert creation")
            return False

        if (
            not force
            and self.server_cert_path.exists()
            and self.server_key_path.exists()
        ):
            logger.info(f"Server certificate already exists at {self.server_cert_path}")
            return False

        # Ensure CA exists
        if not self.ca_cert_path.exists() or not self.ca_key_path.exists():
            logger.info("CA not found, creating CA first...")
            self.create_ca()

        logger.info("Generating server certificate...")

        # Load CA
        ca_key = self._load_private_key(self.ca_key_path)
        ca_cert = self._load_certificate(self.ca_cert_path)

        # Generate server private key
        server_key = self._generate_private_key()

        # Determine hostname
        if not hostname:
            import socket
            hostname = socket.getfqdn()

        # Determine IP addresses for SAN
        if not ip_addresses:
            ip_addresses = ["127.0.0.1", "::1"]

        # Build Subject Alternative Names (SANs)
        san_list = [
            x509.DNSName(hostname),
            x509.DNSName("localhost"),
        ]

        for ip in ip_addresses:
            try:
                san_list.append(x509.IPAddress(ipaddress.ip_address(ip)))
            except Exception:
                pass

        # Create server certificate
        subject = x509.Name(
            [
                x509.NameAttribute(
                    NameOID.COUNTRY_NAME, os.getenv("SERVER_COUNTRY", "US")
                ),
                x509.NameAttribute(
                    NameOID.STATE_OR_PROVINCE_NAME, os.getenv("SERVER_STATE", "State")
                ),
                x509.NameAttribute(
                    NameOID.LOCALITY_NAME, os.getenv("SERVER_LOCALITY", "City")
                ),
                x509.NameAttribute(
                    NameOID.ORGANIZATION_NAME, os.getenv("SERVER_ORG", "Squawk DNS")
                ),
                x509.NameAttribute(
                    NameOID.ORGANIZATIONAL_UNIT_NAME,
                    os.getenv("SERVER_OU", "DNS Server"),
                ),
                # X.509 CommonName is capped at 64 chars; the full hostname
                # still goes in the SAN above (a long FQDN would otherwise
                # raise ValueError during cert generation).
                x509.NameAttribute(NameOID.COMMON_NAME, hostname[:64]),
            ]
        )

        server_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(
                datetime.datetime.utcnow()
                + datetime.timedelta(days=self.cert_validity_days)
            )
            .add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .sign(ca_key, self._get_signing_algorithm(), default_backend())
        )

        # Save server certificate and key
        self._save_private_key(server_key, self.server_key_path)
        self._save_certificate(server_cert, self.server_cert_path)

        # Persist server cert info to database
        server_info = self._extract_cert_info(server_cert, "server")
        self._persist_certificate(server_info)

        logger.info(
            f"Server certificate created for {hostname}, "
            f"valid until {server_cert.not_valid_after}"
        )
        return True

    def create_client_cert(
        self,
        client_name: str,
        force: bool = False,
    ) -> Optional[str]:
        """
        Create client certificate signed by CA.
        Returns the client certificate in PEM format.

        Args:
            client_name: Client identity (Common Name)
            force: Force regeneration if already exists

        Returns:
            PEM-encoded certificate string, or None on failure
        """
        if not self.mtls_enabled:
            logger.warning("mTLS not enabled, skipping client cert creation")
            return None

        client_key_path = self.clients_dir / f"{client_name}.key"
        client_cert_path = self.clients_dir / f"{client_name}.crt"

        if (
            not force
            and client_cert_path.exists()
            and client_key_path.exists()
        ):
            logger.info(f"Client certificate already exists for {client_name}")
            with open(client_cert_path, "r") as f:
                return f.read()

        # Ensure CA exists
        if not self.ca_cert_path.exists() or not self.ca_key_path.exists():
            logger.info("CA not found, creating CA first...")
            self.create_ca()

        logger.info(f"Generating client certificate for {client_name}...")

        # Load CA
        ca_key = self._load_private_key(self.ca_key_path)
        ca_cert = self._load_certificate(self.ca_cert_path)

        # Generate client private key
        client_key = self._generate_private_key()

        # Create client certificate
        subject = x509.Name(
            [
                x509.NameAttribute(
                    NameOID.COUNTRY_NAME, os.getenv("CLIENT_COUNTRY", "US")
                ),
                x509.NameAttribute(
                    NameOID.STATE_OR_PROVINCE_NAME, os.getenv("CLIENT_STATE", "State")
                ),
                x509.NameAttribute(
                    NameOID.LOCALITY_NAME, os.getenv("CLIENT_LOCALITY", "City")
                ),
                x509.NameAttribute(
                    NameOID.ORGANIZATION_NAME, os.getenv("CLIENT_ORG", "Squawk DNS")
                ),
                x509.NameAttribute(
                    NameOID.ORGANIZATIONAL_UNIT_NAME,
                    os.getenv("CLIENT_OU", "DNS Client"),
                ),
                x509.NameAttribute(NameOID.COMMON_NAME, client_name),
            ]
        )

        client_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(client_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(
                datetime.datetime.utcnow()
                + datetime.timedelta(days=self.cert_validity_days)
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(client_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .sign(ca_key, self._get_signing_algorithm(), default_backend())
        )

        # Save client certificate and key
        self._save_private_key(client_key, client_key_path)
        self._save_certificate(client_cert, client_cert_path)

        # Persist client cert info to database
        client_info = self._extract_cert_info(client_cert, "client")
        self._persist_certificate(client_info)

        logger.info(f"Client certificate created for {client_name}")

        # Return PEM-encoded certificate
        return client_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    def verify_client_cert(self, cert_pem: str) -> VerificationResult:
        """
        Verify a client certificate against the CA and check revocation.

        Args:
            cert_pem: PEM-encoded certificate string

        Returns:
            VerificationResult with validity status and identity
        """
        if not self.mtls_enabled:
            logger.warning("mTLS not enabled, skipping verification")
            return VerificationResult(valid=False, reason="mTLS not enabled")

        try:
            # Load the presented certificate
            cert = x509.load_pem_x509_certificate(
                cert_pem.encode(), default_backend()
            )

            # Check expiration
            now = datetime.datetime.utcnow()
            if now < cert.not_valid_before or now > cert.not_valid_after:
                cn = self._extract_common_name(cert)
                return VerificationResult(
                    valid=False,
                    reason="Certificate expired",
                    common_name=cn,
                    is_expired=True,
                )

            # Load CA certificate
            if not self.ca_cert_path.exists():
                return VerificationResult(
                    valid=False, reason="CA certificate not found"
                )

            ca_cert = self._load_certificate(self.ca_cert_path)
            ca_key = self._load_private_key(self.ca_key_path)

            # Verify signature
            try:
                ca_public_key = ca_cert.public_key()
                if isinstance(ca_public_key, ec.EllipticCurvePublicKey):
                    sig_algo = ec.ECDSA(hashes.SHA384())
                else:
                    sig_algo = hashes.SHA256()

                ca_public_key.verify(
                    cert.signature, cert.tbs_certificate_bytes, sig_algo
                )
            except Exception as e:
                cn = self._extract_common_name(cert)
                return VerificationResult(
                    valid=False,
                    reason=f"Signature verification failed: {e}",
                    common_name=cn,
                )

            # Check revocation
            cn = self._extract_common_name(cert)
            serial_str = str(cert.serial_number)
            is_revoked = self._is_revoked(serial_str)

            if is_revoked:
                return VerificationResult(
                    valid=False,
                    reason="Certificate is revoked",
                    common_name=cn,
                    is_revoked=True,
                )

            logger.info(f"Client certificate verified for {cn}")
            return VerificationResult(valid=True, common_name=cn)

        except Exception as e:
            logger.error(f"Certificate verification failed: {e}")
            return VerificationResult(
                valid=False, reason=f"Verification error: {e}"
            )

    def _extract_common_name(self, cert) -> Optional[str]:
        """Extract Common Name (identity) from certificate subject."""
        try:
            cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            return cn_attr[0].value if cn_attr else None
        except Exception:
            return None

    def _is_revoked(self, serial_number: str) -> bool:
        """Check if a certificate serial number is revoked via penguin-dal."""
        if not self.db_url:
            logger.debug("No database URL, skipping revocation check")
            return False

        try:
            db = self._get_db()
            if not db:
                return False

            # Query mtls_revocation via penguin-dal
            revocation = db(
                db.mtls_revocation.serial_number == serial_number
            ).select()
            return bool(revocation)
        except Exception as e:
            logger.error(f"Failed to check revocation status: {e}")
            return False

    def revoke_client_cert(
        self, client_name: str, reason: str = "Unspecified"
    ) -> bool:
        """
        Revoke a client certificate.

        Args:
            client_name: Client identity
            reason: Revocation reason

        Returns:
            True if revoked, False otherwise
        """
        if not self.mtls_enabled:
            logger.warning("mTLS not enabled, skipping revocation")
            return False

        client_cert_path = self.clients_dir / f"{client_name}.crt"

        if not client_cert_path.exists():
            logger.error(f"Client certificate not found for {client_name}")
            return False

        try:
            # Load certificate to get serial number
            cert = self._load_certificate(client_cert_path)
            serial_str = str(cert.serial_number)

            # Mark as revoked in database via penguin-dal
            if self.db_url:
                db = self._get_db()
                if db:
                    now = datetime.datetime.utcnow()

                    # Update mtls_certificate table
                    db(db.mtls_certificate.serial_number == serial_str).update(
                        is_revoked=True,
                        revoked_at=now,
                        revocation_reason=reason,
                    )

                    # Insert into mtls_revocation table if not already there
                    existing = db(
                        db.mtls_revocation.serial_number == serial_str
                    ).select()
                    if not existing:
                        db.mtls_revocation.insert(
                            serial_number=serial_str,
                            common_name=client_name,
                            revocation_reason=reason,
                        )

                    db.commit()

            logger.info(f"Client certificate revoked for {client_name}: {reason}")
            return True

        except Exception as e:
            logger.error(f"Failed to revoke certificate for {client_name}: {e}")
            return False

    def rotate_server_cert(self) -> bool:
        """
        Rotate server certificate (reissue before expiry).

        Returns:
            True if rotated, False otherwise
        """
        if not self.mtls_enabled:
            logger.warning("mTLS not enabled, skipping rotation")
            return False

        if not self.server_cert_path.exists():
            logger.info("Server certificate does not exist, creating...")
            return self.create_server_cert()

        try:
            # Load current server cert to get its hostname
            current_cert = self._load_certificate(self.server_cert_path)
            cn = self._extract_common_name(current_cert)

            logger.info(f"Rotating server certificate (CN={cn})")

            # Regenerate with force=True
            return self.create_server_cert(hostname=cn, force=True)

        except Exception as e:
            logger.error(f"Failed to rotate server certificate: {e}")
            return False

    def check_cert_expiry(self, days_before: int = 30) -> dict:
        """
        Check for certificates expiring within N days.

        Args:
            days_before: Number of days before expiry to alert

        Returns:
            Dict with expiring certificates
        """
        expiring = {"ca": [], "server": [], "clients": []}

        threshold = datetime.datetime.utcnow() + datetime.timedelta(days=days_before)

        # Check CA
        if self.ca_cert_path.exists():
            try:
                ca_cert = self._load_certificate(self.ca_cert_path)
                if ca_cert.not_valid_after <= threshold:
                    expiring["ca"].append(
                        {
                            "cn": self._extract_common_name(ca_cert),
                            "expires_at": ca_cert.not_valid_after.isoformat(),
                        }
                    )
            except Exception as e:
                logger.error(f"Failed to check CA expiry: {e}")

        # Check Server
        if self.server_cert_path.exists():
            try:
                server_cert = self._load_certificate(self.server_cert_path)
                if server_cert.not_valid_after <= threshold:
                    expiring["server"].append(
                        {
                            "cn": self._extract_common_name(server_cert),
                            "expires_at": server_cert.not_valid_after.isoformat(),
                        }
                    )
            except Exception as e:
                logger.error(f"Failed to check server cert expiry: {e}")

        # Check Client Certs
        if self.clients_dir.exists():
            for cert_file in self.clients_dir.glob("*.crt"):
                try:
                    client_cert = self._load_certificate(cert_file)
                    if client_cert.not_valid_after <= threshold:
                        expiring["clients"].append(
                            {
                                "name": cert_file.stem,
                                "cn": self._extract_common_name(client_cert),
                                "expires_at": client_cert.not_valid_after.isoformat(),
                            }
                        )
                except Exception as e:
                    logger.warning(f"Failed to check {cert_file} expiry: {e}")

        return expiring
