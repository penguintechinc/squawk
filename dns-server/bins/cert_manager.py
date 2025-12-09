#!/usr/bin/env python3
"""
TLS Certificate Manager for Squawk DNS
Generates and manages TLS certificates for server and clients
Supports mTLS (mutual TLS) configuration
"""

import os
import sys
import datetime
import ipaddress
import socket
import argparse
import json
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend


class CertificateManager:
    def __init__(self, cert_dir="certs"):
        self.cert_dir = Path(cert_dir)
        self.cert_dir.mkdir(parents=True, exist_ok=True)

        # Certificate paths
        self.ca_key_path = self.cert_dir / "ca.key"
        self.ca_cert_path = self.cert_dir / "ca.crt"
        self.server_key_path = self.cert_dir / "server.key"
        self.server_cert_path = self.cert_dir / "server.crt"
        self.clients_dir = self.cert_dir / "clients"
        self.clients_dir.mkdir(exist_ok=True)

        # Certificate validity period (days)
        self.ca_validity_days = int(os.getenv("CA_VALIDITY_DAYS", "3650"))  # 10 years
        self.cert_validity_days = int(os.getenv("CERT_VALIDITY_DAYS", "365"))  # 1 year

        # mTLS configuration
        self.mtls_enabled = os.getenv("ENABLE_MTLS", "false").lower() == "true"
        self.mtls_enforce = os.getenv("MTLS_ENFORCE", "false").lower() == "true"

        # Key algorithm configuration (ECC preferred)
        self.use_ecc = os.getenv("USE_ECC_KEYS", "true").lower() == "true"
        self.ecc_curve = getattr(
            ec, os.getenv("ECC_CURVE", "SECP384R1")
        )()  # Default to P-384

    def _get_signing_algorithm(self):
        """Get appropriate signing algorithm based on key type"""
        if self.use_ecc:
            # Use SHA-384 with ECC (stronger for P-384 curve)
            return hashes.SHA384()
        else:
            # Use SHA-256 with RSA
            return hashes.SHA256()

    def generate_private_key(self, key_size=4096):
        """Generate a private key (ECC preferred, RSA fallback)"""
        if self.use_ecc:
            # Generate ECC private key
            return ec.generate_private_key(self.ecc_curve, backend=default_backend())
        else:
            # Generate RSA private key (fallback)
            return rsa.generate_private_key(
                public_exponent=65537, key_size=key_size, backend=default_backend()
            )

    def save_private_key(self, key, filepath, password=None):
        """Save private key to file"""
        encryption = serialization.NoEncryption()
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode())

        with open(filepath, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=encryption,
                )
            )

        # Set secure permissions
        os.chmod(filepath, 0o600)

    def load_private_key(self, filepath, password=None):
        """Load private key from file"""
        with open(filepath, "rb") as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=password.encode() if password else None,
                backend=default_backend(),
            )

    def save_certificate(self, cert, filepath):
        """Save certificate to file"""
        with open(filepath, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        # Set readable permissions
        os.chmod(filepath, 0o644)

    def load_certificate(self, filepath):
        """Load certificate from file"""
        with open(filepath, "rb") as f:
            return x509.load_pem_x509_certificate(f.read(), default_backend())

    def generate_ca_certificate(self, force=False):
        """Generate CA certificate and key"""
        if not force and self.ca_cert_path.exists() and self.ca_key_path.exists():
            print(f"CA certificate already exists at {self.ca_cert_path}")
            return False

        print("Generating CA certificate...")

        # Generate CA private key
        ca_key = self.generate_private_key()

        # Generate CA certificate
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
        self.save_private_key(ca_key, self.ca_key_path)
        self.save_certificate(ca_cert, self.ca_cert_path)

        print(f"CA certificate generated: {self.ca_cert_path}")
        print(f"CA private key generated: {self.ca_key_path}")

        return True

    def generate_server_certificate(
        self, hostname=None, ip_addresses=None, force=False
    ):
        """Generate server certificate signed by CA"""
        if (
            not force
            and self.server_cert_path.exists()
            and self.server_key_path.exists()
        ):
            print(f"Server certificate already exists at {self.server_cert_path}")
            return False

        # Ensure CA exists
        if not self.ca_cert_path.exists() or not self.ca_key_path.exists():
            print("CA certificate not found. Generating CA first...")
            self.generate_ca_certificate()

        print("Generating server certificate...")

        # Load CA
        ca_key = self.load_private_key(self.ca_key_path)
        ca_cert = self.load_certificate(self.ca_cert_path)

        # Generate server private key
        server_key = self.generate_private_key()

        # Determine hostname and IPs
        if not hostname:
            hostname = socket.getfqdn()

        if not ip_addresses:
            ip_addresses = ["127.0.0.1", "::1"]
            # Try to get local IP
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
                if local_ip not in ip_addresses:
                    ip_addresses.append(local_ip)
            except:
                pass

        # Build subject alternative names
        san_list = [
            x509.DNSName(hostname),
            x509.DNSName("localhost"),
            x509.DNSName("*.localhost"),
        ]

        # Add additional hostnames from environment
        additional_hosts = os.getenv("TLS_ADDITIONAL_HOSTS", "").split(",")
        for host in additional_hosts:
            if host.strip():
                san_list.append(x509.DNSName(host.strip()))

        # Add IP addresses
        for ip in ip_addresses:
            try:
                san_list.append(x509.IPAddress(ipaddress.ip_address(ip)))
            except:
                pass

        # Generate server certificate
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
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
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
                x509.ExtendedKeyUsage(
                    [
                        x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                        x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,  # Allow for mTLS
                    ]
                ),
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
        self.save_private_key(server_key, self.server_key_path)
        self.save_certificate(server_cert, self.server_cert_path)

        print(f"Server certificate generated: {self.server_cert_path}")
        print(f"Server private key generated: {self.server_key_path}")
        print(f"Certificate valid for: {', '.join([hostname] + ip_addresses)}")

        return True

    def generate_client_certificate(self, client_name, email=None, force=False):
        """Generate client certificate for mTLS"""
        client_key_path = self.clients_dir / f"{client_name}.key"
        client_cert_path = self.clients_dir / f"{client_name}.crt"
        client_p12_path = self.clients_dir / f"{client_name}.p12"

        if not force and client_cert_path.exists() and client_key_path.exists():
            print(f"Client certificate already exists for {client_name}")
            return False

        # Ensure CA exists
        if not self.ca_cert_path.exists() or not self.ca_key_path.exists():
            print("CA certificate not found. Generating CA first...")
            self.generate_ca_certificate()

        print(f"Generating client certificate for {client_name}...")

        # Load CA
        ca_key = self.load_private_key(self.ca_key_path)
        ca_cert = self.load_certificate(self.ca_cert_path)

        # Generate client private key (smaller for ECC, regular for RSA)
        key_size = (
            256 if self.use_ecc else 2048
        )  # ECC doesn't use key_size parameter, but for consistency
        client_key = self.generate_private_key(key_size=key_size)

        # Generate client certificate
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

        builder = (
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
        )

        # Add email if provided
        if email:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.RFC822Name(email)]),
                critical=False,
            )

        client_cert = builder.sign(
            ca_key, self._get_signing_algorithm(), default_backend()
        )

        # Save client certificate and key
        self.save_private_key(client_key, client_key_path)
        self.save_certificate(client_cert, client_cert_path)

        # Generate PKCS12 bundle for easy import
        self.generate_pkcs12(client_name, client_key, client_cert, ca_cert)

        print(f"Client certificate generated: {client_cert_path}")
        print(f"Client private key generated: {client_key_path}")
        print(f"Client PKCS12 bundle generated: {client_p12_path}")

        # Store client info in database
        self.register_client_certificate(client_name, client_cert)

        return True

    def generate_pkcs12(self, client_name, client_key, client_cert, ca_cert):
        """Generate PKCS12 bundle for client certificate"""
        from cryptography.hazmat.primitives.serialization import pkcs12

        p12_path = self.clients_dir / f"{client_name}.p12"
        password = os.getenv("CLIENT_P12_PASSWORD", client_name).encode()

        p12 = pkcs12.serialize_key_and_certificates(
            name=client_name.encode(),
            key=client_key,
            cert=client_cert,
            cas=[ca_cert],
            encryption_algorithm=serialization.BestAvailableEncryption(password),
        )

        with open(p12_path, "wb") as f:
            f.write(p12)

        os.chmod(p12_path, 0o600)

        # Save password hint
        with open(p12_path.with_suffix(".password"), "w") as f:
            f.write(f"Password: {password.decode()}\n")

        return p12_path

    def register_client_certificate(self, client_name, certificate):
        """Register client certificate in database for tracking"""
        # Extract certificate information
        cert_info = {
            "client_name": client_name,
            "serial_number": str(certificate.serial_number),
            "fingerprint": certificate.fingerprint(hashes.SHA256()).hex(),
            "not_before": certificate.not_valid_before.isoformat(),
            "not_after": certificate.not_valid_after.isoformat(),
            "subject": certificate.subject.rfc4514_string(),
            "created_at": datetime.datetime.utcnow().isoformat(),
        }

        # Save to JSON file (in production, save to database)
        clients_db = self.cert_dir / "clients.json"
        clients = {}

        if clients_db.exists():
            with open(clients_db, "r") as f:
                clients = json.load(f)

        clients[client_name] = cert_info

        with open(clients_db, "w") as f:
            json.dump(clients, f, indent=2)

        return cert_info

    def list_client_certificates(self):
        """List all client certificates"""
        clients_db = self.cert_dir / "clients.json"

        if not clients_db.exists():
            return {}

        with open(clients_db, "r") as f:
            return json.load(f)

    def revoke_client_certificate(self, client_name):
        """Revoke a client certificate"""
        client_cert_path = self.clients_dir / f"{client_name}.crt"

        if not client_cert_path.exists():
            print(f"Client certificate not found for {client_name}")
            return False

        # Create revoked directory
        revoked_dir = self.cert_dir / "revoked"
        revoked_dir.mkdir(exist_ok=True)

        # Move certificate to revoked directory
        import shutil

        shutil.move(str(client_cert_path), str(revoked_dir / f"{client_name}.crt"))

        # Move key as well
        client_key_path = self.clients_dir / f"{client_name}.key"
        if client_key_path.exists():
            shutil.move(str(client_key_path), str(revoked_dir / f"{client_name}.key"))

        # Update clients database
        clients_db = self.cert_dir / "clients.json"
        if clients_db.exists():
            with open(clients_db, "r") as f:
                clients = json.load(f)

            if client_name in clients:
                clients[client_name]["revoked"] = True
                clients[client_name][
                    "revoked_at"
                ] = datetime.datetime.utcnow().isoformat()

                with open(clients_db, "w") as f:
                    json.dump(clients, f, indent=2)

        print(f"Client certificate revoked for {client_name}")
        return True

    def export_ca_certificate(self):
        """Export CA certificate for distribution to clients"""
        if not self.ca_cert_path.exists():
            print("CA certificate not found")
            return None

        return self.ca_cert_path

    def verify_certificate_chain(self, cert_path):
        """Verify a certificate against the CA"""
        try:
            cert = self.load_certificate(cert_path)
            ca_cert = self.load_certificate(self.ca_cert_path)

            # Verify the certificate was signed by our CA
            ca_public_key = ca_cert.public_key()

            # Determine signature algorithm based on key type
            if isinstance(ca_public_key, ec.EllipticCurvePublicKey):
                sig_algo = ec.ECDSA(hashes.SHA384())
            else:
                sig_algo = hashes.SHA256()

            ca_public_key.verify(cert.signature, cert.tbs_certificate_bytes, sig_algo)

            print(f"Certificate {cert_path} is valid and signed by our CA")
            return True

        except Exception as e:
            print(f"Certificate verification failed: {e}")
            return False

    def get_certificate_info(self, cert_path):
        """Get information about a certificate"""
        cert = self.load_certificate(cert_path)

        info = {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial_number": str(cert.serial_number),
            "not_before": cert.not_valid_before.isoformat(),
            "not_after": cert.not_valid_after.isoformat(),
            "fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
            "version": cert.version.name,
            "signature_algorithm": cert.signature_algorithm_oid._name,
        }

        # Extract SANs if present
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            sans = []
            for san in san_ext.value:
                sans.append(str(san))
            info["subject_alternative_names"] = sans
        except:
            pass

        return info


def main():
    parser = argparse.ArgumentParser(description="Squawk DNS TLS Certificate Manager")

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Init command
    init_parser = subparsers.add_parser("init", help="Initialize all certificates")
    init_parser.add_argument("--force", action="store_true", help="Force regeneration")

    # CA command
    ca_parser = subparsers.add_parser("ca", help="Generate CA certificate")
    ca_parser.add_argument("--force", action="store_true", help="Force regeneration")

    # Server command
    server_parser = subparsers.add_parser("server", help="Generate server certificate")
    server_parser.add_argument("--hostname", help="Server hostname")
    server_parser.add_argument("--ip", action="append", help="Server IP addresses")
    server_parser.add_argument(
        "--force", action="store_true", help="Force regeneration"
    )

    # Client command
    client_parser = subparsers.add_parser("client", help="Generate client certificate")
    client_parser.add_argument("name", help="Client name")
    client_parser.add_argument("--email", help="Client email")
    client_parser.add_argument(
        "--force", action="store_true", help="Force regeneration"
    )

    # List command
    list_parser = subparsers.add_parser("list", help="List client certificates")

    # Revoke command
    revoke_parser = subparsers.add_parser("revoke", help="Revoke client certificate")
    revoke_parser.add_argument("name", help="Client name")

    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify certificate")
    verify_parser.add_argument("cert", help="Certificate file path")

    # Info command
    info_parser = subparsers.add_parser("info", help="Show certificate info")
    info_parser.add_argument("cert", help="Certificate file path")

    # Export command
    export_parser = subparsers.add_parser("export-ca", help="Export CA certificate")

    args = parser.parse_args()

    cert_manager = CertificateManager()

    if args.command == "init":
        # Initialize all certificates
        cert_manager.generate_ca_certificate(force=args.force)
        cert_manager.generate_server_certificate(force=args.force)
        print("\nInitialization complete!")
        print(f"CA certificate: {cert_manager.ca_cert_path}")
        print(f"Server certificate: {cert_manager.server_cert_path}")
        print(f"Server key: {cert_manager.server_key_path}")

        if cert_manager.mtls_enabled:
            print("\nmTLS is enabled. Generate client certificates with:")
            print("  python cert_manager.py client <client_name>")

    elif args.command == "ca":
        cert_manager.generate_ca_certificate(force=args.force)

    elif args.command == "server":
        cert_manager.generate_server_certificate(
            hostname=args.hostname, ip_addresses=args.ip, force=args.force
        )

    elif args.command == "client":
        cert_manager.generate_client_certificate(
            args.name, email=args.email, force=args.force
        )

    elif args.command == "list":
        clients = cert_manager.list_client_certificates()
        if clients:
            print("Client certificates:")
            for name, info in clients.items():
                status = "REVOKED" if info.get("revoked") else "ACTIVE"
                print(f"  - {name}: {status}")
                print(f"    Serial: {info['serial_number']}")
                print(f"    Valid until: {info['not_after']}")
        else:
            print("No client certificates found")

    elif args.command == "revoke":
        cert_manager.revoke_client_certificate(args.name)

    elif args.command == "verify":
        cert_manager.verify_certificate_chain(args.cert)

    elif args.command == "info":
        info = cert_manager.get_certificate_info(args.cert)
        print(json.dumps(info, indent=2))

    elif args.command == "export-ca":
        ca_path = cert_manager.export_ca_certificate()
        if ca_path:
            print(f"CA certificate: {ca_path}")
            print("\nDistribute this certificate to clients for trust verification")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
