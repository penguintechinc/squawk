"""
Comprehensive coverage tests for app.services.cert_manager.CertManager.

Exercises CA generation, server/client cert issuance, ECC/RSA key
generation, signing, verification, revocation, rotation, expiry checks,
file-permission handling, and the database-persistence/error paths --
using real cryptography objects wherever practical (not mocked-out
no-ops) so assertions are against actual cert fields, exceptions, and
on-disk file modes.
"""

from __future__ import annotations

import datetime
import os
import stat
import sys
import types
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from app.services.cert_manager import CertManager, CertificateInfo, VerificationResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_self_signed_cert(
    key=None,
    common_name: str = "standalone",
    not_valid_before: datetime.datetime | None = None,
    not_valid_after: datetime.datetime | None = None,
    include_cn: bool = True,
):
    """Build a standalone self-signed certificate not tied to any CertManager CA.

    Used to exercise verify_client_cert() paths that must fail on
    expiration or signature mismatch without going through the full
    create_ca()/create_client_cert() flow.
    """
    if key is None:
        key = ec.generate_private_key(ec.SECP384R1(), backend=default_backend())

    now = datetime.datetime.utcnow()
    if not_valid_before is None:
        not_valid_before = now - datetime.timedelta(days=1)
    if not_valid_after is None:
        not_valid_after = now + datetime.timedelta(days=30)

    attrs = []
    if include_cn:
        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    else:
        attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, "US"))
    subject = issuer = x509.Name(attrs)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
        .sign(key, hashes.SHA384(), default_backend())
    )
    return cert, key


class _FakePostHogModuleChain:
    """Context manager injecting a fake PostHog client import chain.

    cert_manager._check_mtls_feature_flag() does a deep local import of
    manager.backend.app.services.posthog_client -- injecting fake modules
    into sys.modules lets us exercise the "import succeeded" branch
    without the real manager package's own transitive imports.
    """

    MODULE_NAMES = (
        "manager",
        "manager.backend",
        "manager.backend.app",
        "manager.backend.app.services",
        "manager.backend.app.services.posthog_client",
    )

    def __init__(self, client_factory):
        self._client_factory = client_factory
        self._saved: dict[str, object] = {}

    def __enter__(self):
        for name in self.MODULE_NAMES:
            self._saved[name] = sys.modules.get(name)
            sys.modules[name] = types.ModuleType(name)

        fake_module = sys.modules["manager.backend.app.services.posthog_client"]
        fake_module.PostHogClient = self._client_factory
        return fake_module

    def __exit__(self, *exc_info):
        for name, mod in self._saved.items():
            if mod is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = mod
        return False


# ---------------------------------------------------------------------------
# __init__ / configuration
# ---------------------------------------------------------------------------


def test_init_creates_directories_and_paths(tmp_path):
    cert_dir = tmp_path / "certs"
    mgr = CertManager(cert_dir=str(cert_dir), mtls_enabled=True)

    assert cert_dir.is_dir()
    assert mgr.clients_dir.is_dir()
    assert mgr.ca_key_path == cert_dir / "ca.key"
    assert mgr.ca_cert_path == cert_dir / "ca.crt"
    assert mgr.server_key_path == cert_dir / "server.key"
    assert mgr.server_cert_path == cert_dir / "server.crt"


def test_init_default_validity_days(tmp_path, monkeypatch):
    monkeypatch.delenv("CA_VALIDITY_DAYS", raising=False)
    monkeypatch.delenv("CERT_VALIDITY_DAYS", raising=False)
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    assert mgr.ca_validity_days == 3650
    assert mgr.cert_validity_days == 365


def test_init_validity_days_from_env(tmp_path, monkeypatch):
    monkeypatch.setenv("CA_VALIDITY_DAYS", "100")
    monkeypatch.setenv("CERT_VALIDITY_DAYS", "7")
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    assert mgr.ca_validity_days == 100
    assert mgr.cert_validity_days == 7


def test_init_explicit_mtls_enabled_skips_feature_flag_check(tmp_path):
    """Passing mtls_enabled explicitly must never invoke the flag check."""
    with patch.object(
        CertManager, "_check_mtls_feature_flag", side_effect=AssertionError("should not be called")
    ):
        mgr_true = CertManager(cert_dir=str(tmp_path / "a"), mtls_enabled=True)
        mgr_false = CertManager(cert_dir=str(tmp_path / "b"), mtls_enabled=False)
    assert mgr_true.mtls_enabled is True
    assert mgr_false.mtls_enabled is False


def test_init_mtls_enabled_none_uses_feature_flag_default_false(tmp_path):
    """With no PostHog client importable, mtls defaults to disabled (fail-safe)."""
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=None)
    assert mgr.mtls_enabled is False


def test_init_use_ecc_default_true(tmp_path, monkeypatch):
    monkeypatch.delenv("USE_ECC_KEYS", raising=False)
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    assert mgr.use_ecc is True
    key = mgr._generate_private_key()
    assert isinstance(key, ec.EllipticCurvePrivateKey)


def test_init_use_ecc_false_generates_rsa(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_ECC_KEYS", "false")
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    assert mgr.use_ecc is False
    key = mgr._generate_private_key()
    assert isinstance(key, rsa.RSAPrivateKey)
    assert key.key_size == 4096


def test_init_ecc_curve_override(tmp_path, monkeypatch):
    monkeypatch.setenv("ECC_CURVE", "SECP256R1")
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    assert isinstance(mgr.ecc_curve, ec.SECP256R1)


def test_init_logs_enabled_and_disabled(tmp_path, caplog):
    with caplog.at_level("INFO"):
        CertManager(cert_dir=str(tmp_path / "en"), mtls_enabled=True)
    assert "mTLS certificate management enabled" in caplog.text

    caplog.clear()
    with caplog.at_level("INFO"):
        CertManager(cert_dir=str(tmp_path / "dis"), mtls_enabled=False)
    assert "mTLS certificate management disabled" in caplog.text


# ---------------------------------------------------------------------------
# _check_mtls_feature_flag
# ---------------------------------------------------------------------------


def test_check_mtls_feature_flag_import_error_returns_false(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    assert mgr._check_mtls_feature_flag() is False


def test_check_mtls_feature_flag_true_when_client_reports_enabled(tmp_path, monkeypatch):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    monkeypatch.setenv("DEPLOYMENT_ID", "dep-123")

    fake_client_instance = MagicMock()
    fake_client_instance.feature_enabled.return_value = True

    def _factory():
        return fake_client_instance

    with _FakePostHogModuleChain(_factory):
        result = mgr._check_mtls_feature_flag()

    assert result is True
    fake_client_instance.feature_enabled.assert_called_once_with(
        "squawkdns.mtls", "dep-123", default=False
    )


def test_check_mtls_feature_flag_false_when_client_reports_disabled(tmp_path, monkeypatch):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    monkeypatch.delenv("DEPLOYMENT_ID", raising=False)

    fake_client_instance = MagicMock()
    fake_client_instance.feature_enabled.return_value = False

    with _FakePostHogModuleChain(lambda: fake_client_instance):
        result = mgr._check_mtls_feature_flag()

    assert result is False
    # default distinct_id falls back to "default" when DEPLOYMENT_ID unset
    fake_client_instance.feature_enabled.assert_called_once_with(
        "squawkdns.mtls", "default", default=False
    )


def test_check_mtls_feature_flag_exception_returns_false(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)

    def _raise_ctor():
        raise RuntimeError("posthog unreachable")

    with _FakePostHogModuleChain(_raise_ctor):
        result = mgr._check_mtls_feature_flag()

    assert result is False


# ---------------------------------------------------------------------------
# _get_db
# ---------------------------------------------------------------------------


def test_get_db_returns_none_without_db_url(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True, db_url=None)
    assert mgr._get_db() is None


def test_get_db_creates_and_caches_instance(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True, db_url="sqlite:///:memory:")
    fake_instance = MagicMock()

    with patch("penguin_dal.DB", return_value=fake_instance) as mock_ctor:
        first = mgr._get_db()
        second = mgr._get_db()

    assert first is fake_instance
    assert second is fake_instance
    mock_ctor.assert_called_once_with("sqlite:///:memory:")


def test_get_db_returns_none_on_exception(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True, db_url="sqlite:///:memory:")

    with patch("penguin_dal.DB", side_effect=RuntimeError("connection refused")):
        result = mgr._get_db()

    assert result is None
    assert mgr._db is None


# ---------------------------------------------------------------------------
# _get_signing_algorithm
# ---------------------------------------------------------------------------


def test_get_signing_algorithm_ecc(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    mgr.use_ecc = True
    assert isinstance(mgr._get_signing_algorithm(), hashes.SHA384)


def test_get_signing_algorithm_rsa(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    mgr.use_ecc = False
    assert isinstance(mgr._get_signing_algorithm(), hashes.SHA256)


# ---------------------------------------------------------------------------
# private key save/load
# ---------------------------------------------------------------------------


def test_save_and_load_private_key_roundtrip_no_password(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    key = mgr._generate_private_key()
    path = tmp_path / "k.key"

    mgr._save_private_key(key, path)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600

    loaded = mgr._load_private_key(path)
    # Confirm it round-trips to an equivalent key (same public numbers).
    assert (
        loaded.public_key().public_numbers() == key.public_key().public_numbers()
    )


def test_save_and_load_private_key_with_password(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    key = mgr._generate_private_key()
    path = tmp_path / "k_pw.key"

    mgr._save_private_key(key, path, password="s3cr3t-pw")

    # Loading without the password must fail.
    with pytest.raises(TypeError):
        mgr._load_private_key(path)

    loaded = mgr._load_private_key(path, password="s3cr3t-pw")
    assert loaded.public_key().public_numbers() == key.public_key().public_numbers()


# ---------------------------------------------------------------------------
# certificate save/load
# ---------------------------------------------------------------------------


def test_save_and_load_certificate_roundtrip(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    cert, _key = _build_self_signed_cert(common_name="save-load-test")
    path = tmp_path / "c.crt"

    mgr._save_certificate(cert, path)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o644

    loaded = mgr._load_certificate(path)
    assert loaded.serial_number == cert.serial_number


def test_load_certificate_missing_file_raises(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    with pytest.raises(FileNotFoundError):
        mgr._load_certificate(tmp_path / "does-not-exist.crt")


def test_load_private_key_missing_file_raises(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    with pytest.raises(FileNotFoundError):
        mgr._load_private_key(tmp_path / "does-not-exist.key")


# ---------------------------------------------------------------------------
# _extract_cert_info / _extract_common_name
# ---------------------------------------------------------------------------


def test_extract_cert_info_with_common_name(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    cert, _key = _build_self_signed_cert(common_name="widget.example.com")

    info = mgr._extract_cert_info(cert, "server")

    assert isinstance(info, CertificateInfo)
    assert info.cert_type == "server"
    assert info.common_name == "widget.example.com"
    assert info.serial_number == str(cert.serial_number)
    assert info.fingerprint_sha256 == cert.fingerprint(hashes.SHA256()).hex()
    assert info.subject_dn == cert.subject.rfc4514_string()
    assert info.issuer_dn == cert.issuer.rfc4514_string()
    assert info.is_revoked is False


def test_extract_cert_info_without_common_name_falls_back_to_unknown(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    cert, _key = _build_self_signed_cert(include_cn=False)

    info = mgr._extract_cert_info(cert, "client")
    assert info.common_name == "Unknown"


def test_extract_cert_info_handles_exception_from_subject(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    real_cert, _key = _build_self_signed_cert(common_name="broken")

    broken_subject = MagicMock()
    broken_subject.get_attributes_for_oid.side_effect = RuntimeError("boom")
    broken_subject.rfc4514_string.return_value = "CN=broken"

    fake_cert = MagicMock(wraps=real_cert)
    fake_cert.subject = broken_subject
    fake_cert.issuer = real_cert.issuer
    fake_cert.serial_number = real_cert.serial_number
    fake_cert.not_valid_before = real_cert.not_valid_before
    fake_cert.not_valid_after = real_cert.not_valid_after
    fake_cert.fingerprint.return_value = real_cert.fingerprint(hashes.SHA256())

    info = mgr._extract_cert_info(fake_cert, "ca")
    assert info.common_name == "Unknown"


def test_extract_common_name_returns_none_when_absent(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    cert, _key = _build_self_signed_cert(include_cn=False)
    assert mgr._extract_common_name(cert) is None


def test_extract_common_name_handles_exception(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    broken_cert = MagicMock()
    broken_cert.subject.get_attributes_for_oid.side_effect = RuntimeError("boom")
    assert mgr._extract_common_name(broken_cert) is None


# ---------------------------------------------------------------------------
# _persist_certificate
# ---------------------------------------------------------------------------


def _cert_info(serial="123") -> CertificateInfo:
    now = datetime.datetime.utcnow()
    return CertificateInfo(
        cert_type="server",
        common_name="host.example.com",
        serial_number=serial,
        fingerprint_sha256="deadbeef",
        not_valid_before=now,
        not_valid_after=now + datetime.timedelta(days=1),
        subject_dn="CN=host.example.com",
        issuer_dn="CN=Squawk DNS CA",
    )


def test_persist_certificate_skips_without_db_url(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True, db_url=None)
    mgr._get_db = MagicMock(side_effect=AssertionError("must not be called"))
    mgr._persist_certificate(_cert_info())  # should not raise, no-op


def test_persist_certificate_skips_when_db_unavailable(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True, db_url="sqlite:///:memory:")
    mgr._get_db = MagicMock(return_value=None)
    mgr._persist_certificate(_cert_info())  # returns quietly


def test_persist_certificate_skips_when_already_exists(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True, db_url="sqlite:///:memory:")
    fake_db = MagicMock()
    fake_db.return_value.select.return_value = [MagicMock()]
    mgr._get_db = MagicMock(return_value=fake_db)

    mgr._persist_certificate(_cert_info(serial="already-there"))

    fake_db.mtls_certificate.insert.assert_not_called()
    fake_db.commit.assert_not_called()


def test_persist_certificate_inserts_when_new(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True, db_url="sqlite:///:memory:")
    fake_db = MagicMock()
    fake_db.return_value.select.return_value = []
    mgr._get_db = MagicMock(return_value=fake_db)

    info = _cert_info(serial="new-serial")
    mgr._persist_certificate(info)

    fake_db.mtls_certificate.insert.assert_called_once()
    kwargs = fake_db.mtls_certificate.insert.call_args.kwargs
    assert kwargs["serial_number"] == "new-serial"
    assert kwargs["cert_type"] == "server"
    fake_db.commit.assert_called_once()


def test_persist_certificate_logs_and_swallows_exception(tmp_path, caplog):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True, db_url="sqlite:///:memory:")
    mgr._get_db = MagicMock(side_effect=RuntimeError("db exploded"))

    with caplog.at_level("ERROR"):
        mgr._persist_certificate(_cert_info())  # must not raise

    assert "Failed to persist certificate" in caplog.text


# ---------------------------------------------------------------------------
# create_ca
# ---------------------------------------------------------------------------


def test_create_ca_disabled_returns_false(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=False)
    assert mgr.create_ca() is False
    assert not mgr.ca_cert_path.exists()


def test_create_ca_generates_files_and_fields(tmp_path, monkeypatch):
    monkeypatch.setenv("CA_CN", "Test Root CA")
    monkeypatch.setenv("CA_ORG", "TestOrg")
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)

    created = mgr.create_ca()

    assert created is True
    assert mgr.ca_key_path.exists()
    assert mgr.ca_cert_path.exists()

    key_mode = stat.S_IMODE(os.stat(mgr.ca_key_path).st_mode)
    assert key_mode == 0o600
    cert_mode = stat.S_IMODE(os.stat(mgr.ca_cert_path).st_mode)
    assert cert_mode == 0o644

    ca_cert = mgr._load_certificate(mgr.ca_cert_path)
    cn_attr = ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert cn_attr[0].value == "Test Root CA"
    basic_constraints = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert basic_constraints.value.ca is True


def test_create_ca_already_exists_no_force_returns_false(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    assert mgr.create_ca() is True
    original_serial = mgr._load_certificate(mgr.ca_cert_path).serial_number

    assert mgr.create_ca() is False

    unchanged_serial = mgr._load_certificate(mgr.ca_cert_path).serial_number
    assert unchanged_serial == original_serial


def test_create_ca_force_regenerates(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    assert mgr.create_ca() is True
    original_serial = mgr._load_certificate(mgr.ca_cert_path).serial_number

    assert mgr.create_ca(force=True) is True

    new_serial = mgr._load_certificate(mgr.ca_cert_path).serial_number
    assert new_serial != original_serial


def test_create_ca_persists_to_db(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True, db_url="sqlite:///:memory:")
    fake_db = MagicMock()
    fake_db.return_value.select.return_value = []
    mgr._get_db = MagicMock(return_value=fake_db)

    assert mgr.create_ca() is True

    fake_db.mtls_certificate.insert.assert_called_once()
    kwargs = fake_db.mtls_certificate.insert.call_args.kwargs
    assert kwargs["cert_type"] == "ca"


# ---------------------------------------------------------------------------
# create_server_cert
# ---------------------------------------------------------------------------


def test_create_server_cert_disabled_returns_false(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=False)
    assert mgr.create_server_cert() is False


def test_create_server_cert_creates_ca_first_when_missing(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    assert not mgr.ca_cert_path.exists()

    created = mgr.create_server_cert(hostname="svc.example.com")

    assert created is True
    assert mgr.ca_cert_path.exists()
    assert mgr.server_cert_path.exists()
    assert mgr.server_key_path.exists()

    key_mode = stat.S_IMODE(os.stat(mgr.server_key_path).st_mode)
    assert key_mode == 0o600


def test_create_server_cert_fields_and_extensions(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    mgr.create_server_cert(hostname="svc.example.com", ip_addresses=["10.0.0.5", "not-an-ip"])

    cert = mgr._load_certificate(mgr.server_cert_path)
    cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert cn_attr[0].value == "svc.example.com"

    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    dns_names = san.value.get_values_for_type(x509.DNSName)
    assert "svc.example.com" in dns_names
    assert "localhost" in dns_names

    ip_addrs = [str(ip) for ip in san.value.get_values_for_type(x509.IPAddress)]
    assert "10.0.0.5" in ip_addrs
    # "not-an-ip" must have been silently skipped, not crashed on.
    assert len(ip_addrs) == 1

    basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert basic_constraints.value.ca is False

    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert x509.oid.ExtendedKeyUsageOID.SERVER_AUTH in eku.value

    ca_cert = mgr._load_certificate(mgr.ca_cert_path)
    assert cert.issuer == ca_cert.subject


def test_create_server_cert_default_hostname_uses_fqdn(tmp_path, monkeypatch):
    monkeypatch.setattr("socket.getfqdn", lambda: "fqdn-host.example.net")
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)

    mgr.create_server_cert()

    cert = mgr._load_certificate(mgr.server_cert_path)
    cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert cn_attr[0].value == "fqdn-host.example.net"


def test_create_server_cert_default_ip_addresses(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    mgr.create_server_cert(hostname="svc.example.com")

    cert = mgr._load_certificate(mgr.server_cert_path)
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    ip_addrs = {str(ip) for ip in san.value.get_values_for_type(x509.IPAddress)}
    assert "127.0.0.1" in ip_addrs
    assert "::1" in ip_addrs


def test_create_server_cert_already_exists_no_force(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    assert mgr.create_server_cert(hostname="svc.example.com") is True
    original_serial = mgr._load_certificate(mgr.server_cert_path).serial_number

    assert mgr.create_server_cert(hostname="svc.example.com") is False

    unchanged_serial = mgr._load_certificate(mgr.server_cert_path).serial_number
    assert unchanged_serial == original_serial


def test_create_server_cert_force_regenerates(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    mgr.create_server_cert(hostname="svc.example.com")
    original_serial = mgr._load_certificate(mgr.server_cert_path).serial_number

    assert mgr.create_server_cert(hostname="svc.example.com", force=True) is True

    new_serial = mgr._load_certificate(mgr.server_cert_path).serial_number
    assert new_serial != original_serial


def test_create_server_cert_rsa_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("USE_ECC_KEYS", "false")
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)

    assert mgr.create_server_cert(hostname="rsa-host.example.com") is True

    key = mgr._load_private_key(mgr.server_key_path)
    assert isinstance(key, rsa.RSAPrivateKey)


# ---------------------------------------------------------------------------
# create_client_cert
# ---------------------------------------------------------------------------


def test_create_client_cert_disabled_returns_none(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=False)
    assert mgr.create_client_cert("alice") is None


def test_create_client_cert_creates_ca_first_and_returns_pem(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)

    pem = mgr.create_client_cert("alice")

    assert pem is not None
    assert pem.startswith("-----BEGIN CERTIFICATE-----")
    assert mgr.ca_cert_path.exists()

    client_key_path = mgr.clients_dir / "alice.key"
    client_cert_path = mgr.clients_dir / "alice.crt"
    assert client_key_path.exists()
    assert client_cert_path.exists()
    assert stat.S_IMODE(os.stat(client_key_path).st_mode) == 0o600

    cert = x509.load_pem_x509_certificate(pem.encode(), default_backend())
    cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert cn_attr[0].value == "alice"

    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in eku.value


def test_create_client_cert_returns_existing_without_force(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    first_pem = mgr.create_client_cert("bob")

    second_pem = mgr.create_client_cert("bob")

    assert second_pem == first_pem


def test_create_client_cert_force_regenerates(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    first_pem = mgr.create_client_cert("carol")

    second_pem = mgr.create_client_cert("carol", force=True)

    assert second_pem != first_pem


def test_create_client_cert_persists_to_db(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True, db_url="sqlite:///:memory:")
    # Pre-create the CA (without db mocking) so create_client_cert's own
    # persistence call is the only one under test below.
    mgr.create_ca()

    fake_db = MagicMock()
    fake_db.return_value.select.return_value = []
    mgr._get_db = MagicMock(return_value=fake_db)

    mgr.create_client_cert("dave")

    fake_db.mtls_certificate.insert.assert_called_once()
    kwargs = fake_db.mtls_certificate.insert.call_args.kwargs
    assert kwargs["cert_type"] == "client"
    assert kwargs["common_name"] == "dave"


# ---------------------------------------------------------------------------
# verify_client_cert
# ---------------------------------------------------------------------------


def test_verify_client_cert_disabled(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=False)
    result = mgr.verify_client_cert("garbage")
    assert isinstance(result, VerificationResult)
    assert result.valid is False
    assert result.reason == "mTLS not enabled"


def test_verify_client_cert_malformed_pem(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    result = mgr.verify_client_cert("not a real certificate")
    assert result.valid is False
    assert "Verification error" in result.reason


def test_verify_client_cert_expired(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    now = datetime.datetime.utcnow()
    cert, _key = _build_self_signed_cert(
        common_name="expired-client",
        not_valid_before=now - datetime.timedelta(days=10),
        not_valid_after=now - datetime.timedelta(days=1),
    )
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()

    result = mgr.verify_client_cert(pem)

    assert result.valid is False
    assert result.is_expired is True
    assert result.common_name == "expired-client"
    assert result.reason == "Certificate expired"


def test_verify_client_cert_not_yet_valid(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    now = datetime.datetime.utcnow()
    cert, _key = _build_self_signed_cert(
        common_name="future-client",
        not_valid_before=now + datetime.timedelta(days=5),
        not_valid_after=now + datetime.timedelta(days=10),
    )
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()

    result = mgr.verify_client_cert(pem)

    assert result.valid is False
    assert result.is_expired is True


def test_verify_client_cert_no_ca_present(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    cert, _key = _build_self_signed_cert(common_name="whoever")
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()

    result = mgr.verify_client_cert(pem)

    assert result.valid is False
    assert result.reason == "CA certificate not found"


def test_verify_client_cert_signature_mismatch_ecc(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    mgr.create_ca()

    # Cert signed by an unrelated key, not the manager's CA.
    foreign_cert, _foreign_key = _build_self_signed_cert(common_name="impostor")
    pem = foreign_cert.public_bytes(serialization.Encoding.PEM).decode()

    result = mgr.verify_client_cert(pem)

    assert result.valid is False
    assert "Signature verification failed" in result.reason
    assert result.common_name == "impostor"


def test_verify_client_cert_valid_ecc(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    pem = mgr.create_client_cert("erin")

    result = mgr.verify_client_cert(pem)

    assert result.valid is True
    assert result.common_name == "erin"
    assert result.reason is None
    assert result.is_revoked is False


def test_verify_client_cert_rsa_ca_signature_check_fails(tmp_path, monkeypatch):
    """RSA-CA path: ca_public_key.verify() is called without a padding
    argument, which cryptography's RSAPublicKey.verify() requires --
    exercising the branch confirms current (buggy) behavior: any RSA-CA
    verification always lands in the signature-failure branch.
    """
    monkeypatch.setenv("USE_ECC_KEYS", "false")
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    pem = mgr.create_client_cert("frank")

    result = mgr.verify_client_cert(pem)

    assert result.valid is False
    assert "Signature verification failed" in result.reason


def test_verify_client_cert_revoked(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True, db_url="sqlite:///:memory:")
    pem = mgr.create_client_cert("grace")

    mgr._is_revoked = MagicMock(return_value=True)

    result = mgr.verify_client_cert(pem)

    assert result.valid is False
    assert result.is_revoked is True
    assert result.reason == "Certificate is revoked"
    assert result.common_name == "grace"


# ---------------------------------------------------------------------------
# _is_revoked
# ---------------------------------------------------------------------------


def test_is_revoked_no_db_url_returns_false(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True, db_url=None)
    assert mgr._is_revoked("123") is False


def test_is_revoked_db_unavailable_returns_false(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True, db_url="sqlite:///:memory:")
    mgr._get_db = MagicMock(return_value=None)
    assert mgr._is_revoked("123") is False


def test_is_revoked_true_when_row_found(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True, db_url="sqlite:///:memory:")
    fake_db = MagicMock()
    fake_db.return_value.select.return_value = [MagicMock()]
    mgr._get_db = MagicMock(return_value=fake_db)

    assert mgr._is_revoked("123") is True


def test_is_revoked_false_when_no_row(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True, db_url="sqlite:///:memory:")
    fake_db = MagicMock()
    fake_db.return_value.select.return_value = []
    mgr._get_db = MagicMock(return_value=fake_db)

    assert mgr._is_revoked("123") is False


def test_is_revoked_exception_returns_false(tmp_path, caplog):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True, db_url="sqlite:///:memory:")
    mgr._get_db = MagicMock(side_effect=RuntimeError("db down"))

    with caplog.at_level("ERROR"):
        result = mgr._is_revoked("123")

    assert result is False
    assert "Failed to check revocation status" in caplog.text


# ---------------------------------------------------------------------------
# revoke_client_cert
# ---------------------------------------------------------------------------


def test_revoke_client_cert_disabled(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=False)
    assert mgr.revoke_client_cert("nobody") is False


def test_revoke_client_cert_missing_cert_returns_false(tmp_path, caplog):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    with caplog.at_level("ERROR"):
        result = mgr.revoke_client_cert("ghost")
    assert result is False
    assert "Client certificate not found" in caplog.text


def test_revoke_client_cert_without_db_url_still_succeeds(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True, db_url=None)
    mgr.create_client_cert("heidi")

    assert mgr.revoke_client_cert("heidi", reason="key compromised") is True


def test_revoke_client_cert_db_unavailable_still_succeeds(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True, db_url="sqlite:///:memory:")
    mgr.create_client_cert("ivan")
    mgr._get_db = MagicMock(return_value=None)

    assert mgr.revoke_client_cert("ivan") is True


def test_revoke_client_cert_inserts_new_revocation_row(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True, db_url="sqlite:///:memory:")
    mgr.create_client_cert("judy")

    fake_db = MagicMock()
    fake_db.return_value.select.return_value = []
    mgr._get_db = MagicMock(return_value=fake_db)

    result = mgr.revoke_client_cert("judy", reason="rotation")

    assert result is True
    fake_db.mtls_certificate.__eq__  # sanity: attribute access works
    fake_db.return_value.update.assert_called_once()
    update_kwargs = fake_db.return_value.update.call_args.kwargs
    assert update_kwargs["is_revoked"] is True
    assert update_kwargs["revocation_reason"] == "rotation"
    fake_db.mtls_revocation.insert.assert_called_once()
    insert_kwargs = fake_db.mtls_revocation.insert.call_args.kwargs
    assert insert_kwargs["common_name"] == "judy"
    fake_db.commit.assert_called_once()


def test_revoke_client_cert_skips_insert_when_already_revoked(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True, db_url="sqlite:///:memory:")
    mgr.create_client_cert("kevin")

    fake_db = MagicMock()
    fake_db.return_value.select.return_value = [MagicMock()]
    mgr._get_db = MagicMock(return_value=fake_db)

    result = mgr.revoke_client_cert("kevin")

    assert result is True
    fake_db.mtls_revocation.insert.assert_not_called()
    fake_db.commit.assert_called_once()


def test_revoke_client_cert_exception_returns_false(tmp_path, caplog):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True, db_url="sqlite:///:memory:")
    mgr.create_client_cert("laura")
    mgr._get_db = MagicMock(side_effect=RuntimeError("db exploded"))

    with caplog.at_level("ERROR"):
        result = mgr.revoke_client_cert("laura")

    assert result is False
    assert "Failed to revoke certificate" in caplog.text


# ---------------------------------------------------------------------------
# rotate_server_cert
# ---------------------------------------------------------------------------


def test_rotate_server_cert_disabled(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=False)
    assert mgr.rotate_server_cert() is False


def test_rotate_server_cert_creates_when_missing(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    assert not mgr.server_cert_path.exists()

    result = mgr.rotate_server_cert()

    assert result is True
    assert mgr.server_cert_path.exists()


def test_rotate_server_cert_reissues_with_same_cn(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    mgr.create_server_cert(hostname="rotate-me.example.com")
    original_serial = mgr._load_certificate(mgr.server_cert_path).serial_number

    result = mgr.rotate_server_cert()

    assert result is True
    new_cert = mgr._load_certificate(mgr.server_cert_path)
    assert new_cert.serial_number != original_serial
    cn_attr = new_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert cn_attr[0].value == "rotate-me.example.com"


def test_rotate_server_cert_exception_returns_false(tmp_path, caplog):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    mgr.create_server_cert(hostname="broken.example.com")
    # Corrupt the on-disk cert so _load_certificate raises inside rotate.
    mgr.server_cert_path.write_bytes(b"not a valid certificate")

    with caplog.at_level("ERROR"):
        result = mgr.rotate_server_cert()

    assert result is False
    assert "Failed to rotate server certificate" in caplog.text


# ---------------------------------------------------------------------------
# check_cert_expiry
# ---------------------------------------------------------------------------


def test_check_cert_expiry_empty_when_nothing_exists(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    result = mgr.check_cert_expiry()
    assert result == {"ca": [], "server": [], "clients": []}


def test_check_cert_expiry_flags_expiring_ca_and_server(tmp_path, monkeypatch):
    monkeypatch.setenv("CA_VALIDITY_DAYS", "10")
    monkeypatch.setenv("CERT_VALIDITY_DAYS", "5")
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    mgr.create_server_cert(hostname="soon-expires.example.com")

    result = mgr.check_cert_expiry(days_before=30)

    assert len(result["ca"]) == 1
    assert len(result["server"]) == 1
    assert result["server"][0]["cn"] == "soon-expires.example.com"


def test_check_cert_expiry_not_flagged_when_far_in_future(tmp_path):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    mgr.create_server_cert(hostname="long-lived.example.com")

    result = mgr.check_cert_expiry(days_before=1)

    assert result["ca"] == []
    assert result["server"] == []


def test_check_cert_expiry_clients(tmp_path, monkeypatch):
    monkeypatch.setenv("CERT_VALIDITY_DAYS", "3")
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    mgr.create_client_cert("expiring-client")

    monkeypatch.setenv("CERT_VALIDITY_DAYS", "365")
    mgr2 = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    mgr2.create_client_cert("healthy-client", force=False)

    result = mgr.check_cert_expiry(days_before=30)

    names = {c["name"] for c in result["clients"]}
    assert "expiring-client" in names
    assert "healthy-client" not in names


def test_check_cert_expiry_handles_corrupt_files(tmp_path, caplog):
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    mgr.create_ca()
    mgr.create_server_cert(hostname="host.example.com")
    mgr.create_client_cert("client1")

    mgr.ca_cert_path.write_bytes(b"garbage")
    mgr.server_cert_path.write_bytes(b"garbage")
    (mgr.clients_dir / "client1.crt").write_bytes(b"garbage")

    with caplog.at_level("ERROR"):
        result = mgr.check_cert_expiry()

    assert result == {"ca": [], "server": [], "clients": []}
    assert "Failed to check CA expiry" in caplog.text
    assert "Failed to check server cert expiry" in caplog.text
