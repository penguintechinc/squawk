"""Regression tests: deployment-domain JWTs are asymmetrically signed.

Domain tokens minted by ClientConfigManager must be signed with the manager's
private key (ES256 default / RS256 fallback) and verified with the public key.
HS256/none and wrong-key tokens must be rejected (algorithm-confusion defense),
matching the platform-wide JWT scheme.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.services.client_config_service import ClientConfigManager


def _gen_es256_pem() -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    priv = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv, pub


class _FakeField:
    """Supports the ``==`` / ``&`` operators used to build penguin-dal queries."""

    def __eq__(self, other):  # noqa: D105
        return self

    def __and__(self, other):  # noqa: D105
        return self

    __rand__ = __and__


class _FakeSelect:
    def __init__(self, row):
        self._row = row

    def first(self):
        return self._row


class _FakeQuery:
    def __init__(self, row):
        self._row = row

    def select(self):
        return _FakeSelect(self._row)


class _FakeTable:
    def __getattr__(self, _name):
        return _FakeField()


class _FakeDB:
    """Minimal penguin-dal stand-in: returns a preset domain row from queries."""

    def __init__(self, row):
        self._row = row

    def __getattr__(self, _name):
        return _FakeTable()

    def __call__(self, _query):
        return _FakeQuery(self._row)

    def close(self):
        pass


class _Row:
    def __init__(self, id_, name, description=""):
        self.id = id_
        self.name = name
        self.description = description


@pytest.fixture
def manager(monkeypatch):
    """A ClientConfigManager with a real ES256 keypair and no DB side effects."""
    priv, pub = _gen_es256_pem()
    monkeypatch.setattr(
        ClientConfigManager, "_initialize_default_roles", lambda self: None
    )
    mgr = ClientConfigManager(
        db_url="sqlite://:memory:", private_key=priv, public_key=pub
    )
    # Domain lookups return a matching active row for whatever token verifies.
    mgr._get_db = lambda: _FakeDB(_Row(1, "prod-domain", "Production"))  # type: ignore[attr-defined]
    return mgr, priv, pub


def test_domain_jwt_signed_es256_not_hs256(manager):
    mgr, _priv, pub = manager
    token = mgr._generate_domain_jwt("prod-domain")
    assert jwt.get_unverified_header(token)["alg"] == "ES256"

    payload = jwt.decode(
        token, pub, algorithms=["ES256"], audience="squawk", issuer="squawk-manager"
    )
    assert payload["domain"] == "prod-domain"
    assert payload["type"] == "deployment_domain"
    assert "exp" in payload and "iat" in payload


def test_valid_domain_jwt_verifies(manager):
    mgr, _priv, _pub = manager
    token = mgr._generate_domain_jwt("prod-domain")
    result = mgr._verify_domain_jwt(token)
    assert result is not None
    assert result["name"] == "prod-domain"


def test_wrong_key_domain_jwt_rejected(manager):
    """A token signed by a different private key must fail verification."""
    mgr, _priv, _pub = manager
    attacker_priv, _attacker_pub = _gen_es256_pem()
    now = datetime.now(timezone.utc)
    forged = jwt.encode(
        {
            "domain": "prod-domain",
            "type": "deployment_domain",
            "iss": "squawk-manager",
            "aud": "squawk",
            "iat": now,
            "exp": now + timedelta(days=1),
        },
        attacker_priv,
        algorithm="ES256",
    )
    assert mgr._verify_domain_jwt(forged) is None


def test_hs256_domain_jwt_rejected(manager):
    """HS256 tokens must be rejected — verifier allows ES256/RS256 only.

    This defeats the public-key-as-HMAC algorithm-confusion attack: even a
    validly-formed HS256 token cannot pass the algorithm allowlist.
    """
    mgr, _priv, _pub = manager
    now = datetime.now(timezone.utc)
    forged = jwt.encode(
        {
            "domain": "prod-domain",
            "type": "deployment_domain",
            "iss": "squawk-manager",
            "aud": "squawk",
            "iat": now,
            "exp": now + timedelta(days=1),
        },
        "attacker-hmac-secret",
        algorithm="HS256",
    )
    assert mgr._verify_domain_jwt(forged) is None


def test_expired_domain_jwt_rejected(manager):
    mgr, priv, _pub = manager
    now = datetime.now(timezone.utc)
    expired = jwt.encode(
        {
            "domain": "prod-domain",
            "type": "deployment_domain",
            "iss": "squawk-manager",
            "aud": "squawk",
            "iat": now - timedelta(days=2),
            "exp": now - timedelta(days=1),
        },
        priv,
        algorithm="ES256",
    )
    assert mgr._verify_domain_jwt(expired) is None


def test_missing_exp_domain_jwt_rejected(manager):
    """Tokens without a required exp claim must be rejected."""
    mgr, priv, _pub = manager
    now = datetime.now(timezone.utc)
    no_exp = jwt.encode(
        {
            "domain": "prod-domain",
            "type": "deployment_domain",
            "iss": "squawk-manager",
            "aud": "squawk",
            "iat": now,
        },
        priv,
        algorithm="ES256",
    )
    assert mgr._verify_domain_jwt(no_exp) is None


def test_ephemeral_keypair_when_unconfigured(monkeypatch):
    """With no keypair supplied, a working ephemeral ES256 pair is generated."""
    monkeypatch.setattr(
        ClientConfigManager, "_initialize_default_roles", lambda self: None
    )
    mgr = ClientConfigManager(db_url="sqlite://:memory:")
    mgr._get_db = lambda: _FakeDB(_Row(1, "d", "d"))  # type: ignore[attr-defined]
    token = mgr._generate_domain_jwt("d")
    assert mgr._verify_domain_jwt(token) is not None
