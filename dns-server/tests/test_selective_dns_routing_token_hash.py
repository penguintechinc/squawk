"""Regression test: SelectiveDNSRouter looks up DNS tokens by hash, never
plaintext (see [[fix-token-hash-at-rest]]).

The `token` table only persists `token_hash` (SHA-256 hex digest) at rest --
`_get_user_id_from_token` must hash the incoming token before querying.

regression: at-rest credential storage (5-agent audit finding)
"""
import hashlib
import os

from app.services.selective_dns_routing import SelectiveDNSRouter


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def test_get_user_id_from_token_matches_by_hash(db):
    """A token row storing only `token_hash` resolves correctly when the
    plaintext value is presented -- proves the lookup hashes before query."""
    plaintext = "regression-test-token-value"
    token_id = db.token.insert(
        token_hash=_sha256_hex(plaintext),
        name="hash-lookup-test",
        active=True,
    )
    db.commit()

    router = SelectiveDNSRouter(db_url=os.environ["DATABASE_URI"])
    resolved_id = router._get_user_id_from_token(plaintext)

    assert resolved_id == token_id


def test_get_user_id_from_token_rejects_wrong_token(db):
    """A token value that doesn't match any stored hash returns None
    (strict lookup, no auto-create)."""
    db.token.insert(
        token_hash=_sha256_hex("correct-token-value"),
        name="hash-lookup-wrong-test",
        active=True,
    )
    db.commit()

    router = SelectiveDNSRouter(db_url=os.environ["DATABASE_URI"])
    resolved_id = router._get_user_id_from_token("wrong-token-value")

    assert resolved_id is None


def test_plaintext_token_column_does_not_exist(db):
    """The `token` table must not carry a plaintext `token` column -- only
    `token_hash` is persisted at rest."""
    from sqlalchemy import inspect

    columns = {col["name"] for col in inspect(db.engine).get_columns("token")}
    assert "token_hash" in columns
    assert "token" not in columns
