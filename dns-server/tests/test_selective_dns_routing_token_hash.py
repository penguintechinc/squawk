"""Regression test: SelectiveDNSRouter looks up DNS tokens by hash, never
plaintext (see [[fix-token-hash-at-rest]]).

The `token` table only persists `token_hash` (SHA-256 hex digest) at rest --
`_get_user_id_from_token` must hash the incoming token before querying.

Self-contained schema setup: in production, dns-server never owns/creates
the `token` table -- `SelectiveDNSRouter._get_db()` calls
``penguin_dal.DB(db_url)``, which purely reflects whatever tables already
exist in the shared database (``MetaData.reflect(bind=engine)``); the
manager service is what actually creates the table via its
schema.py/Alembic migration. This test mirrors that split by creating the
table directly against the raw engine (``token_table`` fixture below) --
independent of conftest.py's `_schema_metadata` import-or-fallback-to-empty
mechanism, which is unreliable across CI job layouts that don't check out
manager/backend alongside dns-server (see conftest.py's docstring on that
fallback). The fixture is idempotent (`checkfirst=True`) and only cleans up
rows -- never the table -- so it works identically whether that import
succeeded or fell back to empty metadata, and this suite passes from a
completely clean database without depending on any other test in the
session having created the table first.

regression: at-rest credential storage (5-agent audit finding)
"""
import hashlib
import os

import pytest
from sqlalchemy import Boolean, Column, DateTime, Integer, MetaData, String, Table

from app.services.selective_dns_routing import SelectiveDNSRouter


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@pytest.fixture
def token_table(db_engine):
    """Ensure a minimal `token` table (matching the manager's post-migration
    schema: token_hash only, no plaintext token column) exists against the
    raw engine -- self-contained, no dependency on any other fixture/test
    having created it first.

    ``checkfirst=True`` makes this a no-op when conftest.py's manager-schema
    import *did* succeed (the real, fuller table already exists) -- only
    rows are cleaned up afterward, never the table itself, so this fixture
    never conflicts with conftest.py's own autouse `clean_db_tables`
    cleanup (which iterates the real schema's tables when that import
    succeeds, and does nothing when it falls back to empty metadata)."""
    metadata = MetaData()
    table = Table(
        "token", metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("token_hash", String(64), unique=True, nullable=False),
        Column("name", String(100), nullable=False),
        Column("team_id", Integer, nullable=True),
        Column("created_by", Integer, nullable=True),
        Column("active", Boolean, nullable=False, default=True),
        Column("expires_at", DateTime, nullable=True),
        Column("last_used", DateTime, nullable=True),
        Column("created_at", DateTime, nullable=True),
        Column("updated_at", DateTime, nullable=True),
    )
    table.create(db_engine, checkfirst=True)
    yield table
    with db_engine.begin() as conn:
        conn.execute(table.delete())


def _insert_token(db_engine, table, *, token_hash: str, name: str) -> int:
    with db_engine.begin() as conn:
        result = conn.execute(table.insert().values(token_hash=token_hash, name=name, active=True))
        return result.inserted_primary_key[0]


def test_get_user_id_from_token_matches_by_hash(db_engine, token_table):
    """A token row storing only `token_hash` resolves correctly when the
    plaintext value is presented -- proves the lookup hashes before query."""
    plaintext = "regression-test-token-value"
    token_id = _insert_token(
        db_engine, token_table, token_hash=_sha256_hex(plaintext), name="hash-lookup-test"
    )

    # SelectiveDNSRouter opens a fresh penguin_dal.DB(url) per call, which
    # reflects the table just created above -- exactly the production path.
    router = SelectiveDNSRouter(db_url=os.environ["DATABASE_URI"])
    resolved_id = router._get_user_id_from_token(plaintext)

    assert resolved_id == token_id


def test_get_user_id_from_token_rejects_wrong_token(db_engine, token_table):
    """A token value that doesn't match any stored hash returns None
    (strict lookup, no auto-create)."""
    _insert_token(
        db_engine, token_table, token_hash=_sha256_hex("correct-token-value"),
        name="hash-lookup-wrong-test",
    )

    router = SelectiveDNSRouter(db_url=os.environ["DATABASE_URI"])
    resolved_id = router._get_user_id_from_token("wrong-token-value")

    assert resolved_id is None


def test_plaintext_token_column_does_not_exist(db_engine, token_table):
    """The `token` table must not carry a plaintext `token` column -- only
    `token_hash` is persisted at rest."""
    from sqlalchemy import inspect

    columns = {col["name"] for col in inspect(db_engine).get_columns("token")}
    assert "token_hash" in columns
    assert "token" not in columns
