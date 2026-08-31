"""Hash/encrypt at-rest credentials that were previously stored in plaintext.

Flagged by security audit (highest-confidence finding): DNS resolver tokens,
dns_server.join_key, dns_server.jwt_secret, and deployment_domain.jwt_token
were all stored, compared, and (for tokens) returned in plaintext. This
migration:

  - `token`: adds `token_hash` (SHA-256 hex digest), backfills it from the
    existing plaintext `token` column, then DROPS `token` -- nothing
    readable remains at rest. Runtime lookup moves to hash equality
    (app.services.auth_service.AuthService.validate_dns_token,
    app.blueprints.tokens, dns-server's selective_dns_routing).
  - `dns_server.join_key`: same treatment -> `join_key_hash`, plaintext
    column dropped (app.services.join_key_service.JoinKeyService).
  - `dns_server.jwt_secret`: re-encrypted in place with the shared
    Fernet/HKDF-from-SECRET_KEY cipher (recoverable -- it's the HMAC
    signing/verification key for server JWTs, so it can't be a one-way
    hash). Column name/type unchanged; only the stored value changes.
  - `deployment_domain.jwt_token`: the JWT is self-verifying via signature;
    the stored value only backs a revocation/rollover equality check, so it
    is hashed the same way as `token`/`join_key` -> `jwt_token_hash`,
    plaintext column dropped.

Uses `op.batch_alter_table()` for the drop-column/nullable/constraint steps:
the columns being dropped (`token`, `join_key`, `jwt_token`) all carry a
single-column UNIQUE constraint, which SQLite's `ALTER TABLE ... DROP
COLUMN` refuses to touch directly ("no such column" once the constraint's
implicit index is in the way) -- batch mode recreates the table on SQLite to
work around this, and is a transparent passthrough (no recreate) on
PostgreSQL/MySQL, so behavior there is unchanged. Verified against a
pre-migration SQLite fixture, not just read for plausibility.

Downgrade is best-effort: hashed values cannot be un-hashed, so the
recreated plaintext columns are populated with NULL for `token`/`join_key`/
`jwt_token` (any row written after this migration ran will need a new
token/join-key/domain-JWT issued). `jwt_secret` IS decrypted back to
plaintext on downgrade since Fernet encryption is reversible.

Revision ID: 015_hash_tokens_at_rest
Revises: 014_add_login_lockout
"""
from __future__ import annotations

import hashlib
import os
import sys

from alembic import op
import sqlalchemy as sa

revision = "015_hash_tokens_at_rest"
down_revision = "014_add_login_lockout"
branch_labels = None
depends_on = None

# Make `app.*` importable so this migration can reuse the exact same
# Fernet/HKDF cipher app.services.join_key_service.JoinKeyService and
# app.utils.crypto use at runtime -- avoids re-deriving the key with
# slightly different (and therefore incompatible) KDF parameters.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


def _sha256_hex(value: str) -> str:
    """Hex-encoded SHA-256 digest (matches app.utils.crypto.sha256_hex)."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _app_context():
    """Push a minimal Flask app context so JoinKeyService's Fernet cipher
    (which reads SECRET_KEY via ``current_app.config``) can be reused
    verbatim during the migration, instead of duplicating the HKDF
    derivation here and risking drift from the runtime implementation."""
    from flask import Flask

    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "")
    return app.app_context()


def upgrade() -> None:
    """Backfill hash/encrypted columns, then drop the plaintext originals."""
    bind = op.get_bind()

    # ── token.token -> token.token_hash ─────────────────────────────────
    op.add_column("token", sa.Column("token_hash", sa.String(64), nullable=True))

    token_tbl = sa.table(
        "token", sa.column("id", sa.Integer), sa.column("token", sa.String),
        sa.column("token_hash", sa.String),
    )
    for row in bind.execute(sa.select(token_tbl.c.id, token_tbl.c.token)).fetchall():
        bind.execute(
            token_tbl.update()
            .where(token_tbl.c.id == row.id)
            .values(token_hash=_sha256_hex(row.token))
        )

    op.drop_index("idx_token_active", table_name="token")
    with op.batch_alter_table("token") as batch_op:
        batch_op.alter_column("token_hash", nullable=False)
        batch_op.drop_column("token")
        batch_op.create_unique_constraint("uq_token_token_hash", ["token_hash"])
    op.create_index("ix_token_token_hash", "token", ["token_hash"])
    op.create_index("idx_token_active", "token", ["token_hash", "active"])

    # ── dns_server.join_key -> dns_server.join_key_hash ─────────────────
    op.add_column("dns_server", sa.Column("join_key_hash", sa.String(64), nullable=True))

    dns_server_tbl = sa.table(
        "dns_server", sa.column("id", sa.Integer), sa.column("join_key", sa.String),
        sa.column("join_key_hash", sa.String), sa.column("jwt_secret", sa.String),
    )
    rows = bind.execute(
        sa.select(dns_server_tbl.c.id, dns_server_tbl.c.join_key, dns_server_tbl.c.jwt_secret)
    ).fetchall()

    with _app_context():
        from app.services.join_key_service import JoinKeyService

        for row in rows:
            bind.execute(
                dns_server_tbl.update()
                .where(dns_server_tbl.c.id == row.id)
                .values(
                    join_key_hash=JoinKeyService.hash_join_key(row.join_key),
                    # jwt_secret was plaintext; re-encrypt in place (same
                    # column, no rename -- it must stay recoverable).
                    jwt_secret=JoinKeyService.encrypt_jwt_secret(row.jwt_secret),
                )
            )

    with op.batch_alter_table("dns_server") as batch_op:
        batch_op.alter_column("join_key_hash", nullable=False)
        batch_op.drop_column("join_key")
        batch_op.create_unique_constraint("uq_dns_server_join_key_hash", ["join_key_hash"])
    op.create_index("ix_dns_server_join_key_hash", "dns_server", ["join_key_hash"])

    # ── deployment_domain.jwt_token -> deployment_domain.jwt_token_hash ──
    op.add_column(
        "deployment_domain", sa.Column("jwt_token_hash", sa.String(64), nullable=True)
    )

    domain_tbl = sa.table(
        "deployment_domain", sa.column("id", sa.Integer),
        sa.column("jwt_token", sa.String), sa.column("jwt_token_hash", sa.String),
    )
    for row in bind.execute(sa.select(domain_tbl.c.id, domain_tbl.c.jwt_token)).fetchall():
        bind.execute(
            domain_tbl.update()
            .where(domain_tbl.c.id == row.id)
            .values(jwt_token_hash=_sha256_hex(row.jwt_token))
        )

    with op.batch_alter_table("deployment_domain") as batch_op:
        batch_op.alter_column("jwt_token_hash", nullable=False)
        batch_op.drop_column("jwt_token")
        batch_op.create_unique_constraint(
            "uq_deployment_domain_jwt_token_hash", ["jwt_token_hash"]
        )


def downgrade() -> None:
    """Best-effort reversal. Hashed values are NOT recoverable: rows written
    after this migration ran get a NULL plaintext column back (callers must
    reissue a token/join-key/domain-JWT). `jwt_secret` IS restored to
    plaintext since Fernet encryption is reversible."""
    bind = op.get_bind()

    # ── deployment_domain ────────────────────────────────────────────────
    op.add_column("deployment_domain", sa.Column("jwt_token", sa.String(512), nullable=True))
    with op.batch_alter_table("deployment_domain") as batch_op:
        batch_op.drop_constraint("uq_deployment_domain_jwt_token_hash", type_="unique")
        batch_op.create_unique_constraint("uq_deployment_domain_jwt_token", ["jwt_token"])
        batch_op.drop_column("jwt_token_hash")

    # ── dns_server ───────────────────────────────────────────────────────
    dns_server_tbl = sa.table(
        "dns_server", sa.column("id", sa.Integer), sa.column("jwt_secret", sa.String),
    )
    rows = bind.execute(sa.select(dns_server_tbl.c.id, dns_server_tbl.c.jwt_secret)).fetchall()

    with _app_context():
        from app.services.join_key_service import JoinKeyService

        for row in rows:
            bind.execute(
                dns_server_tbl.update()
                .where(dns_server_tbl.c.id == row.id)
                .values(jwt_secret=JoinKeyService.decrypt_jwt_secret(row.jwt_secret))
            )

    op.drop_index("ix_dns_server_join_key_hash", table_name="dns_server")
    op.add_column("dns_server", sa.Column("join_key", sa.String(64), nullable=True))
    with op.batch_alter_table("dns_server") as batch_op:
        batch_op.drop_constraint("uq_dns_server_join_key_hash", type_="unique")
        batch_op.create_unique_constraint("uq_dns_server_join_key", ["join_key"])
        batch_op.drop_column("join_key_hash")

    # ── token ────────────────────────────────────────────────────────────
    op.drop_index("idx_token_active", table_name="token")
    op.drop_index("ix_token_token_hash", table_name="token")
    op.add_column("token", sa.Column("token", sa.String(255), nullable=True))
    with op.batch_alter_table("token") as batch_op:
        batch_op.drop_constraint("uq_token_token_hash", type_="unique")
        batch_op.create_unique_constraint("uq_token_token", ["token"])
        batch_op.drop_column("token_hash")
    op.create_index("idx_token_active", "token", ["token", "active"])
