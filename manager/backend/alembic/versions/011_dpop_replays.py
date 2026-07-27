"""
Alembic migration: DPoP replay defense table.

DPoP (RFC 9449) sender-constrained tokens use a unique jti (JWT ID) claim
in each proof. This table tracks which jtis have been used to prevent replay.
Expired entries are cleaned up opportunistically on each new write.

Revision ID: 011_dpop_replays
Revises: 010_dns_domain_allowlists
"""

from alembic import op
import sqlalchemy as sa

revision = "011_dpop_replays"
down_revision = "010_dns_domain_allowlists"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create dpop_replay table."""
    op.create_table(
        "dpop_replay",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("jti", sa.String(36), nullable=False, unique=True, index=True),
        sa.Column(
            "expires_at",
            sa.DateTime(),
            nullable=False,
            doc="Proof expires at this time; rows past expiry are purged",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_dpop_replay_expires", "dpop_replay", ["expires_at"])


def downgrade() -> None:
    """Drop dpop_replay table."""
    op.drop_index("idx_dpop_replay_expires", table_name="dpop_replay")
    op.drop_table("dpop_replay")
