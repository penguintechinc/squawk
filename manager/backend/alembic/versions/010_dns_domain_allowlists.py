"""Add DNS domain allowlists — per-identity DNS domain allowlists enforced at DoH.

Revision ID: 010_dns_domain_allowlists
Revises: 009_oidc_trust_anchors
"""
from alembic import op
from sqlalchemy import Column, Text

revision = "010_dns_domain_allowlists"
down_revision = "009_oidc_trust_anchors"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add allowed_domains column to machine_client and oidc_trust_anchor tables."""
    # Add to machine_client
    op.add_column(
        'machine_client',
        Column('allowed_domains', Text, nullable=True)
    )

    # Add to oidc_trust_anchor
    op.add_column(
        'oidc_trust_anchor',
        Column('allowed_domains', Text, nullable=True)
    )


def downgrade() -> None:
    """Remove allowed_domains columns."""
    op.drop_column('machine_client', 'allowed_domains')
    op.drop_column('oidc_trust_anchor', 'allowed_domains')
