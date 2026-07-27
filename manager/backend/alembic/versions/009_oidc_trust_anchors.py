"""Add oidc_trust_anchor table — OIDC token exchange for federated workloads.

Revision ID: 009_oidc_trust_anchors
Revises: 008_machine_clients
"""
from alembic import op
from sqlalchemy import (
    Column, DateTime, Boolean, Index, Integer, String, Text, func
)

revision = "009_oidc_trust_anchors"
down_revision = "008_machine_clients"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add oidc_trust_anchor table."""
    op.create_table(
        'oidc_trust_anchor',
        Column('id', Integer, primary_key=True, autoincrement=True),
        Column('issuer', String(1024), nullable=False, unique=True, index=True),
        Column('audience', String(512), nullable=False),
        Column('jwks_url', String(1024)),
        Column('static_jwks_pem', Text),
        Column('tenant', String(255), nullable=False, server_default='default'),
        Column('allowed_scopes', String(1024), nullable=False),
        Column('subject_pattern', String(255)),
        Column('active', Boolean, nullable=False, server_default='1'),
        Column('created_at', DateTime, nullable=False, server_default=func.now()),
        Column('updated_at', DateTime, onupdate=func.now()),
    )
    op.create_index('idx_oidc_trust_anchor_active', 'oidc_trust_anchor',
                    ['issuer', 'active'])


def downgrade() -> None:
    """Remove oidc_trust_anchor table."""
    op.drop_index('idx_oidc_trust_anchor_active', table_name='oidc_trust_anchor')
    op.drop_table('oidc_trust_anchor')
