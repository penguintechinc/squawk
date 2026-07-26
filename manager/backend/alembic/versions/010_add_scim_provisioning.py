"""Add SCIM 2.0 provisioning support with dedicated token management.

Revision ID: 010_add_scim_provisioning
Revises: 008_add_mfa_fields
"""
from alembic import op
from sqlalchemy import Column, String, Boolean, DateTime, Integer, Text
from sqlalchemy.sql import func

revision = "010_add_scim_provisioning"
down_revision = "008_add_mfa_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add SCIM provisioning tables and columns."""
    # Add external_id and provisioning columns to auth_user
    op.add_column('auth_user',
        Column('external_id', String(255), nullable=True, unique=True, index=True)
    )

    # Create scim_tokens table for enterprise IdP provisioning
    op.create_table(
        'scim_tokens',
        Column('id', Integer, primary_key=True, autoincrement=True),
        Column('token_hash', String(255), nullable=False, unique=True, index=True),
        Column('description', String(255), nullable=True),
        Column('tenant', String(100), nullable=False),
        Column('active', Boolean, nullable=False, server_default="1"),
        Column('created_at', DateTime, nullable=False, server_default=func.now()),
        Column('last_used_at', DateTime, nullable=True),
    )


def downgrade() -> None:
    """Remove SCIM provisioning tables and columns."""
    op.drop_table('scim_tokens')
    op.drop_column('auth_user', 'external_id')
