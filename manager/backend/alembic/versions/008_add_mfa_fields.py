"""Add MFA (TOTP) fields to auth_user table.

Revision ID: 008_add_mfa_fields
Revises: 007_revoked_token
"""
from alembic import op
from sqlalchemy import Column, Boolean, String, Text, Integer, func

revision = "008_add_mfa_fields"
down_revision = "007_revoked_token"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add TOTP MFA fields to auth_user."""
    op.add_column('auth_user',
        Column('mfa_enabled', Boolean, nullable=False, server_default="0")
    )
    op.add_column('auth_user',
        Column('mfa_secret', String(255), nullable=True)
    )
    op.add_column('auth_user',
        Column('mfa_recovery_codes', Text, nullable=True)
    )
    op.add_column('auth_user',
        Column('mfa_last_totp_counter', Integer, nullable=False, server_default="0")
    )


def downgrade() -> None:
    """Remove TOTP MFA fields from auth_user."""
    op.drop_column('auth_user', 'mfa_last_totp_counter')
    op.drop_column('auth_user', 'mfa_recovery_codes')
    op.drop_column('auth_user', 'mfa_secret')
    op.drop_column('auth_user', 'mfa_enabled')
