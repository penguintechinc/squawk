"""Add revoked_token table — refresh-token rotation + logout revocation.

Revision ID: 007_revoked_token
Revises: 006_mtls_certificates
"""
from alembic import op
from sqlalchemy import (
    Column, DateTime, ForeignKey, Index, Integer, String, func
)

revision = "007_revoked_token"
down_revision = "006_mtls_certificates"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add refresh-token revocation denylist."""
    op.create_table(
        'revoked_token',
        Column('id', Integer, primary_key=True, autoincrement=True),
        Column('jti', String(36), nullable=False, unique=True, index=True),
        Column('user_id', Integer, ForeignKey('auth_user.id', ondelete='CASCADE')),
        Column('reason', String(50)),
        Column('revoked_at', DateTime, nullable=False, server_default=func.now()),
        Column('expires_at', DateTime, nullable=False),
    )
    op.create_index('idx_revoked_token_expires', 'revoked_token', ['expires_at'])


def downgrade() -> None:
    """Remove refresh-token revocation denylist."""
    op.drop_index('idx_revoked_token_expires', table_name='revoked_token')
    op.drop_table('revoked_token')
