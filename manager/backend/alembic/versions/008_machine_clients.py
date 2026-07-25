"""Add machine_client table — OAuth2 client_credentials for machine identities.

Revision ID: 008_machine_clients
Revises: 007_revoked_token
"""
from alembic import op
from sqlalchemy import (
    Column, DateTime, Boolean, Index, Integer, String, Text, func
)

revision = "008_machine_clients"
down_revision = "007_revoked_token"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add machine_client table."""
    op.create_table(
        'machine_client',
        Column('id', Integer, primary_key=True, autoincrement=True),
        Column('client_id', String(64), nullable=False, unique=True, index=True),
        Column('client_secret_hash', String(255), nullable=False),
        Column('tenant', String(255), nullable=False, server_default='default'),
        Column('scopes', String(1024), nullable=False),
        Column('description', Text),
        Column('active', Boolean, nullable=False, server_default='1'),
        Column('created_at', DateTime, nullable=False, server_default=func.now()),
        Column('last_used_at', DateTime),
    )
    op.create_index('idx_machine_client_active', 'machine_client',
                    ['client_id', 'active'])


def downgrade() -> None:
    """Remove machine_client table."""
    op.drop_index('idx_machine_client_active', table_name='machine_client')
    op.drop_table('machine_client')
