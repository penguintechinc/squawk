"""Add SAML assertion ID replay prevention table.

Stores consumed assertion IDs to prevent replay attacks.

Revision ID: 013_add_saml_assertion_ids
Revises: 012_add_saml_providers
"""
from alembic import op
from sqlalchemy import Column, Integer, String, DateTime, func

revision = "013_add_saml_assertion_ids"
down_revision = "012_add_saml_providers"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create saml_assertion_ids table for replay prevention."""
    op.create_table(
        'saml_assertion_ids',
        Column('id', Integer, primary_key=True, autoincrement=True),
        Column('provider_id', Integer, nullable=False),  # FK to saml_providers.id
        Column('assertion_id', String(255), nullable=False),  # @ID from SAML Assertion
        Column('consumed_at', DateTime, nullable=False, server_default=func.now()),
    )
    # Create index for fast lookup during assertion validation
    op.create_index('ix_saml_assertion_ids_provider_id_assertion_id',
                    'saml_assertion_ids', ['provider_id', 'assertion_id'])


def downgrade() -> None:
    """Drop saml_assertion_ids table."""
    op.drop_table('saml_assertion_ids')
