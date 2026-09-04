"""Add IOC entries and overrides schema — ioc_entry, ioc_override tables and ioc_feed columns.

Revision ID: 002_ioc_entries
Revises: 001_initial
"""
import os
import sys

from alembic import op
from sqlalchemy import (
    Column, DateTime, ForeignKey, Index, Integer, JSON, String, Table, MetaData, func
)

# Add project root to path for imports
sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "..", "..")
)

revision = "002_ioc_entries"
down_revision = "001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add new IOC columns and tables."""
    # Add columns to ioc_feed
    op.add_column('ioc_feed', Column('enabled', type_=Integer, server_default='1'))
    op.add_column('ioc_feed', Column('format', type_=String(50)))
    op.add_column('ioc_feed', Column('parser_config', type_=JSON))
    op.add_column('ioc_feed', Column('authentication', type_=JSON))
    op.add_column('ioc_feed', Column('entry_count', type_=Integer, server_default='0'))
    op.add_column('ioc_feed', Column('last_success', type_=DateTime))

    # Create ioc_entry table
    op.create_table(
        'ioc_entry',
        Column('id', Integer, primary_key=True, autoincrement=True),
        Column('feed_id', Integer, ForeignKey('ioc_feed.id', ondelete='CASCADE'),
               nullable=False),
        Column('indicator', String(1024), nullable=False),
        Column('indicator_type', String(50), nullable=False),
        Column('threat_type', String(100)),
        Column('confidence', Integer),
        Column('first_seen', DateTime),
        Column('last_seen', DateTime),
        Column('tags', JSON),
        Column('context', JSON),
        Column('source_format', String(50)),
        Column('misp_event_id', String(100)),
        Column('misp_attribute_id', String(100)),
        Column('created_at', DateTime, nullable=False, server_default=func.now()),
        Column('updated_at', DateTime, onupdate=func.now()),
    )

    # Create indexes on ioc_entry
    op.create_index('idx_ioc_entry_indicator', 'ioc_entry', ['indicator'])
    op.create_index('idx_ioc_entry_feed_indicator', 'ioc_entry', ['feed_id', 'indicator'])

    # Create ioc_override table
    op.create_table(
        'ioc_override',
        Column('id', Integer, primary_key=True, autoincrement=True),
        Column('token_id', Integer, nullable=False),
        Column('indicator', String(1024), nullable=False),
        Column('indicator_type', String(50), nullable=False),
        Column('override_type', String(20), nullable=False),
        Column('reason', String(1024)),
        Column('created_by', String(255)),
        Column('created_at', DateTime, nullable=False, server_default=func.now()),
        Column('expires_at', DateTime),
    )

    # Create indexes on ioc_override
    op.create_index('idx_ioc_override_token_id', 'ioc_override', ['token_id'])
    op.create_index('idx_ioc_override_indicator', 'ioc_override', ['indicator'])
    op.create_index('idx_ioc_override_token_indicator', 'ioc_override', ['token_id', 'indicator'])


def downgrade() -> None:
    """Rollback: drop IOC tables and remove columns from ioc_feed."""
    # Drop ioc_override table and indexes
    op.drop_index('idx_ioc_override_token_indicator', table_name='ioc_override')
    op.drop_index('idx_ioc_override_indicator', table_name='ioc_override')
    op.drop_index('idx_ioc_override_token_id', table_name='ioc_override')
    op.drop_table('ioc_override')

    # Drop ioc_entry table and indexes
    op.drop_index('idx_ioc_entry_feed_indicator', table_name='ioc_entry')
    op.drop_index('idx_ioc_entry_indicator', table_name='ioc_entry')
    op.drop_table('ioc_entry')

    # Remove columns from ioc_feed
    op.drop_column('ioc_feed', 'last_success')
    op.drop_column('ioc_feed', 'entry_count')
    op.drop_column('ioc_feed', 'authentication')
    op.drop_column('ioc_feed', 'parser_config')
    op.drop_column('ioc_feed', 'format')
    op.drop_column('ioc_feed', 'enabled')
