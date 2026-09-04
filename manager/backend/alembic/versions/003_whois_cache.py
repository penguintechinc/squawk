"""Add WHOIS cache schema — whois_cache, whois_search_index, whois_query_log tables.

Revision ID: 003_whois_cache
Revises: 002_ioc_entries
"""
import os
import sys

from alembic import op
from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Index, Integer, JSON, String,
    Table, MetaData, Text, func
)

# Add project root to path for imports
sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "..", "..")
)

revision = "003_whois_cache"
down_revision = "002_ioc_entries"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add WHOIS cache tables."""
    # Create whois_cache table
    op.create_table(
        'whois_cache',
        Column('id', Integer, primary_key=True, autoincrement=True),
        Column('query', String(1024), unique=True, nullable=False),
        Column('query_type', String(20), nullable=False),
        Column('whois_data', Text),
        Column('parsed_data', JSON),
        Column('registrar', String(255)),
        Column('creation_date', DateTime),
        Column('expiration_date', DateTime),
        Column('nameservers', JSON),
        Column('query_timestamp', DateTime, nullable=False, server_default=func.now()),
        Column('last_updated', DateTime, nullable=False, server_default=func.now(),
               onupdate=func.now()),
    )

    # Create indexes on whois_cache
    op.create_index('idx_whois_cache_query', 'whois_cache', ['query'])

    # Create whois_search_index table
    op.create_table(
        'whois_search_index',
        Column('id', Integer, primary_key=True, autoincrement=True),
        Column('whois_id', Integer, ForeignKey('whois_cache.id', ondelete='CASCADE'),
               nullable=False),
        Column('search_field', String(100), nullable=False),
        Column('search_value', String(1024), nullable=False),
        Column('indexed_at', DateTime, nullable=False, server_default=func.now()),
    )

    # Create indexes on whois_search_index
    op.create_index('idx_whois_search_index_whois_id', 'whois_search_index', ['whois_id'])
    op.create_index('idx_whois_search_index_search_value', 'whois_search_index', ['search_value'])

    # Create whois_query_log table
    op.create_table(
        'whois_query_log',
        Column('id', Integer, primary_key=True, autoincrement=True),
        Column('query', String(1024), nullable=False),
        Column('query_type', String(20), nullable=False),
        Column('cache_hit', Boolean, nullable=False, server_default='0'),
        Column('response_time_ms', Integer),
        Column('client_ip', String(45)),
        Column('timestamp', DateTime, nullable=False, server_default=func.now()),
    )

    # Create index on whois_query_log
    op.create_index('idx_whois_query_log_timestamp', 'whois_query_log', ['timestamp'])


def downgrade() -> None:
    """Rollback: drop WHOIS cache tables."""
    # Drop whois_query_log table and indexes
    op.drop_index('idx_whois_query_log_timestamp', table_name='whois_query_log')
    op.drop_table('whois_query_log')

    # Drop whois_search_index table and indexes
    op.drop_index('idx_whois_search_index_search_value', table_name='whois_search_index')
    op.drop_index('idx_whois_search_index_whois_id', table_name='whois_search_index')
    op.drop_table('whois_search_index')

    # Drop whois_cache table and indexes
    op.drop_index('idx_whois_cache_query', table_name='whois_cache')
    op.drop_table('whois_cache')
