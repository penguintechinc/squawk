"""Add selective DNS routing schema — dns_group, user_group_assignment, dns_routing_zone, group_zone_access.

Revision ID: 005_selective_dns_routing
Revises: 004_client_config
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

revision = "005_selective_dns_routing"
down_revision = "004_client_config"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add selective DNS routing schema."""
    # Create dns_group table
    op.create_table(
        'dns_group',
        Column('id', Integer, primary_key=True, autoincrement=True),
        Column('name', String(100), unique=True, nullable=False),
        Column('description', Text),
        Column('visibility_levels', JSON),
        Column('created_at', DateTime, nullable=False, server_default=func.now()),
        Column('updated_at', DateTime, onupdate=func.now()),
    )
    op.create_index('idx_dns_group_name', 'dns_group', ['name'], unique=True)

    # Create user_group_assignment table
    op.create_table(
        'user_group_assignment',
        Column('id', Integer, primary_key=True, autoincrement=True),
        Column('user_id', Integer, nullable=False),
        Column('group_id', Integer, ForeignKey('dns_group.id', ondelete='CASCADE'),
               nullable=False),
        Column('role', String(50), nullable=False, server_default='member'),
        Column('assigned_at', DateTime, nullable=False, server_default=func.now()),
        Column('updated_at', DateTime, onupdate=func.now()),
    )
    op.create_index('idx_user_group_assignment_user_group',
                    'user_group_assignment',
                    ['user_id', 'group_id'],
                    unique=True)

    # Create dns_routing_zone table
    op.create_table(
        'dns_routing_zone',
        Column('id', Integer, primary_key=True, autoincrement=True),
        Column('name', String(255), unique=True, nullable=False),
        Column('visibility', String(50), nullable=False),
        Column('description', Text),
        Column('created_at', DateTime, nullable=False, server_default=func.now()),
        Column('updated_at', DateTime, onupdate=func.now()),
    )
    op.create_index('idx_dns_routing_zone_name', 'dns_routing_zone', ['name'], unique=True)

    # Create group_zone_access table
    op.create_table(
        'group_zone_access',
        Column('id', Integer, primary_key=True, autoincrement=True),
        Column('group_id', Integer, ForeignKey('dns_group.id', ondelete='CASCADE'),
               nullable=False),
        Column('zone_id', Integer, ForeignKey('dns_routing_zone.id', ondelete='CASCADE'),
               nullable=False),
        Column('created_at', DateTime, nullable=False, server_default=func.now()),
    )
    op.create_index('idx_group_zone_access_group_zone',
                    'group_zone_access',
                    ['group_id', 'zone_id'],
                    unique=True)


def downgrade() -> None:
    """Drop selective DNS routing schema."""
    op.drop_table('group_zone_access')
    op.drop_table('dns_routing_zone')
    op.drop_table('user_group_assignment')
    op.drop_table('dns_group')
