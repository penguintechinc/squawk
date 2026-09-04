"""Add client configuration schema — deployment_domain, client_config, and related tables.

Revision ID: 004_client_config
Revises: 003_whois_cache
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

revision = "004_client_config"
down_revision = "003_whois_cache"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add client configuration schema."""
    # Create deployment_domain table
    op.create_table(
        'deployment_domain',
        Column('id', Integer, primary_key=True, autoincrement=True),
        Column('name', String(100), unique=True, nullable=False),
        Column('description', Text),
        Column('jwt_token', String(512), unique=True, nullable=False),
        Column('jwt_expires', DateTime, nullable=False),
        Column('active', Boolean, nullable=False, server_default='1'),
        Column('created_at', DateTime, nullable=False, server_default=func.now()),
        Column('updated_at', DateTime, onupdate=func.now()),
    )

    # Create client_config table
    op.create_table(
        'client_config',
        Column('id', Integer, primary_key=True, autoincrement=True),
        Column('name', String(100), nullable=False),
        Column('domain_id', Integer, ForeignKey('deployment_domain.id', ondelete='CASCADE'),
               nullable=False),
        Column('config_data', JSON, nullable=False),
        Column('version', Integer, nullable=False, server_default='1'),
        Column('description', Text),
        Column('created_by', String(255)),
        Column('active', Boolean, nullable=False, server_default='1'),
        Column('created_at', DateTime, nullable=False, server_default=func.now()),
        Column('updated_at', DateTime, onupdate=func.now()),
    )

    # Create config_role table
    op.create_table(
        'config_role',
        Column('id', Integer, primary_key=True, autoincrement=True),
        Column('name', String(50), unique=True, nullable=False),
        Column('permissions', JSON, nullable=False),
        Column('description', Text),
        Column('created_at', DateTime, nullable=False, server_default=func.now()),
    )

    # Create config_user_role table
    op.create_table(
        'config_user_role',
        Column('id', Integer, primary_key=True, autoincrement=True),
        Column('user_token_id', Integer, ForeignKey('token.id', ondelete='CASCADE'),
               nullable=False),
        Column('role_id', Integer, ForeignKey('config_role.id', ondelete='CASCADE'),
               nullable=False),
        Column('domain_id', Integer, ForeignKey('deployment_domain.id', ondelete='CASCADE')),
        Column('granted_by', String(255)),
        Column('granted_at', DateTime, nullable=False, server_default=func.now()),
    )

    # Create client_instance table
    op.create_table(
        'client_instance',
        Column('id', Integer, primary_key=True, autoincrement=True),
        Column('client_id', String(100), unique=True, nullable=False),
        Column('domain_id', Integer, ForeignKey('deployment_domain.id', ondelete='CASCADE'),
               nullable=False),
        Column('config_id', Integer, ForeignKey('client_config.id', ondelete='SET NULL')),
        Column('hostname', String(255), nullable=False),
        Column('ip_address', String(45), nullable=False),
        Column('last_checkin', DateTime),
        Column('last_config_pull', DateTime),
        Column('client_version', String(50)),
        Column('os_info', String(255)),
        Column('status', String(20), nullable=False, server_default='active'),
        Column('registered_at', DateTime, nullable=False, server_default=func.now()),
        Column('updated_at', DateTime, onupdate=func.now()),
    )

    # Create indexes on client_instance
    op.create_index('idx_client_instance_domain', 'client_instance', ['domain_id'])
    op.create_index('idx_client_instance_status', 'client_instance', ['status'])

    # Create config_history table
    op.create_table(
        'config_history',
        Column('id', Integer, primary_key=True, autoincrement=True),
        Column('config_id', Integer, ForeignKey('client_config.id', ondelete='CASCADE'),
               nullable=False),
        Column('version', Integer, nullable=False),
        Column('config_data', JSON, nullable=False),
        Column('change_description', String(1024)),
        Column('changed_by', String(255)),
        Column('changed_at', DateTime, nullable=False, server_default=func.now()),
    )

    # Create index on config_history
    op.create_index('idx_config_history_config_version', 'config_history',
                    ['config_id', 'version'])


def downgrade() -> None:
    """Rollback: drop client configuration schema."""
    # Drop config_history and indexes
    op.drop_index('idx_config_history_config_version', table_name='config_history')
    op.drop_table('config_history')

    # Drop client_instance and indexes
    op.drop_index('idx_client_instance_status', table_name='client_instance')
    op.drop_index('idx_client_instance_domain', table_name='client_instance')
    op.drop_table('client_instance')

    # Drop config_user_role
    op.drop_table('config_user_role')

    # Drop config_role
    op.drop_table('config_role')

    # Drop client_config
    op.drop_table('client_config')

    # Drop deployment_domain
    op.drop_table('deployment_domain')
