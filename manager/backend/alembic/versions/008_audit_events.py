"""Add audit_event table — durable, SIEM-exportable audit trail.

Revision ID: 008_audit_events
Revises: 007_revoked_token
"""
from alembic import op
from sqlalchemy import (
    Column, DateTime, ForeignKey, Index, Integer, String, func
)

revision = "008_audit_events"
down_revision = "007_revoked_token"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add durable audit event log."""
    op.create_table(
        'audit_event',
        Column('id', Integer, primary_key=True, autoincrement=True),
        Column('created_at', DateTime, nullable=False, server_default=func.now(), index=True),
        Column('actor_id', Integer, ForeignKey('auth_user.id', ondelete='SET NULL')),
        Column('tenant', String(100)),
        Column('action', String(100), nullable=False, index=True),
        Column('resource_type', String(50), index=True),
        Column('resource_id', Integer, index=True),
        Column('outcome', String(20), nullable=False, server_default='success'),
        Column('status_code', Integer),
        Column('request_id', String(36), index=True),
        Column('source_ip', String(45)),
    )
    op.create_index('idx_audit_event_actor', 'audit_event', ['actor_id'])
    op.create_index('idx_audit_event_action_created', 'audit_event', ['action', 'created_at'])
    op.create_index('idx_audit_event_resource', 'audit_event', ['resource_type', 'resource_id'])


def downgrade() -> None:
    """Remove audit event log."""
    op.drop_index('idx_audit_event_resource', table_name='audit_event')
    op.drop_index('idx_audit_event_action_created', table_name='audit_event')
    op.drop_index('idx_audit_event_actor', table_name='audit_event')
    op.drop_table('audit_event')
