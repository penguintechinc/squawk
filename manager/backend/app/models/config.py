"""
Configuration models for Squawk DNS Manager.
Defines ioc_feed and token tables.
"""

from pydal import Field
from datetime import datetime


def define_config_tables(db):
    """Define configuration-related tables."""

    # IOC Feed table
    db.define_table('ioc_feed',
        Field('name', 'string', unique=True, notnull=True, length=100),
        Field('url', 'string', notnull=True, length=1024),
        Field('feed_type', 'string', notnull=True,
              requires=lambda value: value in ['domain', 'ip', 'url', 'hash']),
        Field('update_interval', 'integer', default=24, notnull=True),  # hours
        Field('last_updated', 'datetime'),
        Field('active', 'boolean', default=True, notnull=True),
        Field('description', 'text'),
        Field('created_at', 'datetime', default=lambda: datetime.utcnow(), notnull=True),
        Field('updated_at', 'datetime', update=lambda: datetime.utcnow()),
        format='%(name)s'
    )

    # Token table for DNS authentication
    db.define_table('token',
        Field('token', 'string', unique=True, notnull=True, length=255),
        Field('name', 'string', notnull=True, length=100),
        Field('team_id', 'reference team', ondelete='CASCADE'),
        Field('created_by', 'reference auth_user', ondelete='SET NULL'),
        Field('active', 'boolean', default=True, notnull=True),
        Field('expires_at', 'datetime'),
        Field('last_used', 'datetime'),
        Field('created_at', 'datetime', default=lambda: datetime.utcnow(), notnull=True),
        Field('updated_at', 'datetime', update=lambda: datetime.utcnow()),
        format='%(name)s'
    )

    # Index for fast token lookups
    db.executesql('CREATE INDEX IF NOT EXISTS idx_token_active ON token(token, active);')

    return db
