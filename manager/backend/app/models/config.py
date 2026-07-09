"""
Configuration models for Squawk DNS Manager.
Defines ioc_feed and token tables.
"""

from pydal import Field
from datetime import datetime


def define_config_tables(db):
    """Define configuration-related tables.

    NOTE: This function is maintained for backward compatibility and import tests.
    Schema is now defined in app/schema.py and migrated via Alembic.
    penguin-dal reflects the actual tables at runtime.
    """

    # IOC Feed table (matches schema.py)
    db.define_table('ioc_feed',
        Field('name', 'string', unique=True, notnull=True, length=100),
        Field('url', 'string', notnull=True, length=1024),
        Field('feed_type', 'string', notnull=True),
        Field('update_interval', 'integer', default=24, notnull=True),
        Field('last_updated', 'datetime'),
        Field('active', 'boolean', default=True, notnull=True),
        Field('enabled', 'boolean', default=True, notnull=True),
        Field('description', 'text'),
        Field('format', 'string', length=50),
        Field('parser_config', 'json'),
        Field('authentication', 'json'),
        Field('entry_count', 'integer', default=0, notnull=True),
        Field('last_success', 'datetime'),
        Field('created_at', 'datetime', default=lambda: datetime.utcnow(), notnull=True),
        Field('updated_at', 'datetime', update=lambda: datetime.utcnow()),
        format='%(name)s'
    )

    # IOC Entry table (matches schema.py)
    db.define_table('ioc_entry',
        Field('feed_id', 'reference ioc_feed', notnull=True, ondelete='CASCADE'),
        Field('indicator', 'string', notnull=True, length=1024),
        Field('indicator_type', 'string', notnull=True, length=50),
        Field('threat_type', 'string', length=100),
        Field('confidence', 'integer'),
        Field('first_seen', 'datetime'),
        Field('last_seen', 'datetime'),
        Field('tags', 'json'),
        Field('context', 'json'),
        Field('source_format', 'string', length=50),
        Field('misp_event_id', 'string', length=100),
        Field('misp_attribute_id', 'string', length=100),
        Field('created_at', 'datetime', default=lambda: datetime.utcnow(), notnull=True),
        Field('updated_at', 'datetime', update=lambda: datetime.utcnow()),
        format='%(feed_id)s'
    )

    # IOC Override table (matches schema.py)
    db.define_table('ioc_override',
        Field('token_id', 'integer', notnull=True),
        Field('indicator', 'string', notnull=True, length=1024),
        Field('indicator_type', 'string', notnull=True, length=50),
        Field('override_type', 'string', notnull=True, length=20),
        Field('reason', 'string', length=1024),
        Field('created_by', 'string', length=255),
        Field('created_at', 'datetime', default=lambda: datetime.utcnow(), notnull=True),
        Field('expires_at', 'datetime'),
        format='%(token_id)s'
    )

    # Token table for DNS authentication (matches schema.py)
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

    # Indexes for fast lookups
    db.executesql('CREATE INDEX IF NOT EXISTS idx_token_active ON token(token, active);')
    db.executesql('CREATE INDEX IF NOT EXISTS idx_ioc_entry_indicator ON ioc_entry(indicator);')
    db.executesql('CREATE INDEX IF NOT EXISTS idx_ioc_entry_feed_indicator ON ioc_entry(feed_id, indicator);')
    db.executesql('CREATE INDEX IF NOT EXISTS idx_ioc_override_token_id ON ioc_override(token_id);')
    db.executesql('CREATE INDEX IF NOT EXISTS idx_ioc_override_indicator ON ioc_override(indicator);')
    db.executesql('CREATE INDEX IF NOT EXISTS idx_ioc_override_token_indicator ON ioc_override(token_id, indicator);')

    return db
