"""
DNS Server models for Squawk DNS Manager.
Defines dns_server and dns_server_metrics tables.
"""

from pydal import Field
from datetime import datetime


def define_dns_server_tables(db):
    """Define DNS server-related tables."""

    # DNS Server table
    db.define_table('dns_server',
        Field('name', 'string', notnull=True, length=100),
        Field('join_key', 'string', unique=True, notnull=True, length=64),  # 64-char hex
        Field('jwt_secret', 'string', notnull=True, length=255),  # Unique JWT secret per server
        Field('status', 'string', notnull=True, default='offline',
              requires=lambda value: value in ['online', 'offline', 'degraded']),
        Field('last_heartbeat', 'datetime'),
        Field('version', 'string', length=50),
        Field('region', 'string', length=100),
        Field('hostname', 'string', length=255),
        Field('created_at', 'datetime', default=lambda: datetime.utcnow(), notnull=True),
        Field('updated_at', 'datetime', update=lambda: datetime.utcnow()),
        format='%(name)s'
    )

    # DNS Server metrics table
    db.define_table('dns_server_metrics',
        Field('server_id', 'reference dns_server', notnull=True, ondelete='CASCADE'),
        Field('timestamp', 'datetime', default=lambda: datetime.utcnow(), notnull=True),
        Field('queries_total', 'integer', default=0, notnull=True),
        Field('cache_hits', 'integer', default=0, notnull=True),
        Field('errors', 'integer', default=0, notnull=True),
        Field('avg_response_ms', 'double', default=0.0, notnull=True)
    )

    # Index for efficient metrics queries
    db.executesql('CREATE INDEX IF NOT EXISTS idx_metrics_server_timestamp ON dns_server_metrics(server_id, timestamp);')

    return db
