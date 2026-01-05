"""
Time synchronization models for Squawk Manager.
Defines time_server and time_sync_log tables.
Supports PTP (IEEE 1588) as primary and NTPv4 as fallback.
"""

from pydal import Field
from datetime import datetime


def define_time_tables(db):
    """Define time synchronization-related tables."""

    # Time Server table
    db.define_table('time_server',
        Field('name', 'string', notnull=True, length=100),
        Field('server_url', 'string', notnull=True, length=255),  # 'ptp://host' or 'ntp://host'
        Field('protocol', 'string', notnull=True, default='ntp',
              requires=lambda value: value in ['ptp', 'ntp']),
        Field('stratum', 'integer', default=2, notnull=True),
        Field('priority', 'integer', default=100, notnull=True),  # Lower = higher priority
        Field('team_id', 'reference team', ondelete='CASCADE'),
        Field('active', 'boolean', default=True, notnull=True),
        Field('status', 'string', notnull=True, default='unknown',
              requires=lambda value: value in ['synchronized', 'unsynchronized', 'unreachable', 'unknown']),
        Field('last_sync', 'datetime'),
        Field('last_offset_ms', 'double'),  # Last measured time offset in milliseconds
        Field('last_delay_ms', 'double'),   # Last measured network delay in milliseconds
        # PTP-specific configuration (JSON)
        Field('ptp_config', 'json'),  # {"domain": 0, "transport": "udp", "delay_mechanism": "e2e"}
        Field('created_at', 'datetime', default=lambda: datetime.utcnow(), notnull=True),
        Field('updated_at', 'datetime', update=lambda: datetime.utcnow()),
        format='%(name)s'
    )

    # Time Sync Log table (historical sync records)
    db.define_table('time_sync_log',
        Field('server_id', 'reference time_server', notnull=True, ondelete='CASCADE'),
        Field('timestamp', 'datetime', default=lambda: datetime.utcnow(), notnull=True),
        Field('offset_ms', 'double', notnull=True),  # Time offset in milliseconds
        Field('delay_ms', 'double', notnull=True),   # Network delay in milliseconds
        Field('protocol', 'string', notnull=True, length=10),
        Field('status', 'string', notnull=True, default='success',
              requires=lambda value: value in ['success', 'failed', 'timeout']),
        Field('error_message', 'text')  # Error details if failed
    )

    # Time Client table (clients forwarding NTP requests)
    db.define_table('time_client',
        Field('name', 'string', notnull=True, length=100),
        Field('hostname', 'string', length=255),
        Field('os_type', 'string', length=50),  # 'windows', 'macos', 'linux'
        Field('status', 'string', notnull=True, default='offline',
              requires=lambda value: value in ['online', 'offline', 'syncing']),
        Field('last_heartbeat', 'datetime'),
        Field('last_sync', 'datetime'),
        Field('current_offset_ms', 'double'),
        Field('time_server_id', 'reference time_server', ondelete='SET NULL'),  # Preferred server
        Field('created_at', 'datetime', default=lambda: datetime.utcnow(), notnull=True),
        Field('updated_at', 'datetime', update=lambda: datetime.utcnow()),
        format='%(name)s'
    )

    # System Time Configuration table (global settings)
    db.define_table('time_config',
        Field('key', 'string', unique=True, notnull=True, length=100),
        Field('value', 'text', notnull=True),
        Field('description', 'text'),
        Field('updated_at', 'datetime', update=lambda: datetime.utcnow()),
        format='%(key)s'
    )

    # Indexes for efficient queries
    db.executesql('CREATE INDEX IF NOT EXISTS idx_time_server_protocol ON time_server(protocol, active);')
    db.executesql('CREATE INDEX IF NOT EXISTS idx_time_server_priority ON time_server(priority, active);')
    db.executesql('CREATE INDEX IF NOT EXISTS idx_time_sync_log_server_ts ON time_sync_log(server_id, timestamp);')
    db.executesql('CREATE INDEX IF NOT EXISTS idx_time_sync_log_status ON time_sync_log(status, timestamp);')

    return db
