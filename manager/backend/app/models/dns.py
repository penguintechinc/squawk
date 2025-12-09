"""
DNS zone and record models for Squawk DNS Manager.
Defines dns_zone and dns_record tables with visibility controls.
"""

from pydal import Field
from datetime import datetime


def define_dns_tables(db):
    """Define DNS-related tables."""

    # DNS Zone table
    db.define_table('dns_zone',
        Field('name', 'string', unique=True, notnull=True, length=255),
        Field('team_id', 'reference team', ondelete='CASCADE'),
        Field('visibility', 'string', notnull=True, default='public',
              requires=lambda value: value in ['public', 'internal', 'restricted', 'private']),
        Field('description', 'text'),
        Field('created_at', 'datetime', default=lambda: datetime.utcnow(), notnull=True),
        Field('updated_at', 'datetime', update=lambda: datetime.utcnow()),
        format='%(name)s'
    )

    # DNS Record table
    db.define_table('dns_record',
        Field('zone_id', 'reference dns_zone', notnull=True, ondelete='CASCADE'),
        Field('name', 'string', notnull=True, length=255),
        Field('type', 'string', notnull=True, length=10,
              requires=lambda value: value in ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR', 'SRV']),
        Field('value', 'string', notnull=True, length=1024),
        Field('ttl', 'integer', default=300, notnull=True),
        Field('priority', 'integer'),  # For MX, SRV records
        Field('weight', 'integer'),    # For SRV records
        Field('port', 'integer'),      # For SRV records
        Field('created_at', 'datetime', default=lambda: datetime.utcnow(), notnull=True),
        Field('updated_at', 'datetime', update=lambda: datetime.utcnow())
    )

    # Index for efficient DNS lookups
    db.executesql('CREATE INDEX IF NOT EXISTS idx_record_zone_name_type ON dns_record(zone_id, name, type);')

    return db
