"""
DHCP models for Squawk Manager.
Defines dhcp_pool, dhcp_reservation, and dhcp_lease tables.
"""

from pydal import Field
from datetime import datetime


def define_dhcp_tables(db):
    """Define DHCP-related tables."""

    # DHCP Pool table
    db.define_table('dhcp_pool',
        Field('name', 'string', notnull=True, length=100),
        Field('network', 'string', notnull=True, length=50),  # CIDR notation e.g., '192.168.1.0/24'
        Field('range_start', 'string', notnull=True, length=50),  # e.g., '192.168.1.100'
        Field('range_end', 'string', notnull=True, length=50),    # e.g., '192.168.1.200'
        Field('gateway', 'string', length=50),                     # e.g., '192.168.1.1'
        Field('dns_servers', 'json'),                              # JSON array of DNS server IPs
        Field('ntp_servers', 'json'),                              # JSON array of NTP server IPs
        Field('domain_name', 'string', length=255),                # e.g., 'office.local'
        Field('lease_duration', 'integer', default=86400, notnull=True),  # Seconds (default 24h)
        Field('team_id', 'reference team', ondelete='CASCADE'),
        Field('active', 'boolean', default=True, notnull=True),
        Field('enable_ddns', 'boolean', default=False, notnull=True),  # Dynamic DNS updates
        Field('ddns_zone_id', 'reference dns_zone', ondelete='SET NULL'),  # Link to DNS zone for DDNS
        Field('created_at', 'datetime', default=lambda: datetime.utcnow(), notnull=True),
        Field('updated_at', 'datetime', update=lambda: datetime.utcnow()),
        format='%(name)s'
    )

    # DHCP Reservation table (static IP assignments)
    db.define_table('dhcp_reservation',
        Field('pool_id', 'reference dhcp_pool', notnull=True, ondelete='CASCADE'),
        Field('mac_address', 'string', notnull=True, length=17),  # 'AA:BB:CC:DD:EE:FF'
        Field('ip_address', 'string', notnull=True, length=50),
        Field('hostname', 'string', length=255),
        Field('description', 'text'),
        Field('created_at', 'datetime', default=lambda: datetime.utcnow(), notnull=True),
        Field('updated_at', 'datetime', update=lambda: datetime.utcnow())
    )

    # DHCP Lease table (active and historical leases)
    db.define_table('dhcp_lease',
        Field('pool_id', 'reference dhcp_pool', notnull=True, ondelete='CASCADE'),
        Field('mac_address', 'string', notnull=True, length=17),
        Field('ip_address', 'string', notnull=True, length=50),
        Field('hostname', 'string', length=255),
        Field('lease_start', 'datetime', notnull=True),
        Field('lease_end', 'datetime', notnull=True),
        Field('status', 'string', notnull=True, default='active',
              requires=lambda value: value in ['active', 'expired', 'released']),
        Field('created_at', 'datetime', default=lambda: datetime.utcnow(), notnull=True)
    )

    # DHCP Server table (DHCP daemon instances)
    db.define_table('dhcp_server',
        Field('name', 'string', notnull=True, length=100),
        Field('hostname', 'string', length=255),
        Field('listen_address', 'string', length=50, default='0.0.0.0'),  # nosec B104 - DHCP server config default, not an application socket bind
        Field('status', 'string', notnull=True, default='offline',
              requires=lambda value: value in ['online', 'offline', 'degraded']),
        Field('last_heartbeat', 'datetime'),
        Field('version', 'string', length=50),
        Field('created_at', 'datetime', default=lambda: datetime.utcnow(), notnull=True),
        Field('updated_at', 'datetime', update=lambda: datetime.utcnow()),
        format='%(name)s'
    )

    # Indexes for efficient queries
    db.executesql('CREATE INDEX IF NOT EXISTS idx_reservation_pool_mac ON dhcp_reservation(pool_id, mac_address);')
    db.executesql('CREATE INDEX IF NOT EXISTS idx_reservation_pool_ip ON dhcp_reservation(pool_id, ip_address);')
    db.executesql('CREATE INDEX IF NOT EXISTS idx_lease_pool_mac ON dhcp_lease(pool_id, mac_address);')
    db.executesql('CREATE INDEX IF NOT EXISTS idx_lease_pool_status ON dhcp_lease(pool_id, status);')
    db.executesql('CREATE INDEX IF NOT EXISTS idx_lease_end ON dhcp_lease(lease_end);')

    return db
