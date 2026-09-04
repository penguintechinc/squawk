"""SQLAlchemy table definitions for the Squawk DHCP server's own database.

Single source of truth for this service's schema. Used by:
- Alembic for migrations
- penguin-dal for runtime table reflection

This is a separate, isolated database from manager's (per-service DB account
requirement — see backend-database.md) — it holds only the operational
pool/lease/reservation state this service itself reads and writes, not
manager's team/DNS-zone-linked DHCP configuration records.
"""

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    MetaData,
    String,
    Table,
    Text,
)
from sqlalchemy.sql import func

metadata = MetaData()

dhcp_pool = Table(
    "dhcp_pool",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String(100), nullable=False),
    Column("network", String(50), nullable=False),
    Column("range_start", String(50), nullable=False),
    Column("range_end", String(50), nullable=False),
    Column("gateway", String(50)),
    Column("dns_servers", JSON),
    Column("ntp_servers", JSON),
    Column("domain_name", String(255)),
    Column("lease_duration", Integer, nullable=False, server_default="86400"),
    Column("active", Boolean, nullable=False, server_default="1"),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
    Column("updated_at", DateTime, onupdate=func.now()),
)

dhcp_reservation = Table(
    "dhcp_reservation",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("pool_id", Integer, ForeignKey("dhcp_pool.id", ondelete="CASCADE"), nullable=False),
    Column("mac_address", String(17), nullable=False),
    Column("ip_address", String(50), nullable=False),
    Column("hostname", String(255)),
    Column("description", Text),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
    Column("updated_at", DateTime, onupdate=func.now()),
)
Index("idx_reservation_pool_mac", dhcp_reservation.c.pool_id, dhcp_reservation.c.mac_address)
Index("idx_reservation_pool_ip", dhcp_reservation.c.pool_id, dhcp_reservation.c.ip_address)

dhcp_lease = Table(
    "dhcp_lease",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("pool_id", Integer, ForeignKey("dhcp_pool.id", ondelete="CASCADE"), nullable=False),
    Column("mac_address", String(17), nullable=False),
    Column("ip_address", String(50), nullable=False),
    Column("hostname", String(255)),
    Column("lease_start", DateTime, nullable=False),
    Column("lease_end", DateTime, nullable=False),
    Column("status", String(20), nullable=False, server_default="active"),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
)
Index("idx_lease_pool_mac", dhcp_lease.c.pool_id, dhcp_lease.c.mac_address)
Index("idx_lease_pool_status", dhcp_lease.c.pool_id, dhcp_lease.c.status)
Index("idx_lease_end", dhcp_lease.c.lease_end)
