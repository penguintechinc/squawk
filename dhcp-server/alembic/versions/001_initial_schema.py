"""Initial schema — dhcp_pool, dhcp_reservation, dhcp_lease tables.

Revision ID: 001_initial
Revises:
"""

from alembic import op
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text, func

revision = "001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create dhcp_pool, dhcp_reservation, dhcp_lease tables."""
    op.create_table(
        "dhcp_pool",
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

    op.create_table(
        "dhcp_reservation",
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("pool_id", Integer, ForeignKey("dhcp_pool.id", ondelete="CASCADE"), nullable=False),
        Column("mac_address", String(17), nullable=False),
        Column("ip_address", String(50), nullable=False),
        Column("hostname", String(255)),
        Column("description", Text),
        Column("created_at", DateTime, nullable=False, server_default=func.now()),
        Column("updated_at", DateTime, onupdate=func.now()),
    )
    op.create_index("idx_reservation_pool_mac", "dhcp_reservation", ["pool_id", "mac_address"])
    op.create_index("idx_reservation_pool_ip", "dhcp_reservation", ["pool_id", "ip_address"])

    op.create_table(
        "dhcp_lease",
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
    op.create_index("idx_lease_pool_mac", "dhcp_lease", ["pool_id", "mac_address"])
    op.create_index("idx_lease_pool_status", "dhcp_lease", ["pool_id", "status"])
    op.create_index("idx_lease_end", "dhcp_lease", ["lease_end"])


def downgrade() -> None:
    """Drop dhcp_lease, dhcp_reservation, dhcp_pool tables."""
    op.drop_table("dhcp_lease")
    op.drop_table("dhcp_reservation")
    op.drop_table("dhcp_pool")
