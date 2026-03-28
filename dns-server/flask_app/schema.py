"""SQLAlchemy table definitions for Squawk DNS Server.

Single source of truth for database schema. Used by:
- Alembic for migrations
- Tests for in-memory database setup
- penguin-dal for runtime table reflection
"""

from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey,
    Integer, JSON, MetaData, String, Table, Text,
)
from sqlalchemy.sql import func

metadata = MetaData()

auth_user = Table(
    "auth_user",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("email", String(255), unique=True, nullable=False),
    Column("password", String(512), nullable=False),
    Column("first_name", String(255)),
    Column("last_name", String(255)),
    Column("is_active", Boolean, nullable=False, server_default="1"),
    Column("is_admin", Boolean, nullable=False, server_default="0"),
    Column("created_on", DateTime, server_default=func.now()),
    Column("modified_on", DateTime, onupdate=func.now()),
)

dns_query_log = Table(
    "dns_query_log",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("timestamp", DateTime, server_default=func.now()),
    Column("client_ip", String(45)),
    Column("domain", String(255), nullable=False),
    Column("record_type", String(10), server_default="A"),
    Column("response_status", Integer),
    Column("cache_hit", Boolean, server_default="0"),
    Column("processing_time_ms", Float),
    Column("user_id", Integer, ForeignKey("auth_user.id")),
)

ioc_feed = Table(
    "ioc_feed",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String(255), nullable=False),
    Column("url", String(512), nullable=False),
    Column("feed_type", String(50)),
    Column("is_active", Boolean, server_default="1"),
    Column("last_updated", DateTime),
    Column("update_frequency_hours", Integer, server_default="24"),
)

ioc_entry = Table(
    "ioc_entry",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("feed_id", Integer, ForeignKey("ioc_feed.id")),
    Column("indicator", String(512), nullable=False),
    Column("indicator_type", String(50)),
    Column("threat_level", String(20)),
    Column("description", Text),
    Column("first_seen", DateTime, server_default=func.now()),
    Column("last_seen", DateTime, server_default=func.now()),
)

whois_cache = Table(
    "whois_cache",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("domain", String(255), unique=True, nullable=False),
    Column("whois_data", JSON),
    Column("cached_at", DateTime, server_default=func.now()),
    Column("expires_at", DateTime),
)

client_config = Table(
    "client_config",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("client_id", String(255), unique=True, nullable=False),
    Column("config_data", JSON),
    Column("created_at", DateTime, server_default=func.now()),
    Column("updated_at", DateTime, onupdate=func.now()),
    Column("user_id", Integer, ForeignKey("auth_user.id")),
)

internal_domain = Table(
    "internal_domain",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String(255), unique=True, nullable=False),
    Column("ip_address", String(45), nullable=False),
    Column("description", Text),
    Column("access_type", String(20), server_default="all"),
    Column("is_active", Boolean, server_default="1"),
    Column("created_on", DateTime, server_default=func.now()),
    Column("modified_on", DateTime, onupdate=func.now()),
    Column("created_by", Integer, ForeignKey("auth_user.id")),
)

internal_domain_group = Table(
    "internal_domain_group",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("domain_id", Integer, ForeignKey("internal_domain.id"), nullable=False),
    Column("group_name", String(255), nullable=False),
    Column("created_on", DateTime, server_default=func.now()),
)

internal_domain_user = Table(
    "internal_domain_user",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("domain_id", Integer, ForeignKey("internal_domain.id"), nullable=False),
    Column("user_id", Integer, ForeignKey("auth_user.id"), nullable=False),
    Column("created_on", DateTime, server_default=func.now()),
)

dns_group = Table(
    "dns_group",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String(255), unique=True, nullable=False),
    Column("group_type", String(50)),
    Column("description", Text),
    Column("created_on", DateTime, server_default=func.now()),
)

dns_zone = Table(
    "dns_zone",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String(255), unique=True, nullable=False),
    Column("visibility", String(20), server_default="PUBLIC"),
    Column("primary_ns", String(255)),
    Column("admin_email", String(255)),
    Column("ttl", Integer, server_default="3600"),
    Column("created_on", DateTime, server_default=func.now()),
)

dns_record = Table(
    "dns_record",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("zone", String(255), nullable=False),
    Column("name", String(255), nullable=False),
    Column("record_type", String(20), nullable=False),
    Column("value", String(512), nullable=False),
    Column("ttl", Integer, server_default="3600"),
    Column("created_on", DateTime, server_default=func.now()),
)

dns_permission = Table(
    "dns_permission",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("group_name", String(255), nullable=False),
    Column("zone_pattern", String(255), nullable=False),
    Column("access_level", String(20), server_default="READ"),
    Column("can_query", Boolean, server_default="1"),
    Column("can_modify", Boolean, server_default="0"),
    Column("created_on", DateTime, server_default=func.now()),
)

blocked_query = Table(
    "blocked_query",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("domain", String(255)),
    Column("client_ip", String(45)),
    Column("reason", String(255)),
    Column("threat_level", String(20)),
    Column("feed_source", String(255)),
    Column("blocked_at", DateTime, server_default=func.now()),
)
