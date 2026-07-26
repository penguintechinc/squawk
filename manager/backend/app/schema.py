"""SQLAlchemy table definitions for Squawk DNS Manager backend.

Single source of truth for the database schema. Used by:
- Alembic for migrations
- Tests for in-memory database setup
- penguin-dal for runtime table reflection

Table creation order follows foreign key dependencies.
"""

from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey, Index,
    Integer, JSON, MetaData, String, Table, Text,
)
from sqlalchemy.sql import func

metadata = MetaData()

# ── Auth ────────────────────────────────────────────────────────────────────

auth_user = Table(
    "auth_user",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("username", String(100), unique=True, nullable=False),
    Column("email", String(255), unique=True, nullable=False),
    Column("password_hash", String(255), nullable=False),
    Column("global_role", String(50), nullable=False, server_default="Viewer"),
    Column("active", Boolean, nullable=False, server_default="1"),
    Column("mfa_enabled", Boolean, nullable=False, server_default="0"),
    Column("mfa_secret", String(255)),  # Encrypted TOTP secret (Fernet)
    Column("mfa_recovery_codes", Text),  # JSON array of hashed recovery codes
    Column("mfa_last_totp_counter", Integer, default=0),  # Tracks last used TOTP counter for replay prevention
    Column("sso_provider", String(100)),  # SSO provider name (null if local auth)
    Column("sso_subject", String(500)),  # IdP-specific user identifier (e.g. sub claim)
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
    Column("updated_at", DateTime, onupdate=func.now()),
)

# ── Teams ───────────────────────────────────────────────────────────────────

team = Table(
    "team",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String(100), unique=True, nullable=False),
    Column("description", Text),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
    Column("updated_at", DateTime, onupdate=func.now()),
)

team_member = Table(
    "team_member",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("team_id", Integer, ForeignKey("team.id", ondelete="CASCADE"),
           nullable=False),
    Column("user_id", Integer, ForeignKey("auth_user.id", ondelete="CASCADE"),
           nullable=False),
    Column("role", String(50), nullable=False, server_default="TeamMember"),
    Column("joined_at", DateTime, nullable=False, server_default=func.now()),
    Column("updated_at", DateTime, onupdate=func.now()),
)
Index("uq_team_member", team_member.c.team_id, team_member.c.user_id,
      unique=True)

# ── SSO Configuration ───────────────────────────────────────────────────────

sso_provider = Table(
    "sso_providers",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String(100), unique=True, nullable=False),  # slug (e.g. 'okta')
    Column("display_name", String(255), nullable=False),  # User-facing name
    Column("issuer", String(500), nullable=False),  # IdP issuer URL (iss claim)
    Column("client_id", String(255), nullable=False),
    Column("client_secret", Text, nullable=False),  # Fernet-encrypted at rest
    Column("authorization_endpoint", String(500), nullable=False),  # Must be https://
    Column("token_endpoint", String(500), nullable=False),  # Must be https://
    Column("jwks_url", String(500), nullable=False),  # OIDC JWKS endpoint for ID token sig verification
    Column("scopes", String(500), nullable=False, server_default='openid email profile'),
    Column("enabled", Boolean, nullable=False, server_default='0'),
    Column("tenant", String(100), nullable=False, server_default='default'),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
    Column("updated_at", DateTime, onupdate=func.now()),
)

# ── DNS Servers ─────────────────────────────────────────────────────────────

dns_server = Table(
    "dns_server",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String(100), nullable=False),
    Column("join_key", String(64), unique=True, nullable=False),
    Column("jwt_secret", String(255), nullable=False),
    Column("status", String(20), nullable=False, server_default="offline"),
    Column("last_heartbeat", DateTime),
    Column("version", String(50)),
    Column("region", String(100)),
    Column("hostname", String(255)),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
    Column("updated_at", DateTime, onupdate=func.now()),
)

dns_server_metrics = Table(
    "dns_server_metrics",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("server_id", Integer, ForeignKey("dns_server.id", ondelete="CASCADE"),
           nullable=False),
    Column("timestamp", DateTime, nullable=False, server_default=func.now()),
    Column("queries_total", Integer, nullable=False, server_default="0"),
    Column("cache_hits", Integer, nullable=False, server_default="0"),
    Column("errors", Integer, nullable=False, server_default="0"),
    Column("avg_response_ms", Float, nullable=False, server_default="0.0"),
)
Index("idx_metrics_server_timestamp", dns_server_metrics.c.server_id,
      dns_server_metrics.c.timestamp)

# ── DNS Zones & Records ──────────────────────────────────────────────────────

dns_zone = Table(
    "dns_zone",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String(255), unique=True, nullable=False),
    Column("team_id", Integer, ForeignKey("team.id", ondelete="CASCADE")),
    Column("visibility", String(20), nullable=False, server_default="public"),
    Column("description", Text),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
    Column("updated_at", DateTime, onupdate=func.now()),
)

dns_record = Table(
    "dns_record",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("zone_id", Integer, ForeignKey("dns_zone.id", ondelete="CASCADE"),
           nullable=False),
    Column("name", String(255), nullable=False),
    Column("type", String(10), nullable=False),
    Column("value", String(1024), nullable=False),
    Column("ttl", Integer, nullable=False, server_default="300"),
    Column("priority", Integer),
    Column("weight", Integer),
    Column("port", Integer),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
    Column("updated_at", DateTime, onupdate=func.now()),
)
Index("idx_record_zone_name_type", dns_record.c.zone_id, dns_record.c.name,
      dns_record.c.type)

# ── Config (IOC feeds + API tokens) ─────────────────────────────────────────

ioc_feed = Table(
    "ioc_feed",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String(100), unique=True, nullable=False),
    Column("url", String(1024), nullable=False),
    Column("feed_type", String(20), nullable=False),
    Column("update_interval", Integer, nullable=False, server_default="24"),
    Column("last_updated", DateTime),
    Column("active", Boolean, nullable=False, server_default="1"),
    Column("enabled", Boolean, nullable=False, server_default="1"),
    Column("description", Text),
    Column("format", String(50), nullable=True),
    Column("parser_config", JSON),
    Column("authentication", JSON),
    Column("entry_count", Integer, nullable=False, server_default="0"),
    Column("last_success", DateTime),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
    Column("updated_at", DateTime, onupdate=func.now()),
)

ioc_entry = Table(
    "ioc_entry",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("feed_id", Integer, ForeignKey("ioc_feed.id", ondelete="CASCADE"),
           nullable=False),
    Column("indicator", String(1024), nullable=False, index=True),
    Column("indicator_type", String(50), nullable=False),
    Column("threat_type", String(100), nullable=True),
    Column("confidence", Integer, nullable=True),
    Column("first_seen", DateTime, nullable=True),
    Column("last_seen", DateTime, nullable=True),
    Column("tags", JSON),
    Column("context", JSON),
    Column("source_format", String(50), nullable=True),
    Column("misp_event_id", String(100), nullable=True),
    Column("misp_attribute_id", String(100), nullable=True),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
    Column("updated_at", DateTime, onupdate=func.now()),
)
Index("idx_ioc_entry_feed_indicator", ioc_entry.c.feed_id,
      ioc_entry.c.indicator)

ioc_override = Table(
    "ioc_override",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("token_id", Integer, nullable=False, index=True),
    Column("indicator", String(1024), nullable=False, index=True),
    Column("indicator_type", String(50), nullable=False),
    Column("override_type", String(20), nullable=False),
    Column("reason", String(1024), nullable=True),
    Column("created_by", String(255), nullable=True),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
    Column("expires_at", DateTime, nullable=True),
)
Index("idx_ioc_override_token_indicator", ioc_override.c.token_id,
      ioc_override.c.indicator)

token = Table(
    "token",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("token", String(255), unique=True, nullable=False),
    Column("name", String(100), nullable=False),
    Column("team_id", Integer, ForeignKey("team.id", ondelete="CASCADE")),
    Column("created_by", Integer, ForeignKey("auth_user.id",
           ondelete="SET NULL")),
    Column("active", Boolean, nullable=False, server_default="1"),
    Column("expires_at", DateTime),
    Column("last_used", DateTime),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
    Column("updated_at", DateTime, onupdate=func.now()),
)
Index("idx_token_active", token.c.token, token.c.active)

# ── WHOIS Cache ─────────────────────────────────────────────────────────────

whois_cache = Table(
    "whois_cache",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("query", String(1024), unique=True, nullable=False, index=True),
    Column("query_type", String(20), nullable=False),
    Column("whois_data", Text),
    Column("parsed_data", JSON),
    Column("registrar", String(255), nullable=True),
    Column("creation_date", DateTime, nullable=True),
    Column("expiration_date", DateTime, nullable=True),
    Column("nameservers", JSON, nullable=True),
    Column("query_timestamp", DateTime, nullable=False, server_default=func.now()),
    Column("last_updated", DateTime, nullable=False, server_default=func.now(),
           onupdate=func.now()),
)

whois_search_index = Table(
    "whois_search_index",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("whois_id", Integer, ForeignKey("whois_cache.id", ondelete="CASCADE"),
           nullable=False, index=True),
    Column("search_field", String(100), nullable=False),
    Column("search_value", String(1024), nullable=False, index=True),
    Column("indexed_at", DateTime, nullable=False, server_default=func.now()),
)

whois_query_log = Table(
    "whois_query_log",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("query", String(1024), nullable=False),
    Column("query_type", String(20), nullable=False),
    Column("cache_hit", Boolean, nullable=False, server_default="0"),
    Column("response_time_ms", Integer, nullable=True),
    Column("client_ip", String(45), nullable=True),
    Column("timestamp", DateTime, nullable=False, server_default=func.now(), index=True),
)

# ── DHCP ────────────────────────────────────────────────────────────────────

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
    Column("team_id", Integer, ForeignKey("team.id", ondelete="CASCADE")),
    Column("active", Boolean, nullable=False, server_default="1"),
    Column("enable_ddns", Boolean, nullable=False, server_default="0"),
    Column("ddns_zone_id", Integer, ForeignKey("dns_zone.id",
           ondelete="SET NULL")),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
    Column("updated_at", DateTime, onupdate=func.now()),
)

dhcp_reservation = Table(
    "dhcp_reservation",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("pool_id", Integer, ForeignKey("dhcp_pool.id", ondelete="CASCADE"),
           nullable=False),
    Column("mac_address", String(17), nullable=False),
    Column("ip_address", String(50), nullable=False),
    Column("hostname", String(255)),
    Column("description", Text),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
    Column("updated_at", DateTime, onupdate=func.now()),
)
Index("idx_reservation_pool_mac", dhcp_reservation.c.pool_id,
      dhcp_reservation.c.mac_address)
Index("idx_reservation_pool_ip", dhcp_reservation.c.pool_id,
      dhcp_reservation.c.ip_address)

dhcp_lease = Table(
    "dhcp_lease",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("pool_id", Integer, ForeignKey("dhcp_pool.id", ondelete="CASCADE"),
           nullable=False),
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

dhcp_server = Table(
    "dhcp_server",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String(100), nullable=False),
    Column("hostname", String(255)),
    Column("listen_address", String(50), server_default="0.0.0.0"),
    Column("status", String(20), nullable=False, server_default="offline"),
    Column("last_heartbeat", DateTime),
    Column("version", String(50)),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
    Column("updated_at", DateTime, onupdate=func.now()),
)

# ── Time Sync ────────────────────────────────────────────────────────────────

time_server = Table(
    "time_server",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String(100), nullable=False),
    Column("server_url", String(255), nullable=False),
    Column("protocol", String(10), nullable=False, server_default="ntp"),
    Column("stratum", Integer, nullable=False, server_default="2"),
    Column("priority", Integer, nullable=False, server_default="100"),
    Column("team_id", Integer, ForeignKey("team.id", ondelete="CASCADE")),
    Column("active", Boolean, nullable=False, server_default="1"),
    Column("status", String(20), nullable=False, server_default="unknown"),
    Column("last_sync", DateTime),
    Column("last_offset_ms", Float),
    Column("last_delay_ms", Float),
    Column("ptp_config", JSON),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
    Column("updated_at", DateTime, onupdate=func.now()),
)
Index("idx_time_server_protocol", time_server.c.protocol, time_server.c.active)
Index("idx_time_server_priority", time_server.c.priority, time_server.c.active)

time_sync_log = Table(
    "time_sync_log",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("server_id", Integer, ForeignKey("time_server.id",
           ondelete="CASCADE"), nullable=False),
    Column("timestamp", DateTime, nullable=False, server_default=func.now()),
    Column("offset_ms", Float, nullable=False),
    Column("delay_ms", Float, nullable=False),
    Column("protocol", String(10), nullable=False),
    Column("status", String(20), nullable=False, server_default="success"),
    Column("error_message", Text),
)
Index("idx_time_sync_log_server_ts", time_sync_log.c.server_id,
      time_sync_log.c.timestamp)

time_client = Table(
    "time_client",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String(100), nullable=False),
    Column("hostname", String(255)),
    Column("os_type", String(50)),
    Column("status", String(20), nullable=False, server_default="offline"),
    Column("last_heartbeat", DateTime),
    Column("last_sync", DateTime),
    Column("current_offset_ms", Float),
    Column("time_server_id", Integer, ForeignKey("time_server.id",
           ondelete="SET NULL")),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
    Column("updated_at", DateTime, onupdate=func.now()),
)

time_config = Table(
    "time_config",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("key", String(100), unique=True, nullable=False),
    Column("value", Text, nullable=False),
    Column("description", Text),
    Column("updated_at", DateTime, onupdate=func.now()),
)

# ── Client Configuration ────────────────────────────────────────────────────

deployment_domain = Table(
    "deployment_domain",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String(100), unique=True, nullable=False),
    Column("description", Text),
    Column("jwt_token", String(512), unique=True, nullable=False),
    Column("jwt_expires", DateTime, nullable=False),
    Column("active", Boolean, nullable=False, server_default="1"),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
    Column("updated_at", DateTime, onupdate=func.now()),
)

client_config = Table(
    "client_config",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String(100), nullable=False),
    Column("domain_id", Integer, ForeignKey("deployment_domain.id", ondelete="CASCADE"),
           nullable=False),
    Column("config_data", JSON, nullable=False),
    Column("version", Integer, nullable=False, server_default="1"),
    Column("description", Text),
    Column("created_by", String(255)),
    Column("active", Boolean, nullable=False, server_default="1"),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
    Column("updated_at", DateTime, onupdate=func.now()),
)

config_role = Table(
    "config_role",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String(50), unique=True, nullable=False),
    Column("permissions", JSON, nullable=False),
    Column("description", Text),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
)

config_user_role = Table(
    "config_user_role",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("user_token_id", Integer, ForeignKey("token.id", ondelete="CASCADE"),
           nullable=False),
    Column("role_id", Integer, ForeignKey("config_role.id", ondelete="CASCADE"),
           nullable=False),
    Column("domain_id", Integer, ForeignKey("deployment_domain.id", ondelete="CASCADE")),
    Column("granted_by", String(255)),
    Column("granted_at", DateTime, nullable=False, server_default=func.now()),
)

client_instance = Table(
    "client_instance",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("client_id", String(100), unique=True, nullable=False),
    Column("domain_id", Integer, ForeignKey("deployment_domain.id", ondelete="CASCADE"),
           nullable=False),
    Column("config_id", Integer, ForeignKey("client_config.id", ondelete="SET NULL")),
    Column("hostname", String(255), nullable=False),
    Column("ip_address", String(45), nullable=False),
    Column("last_checkin", DateTime),
    Column("last_config_pull", DateTime),
    Column("client_version", String(50)),
    Column("os_info", String(255)),
    Column("status", String(20), nullable=False, server_default="active"),
    Column("registered_at", DateTime, nullable=False, server_default=func.now()),
    Column("updated_at", DateTime, onupdate=func.now()),
)
Index("idx_client_instance_domain", client_instance.c.domain_id)
Index("idx_client_instance_status", client_instance.c.status)

config_history = Table(
    "config_history",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("config_id", Integer, ForeignKey("client_config.id", ondelete="CASCADE"),
           nullable=False),
    Column("version", Integer, nullable=False),
    Column("config_data", JSON, nullable=False),
    Column("change_description", String(1024)),
    Column("changed_by", String(255)),
    Column("changed_at", DateTime, nullable=False, server_default=func.now()),
)
Index("idx_config_history_config_version", config_history.c.config_id,
      config_history.c.version)

# ── Selective DNS Routing ───────────────────────────────────────────────────────

dns_group = Table(
    "dns_group",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String(100), unique=True, nullable=False),
    Column("description", Text),
    Column("visibility_levels", JSON),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
    Column("updated_at", DateTime, onupdate=func.now()),
)
Index("idx_dns_group_name", dns_group.c.name, unique=True)

user_group_assignment = Table(
    "user_group_assignment",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("user_id", Integer, nullable=False),
    Column("group_id", Integer, ForeignKey("dns_group.id", ondelete="CASCADE"),
           nullable=False),
    Column("role", String(50), nullable=False, server_default="member"),
    Column("assigned_at", DateTime, nullable=False, server_default=func.now()),
    Column("updated_at", DateTime, onupdate=func.now()),
)
Index("idx_user_group_assignment_user_group", user_group_assignment.c.user_id,
      user_group_assignment.c.group_id, unique=True)

dns_routing_zone = Table(
    "dns_routing_zone",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String(255), unique=True, nullable=False),
    Column("visibility", String(50), nullable=False),
    Column("description", Text),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
    Column("updated_at", DateTime, onupdate=func.now()),
)
Index("idx_dns_routing_zone_name", dns_routing_zone.c.name, unique=True)

group_zone_access = Table(
    "group_zone_access",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("group_id", Integer, ForeignKey("dns_group.id", ondelete="CASCADE"),
           nullable=False),
    Column("zone_id", Integer, ForeignKey("dns_routing_zone.id", ondelete="CASCADE"),
           nullable=False),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
)
Index("idx_group_zone_access_group_zone", group_zone_access.c.group_id,
      group_zone_access.c.zone_id, unique=True)

# ── mTLS Certificate Management ──────────────────────────────────────────────

mtls_certificate = Table(
    "mtls_certificate",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("cert_type", String(20), nullable=False),  # 'ca' | 'server' | 'client'
    Column("common_name", String(255), nullable=False),
    Column("serial_number", String(255), nullable=False, unique=True, index=True),
    Column("fingerprint_sha256", String(64), nullable=False, unique=True, index=True),
    Column("pem_certificate", Text, nullable=False),
    Column("issued_at", DateTime, nullable=False, server_default=func.now()),
    Column("not_valid_before", DateTime, nullable=False),
    Column("not_valid_after", DateTime, nullable=False),
    Column("is_revoked", Boolean, nullable=False, server_default="0"),
    Column("revoked_at", DateTime),
    Column("revocation_reason", String(255)),
    Column("subject_dn", String(512), nullable=False),
    Column("issuer_dn", String(512), nullable=False),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
    Column("updated_at", DateTime, onupdate=func.now()),
)
Index("idx_mtls_certificate_type", mtls_certificate.c.cert_type)
Index("idx_mtls_certificate_expiry", mtls_certificate.c.not_valid_after)

mtls_revocation = Table(
    "mtls_revocation",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("serial_number", String(255), nullable=False, unique=True, index=True),
    Column("common_name", String(255), nullable=False),
    Column("revoked_at", DateTime, nullable=False, server_default=func.now()),
    Column("revocation_reason", String(255)),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
)
Index("idx_mtls_revocation_serial", mtls_revocation.c.serial_number)

# ── Refresh-token revocation (rotation + logout) ─────────────────────────────

revoked_token = Table(
    "revoked_token",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("jti", String(36), nullable=False, unique=True, index=True),
    Column("user_id", Integer, ForeignKey("auth_user.id", ondelete="CASCADE")),
    Column("reason", String(50)),  # 'rotated' | 'logout' | 'admin'
    Column("revoked_at", DateTime, nullable=False, server_default=func.now()),
    # Denylist entries only matter until the token would expire anyway;
    # expired rows are purged opportunistically on new revocations.
    Column("expires_at", DateTime, nullable=False),
)
Index("idx_revoked_token_expires", revoked_token.c.expires_at)
