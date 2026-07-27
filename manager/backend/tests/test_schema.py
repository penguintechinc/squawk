"""Tests for manager/backend schema.py."""
from sqlalchemy import create_engine, inspect


def test_schema_creates_all_tables():
    """Schema must define all tables and create them in SQLite."""
    from app.schema import metadata

    engine = create_engine("sqlite:///:memory:")
    metadata.create_all(engine)
    insp = inspect(engine)
    tables = set(insp.get_table_names())

    expected = {
        "auth_user", "team", "team_member",
        "dns_server", "dns_server_metrics",
        "dns_zone", "dns_record",
        "ioc_feed", "token",
        "dhcp_pool", "dhcp_reservation", "dhcp_lease", "dhcp_server",
        "time_server", "time_sync_log", "time_client", "time_config",
        # IOC ingestion (migration)
        "ioc_entry", "ioc_override",
        # WHOIS (migration)
        "whois_cache", "whois_search_index", "whois_query_log",
        # client config (migration)
        "deployment_domain", "client_config", "config_role",
        "config_user_role", "client_instance", "config_history",
        # selective DNS routing (migration)
        "dns_group", "user_group_assignment", "dns_routing_zone", "group_zone_access",
        # mTLS certificate lifecycle (migration)
        "mtls_certificate", "mtls_revocation",
        # refresh-token rotation/revocation
        "revoked_token",
        # machine identities (OAuth2 client_credentials + OIDC token exchange)
        "machine_client", "oidc_trust_anchor",
        # durable audit trail
        "audit_event",
    }
    assert expected == tables
    engine.dispose()
