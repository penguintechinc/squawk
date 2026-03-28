"""
Squawk DNS Server — database table documentation.

Tables are defined as SQLAlchemy Column objects in schema.py.
This file is kept for developer reference only.

Table list:
  auth_user           — authentication users
  dns_query_log       — DNS query audit log
  ioc_feed            — threat intelligence feed sources
  ioc_entry           — individual IOC indicators per feed
  whois_cache         — cached WHOIS lookups
  client_config       — per-client DNS configuration
  internal_domain     — internal split-horizon domain entries
  internal_domain_group — group-restricted internal domains
  internal_domain_user  — user-restricted internal domains

All schema operations (create, alter, drop) are performed via Alembic.
See: flask_app/alembic/versions/
"""
