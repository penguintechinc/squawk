"""
PyDAL Database Models for Squawk DNS
Defines all database tables using PyDAL
"""

from pydal import Field
from datetime import datetime

def define_tables(db):
    """Define all database tables"""
    
    # Authentication tables
    db.define_table('auth_user',
        Field('email', 'string', unique=True, notnull=True),
        Field('password', 'password', notnull=True),
        Field('first_name', 'string'),
        Field('last_name', 'string'),
        Field('is_active', 'boolean', default=True),
        Field('is_admin', 'boolean', default=False),
        Field('created_on', 'datetime', default=datetime.utcnow),
        Field('modified_on', 'datetime', update=datetime.utcnow),
    )
    
    # DNS query logs
    db.define_table('dns_query_log',
        Field('timestamp', 'datetime', default=datetime.utcnow),
        Field('client_ip', 'string'),
        Field('domain', 'string', notnull=True),
        Field('record_type', 'string', default='A'),
        Field('response_status', 'integer'),
        Field('cache_hit', 'boolean', default=False),
        Field('processing_time_ms', 'double'),
        Field('user_id', 'reference auth_user'),
    )
    
    # IOC (Indicators of Compromise) feeds
    db.define_table('ioc_feed',
        Field('name', 'string', notnull=True),
        Field('url', 'string', notnull=True),
        Field('feed_type', 'string'),  # domain, ip, hash
        Field('is_active', 'boolean', default=True),
        Field('last_updated', 'datetime'),
        Field('update_frequency_hours', 'integer', default=24),
    )
    
    # IOC entries
    db.define_table('ioc_entry',
        Field('feed_id', 'reference ioc_feed'),
        Field('indicator', 'string', notnull=True),
        Field('indicator_type', 'string'),  # domain, ip, hash
        Field('threat_level', 'string'),  # low, medium, high, critical
        Field('description', 'text'),
        Field('first_seen', 'datetime', default=datetime.utcnow),
        Field('last_seen', 'datetime', default=datetime.utcnow),
    )
    
    # WHOIS cache
    db.define_table('whois_cache',
        Field('domain', 'string', unique=True, notnull=True),
        Field('whois_data', 'json'),
        Field('cached_at', 'datetime', default=datetime.utcnow),
        Field('expires_at', 'datetime'),
    )
    
    # Client configurations
    db.define_table('client_config',
        Field('client_id', 'string', unique=True, notnull=True),
        Field('config_data', 'json'),
        Field('created_at', 'datetime', default=datetime.utcnow),
        Field('updated_at', 'datetime', update=datetime.utcnow),
        Field('user_id', 'reference auth_user'),
    )
    
    return db
