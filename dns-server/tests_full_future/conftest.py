"""
Test configuration and fixtures for DNS server tests
Enhanced for new feature testing
"""
import pytest
import asyncio
import tempfile
import os
import sys
import logging
from unittest.mock import Mock, patch, AsyncMock
from pydal import DAL, Field
from datetime import datetime, timedelta

# Add manager backend for IOCManager
manager_backend_path = os.path.join(os.path.dirname(__file__), '..', '..', 'manager', 'backend', 'app', 'services')
if manager_backend_path not in sys.path:
    sys.path.insert(0, manager_backend_path)

# Add dns-server app/services so feature modules resolve to their canonical home.
# NOTE: do NOT add the dns-server root here — it makes `app` resolve to dns-server/app
# and collides with the manager's `app.` package used by cross-imported tests.
app_services_path = os.path.join(os.path.dirname(__file__), '..', 'app', 'services')
if app_services_path not in sys.path:
    sys.path.insert(0, app_services_path)

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
def temp_db():
    """Create temporary SQLite database for testing"""
    from sqlalchemy import create_engine

    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
        db_path = tmp.name

    # Import schema from manager backend
    try:
        # Adjust path relative to where this conftest is
        manager_schema_path = os.path.join(os.path.dirname(__file__), '..', '..', 'manager', 'backend', 'app', 'schema')
        if manager_schema_path not in sys.path:
            sys.path.insert(0, os.path.dirname(manager_schema_path))
        from schema import metadata
    except ImportError:
        # Fallback: create basic schema
        logger = logging.getLogger(__name__)
        logger.warning("Could not import schema from manager backend, using basic schema")
        metadata = None

    # Create SQLAlchemy engine
    engine = create_engine(f'sqlite:///{db_path}')

    # Create IOC tables from schema
    if metadata:
        # Create only the IOC-related and WHOIS tables (not client_config, which pydal will create)
        from sqlalchemy import MetaData as SAMetadata, inspect
        inspector = inspect(engine)
        existing_tables = inspector.get_table_names()

        # Create all required tables from schema metadata to satisfy foreign key dependencies
        # Create in order of dependency
        table_order = [
            'auth_user', 'team', 'token',  # Base tables
            'ioc_feed', 'ioc_entry', 'ioc_override',  # IOC tables
            'whois_cache', 'whois_search_index', 'whois_query_log',  # WHOIS tables
            'deployment_domain', 'client_config', 'config_role',  # Client config core tables
            'config_user_role', 'client_instance', 'config_history',  # Client config detail tables
            'dns_group', 'user_group_assignment', 'dns_routing_zone', 'group_zone_access',  # Selective DNS routing tables
            'mtls_certificate', 'mtls_revocation'  # mTLS certificate tables
        ]
        for table_name in table_order:
            if table_name in metadata.tables and table_name not in existing_tables:
                metadata.tables[table_name].create(engine, checkfirst=True)
    else:
        # Fallback: create basic IOC tables
        from sqlalchemy import Table, Column, Integer, String, DateTime, Boolean, Text, MetaData as SAMetadata, ForeignKey
        from sqlalchemy.sql import func

        temp_metadata = SAMetadata()

        ioc_feed_table = Table(
            'ioc_feed', temp_metadata,
            Column('id', Integer, primary_key=True, autoincrement=True),
            Column('name', String(100), unique=True, nullable=False),
            Column('url', String(1024), nullable=False),
            Column('feed_type', String(20), nullable=False),
            Column('format', String(50)),
            Column('update_interval', Integer, server_default='24'),
            Column('last_updated', DateTime),
            Column('enabled', Boolean, server_default='1'),
            Column('active', Boolean, server_default='1'),
            Column('entry_count', Integer, server_default='0'),
            Column('created_at', DateTime, server_default=func.now()),
            Column('updated_at', DateTime, onupdate=func.now()),
        )

        ioc_entry_table = Table(
            'ioc_entry', temp_metadata,
            Column('id', Integer, primary_key=True, autoincrement=True),
            Column('feed_id', Integer, ForeignKey('ioc_feed.id', ondelete='CASCADE'), nullable=False),
            Column('indicator', String(1024), nullable=False, index=True),
            Column('indicator_type', String(50), nullable=False),
            Column('threat_type', String(100)),
            Column('confidence', Integer),
            Column('created_at', DateTime, server_default=func.now()),
            Column('updated_at', DateTime, onupdate=func.now()),
        )

        ioc_override_table = Table(
            'ioc_override', temp_metadata,
            Column('id', Integer, primary_key=True, autoincrement=True),
            Column('token_id', Integer, nullable=False, index=True),
            Column('indicator', String(1024), nullable=False, index=True),
            Column('indicator_type', String(50), nullable=False),
            Column('override_type', String(20), nullable=False),
            Column('reason', String(1024)),
            Column('created_by', String(255)),
            Column('created_at', DateTime, server_default=func.now()),
            Column('expires_at', DateTime),
        )

        # Fallback client_config tables
        token_table = Table(
            'token', temp_metadata,
            Column('id', Integer, primary_key=True, autoincrement=True),
            Column('token', String(255), unique=True, nullable=False),
            Column('name', String(100), nullable=False),
            Column('active', Boolean, server_default='1'),
            Column('last_used', DateTime),
        )

        deployment_domain_table = Table(
            'deployment_domain', temp_metadata,
            Column('id', Integer, primary_key=True, autoincrement=True),
            Column('name', String(100), unique=True, nullable=False),
            Column('description', Text),
            Column('jwt_token', String(512), unique=True, nullable=False),
            Column('jwt_expires', DateTime, nullable=False),
            Column('active', Boolean, server_default='1'),
            Column('created_at', DateTime, server_default=func.now()),
        )

        client_config_table = Table(
            'client_config', temp_metadata,
            Column('id', Integer, primary_key=True, autoincrement=True),
            Column('name', String(100), nullable=False),
            Column('domain_id', Integer, ForeignKey('deployment_domain.id', ondelete='CASCADE'), nullable=False),
            Column('config_data', String, nullable=False),
            Column('version', Integer, server_default='1'),
            Column('description', Text),
            Column('created_by', String(255)),
            Column('active', Boolean, server_default='1'),
            Column('created_at', DateTime, server_default=func.now()),
        )

        config_role_table = Table(
            'config_role', temp_metadata,
            Column('id', Integer, primary_key=True, autoincrement=True),
            Column('name', String(50), unique=True, nullable=False),
            Column('permissions', String, nullable=False),
            Column('description', Text),
            Column('created_at', DateTime, server_default=func.now()),
        )

        config_user_role_table = Table(
            'config_user_role', temp_metadata,
            Column('id', Integer, primary_key=True, autoincrement=True),
            Column('user_token_id', Integer, ForeignKey('token.id', ondelete='CASCADE'), nullable=False),
            Column('role_id', Integer, ForeignKey('config_role.id', ondelete='CASCADE'), nullable=False),
            Column('domain_id', Integer, ForeignKey('deployment_domain.id', ondelete='CASCADE')),
            Column('granted_by', String(255)),
            Column('granted_at', DateTime, server_default=func.now()),
        )

        client_instance_table = Table(
            'client_instance', temp_metadata,
            Column('id', Integer, primary_key=True, autoincrement=True),
            Column('client_id', String(100), unique=True, nullable=False),
            Column('domain_id', Integer, ForeignKey('deployment_domain.id', ondelete='CASCADE'), nullable=False),
            Column('config_id', Integer, ForeignKey('client_config.id', ondelete='SET NULL')),
            Column('hostname', String(255), nullable=False),
            Column('ip_address', String(45), nullable=False),
            Column('last_checkin', DateTime),
            Column('last_config_pull', DateTime),
            Column('client_version', String(50)),
            Column('os_info', String(255)),
            Column('status', String(20), server_default='active'),
            Column('registered_at', DateTime, server_default=func.now()),
        )

        config_history_table = Table(
            'config_history', temp_metadata,
            Column('id', Integer, primary_key=True, autoincrement=True),
            Column('config_id', Integer, ForeignKey('client_config.id', ondelete='CASCADE'), nullable=False),
            Column('version', Integer, nullable=False),
            Column('config_data', String, nullable=False),
            Column('change_description', String(1024)),
            Column('changed_by', String(255)),
            Column('changed_at', DateTime, server_default=func.now()),
        )

        temp_metadata.create_all(engine)

    # Create PyDAL instance pointing to the same database
    db = DAL(f'sqlite://{db_path}')

    # Define PyDAL tables for legacy DNS server testing (not IOC-related)
    db.define_table('tokens',
        Field('token', 'string', unique=True),
        Field('name', 'string'),
        Field('description', 'text'),
        Field('created_at', 'datetime', default=datetime.now),
        Field('last_used', 'datetime'),
        Field('active', 'boolean', default=True),
        migrate=True
    )

    db.define_table('domains',
        Field('name', 'string', unique=True, notnull=True),
        Field('description', 'text'),
        Field('created_at', 'datetime', default=datetime.now)
    )

    db.define_table('token_domains',
        Field('token_id', 'reference tokens', notnull=True, ondelete='CASCADE'),
        Field('domain_id', 'reference domains', notnull=True, ondelete='CASCADE'),
        Field('created_at', 'datetime', default=datetime.now)
    )

    db.define_table('query_logs',
        Field('token_id', 'reference tokens', ondelete='SET NULL'),
        Field('domain_queried', 'string'),
        Field('query_type', 'string'),
        Field('status', 'string'),
        Field('client_ip', 'string'),
        Field('timestamp', 'datetime', default=datetime.now)
    )

    # Define pydal aliases for client_config tables (created by SQLAlchemy above)
    # These allow tests to access existing SQLAlchemy-created tables via pydal
    db.define_table('deployment_domains',
        Field('name', 'string', unique=True),
        Field('description', 'text'),
        Field('jwt_token', 'string', unique=True),
        Field('jwt_expires', 'datetime'),
        Field('active', 'boolean', default=True),
        Field('created_at', 'datetime'),
        migrate=False  # Table already exists in DB
    )

    db.define_table('client_configs',
        Field('name', 'string'),
        Field('domain_id', 'reference deployment_domains'),
        Field('config_data', 'json'),
        Field('version', 'integer'),
        Field('description', 'text'),
        Field('created_by', 'string'),
        Field('active', 'boolean'),
        Field('created_at', 'datetime'),
        migrate=False
    )

    db.define_table('config_roles',
        Field('name', 'string', unique=True),
        Field('permissions', 'json'),
        Field('description', 'text'),
        Field('created_at', 'datetime'),
        migrate=False
    )

    db.define_table('config_user_roles',
        Field('user_token_id', 'reference tokens'),
        Field('role_id', 'reference config_roles'),
        Field('domain_id', 'reference deployment_domains'),
        Field('granted_by', 'string'),
        Field('granted_at', 'datetime'),
        migrate=False
    )

    db.define_table('client_instances',
        Field('client_id', 'string', unique=True),
        Field('domain_id', 'reference deployment_domains'),
        Field('config_id', 'reference client_configs'),
        Field('hostname', 'string'),
        Field('ip_address', 'string'),
        Field('last_checkin', 'datetime'),
        Field('last_config_pull', 'datetime'),
        Field('client_version', 'string'),
        Field('os_info', 'string'),
        Field('status', 'string'),
        Field('registered_at', 'datetime'),
        migrate=False
    )

    db.define_table('config_histories',
        Field('config_id', 'reference client_configs'),
        Field('version', 'integer'),
        Field('config_data', 'json'),
        Field('change_description', 'text'),
        Field('changed_by', 'string'),
        Field('changed_at', 'datetime'),
        migrate=False
    )

    # Store db_path in db for later access by test
    db._db_path = db_path

    yield db

    # Cleanup — tolerate an already-closed DB (some fixtures, e.g. sample_token_data,
    # close temp_db early to release the sqlite write lock before a penguin_dal insert).
    try:
        db.close()
    except Exception:
        pass
    try:
        os.unlink(db_path)
    except Exception:
        pass

@pytest.fixture
def sample_token_data(temp_db):
    """Create sample token data for testing"""
    # Insert test token into pydal legacy table
    token_id = temp_db.tokens.insert(
        token='test-token-123456789',
        name='Test Token',
        description='Token for testing',
        active=True
    )

    # Insert test domain
    domain_id = temp_db.domains.insert(
        name='example.com',
        description='Test domain'
    )

    # Insert wildcard domain
    wildcard_id = temp_db.domains.insert(
        name='*',
        description='Wildcard domain'
    )

    # Grant permissions
    temp_db.token_domains.insert(token_id=token_id, domain_id=domain_id)

    temp_db.commit()
    # CRITICAL: Close pydal DB to release the lock before penguin_dal tries to insert
    temp_db.close()

    # ALSO insert into schema `token` table (used by ClientConfigManager service)
    # Use penguin_dal to insert to avoid database locking issues
    from penguin_dal import DB
    db_path = temp_db._uri[9:] if temp_db._uri.startswith('sqlite://') else temp_db._uri
    schema_db = DB(f'sqlite:///{db_path}')

    schema_token_id = None
    try:
        # Insert token - let DB assign the ID (penguin_dal doesn't support specifying PK on insert)
        schema_token_id = schema_db.token.insert(
            token='test-token-123456789',
            name='test-token-123456789',  # Name must match token for mTLS cert verification tests
            active=True
        )
        schema_db.commit()
    except Exception:
        # Token might already exist — look up its schema id
        existing = schema_db(schema_db.token.token == 'test-token-123456789').select().first()
        if existing:
            schema_token_id = existing.id
    finally:
        schema_db.close()

    # Return the SCHEMA `token` table id (what services + selective router read via
    # penguin_dal), not the legacy pydal `tokens` id — this keeps token_id assertions
    # correct regardless of how many other tokens a test seeds first.
    return {
        'token_id': schema_token_id,
        'domain_id': domain_id,
        'wildcard_id': wildcard_id,
        'token': 'test-token-123456789',
        'domain': 'example.com'
    }

@pytest.fixture
def mock_dns_handler():
    """Mock DNS handler for testing"""
    handler = Mock()
    handler.headers = {'Authorization': 'Bearer test-token-123456789'}
    handler.path = '/dns-query?name=example.com&type=A'
    handler.client_address = ('127.0.0.1', 12345)

    # Mock methods
    handler.send_response = Mock()
    handler.send_header = Mock()
    handler.end_headers = Mock()
    handler.wfile = Mock()
    handler.wfile.write = Mock()

    return handler

@pytest.fixture
def mock_dns_resolver():
    """Mock DNS resolver for testing"""
    with patch('dns.resolver.Resolver') as mock_resolver:
        mock_answer = Mock()
        mock_answer.to_text.return_value = '93.184.216.34'

        mock_resolver_instance = Mock()
        mock_resolver_instance.resolve.return_value = [mock_answer]
        mock_resolver.return_value = mock_resolver_instance

        yield mock_resolver_instance

@pytest.fixture
def sample_dns_response():
    """Sample DNS response data"""
    return {
        "Status": 0,
        "Answer": [
            {
                "name": "example.com",
                "type": "A",
                "data": "93.184.216.34"
            }
        ]
    }

@pytest.fixture
def invalid_domains():
    """List of invalid domain names for testing"""
    return [
        "",  # Empty domain
        "invalid..domain",  # Double dots
        "domain-",  # Trailing hyphen
        "-domain",  # Leading hyphen
        "very-long-domain-name-that-exceeds-the-maximum-length-limit-of-sixty-three-characters.com",
        "domain with spaces",  # Spaces
        "domain@invalid",  # Invalid characters
        "domain\x00.com",  # Null character
        "javascript:alert(1)",  # XSS attempt
    ]

@pytest.fixture
def valid_domains():
    """List of valid domain names for testing"""
    return [
        "example.com",
        "subdomain.example.com",
        "test-domain.co.uk",
        "a.b.c.example.org",
        "123.example.com",
        "localhost",
        "*.example.com",  # Wildcard
    ]

# Additional fixtures for new features
@pytest.fixture
def mock_whois_response():
    """Mock WHOIS response data"""
    return {
        'domain_name': 'example.com',
        'registrar': 'Example Registrar Inc.',
        'creation_date': '2000-01-01T00:00:00',
        'expiration_date': '2025-01-01T00:00:00',
        'nameservers': ['ns1.example.com', 'ns2.example.com'],
        'organization': 'Example Organization',
        'status': ['clientTransferProhibited'],
        'emails': ['admin@example.com'],
        'query_type': 'domain',
        'timestamp': datetime.now().isoformat(),
        'source': 'test'
    }

@pytest.fixture
def mock_ioc_feeds():
    """Mock IOC feed data"""
    return [
        {
            'name': 'Test Malware Domains',
            'url': 'https://test.example.com/malware_domains.txt',
            'feed_type': 'domain',
            'format': 'txt',
            'enabled': True,
            'content': 'malware.example.com\nphishing.test.com\nbad-domain.org\n'
        }
    ]

@pytest.fixture
def mock_client_config():
    """Mock client configuration data"""
    return {
        'server_url': 'https://dns.example.com:8443',
        'dns_port': 53,
        'cache_enabled': True,
        'cache_ttl': 300,
        'auth_token': 'test_token_123',
        'use_mtls': True,
        'cert_path': '/etc/squawk/client.crt',
        'key_path': '/etc/squawk/client.key',
        'ca_cert_path': '/etc/squawk/ca.crt',
        'log_level': 'INFO',
        'timeout': 5,
        'retries': 3
    }

@pytest.fixture
def test_jwt_secret():
    """Test JWT secret"""
    return "test_jwt_secret_key_for_unit_tests_only"


@pytest.fixture(autouse=True)
def _bypass_feed_url_ssrf_check():
    """Keep feed-update tests hermetic: the real SSRF guard does live DNS
    resolution, which these HTTP-mocked tests must not depend on. The SSRF
    guard itself is tested directly in manager/backend/tests/test_ioc_ssrf.py.
    """
    try:
        import ioc_ingestion_service
    except ImportError:
        yield
        return
    with patch.object(ioc_ingestion_service, "_assert_feed_url_safe", new=AsyncMock()):
        yield
