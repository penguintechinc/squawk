"""
Unit Test Configuration and Fixtures
Provides mocked fixtures for isolated unit testing
"""

import os
import sys
import pytest
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime


# Add project paths for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'dns-server'))


@pytest.fixture
def mock_db():
    """Provide a mocked PyDAL database"""
    db = MagicMock()

    # Mock tables
    db.tables = ['auth_user', 'dns_query_log', 'ioc_feed', 'ioc_entry',
                 'internal_domain', 'dns_group', 'dns_zone']

    # Mock auth_user table
    db.auth_user = MagicMock()
    db.auth_user.id = MagicMock()
    db.auth_user.email = MagicMock()

    # Mock query methods
    db.__call__ = MagicMock(return_value=MagicMock())

    return db


@pytest.fixture
def mock_user():
    """Provide a mock user object"""
    user = MagicMock()
    user.id = 1
    user.email = 'test@example.com'
    user.first_name = 'Test'
    user.last_name = 'User'
    user.is_admin = False
    user.is_active = True
    user.is_authenticated = True
    user.is_anonymous = False
    user.get_id = MagicMock(return_value='1')
    return user


@pytest.fixture
def mock_admin_user():
    """Provide a mock admin user object.

    Built independently rather than mutating the shared mock_user fixture, which
    caused cross-test state bleed (mock_user.is_admin left True for other tests).
    """
    user = MagicMock()
    user.id = 2
    user.email = 'admin@example.com'
    user.first_name = 'Admin'
    user.last_name = 'User'
    user.is_admin = True
    user.is_active = True
    user.is_authenticated = True
    user.is_anonymous = False
    user.get_id = MagicMock(return_value='2')
    return user


@pytest.fixture
def mock_request():
    """Provide a mock Flask request object"""
    request = MagicMock()
    request.method = 'GET'
    request.args = {}
    request.form = {}
    request.json = {}
    request.headers = {}
    request.environ = {'REMOTE_ADDR': '127.0.0.1'}
    return request


@pytest.fixture
def sample_dns_query_log():
    """Provide sample DNS query log data"""
    return {
        'id': 1,
        'timestamp': datetime.utcnow(),
        'domain': 'example.com',
        'record_type': 'A',
        'response_code': 0,
        'cache_hit': False,
        'client_ip': '192.168.1.100',
        'response_time_ms': 15.5
    }


@pytest.fixture
def sample_ioc_feed():
    """Provide sample IOC feed data"""
    return {
        'id': 1,
        'name': 'Test IOC Feed',
        'url': 'https://example.com/ioc.txt',
        'feed_type': 'domain',
        'is_active': True,
        'update_frequency_hours': 24,
        'last_updated': datetime.utcnow()
    }


@pytest.fixture
def sample_internal_domain():
    """Provide sample internal domain data"""
    return {
        'id': 1,
        'name': 'internal.example.com',
        'ip_address': '10.0.0.1',
        'description': 'Internal test domain',
        'access_type': 'all',
        'is_active': True,
        'created_by': 1
    }


@pytest.fixture
def sample_dns_zone():
    """Provide sample DNS zone data"""
    return {
        'id': 1,
        'name': 'example.com',
        'visibility': 'PUBLIC',
        'primary_ns': 'ns1.example.com',
        'admin_email': 'admin@example.com',
        'ttl': 3600
    }


# Markers for test categorization
def pytest_configure(config):
    """Configure custom pytest markers"""
    config.addinivalue_line("markers", "unit: mark test as unit test")
    config.addinivalue_line("markers", "model: mark test as model test")
    config.addinivalue_line("markers", "service: mark test as service test")
    config.addinivalue_line("markers", "validation: mark test as validation test")
