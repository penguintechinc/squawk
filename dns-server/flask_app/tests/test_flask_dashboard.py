"""
Test suite for Flask Web Console Dashboard
Tests dashboard views and statistics with mocked data
"""

import pytest
from datetime import datetime, timedelta
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app import app, db
from blueprints.auth import User
from werkzeug.security import generate_password_hash


@pytest.fixture
def client():
    """Create test client"""
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret-key'
    app.config['WTF_CSRF_ENABLED'] = False
    
    with app.test_client() as client:
        yield client


@pytest.fixture
def authenticated_client(client):
    """Create authenticated test client"""
    # Clear and create test user
    db(db.auth_user).delete()
    db.commit()
    
    db.auth_user.insert(
        email='test@example.com',
        password=generate_password_hash('password123'),
        first_name='Test',
        last_name='User',
        is_active=True,
        is_admin=False
    )
    db.commit()
    
    # Login
    client.post('/auth/login', data={
        'email': 'test@example.com',
        'password': 'password123'
    })
    
    return client


@pytest.fixture
def mock_query_data():
    """Create mock DNS query log data"""
    # Clear existing data
    db(db.dns_query_log).delete()
    db.commit()
    
    # Insert test queries
    now = datetime.utcnow()
    for i in range(10):
        db.dns_query_log.insert(
            timestamp=now - timedelta(hours=i),
            client_ip=f'192.168.1.{i}',
            domain=f'example{i}.com',
            record_type='A',
            response_status=0,
            cache_hit=(i % 2 == 0),
            processing_time_ms=10.5 + i
        )
    db.commit()


class TestDashboard:
    """Test dashboard views"""
    
    def test_dashboard_requires_auth(self, client):
        """Test that dashboard requires authentication"""
        response = client.get('/dashboard/')
        # Should redirect to login
        assert response.status_code == 302
        assert '/auth/login' in response.location
    
    def test_dashboard_loads(self, authenticated_client, mock_query_data):
        """Test that dashboard loads with stats"""
        response = authenticated_client.get('/dashboard/')
        assert response.status_code == 200
        assert b'DNS Dashboard' in response.data or b'Dashboard' in response.data
    
    def test_dashboard_shows_stats(self, authenticated_client, mock_query_data):
        """Test that dashboard shows statistics"""
        response = authenticated_client.get('/dashboard/')
        assert response.status_code == 200
        # Should show query count
        assert b'Queries' in response.data or b'queries' in response.data
    
    def test_queries_page(self, authenticated_client, mock_query_data):
        """Test query log page"""
        response = authenticated_client.get('/dashboard/queries')
        assert response.status_code == 200
        # Should show domain names
        assert b'example' in response.data or b'Query' in response.data
    
    def test_queries_pagination(self, authenticated_client, mock_query_data):
        """Test query log pagination"""
        response = authenticated_client.get('/dashboard/queries?page=1')
        assert response.status_code == 200
    
    def test_ioc_page(self, authenticated_client):
        """Test IOC management page"""
        response = authenticated_client.get('/dashboard/ioc')
        assert response.status_code == 200
        assert b'IOC' in response.data or b'Feed' in response.data


class TestDashboardAPI:
    """Test dashboard API endpoints"""
    
    def test_stats_api(self, authenticated_client, mock_query_data):
        """Test stats API endpoint"""
        response = authenticated_client.get('/dashboard/stats/api')
        assert response.status_code == 200
        
        data = response.get_json()
        assert data is not None
        assert isinstance(data, dict)
    
    def test_stats_api_custom_hours(self, authenticated_client, mock_query_data):
        """Test stats API with custom time range"""
        response = authenticated_client.get('/dashboard/stats/api?hours=12')
        assert response.status_code == 200
        
        data = response.get_json()
        assert data is not None
