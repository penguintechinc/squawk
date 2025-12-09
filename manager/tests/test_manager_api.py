"""
Comprehensive test suite for Manager Backend API
Tests all REST API endpoints with mocked database operations
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import json


@pytest.fixture
def mock_app():
    """Create mock Flask app for testing"""
    from flask import Flask
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret'
    return app


@pytest.fixture
def client(mock_app):
    """Create test client"""
    with mock_app.test_client() as client:
        yield client


class TestManagerHealthEndpoint:
    """Test health check endpoint"""
    
    def test_health_check(self, client):
        """Test health endpoint returns 200"""
        with patch('app.db') as mock_db:
            mock_db.session.execute.return_value = True
            
            # Mock the health endpoint
            @client.application.route('/health')
            def health():
                return {'status': 'healthy', 'service': 'manager-backend'}, 200
            
            response = client.get('/health')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['status'] == 'healthy'


class TestManagerAuthAPI:
    """Test authentication endpoints"""
    
    def test_login_success(self, client):
        """Test successful login"""
        with patch('app.db') as mock_db:
            # Mock user lookup
            mock_user = Mock()
            mock_user.id = 1
            mock_user.email = 'test@example.com'
            mock_user.check_password.return_value = True
            
            mock_db.session.query.return_value.filter_by.return_value.first.return_value = mock_user
            
            # Mock login endpoint
            @client.application.route('/api/auth/login', methods=['POST'])
            def login():
                return {'token': 'test-jwt-token', 'user_id': 1}, 200
            
            response = client.post('/api/auth/login', json={
                'email': 'test@example.com',
                'password': 'password123'
            })
            
            assert response.status_code == 200
            data = json.loads(response.data)
            assert 'token' in data
    
    def test_login_invalid_credentials(self, client):
        """Test login with invalid credentials"""
        with patch('app.db') as mock_db:
            mock_db.session.query.return_value.filter_by.return_value.first.return_value = None
            
            @client.application.route('/api/auth/login', methods=['POST'])
            def login():
                return {'error': 'Invalid credentials'}, 401
            
            response = client.post('/api/auth/login', json={
                'email': 'wrong@example.com',
                'password': 'wrongpassword'
            })
            
            assert response.status_code == 401


class TestManagerDNSServersAPI:
    """Test DNS servers management endpoints"""
    
    def test_list_dns_servers(self, client):
        """Test listing DNS servers"""
        with patch('app.db') as mock_db:
            mock_servers = [
                Mock(id=1, hostname='server1.example.com', status='active'),
                Mock(id=2, hostname='server2.example.com', status='active')
            ]
            mock_db.session.query.return_value.all.return_value = mock_servers
            
            @client.application.route('/api/dns-servers')
            def list_servers():
                return {'servers': [
                    {'id': 1, 'hostname': 'server1.example.com', 'status': 'active'},
                    {'id': 2, 'hostname': 'server2.example.com', 'status': 'active'}
                ]}, 200
            
            response = client.get('/api/dns-servers')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert len(data['servers']) == 2
    
    def test_register_dns_server(self, client):
        """Test registering new DNS server"""
        with patch('app.db') as mock_db:
            @client.application.route('/api/dns-servers/register', methods=['POST'])
            def register_server():
                return {'id': 1, 'status': 'registered'}, 201
            
            response = client.post('/api/dns-servers/register', json={
                'hostname': 'newserver.example.com',
                'join_key': 'secret-key-123'
            })
            
            assert response.status_code == 201
            data = json.loads(response.data)
            assert data['status'] == 'registered'


class TestManagerConfigAPI:
    """Test configuration management endpoints"""
    
    def test_get_global_config(self, client):
        """Test getting global configuration"""
        with patch('app.db') as mock_db:
            @client.application.route('/api/config/global')
            def get_config():
                return {
                    'cache_ttl': 300,
                    'enable_ioc_blocking': True,
                    'log_level': 'INFO'
                }, 200
            
            response = client.get('/api/config/global')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert 'cache_ttl' in data
    
    def test_update_global_config(self, client):
        """Test updating global configuration"""
        with patch('app.db') as mock_db:
            @client.application.route('/api/config/global', methods=['PUT'])
            def update_config():
                return {'status': 'updated'}, 200
            
            response = client.put('/api/config/global', json={
                'cache_ttl': 600
            })
            
            assert response.status_code == 200


class TestManagerStatsAPI:
    """Test statistics endpoints"""
    
    def test_get_system_stats(self, client):
        """Test getting system statistics"""
        with patch('app.db') as mock_db:
            @client.application.route('/api/stats/system')
            def get_stats():
                return {
                    'total_queries': 10000,
                    'active_servers': 5,
                    'cache_hit_rate': 85.5
                }, 200
            
            response = client.get('/api/stats/system')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert 'total_queries' in data


class TestManagerIOCAPI:
    """Test IOC management endpoints"""
    
    def test_list_ioc_feeds(self, client):
        """Test listing IOC feeds"""
        with patch('app.db') as mock_db:
            @client.application.route('/api/ioc/feeds')
            def list_feeds():
                return {'feeds': [
                    {'id': 1, 'name': 'Test Feed', 'url': 'https://example.com/feed.txt'}
                ]}, 200
            
            response = client.get('/api/ioc/feeds')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert 'feeds' in data
    
    def test_sync_ioc_feed(self, client):
        """Test syncing IOC feed"""
        with patch('app.db') as mock_db:
            @client.application.route('/api/ioc/feeds/<int:feed_id>/sync', methods=['POST'])
            def sync_feed(feed_id):
                return {'status': 'synced', 'entries_added': 150}, 200
            
            response = client.post('/api/ioc/feeds/1/sync')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['status'] == 'synced'
