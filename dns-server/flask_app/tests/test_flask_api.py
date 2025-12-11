"""
Test suite for Flask Web Console API
Tests all REST API endpoints with mocked data
"""

import pytest
import json
from datetime import datetime
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app import app, db
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
    db(db.auth_user).delete()
    db.commit()
    
    db.auth_user.insert(
        email='test@example.com',
        password=generate_password_hash('password123'),
        first_name='Test',
        last_name='User',
        is_active=True,
        is_admin=True  # Admin for testing
    )
    db.commit()
    
    client.post('/auth/login', data={
        'email': 'test@example.com',
        'password': 'password123'
    })
    
    return client


class TestQueriesAPI:
    """Test queries API endpoints"""
    
    def test_get_queries_requires_auth(self, client):
        """Test that queries API requires authentication"""
        response = client.get('/api/queries')
        assert response.status_code == 302  # Redirect to login
    
    def test_get_queries(self, authenticated_client):
        """Test getting query logs"""
        # Add test data
        db.dns_query_log.insert(
            timestamp=datetime.utcnow(),
            client_ip='192.168.1.1',
            domain='test.com',
            record_type='A',
            response_status=0,
            cache_hit=False,
            processing_time_ms=10.5
        )
        db.commit()
        
        response = authenticated_client.get('/api/queries')
        assert response.status_code == 200
        
        data = response.get_json()
        assert 'queries' in data
        assert 'total' in data
        assert isinstance(data['queries'], list)
    
    def test_get_queries_with_pagination(self, authenticated_client):
        """Test queries with pagination"""
        response = authenticated_client.get('/api/queries?limit=10&offset=0')
        assert response.status_code == 200
        
        data = response.get_json()
        assert 'queries' in data


class TestIOCFeedsAPI:
    """Test IOC feeds API endpoints"""
    
    def test_get_ioc_feeds(self, authenticated_client):
        """Test getting IOC feeds"""
        response = authenticated_client.get('/api/ioc/feeds')
        assert response.status_code == 200
        
        data = response.get_json()
        assert 'feeds' in data
        assert isinstance(data['feeds'], list)
    
    def test_create_ioc_feed(self, authenticated_client):
        """Test creating IOC feed"""
        feed_data = {
            'name': 'Test Feed',
            'url': 'https://example.com/feed.txt',
            'feed_type': 'domain',
            'is_active': True
        }
        
        response = authenticated_client.post(
            '/api/ioc/feeds',
            data=json.dumps(feed_data),
            content_type='application/json'
        )
        
        assert response.status_code == 201
        data = response.get_json()
        assert 'id' in data
        assert data['status'] == 'created'
    
    def test_get_ioc_feed_detail(self, authenticated_client):
        """Test getting specific IOC feed"""
        # Create a feed first
        feed_id = db.ioc_feed.insert(
            name='Test Feed',
            url='https://example.com/feed.txt',
            feed_type='domain',
            is_active=True
        )
        db.commit()
        
        response = authenticated_client.get(f'/api/ioc/feeds/{feed_id}')
        assert response.status_code == 200
        
        data = response.get_json()
        assert data['name'] == 'Test Feed'
    
    def test_update_ioc_feed(self, authenticated_client):
        """Test updating IOC feed"""
        feed_id = db.ioc_feed.insert(
            name='Test Feed',
            url='https://example.com/feed.txt',
            feed_type='domain',
            is_active=True
        )
        db.commit()
        
        update_data = {'name': 'Updated Feed'}
        response = authenticated_client.put(
            f'/api/ioc/feeds/{feed_id}',
            data=json.dumps(update_data),
            content_type='application/json'
        )
        
        assert response.status_code == 200
        assert response.get_json()['status'] == 'updated'
    
    def test_delete_ioc_feed(self, authenticated_client):
        """Test deleting IOC feed"""
        feed_id = db.ioc_feed.insert(
            name='Test Feed',
            url='https://example.com/feed.txt',
            feed_type='domain',
            is_active=True
        )
        db.commit()
        
        response = authenticated_client.delete(f'/api/ioc/feeds/{feed_id}')
        assert response.status_code == 200
        assert response.get_json()['status'] == 'deleted'


class TestWHOISAPI:
    """Test WHOIS API endpoints"""
    
    def test_whois_lookup(self, authenticated_client):
        """Test WHOIS lookup"""
        response = authenticated_client.get('/api/whois/example.com')
        assert response.status_code == 200
        
        data = response.get_json()
        assert 'domain' in data
        assert data['domain'] == 'example.com'


class TestStatsAPI:
    """Test statistics API endpoints"""
    
    def test_stats_summary(self, authenticated_client):
        """Test stats summary endpoint"""
        response = authenticated_client.get('/api/stats/summary')
        assert response.status_code == 200
        
        data = response.get_json()
        assert 'total_queries_24h' in data
        assert 'cache_hit_rate' in data
        assert 'active_feeds' in data
