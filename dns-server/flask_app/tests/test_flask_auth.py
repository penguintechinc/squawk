"""
Test suite for Flask Web Console Authentication
Tests login, logout, and registration endpoints with mocked PyDAL
"""

import pytest
from flask import session
from werkzeug.security import generate_password_hash
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app import app, db
from blueprints.auth import User


@pytest.fixture
def client():
    """Create test client"""
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret-key'
    app.config['WTF_CSRF_ENABLED'] = False
    
    with app.test_client() as client:
        yield client


@pytest.fixture
def mock_user():
    """Create a mock user in the database"""
    # Clear existing users
    db(db.auth_user).delete()
    db.commit()
    
    # Create test user
    user_id = db.auth_user.insert(
        email='test@example.com',
        password=generate_password_hash('password123'),
        first_name='Test',
        last_name='User',
        is_active=True,
        is_admin=False
    )
    db.commit()
    
    user_row = db(db.auth_user.id == user_id).select().first()
    return User(user_row)


class TestAuthentication:
    """Test authentication endpoints"""
    
    def test_login_page_loads(self, client):
        """Test that login page loads"""
        response = client.get('/auth/login')
        assert response.status_code == 200
        assert b'Login to Squawk DNS' in response.data
    
    def test_login_success(self, client, mock_user):
        """Test successful login"""
        response = client.post('/auth/login', data={
            'email': 'test@example.com',
            'password': 'password123'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        # Should redirect to dashboard
        assert b'Dashboard' in response.data or b'DNS Dashboard' in response.data
    
    def test_login_invalid_credentials(self, client, mock_user):
        """Test login with invalid credentials"""
        response = client.post('/auth/login', data={
            'email': 'test@example.com',
            'password': 'wrongpassword'
        })
        
        assert response.status_code == 200
        assert b'Invalid email or password' in response.data
    
    def test_login_nonexistent_user(self, client):
        """Test login with non-existent user"""
        response = client.post('/auth/login', data={
            'email': 'nonexistent@example.com',
            'password': 'password123'
        })
        
        assert response.status_code == 200
        assert b'Invalid email or password' in response.data
    
    def test_logout(self, client, mock_user):
        """Test logout"""
        # Login first
        client.post('/auth/login', data={
            'email': 'test@example.com',
            'password': 'password123'
        })
        
        # Then logout
        response = client.get('/auth/logout', follow_redirects=True)
        assert response.status_code == 200
    
    def test_register_page_loads(self, client):
        """Test that registration page loads"""
        response = client.get('/auth/register')
        assert response.status_code == 200
    
    def test_register_success(self, client):
        """Test successful registration"""
        response = client.post('/auth/register', data={
            'email': 'newuser@example.com',
            'password': 'newpassword123',
            'first_name': 'New',
            'last_name': 'User'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'Registration successful' in response.data or b'Login' in response.data
        
        # Verify user was created
        user = db(db.auth_user.email == 'newuser@example.com').select().first()
        assert user is not None
        assert user.first_name == 'New'
    
    def test_register_duplicate_email(self, client, mock_user):
        """Test registration with duplicate email"""
        response = client.post('/auth/register', data={
            'email': 'test@example.com',  # Already exists
            'password': 'password123',
            'first_name': 'Duplicate',
            'last_name': 'User'
        })
        
        assert response.status_code == 200 or response.status_code == 302
        # Should show error or redirect


class TestUserModel:
    """Test User model for Flask-Login"""
    
    def test_user_properties(self, mock_user):
        """Test User model properties"""
        assert mock_user.is_authenticated == True
        assert mock_user.is_active == True
        assert mock_user.is_anonymous == False
        assert mock_user.email == 'test@example.com'
    
    def test_get_id(self, mock_user):
        """Test get_id method"""
        user_id = mock_user.get_id()
        assert user_id is not None
        assert isinstance(user_id, str)
