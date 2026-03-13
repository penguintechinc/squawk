"""
Test suite for Flask Authentication Blueprint - JSON API Only
Tests /api/v1/auth/* endpoints with JWT and session authentication.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from werkzeug.security import generate_password_hash
from app import app
from database import db
from blueprints.auth import User


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    """Create test client with test config."""
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret-key'
    app.config['JWT_SECRET_KEY'] = 'test-jwt-secret'
    app.config['WTF_CSRF_ENABLED'] = False
    with app.test_client() as client:
        with app.app_context():
            yield client


@pytest.fixture
def mock_user(client):
    """Insert a standard (non-admin) test user and return the User object."""
    db(db.auth_user.email == 'test@example.com').delete()
    db.commit()

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
    yield User(user_row)

    db(db.auth_user.id == user_id).delete()
    db.commit()


@pytest.fixture
def admin_user(client):
    """Insert an admin test user, login, and return (client, access_token)."""
    db(db.auth_user.email == 'admin_test@example.com').delete()
    db.commit()

    db.auth_user.insert(
        email='admin_test@example.com',
        password=generate_password_hash('adminpass'),
        first_name='Admin',
        last_name='Tester',
        is_active=True,
        is_admin=True
    )
    db.commit()

    resp = client.post('/api/v1/auth/login',
                       json={'email': 'admin_test@example.com', 'password': 'adminpass'})
    token = resp.get_json().get('access_token')

    yield client, token

    db(db.auth_user.email == 'admin_test@example.com').delete()
    db.commit()


# ---------------------------------------------------------------------------
# Tests: POST /api/v1/auth/login
# ---------------------------------------------------------------------------

class TestLogin:
    """Tests for POST /api/v1/auth/login"""

    def test_login_success(self, client, mock_user):
        """Successful login returns 200 with access_token."""
        response = client.post('/api/v1/auth/login',
                               json={'email': 'test@example.com', 'password': 'password123'})
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert 'access_token' in data
        assert 'refresh_token' in data
        assert data['user']['email'] == 'test@example.com'

    def test_login_success_token_aliases(self, client, mock_user):
        """Login response includes both token and access_token keys."""
        response = client.post('/api/v1/auth/login',
                               json={'email': 'test@example.com', 'password': 'password123'})
        data = response.get_json()
        assert 'token' in data
        assert 'refreshToken' in data
        assert data['token'] == data['access_token']

    def test_login_invalid_password(self, client, mock_user):
        """Wrong password returns 401."""
        response = client.post('/api/v1/auth/login',
                               json={'email': 'test@example.com', 'password': 'wrongpass'})
        assert response.status_code == 401
        data = response.get_json()
        assert data['success'] is False
        assert 'error' in data

    def test_login_nonexistent_user(self, client):
        """Login with email that does not exist returns 401."""
        db(db.auth_user.email == 'nobody@example.com').delete()
        db.commit()
        response = client.post('/api/v1/auth/login',
                               json={'email': 'nobody@example.com', 'password': 'password123'})
        assert response.status_code == 401
        assert response.get_json()['success'] is False

    def test_login_missing_email(self, client):
        """Missing email field returns 400."""
        response = client.post('/api/v1/auth/login',
                               json={'password': 'password123'})
        assert response.status_code == 400
        data = response.get_json()
        assert data['success'] is False

    def test_login_missing_password(self, client):
        """Missing password field returns 400."""
        response = client.post('/api/v1/auth/login',
                               json={'email': 'test@example.com'})
        assert response.status_code == 400

    def test_login_missing_both_fields(self, client):
        """Empty JSON body returns 400."""
        response = client.post('/api/v1/auth/login', json={})
        assert response.status_code == 400

    def test_login_non_json_returns_400(self, client):
        """Non-JSON Content-Type returns 400 with error message."""
        response = client.post(
            '/api/v1/auth/login',
            data='email=test@example.com&password=password123',
            content_type='application/x-www-form-urlencoded'
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data['success'] is False
        assert 'application/json' in data['error']

    def test_login_response_includes_user_fields(self, client, mock_user):
        """Login response user object has expected fields."""
        response = client.post('/api/v1/auth/login',
                               json={'email': 'test@example.com', 'password': 'password123'})
        user_data = response.get_json()['user']
        assert 'id' in user_data
        assert 'email' in user_data
        assert 'is_admin' in user_data
        assert 'is_active' in user_data

    def test_login_admin_user_roles(self, client):
        """Admin user login response includes admin role."""
        db(db.auth_user.email == 'roletest_admin@example.com').delete()
        db.commit()
        db.auth_user.insert(
            email='roletest_admin@example.com',
            password=generate_password_hash('pass'),
            first_name='Role',
            last_name='Admin',
            is_active=True,
            is_admin=True
        )
        db.commit()
        response = client.post('/api/v1/auth/login',
                               json={'email': 'roletest_admin@example.com', 'password': 'pass'})
        assert response.status_code == 200
        roles = response.get_json()['user']['roles']
        assert 'admin' in roles
        db(db.auth_user.email == 'roletest_admin@example.com').delete()
        db.commit()

    def test_login_viewer_user_roles(self, client, mock_user):
        """Non-admin user login response includes viewer role."""
        response = client.post('/api/v1/auth/login',
                               json={'email': 'test@example.com', 'password': 'password123'})
        roles = response.get_json()['user']['roles']
        assert 'viewer' in roles


# ---------------------------------------------------------------------------
# Tests: POST /api/v1/auth/logout
# ---------------------------------------------------------------------------

class TestLogout:
    """Tests for POST /api/v1/auth/logout"""

    def test_logout_unauthenticated_returns_401(self, client):
        """Logout without session returns 401 (login_required)."""
        response = client.post('/api/v1/auth/logout')
        assert response.status_code == 401

    def test_logout_after_session_login(self, client, mock_user):
        """Logout after session login returns 200."""
        client.post('/api/v1/auth/login',
                    json={'email': 'test@example.com', 'password': 'password123'})
        response = client.post('/api/v1/auth/logout')
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert 'message' in data


# ---------------------------------------------------------------------------
# Tests: POST /api/v1/auth/register
# ---------------------------------------------------------------------------

class TestRegister:
    """Tests for POST /api/v1/auth/register"""

    def test_register_success(self, client):
        """Successful registration returns 201 with user data."""
        db(db.auth_user.email == 'newuser@example.com').delete()
        db.commit()

        response = client.post('/api/v1/auth/register', json={
            'email': 'newuser@example.com',
            'password': 'newpass123',
            'first_name': 'New',
            'last_name': 'User'
        })
        assert response.status_code == 201
        data = response.get_json()
        assert data['success'] is True
        assert 'user' in data
        assert data['user']['email'] == 'newuser@example.com'

        db(db.auth_user.email == 'newuser@example.com').delete()
        db.commit()

    def test_register_creates_user_in_db(self, client):
        """Registered user is persisted in the database."""
        db(db.auth_user.email == 'persist@example.com').delete()
        db.commit()

        client.post('/api/v1/auth/register', json={
            'email': 'persist@example.com',
            'password': 'pass',
            'first_name': 'Per',
            'last_name': 'Sist'
        })
        user = db(db.auth_user.email == 'persist@example.com').select().first()
        assert user is not None
        assert user.first_name == 'Per'

        db(db.auth_user.email == 'persist@example.com').delete()
        db.commit()

    def test_register_duplicate_email_returns_409(self, client, mock_user):
        """Registering with an existing email returns 409."""
        response = client.post('/api/v1/auth/register', json={
            'email': 'test@example.com',
            'password': 'pass',
            'first_name': 'Dup',
            'last_name': 'User'
        })
        assert response.status_code == 409
        data = response.get_json()
        assert data['success'] is False

    def test_register_missing_email_returns_400(self, client):
        """Missing email returns 400."""
        response = client.post('/api/v1/auth/register', json={
            'password': 'pass',
            'first_name': 'No',
            'last_name': 'Email'
        })
        assert response.status_code == 400
        assert response.get_json()['success'] is False

    def test_register_missing_password_returns_400(self, client):
        """Missing password returns 400."""
        response = client.post('/api/v1/auth/register', json={
            'email': 'nopass@example.com',
            'first_name': 'No',
            'last_name': 'Pass'
        })
        assert response.status_code == 400

    def test_register_missing_first_name_returns_400(self, client):
        """Missing first_name returns 400."""
        response = client.post('/api/v1/auth/register', json={
            'email': 'nofirst@example.com',
            'password': 'pass',
            'last_name': 'User'
        })
        assert response.status_code == 400

    def test_register_missing_last_name_returns_400(self, client):
        """Missing last_name returns 400."""
        response = client.post('/api/v1/auth/register', json={
            'email': 'nolast@example.com',
            'password': 'pass',
            'first_name': 'User'
        })
        assert response.status_code == 400

    def test_register_non_json_returns_400(self, client):
        """Non-JSON Content-Type returns 400."""
        response = client.post(
            '/api/v1/auth/register',
            data='email=x@y.com&password=pass&first_name=A&last_name=B',
            content_type='application/x-www-form-urlencoded'
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data['success'] is False
        assert 'application/json' in data['error']

    def test_register_empty_json_returns_400(self, client):
        """Empty JSON body returns 400."""
        response = client.post('/api/v1/auth/register', json={})
        assert response.status_code == 400


# ---------------------------------------------------------------------------
# Tests: GET /api/v1/auth/me
# ---------------------------------------------------------------------------

class TestMe:
    """Tests for GET /api/v1/auth/me"""

    def test_me_unauthenticated_returns_401(self, client):
        """No auth returns 401."""
        response = client.get('/api/v1/auth/me')
        assert response.status_code == 401
        data = response.get_json()
        assert data['success'] is False

    def test_me_with_session_auth(self, client, mock_user):
        """After session login, /me returns the logged-in user."""
        client.post('/api/v1/auth/login',
                    json={'email': 'test@example.com', 'password': 'password123'})
        response = client.get('/api/v1/auth/me')
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['user']['email'] == 'test@example.com'

    def test_me_with_jwt_bearer_token(self, client, mock_user):
        """JWT Bearer token in Authorization header authenticates /me."""
        login_resp = client.post('/api/v1/auth/login',
                                 json={'email': 'test@example.com', 'password': 'password123'})
        token = login_resp.get_json()['access_token']

        response = client.get('/api/v1/auth/me',
                              headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['user']['email'] == 'test@example.com'

    def test_me_with_invalid_jwt_returns_401(self, client):
        """An invalid JWT token returns 401."""
        response = client.get('/api/v1/auth/me',
                              headers={'Authorization': 'Bearer invalidtoken'})
        assert response.status_code == 401

    def test_me_returns_correct_user_fields(self, client, mock_user):
        """User dict returned by /me includes all expected fields."""
        login_resp = client.post('/api/v1/auth/login',
                                 json={'email': 'test@example.com', 'password': 'password123'})
        token = login_resp.get_json()['access_token']

        response = client.get('/api/v1/auth/me',
                              headers={'Authorization': f'Bearer {token}'})
        user = response.get_json()['user']
        assert 'id' in user
        assert 'email' in user
        assert 'first_name' in user
        assert 'last_name' in user
        assert 'is_admin' in user
        assert 'is_active' in user

    def test_me_does_not_return_password(self, client, mock_user):
        """Password hash must not appear in /me response."""
        login_resp = client.post('/api/v1/auth/login',
                                 json={'email': 'test@example.com', 'password': 'password123'})
        token = login_resp.get_json()['access_token']

        response = client.get('/api/v1/auth/me',
                              headers={'Authorization': f'Bearer {token}'})
        assert 'password' not in response.get_json()['user']


# ---------------------------------------------------------------------------
# Tests: POST /api/v1/auth/refresh
# ---------------------------------------------------------------------------

class TestRefresh:
    """Tests for POST /api/v1/auth/refresh"""

    def test_refresh_without_token_returns_401(self, client):
        """Calling /refresh with no token returns 401."""
        response = client.post('/api/v1/auth/refresh')
        assert response.status_code == 401

    def test_refresh_with_access_token_returns_422_or_401(self, client, mock_user):
        """Sending an access token (not refresh token) to /refresh is rejected."""
        login_resp = client.post('/api/v1/auth/login',
                                 json={'email': 'test@example.com', 'password': 'password123'})
        access_token = login_resp.get_json()['access_token']

        response = client.post('/api/v1/auth/refresh',
                               headers={'Authorization': f'Bearer {access_token}'})
        # JWT Extended rejects wrong token type: 401 or 422
        assert response.status_code in (401, 422)

    def test_refresh_with_refresh_token_returns_200(self, client, mock_user):
        """Valid refresh token returns a new access_token."""
        login_resp = client.post('/api/v1/auth/login',
                                 json={'email': 'test@example.com', 'password': 'password123'})
        refresh_token = login_resp.get_json()['refresh_token']

        response = client.post('/api/v1/auth/refresh',
                               headers={'Authorization': f'Bearer {refresh_token}'})
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert 'access_token' in data

    def test_refresh_produces_valid_access_token(self, client, mock_user):
        """New access_token from /refresh can be used to authenticate."""
        login_resp = client.post('/api/v1/auth/login',
                                 json={'email': 'test@example.com', 'password': 'password123'})
        refresh_token = login_resp.get_json()['refresh_token']

        refresh_resp = client.post('/api/v1/auth/refresh',
                                   headers={'Authorization': f'Bearer {refresh_token}'})
        new_token = refresh_resp.get_json()['access_token']

        # Use the new token
        me_resp = client.get('/api/v1/auth/me',
                             headers={'Authorization': f'Bearer {new_token}'})
        assert me_resp.status_code == 200


# ---------------------------------------------------------------------------
# Tests: User model
# ---------------------------------------------------------------------------

class TestUserModel:
    """Tests for the User class in blueprints/auth.py"""

    def test_is_authenticated(self, mock_user):
        """User.is_authenticated is always True."""
        assert mock_user.is_authenticated is True

    def test_is_active_true(self, mock_user):
        """is_active reflects the db value (True for mock_user)."""
        assert mock_user.is_active is True

    def test_is_active_false_for_inactive_user(self, client):
        """is_active is False for an inactive user."""
        db(db.auth_user.email == 'inactive@example.com').delete()
        db.commit()
        uid = db.auth_user.insert(
            email='inactive@example.com',
            password=generate_password_hash('x'),
            is_active=False,
            is_admin=False
        )
        db.commit()
        row = db(db.auth_user.id == uid).select().first()
        u = User(row)
        assert u.is_active is False
        db(db.auth_user.id == uid).delete()
        db.commit()

    def test_is_anonymous(self, mock_user):
        """User.is_anonymous is always False."""
        assert mock_user.is_anonymous is False

    def test_get_id_returns_string(self, mock_user):
        """get_id() returns a string."""
        result = mock_user.get_id()
        assert isinstance(result, str)

    def test_get_id_matches_user_id(self, mock_user):
        """get_id() value equals str(user.id)."""
        assert mock_user.get_id() == str(mock_user.id)

    def test_to_dict_keys(self, mock_user):
        """to_dict() contains expected keys."""
        d = mock_user.to_dict()
        assert 'id' in d
        assert 'email' in d
        assert 'first_name' in d
        assert 'last_name' in d
        assert 'is_admin' in d
        assert 'is_active' in d

    def test_to_dict_no_password(self, mock_user):
        """to_dict() does not include a password key."""
        d = mock_user.to_dict()
        assert 'password' not in d

    def test_to_dict_values(self, mock_user):
        """to_dict() values match the user attributes."""
        d = mock_user.to_dict()
        assert d['email'] == 'test@example.com'
        assert d['first_name'] == 'Test'
        assert d['last_name'] == 'User'
        assert d['is_admin'] is False
        assert d['is_active'] is True

    def test_is_admin_false_for_regular_user(self, mock_user):
        """Regular user has is_admin == False."""
        assert mock_user.is_admin is False

    def test_is_admin_true_for_admin_user(self, client):
        """Admin user has is_admin == True."""
        db(db.auth_user.email == 'admin_model@example.com').delete()
        db.commit()
        uid = db.auth_user.insert(
            email='admin_model@example.com',
            password=generate_password_hash('x'),
            is_active=True,
            is_admin=True
        )
        db.commit()
        row = db(db.auth_user.id == uid).select().first()
        u = User(row)
        assert u.is_admin is True
        db(db.auth_user.id == uid).delete()
        db.commit()
