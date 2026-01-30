"""
Authentication Blueprint for Flask Application - JSON API Only
Handles login, logout, registration, and user management via JSON API.
Supports both JWT (stateless) and Flask-Login (session) authentication.
"""

from flask import Blueprint, jsonify, request
from flask_login import login_user, logout_user, login_required, current_user
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    current_user as jwt_current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import shared database instance
from database import db

auth_bp = Blueprint('auth', __name__)


class User:
    """User class for Flask-Login and JWT"""
    def __init__(self, user_row):
        self.id = user_row.id
        self.email = user_row.email
        self.first_name = user_row.first_name
        self.last_name = user_row.last_name
        self.is_admin = user_row.is_admin
        self._is_active = user_row.is_active

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return self._is_active

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    def to_dict(self):
        """Convert user to dictionary for JSON responses"""
        return {
            'id': self.id,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'is_admin': self.is_admin,
            'is_active': self._is_active
        }


@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Login endpoint - JSON API
    Accepts: {email, password, remember (optional)}
    Returns: {success, user, access_token, refresh_token} or {success, error}
    """
    if not request.is_json:
        return jsonify({
            'success': False,
            'error': 'Content-Type must be application/json'
        }), 400

    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    remember = data.get('remember', False)

    if not email or not password:
        return jsonify({
            'success': False,
            'error': 'Email and password are required'
        }), 400

    user_row = db(db.auth_user.email == email).select().first()

    if user_row and check_password_hash(user_row.password, password):
        user = User(user_row)

        # Flask-Login session authentication
        login_user(user, remember=remember)

        # JWT tokens
        access_token = create_access_token(identity=str(user.id))
        refresh_token = create_refresh_token(identity=str(user.id))

        # Build roles list
        roles = ['admin'] if user.is_admin else ['viewer']

        # Response format matches LoginPageBuilder's LoginResponse
        full_name = f"{user.first_name or ''} {user.last_name or ''}".strip()
        return jsonify({
            'success': True,
            'user': {
                'id': str(user.id),
                'email': user.email,
                'name': full_name or user.email,
                'roles': roles,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'is_admin': user.is_admin,
                'is_active': user.is_active,
            },
            'token': access_token,
            'refreshToken': refresh_token,
            # Also include snake_case for direct API consumers
            'access_token': access_token,
            'refresh_token': refresh_token,
        }), 200
    else:
        return jsonify({
            'success': False,
            'error': 'Invalid email or password'
        }), 401


@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """
    Logout endpoint - JSON API
    Invalidates Flask-Login session.
    Returns: {success, message}
    """
    logout_user()
    return jsonify({
        'success': True,
        'message': 'Logged out successfully'
    }), 200


@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Registration endpoint - JSON API
    Accepts: {email, password, first_name, last_name}
    Returns: {success, user} or {success, error}
    """
    if not request.is_json:
        return jsonify({
            'success': False,
            'error': 'Content-Type must be application/json'
        }), 400

    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    first_name = data.get('first_name')
    last_name = data.get('last_name')

    # Validate required fields
    if not email or not password:
        return jsonify({
            'success': False,
            'error': 'Email and password are required'
        }), 400

    if not first_name or not last_name:
        return jsonify({
            'success': False,
            'error': 'First name and last name are required'
        }), 400

    # Check if user exists
    existing_user = db(db.auth_user.email == email).select().first()
    if existing_user:
        return jsonify({
            'success': False,
            'error': 'Email already registered'
        }), 409

    try:
        # Create new user
        user_id = db.auth_user.insert(
            email=email,
            password=generate_password_hash(password),
            first_name=first_name,
            last_name=last_name
        )
        db.commit()

        # Fetch created user
        user_row = db(db.auth_user.id == user_id).select().first()
        user = User(user_row)

        return jsonify({
            'success': True,
            'user': user.to_dict(),
            'message': 'Registration successful'
        }), 201
    except Exception as e:
        db.rollback()
        return jsonify({
            'success': False,
            'error': f'Registration failed: {str(e)}'
        }), 500


@auth_bp.route('/me', methods=['GET'])
@jwt_required(optional=True)
def me():
    """
    Get current user info - JSON API
    Supports both JWT (Authorization: Bearer <token>) and Flask-Login session.
    Returns: {success, user} or {success, error}
    """
    user = None

    # Try JWT authentication first
    jwt_identity = get_jwt_identity()
    if jwt_identity:
        user_row = db(db.auth_user.id == int(jwt_identity)).select().first()
        if user_row:
            user = User(user_row)

    # Fall back to Flask-Login session
    if not user and current_user.is_authenticated:
        user = current_user

    if user:
        return jsonify({
            'success': True,
            'user': user.to_dict()
        }), 200
    else:
        return jsonify({
            'success': False,
            'error': 'Not authenticated'
        }), 401


@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """
    Refresh JWT access token - JSON API
    Requires refresh token in Authorization header.
    Returns: {success, access_token}
    """
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)

    return jsonify({
        'success': True,
        'access_token': access_token
    }), 200
