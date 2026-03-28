"""
Flask API Application for Squawk DNS
API-only backend - no template rendering.
Supports both JWT (stateless) and Flask-Login (session) authentication.
"""

import os
import sys
from datetime import timedelta

from flask import Flask, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_login import LoginManager
from penguin_limiter import FlaskRateLimiter, MemoryStorage, RateLimitConfig
from werkzeug.security import generate_password_hash

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get(
    'SECRET_KEY', 'dev-secret-key-change-in-production'
)
app.config['DATABASE_URI'] = os.environ.get('DATABASE_URI', 'sqlite://storage.db')

# JWT Configuration
app.config['JWT_SECRET_KEY'] = os.environ.get(
    'JWT_SECRET_KEY', app.config['SECRET_KEY']
)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(
    hours=int(os.environ.get('JWT_ACCESS_TOKEN_HOURS', '1'))
)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(
    days=int(os.environ.get('JWT_REFRESH_TOKEN_DAYS', '30'))
)

# Import shared database instance
from database import db  # noqa: E402

# Initialize extensions
jwt = JWTManager(app)

CORS(app, resources={
    r"/api/*": {
        "origins": os.environ.get('CORS_ORIGINS', '*').split(','),
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True,
    }
})

limiter = FlaskRateLimiter(
    config=RateLimitConfig.from_string("200/minute"),
    storage=MemoryStorage(),
)
limiter.init_app(app)

# Initialize Flask-Login (backward compatibility)
login_manager = LoginManager()
login_manager.init_app(app)

# Import and register blueprints
from blueprints.auth import auth_bp, User  # noqa: E402
from blueprints.dashboard import dashboard_bp  # noqa: E402
from blueprints.api import api_bp  # noqa: E402

app.register_blueprint(auth_bp, url_prefix='/api/v1/auth')
app.register_blueprint(dashboard_bp, url_prefix='/api/v1')
app.register_blueprint(api_bp, url_prefix='/api/v1')


@login_manager.user_loader
def load_user(user_id):
    """Load user for Flask-Login"""
    user_row = db(db.auth_user.id == int(user_id)).select().first()
    if user_row:
        return User(user_row)
    return None


# JWT user lookup
@jwt.user_identity_loader
def user_identity_lookup(user):
    """Return user id as identity for JWT."""
    if isinstance(user, dict):
        return user.get('id')
    return user


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    """Load user from JWT identity."""
    identity = jwt_data['sub']
    user_row = db(db.auth_user.id == int(identity)).select().first()
    if user_row:
        return User(user_row)
    return None


# --- JSON Error Handlers ---

@app.errorhandler(400)
def bad_request(e):
    return jsonify({'error': 'Bad request', 'message': str(e)}), 400


@app.errorhandler(401)
def unauthorized(e):
    return jsonify({'error': 'Unauthorized', 'message': 'Authentication required'}), 401


@app.errorhandler(403)
def forbidden(e):
    return jsonify({'error': 'Forbidden', 'message': 'Insufficient permissions'}), 403


@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found', 'message': 'Resource not found'}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({'error': 'Method not allowed'}), 405


@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': 'Too many requests',
    }), 429


@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500


@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'error': 'Token expired', 'message': 'Please log in again'}), 401


@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({'error': 'Invalid token', 'message': str(error)}), 401


@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({'error': 'Missing token', 'message': 'Authorization required'}), 401


# --- Seed default admin ---

def seed_admin_user():
    """Seed default admin user if not exists"""
    try:
        admin_exists = db(db.auth_user.email == 'admin@localhost').count() > 0
        if not admin_exists:
            print("Seeding default admin user: admin@localhost / admin123")
            db.auth_user.insert(
                email='admin@localhost',
                password=generate_password_hash('admin123'),
                first_name='Admin',
                last_name='User',
                is_admin=True,
                is_active=True,
            )
            db.commit()
            print("Admin user created successfully!")
        else:
            print("Admin user already exists")
    except Exception as e:
        import traceback
        print(f"Error seeding admin user: {e}")
        traceback.print_exc()


seed_admin_user()


# --- Root routes ---

@app.route('/')
def index():
    """API root - service info"""
    return jsonify({
        'service': 'squawk-dns-api',
        'version': 'v1',
        'endpoints': {
            'auth': '/api/v1/auth/',
            'dashboard': '/api/v1/dashboard/stats',
            'domains': '/api/v1/domains',
            'queries': '/api/v1/queries',
            'health': '/health',
        },
    })


@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'squawk-dns-api'}), 200


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    host = os.environ.get('HOST', '0.0.0.0')
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host=host, port=port, debug=debug)
