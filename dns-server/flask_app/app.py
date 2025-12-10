"""
Flask Application for Squawk DNS Web Console
Replaces py4web with Flask while keeping PyDAL for database operations
"""

import os
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, login_required, current_user
from werkzeug.security import generate_password_hash
import sys

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['DATABASE_URI'] = os.environ.get('DATABASE_URI', 'sqlite://storage.db')

# Import shared database instance
from database import db

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'

# Import and register blueprints
from blueprints.auth import auth_bp, User
from blueprints.dashboard import dashboard_bp
from blueprints.api import api_bp

app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
app.register_blueprint(api_bp, url_prefix='/api')

@login_manager.user_loader
def load_user(user_id):
    """Load user for Flask-Login"""
    user_row = db(db.auth_user.id == int(user_id)).select().first()
    if user_row:
        return User(user_row)
    return None

def seed_admin_user():
    """Seed default admin user if not exists"""
    try:
        if not db(db.auth_user.email == 'admin@localhost').count():
            print("Seeding default admin user: admin@localhost")
            db.auth_user.insert(
                email='admin@localhost',
                password=generate_password_hash('admin123'),
                first_name='Admin',
                last_name='User',
                is_admin=True,
                is_active=True
            )
            db.commit()
    except Exception as e:
        print(f"Error seeding admin user: {e}")

# Seed admin user on startup
seed_admin_user()

@app.route('/')
def index():
    """Home page - redirect to dashboard or login"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    return redirect(url_for('auth.login'))

@app.route('/health')
def health():
    """Health check endpoint"""
    return {'status': 'healthy', 'service': 'web-console'}, 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    host = os.environ.get('HOST', '0.0.0.0')
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    app.run(host=host, port=port, debug=debug)
