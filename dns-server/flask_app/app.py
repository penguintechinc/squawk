"""
Flask Application for Squawk DNS Web Console
Replaces py4web with Flask while keeping PyDAL for database operations
"""

import os
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, login_required, current_user
from pydal import DAL, Field

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['DATABASE_URI'] = os.environ.get('DATABASE_URI', 'sqlite://storage.db')

# Initialize PyDAL
db = DAL(app.config['DATABASE_URI'], folder=os.path.join(os.path.dirname(__file__), 'databases'))

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'

# Import and register blueprints
import sys
sys.path.insert(0, os.path.dirname(__file__))

from blueprints.auth import auth_bp, User
from blueprints.dashboard import dashboard_bp
from blueprints.api import api_bp

app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
app.register_blueprint(api_bp, url_prefix='/api')

# Define database models using PyDAL
from models import define_tables
define_tables(db)

@login_manager.user_loader
def load_user(user_id):
    """Load user for Flask-Login"""
    user_row = db(db.auth_user.id == int(user_id)).select().first()
    if user_row:
        return User(user_row)
    return None

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
