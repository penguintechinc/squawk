"""
Authentication Blueprint for Flask Application
Handles login, logout, and user management
"""

from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from models import define_tables
from pydal import DAL

auth_bp = Blueprint('auth', __name__)

# Get database instance
db = DAL(os.environ.get('DATABASE_URI', 'sqlite://storage.db'), 
         folder=os.path.join(os.path.dirname(__file__), '..', 'databases'))
define_tables(db)

class User:
    """User class for Flask-Login"""
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

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = request.form.get('remember', False)
        
        user_row = db(db.auth_user.email == email).select().first()
        
        if user_row and check_password_hash(user_row.password, password):
            user = User(user_row)
            login_user(user, remember=remember)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard.index'))
        else:
            flash('Invalid email or password', 'error')
    
    return render_template('auth/login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    """Logout"""
    logout_user()
    return redirect(url_for('index'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """Registration page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        
        # Check if user exists
        existing_user = db(db.auth_user.email == email).select().first()
        if existing_user:
            flash('Email already registered', 'error')
            return redirect(url_for('auth.register'))
        
        # Create new user
        db.auth_user.insert(
            email=email,
            password=generate_password_hash(password),
            first_name=first_name,
            last_name=last_name
        )
        db.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/register.html')
