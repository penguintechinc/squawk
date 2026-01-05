"""
Flask application factory for Squawk DNS Manager.
"""

from flask import Flask
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging

from app.config import Config
from app.db import init_db
from app.services.license_service import LicenseService


def create_app(config_class=Config):
    """Create and configure Flask application."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Rate limiting
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        storage_uri=app.config.get('RATELIMIT_STORAGE_URL'),
        default_limits=["100/hour"]
    )

    # Initialize database
    db = init_db(app)
    app.db = db

    # Initialize license service
    app.license_service = LicenseService()

    # Register blueprints
    from app.blueprints.auth import auth_bp
    from app.blueprints.users import users_bp
    from app.blueprints.teams import teams_bp
    from app.blueprints.tokens import tokens_bp
    from app.blueprints.dns_servers import dns_servers_bp
    from app.blueprints.zones import zones_bp
    from app.blueprints.ioc_feeds import ioc_feeds_bp
    from app.blueprints.analytics import analytics_bp
    from app.blueprints.dhcp import dhcp_bp
    from app.blueprints.time import time_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(teams_bp)
    app.register_blueprint(tokens_bp)
    app.register_blueprint(dns_servers_bp)
    app.register_blueprint(zones_bp)
    app.register_blueprint(ioc_feeds_bp)
    app.register_blueprint(analytics_bp)
    app.register_blueprint(dhcp_bp)
    app.register_blueprint(time_bp)

    # Health check endpoint
    @app.route('/health')
    def health():
        return {'status': 'healthy'}, 200

    # Configure logging
    logging.basicConfig(
        level=logging.INFO if not app.debug else logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    return app
