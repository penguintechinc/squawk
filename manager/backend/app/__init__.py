"""
Flask application factory for Squawk DNS Manager.
"""

import logging
import os

from flask import Flask
from flask_cors import CORS

from app.config import Config
from app.db import init_db
from app.services.license_service import LicenseService


def create_app(config_class: type = Config) -> Flask:
    """Create and configure Flask application."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize OpenTelemetry tracing (opt-in via OTEL_EXPORTER_OTLP_ENDPOINT)
    from app.observability import init_tracing
    init_tracing(app)

    # CORS with allowlist (default deny cross-origin if ALLOWED_ORIGINS unset)
    allowed_origins_str: str = os.getenv('ALLOWED_ORIGINS', '')
    allowed_origins: list[str] = [
        origin.strip() for origin in allowed_origins_str.split(',') if origin.strip()
    ] if allowed_origins_str else []

    if allowed_origins:
        CORS(app, resources={r"/api/*": {"origins": allowed_origins}})
    else:
        # Empty allowlist = deny cross-origin
        CORS(app, resources={r"/api/*": {"origins": []}})

    # Security headers on every response. This is a JSON API: a restrictive
    # CSP + nosniff blocks it from being abused as a script/style source, and
    # frame-ancestors/X-Frame-Options prevent clickjacking via framed JSON.
    @app.after_request
    def set_security_headers(response):
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('X-Frame-Options', 'DENY')
        response.headers.setdefault(
            'Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'"
        )
        response.headers.setdefault('Referrer-Policy', 'no-referrer')
        # HSTS is only meaningful over TLS; browsers ignore it on plain HTTP,
        # so setting it unconditionally is safe (TLS terminates at ingress).
        response.headers.setdefault(
            'Strict-Transport-Security', 'max-age=31536000; includeSubDomains'
        )
        return response

    # Rate limiting via penguin-limiter
    from penguin_limiter import FlaskRateLimiter, MemoryStorage, RateLimitConfig

    _limit_str = app.config.get("RATELIMIT_DEFAULT", "100/hour")
    _storage_url = app.config.get("RATELIMIT_STORAGE_URL")

    if _storage_url:
        from penguin_limiter.storage.redis_store import RedisStorage
        _storage = RedisStorage(url=_storage_url)
    else:
        _storage = MemoryStorage()

    limiter = FlaskRateLimiter(
        config=RateLimitConfig.from_string(_limit_str),
        storage=_storage,
    )
    limiter.init_app(app)
    app.limiter = limiter

    # Initialize database
    db = init_db(app)
    app.db = db

    # Initialize license service
    app.license_service = LicenseService()

    # Initialize PostHog client for feature flags
    from app.services.posthog_client import PostHogClient
    app.posthog = PostHogClient()

    # Initialize IOC manager
    from app.services.ioc_ingestion_service import IOCManager
    app.ioc_manager = IOCManager(db_url=app.config['DB_URL'])

    # Initialize WHOIS manager
    from app.services.whois_service import WHOISManager
    app.whois_manager = WHOISManager(db_url=app.config['DB_URL'])

    # Initialize Client Config manager. Deployment-domain tokens are signed
    # asymmetrically with the manager's configured JWT keypair (ES256 default,
    # RS256 fallback) so they verify across replicas and restarts.
    from app.services.client_config_service import ClientConfigManager
    app.client_config_manager = ClientConfigManager(
        db_url=app.config['DB_URL'],
        private_key=app.config.get('JWT_PRIVATE_KEY'),
        public_key=app.config.get('JWT_PUBLIC_KEY'),
        algorithm=app.config.get('JWT_ALGORITHM', 'ES256'),
        issuer=app.config.get('JWT_ISSUER', 'squawk-manager'),
        audience=app.config.get('JWT_AUDIENCE', 'squawk'),
    )

    # Register blueprints
    from app.blueprints.auth import auth_bp
    from app.blueprints.mfa import mfa_bp
    from app.blueprints.users import users_bp
    from app.blueprints.teams import teams_bp
    from app.blueprints.tokens import tokens_bp
    from app.blueprints.dns_servers import dns_servers_bp
    from app.blueprints.zones import zones_bp
    from app.blueprints.ioc_feeds import ioc_feeds_bp
    from app.blueprints.whois import whois_bp
    from app.blueprints.client_config import client_config_bp
    from app.blueprints.analytics import analytics_bp
    from app.blueprints.dhcp import dhcp_bp
    from app.blueprints.time import time_bp
    from app.blueprints.scim import scim_bp
    from app.blueprints.machine_clients import machine_clients_bp
    from app.blueprints.oidc_trust_anchors import oidc_trust_anchors_bp
    from app.blueprints.audit import audit_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(mfa_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(teams_bp)
    app.register_blueprint(tokens_bp)
    app.register_blueprint(dns_servers_bp)
    app.register_blueprint(zones_bp)
    app.register_blueprint(ioc_feeds_bp)
    app.register_blueprint(whois_bp)
    app.register_blueprint(client_config_bp)
    app.register_blueprint(analytics_bp)
    app.register_blueprint(dhcp_bp)
    app.register_blueprint(time_bp)
    app.register_blueprint(scim_bp)
    app.register_blueprint(machine_clients_bp)
    app.register_blueprint(oidc_trust_anchors_bp)
    app.register_blueprint(audit_bp)

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
