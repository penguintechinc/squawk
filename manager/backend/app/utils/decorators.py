"""
Utility decorators for Squawk DNS Manager.
"""

from functools import wraps
from flask import jsonify, current_app, request
from datetime import datetime
import time
import logging
import os

logger = logging.getLogger(__name__)


def requires_enterprise_license(feature_name: str):
    """
    Decorator to enforce enterprise license for specific features.

    Args:
        feature_name: Name of the feature requiring enterprise license

    Example:
        @requires_enterprise_license('sso_authentication')
        def configure_sso():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            license_service = current_app.license_service

            if not license_service.is_feature_enabled(feature_name):
                tier = license_service.get_tier()
                return jsonify({
                    'error': 'Feature requires Enterprise license',
                    'feature': feature_name,
                    'tier_required': 'enterprise',
                    'current_tier': tier,
                    'upgrade_url': 'https://squawkdns.com/pricing'
                }), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def rate_limit(calls: int, period: int):
    """
    Simple rate limiting decorator.

    Args:
        calls: Number of calls allowed
        period: Time period in seconds

    Example:
        @rate_limit(calls=10, period=60)  # 10 calls per minute
        def expensive_operation():
            ...
    """
    def decorator(f):
        # Store call timestamps per IP
        call_history = {}

        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.remote_addr
            now = time.time()

            # Initialize or clean old entries
            if client_ip not in call_history:
                call_history[client_ip] = []

            # Remove calls outside the time window
            call_history[client_ip] = [
                timestamp for timestamp in call_history[client_ip]
                if now - timestamp < period
            ]

            # Check if limit exceeded
            if len(call_history[client_ip]) >= calls:
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'limit': f'{calls} calls per {period} seconds'
                }), 429

            # Record this call
            call_history[client_ip].append(now)

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def log_execution_time(f):
    """
    Decorator to log execution time of functions.

    Example:
        @log_execution_time
        def slow_function():
            ...
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        start_time = time.time()
        result = f(*args, **kwargs)
        end_time = time.time()

        duration = (end_time - start_time) * 1000  # Convert to ms
        logger.info(f"{f.__name__} executed in {duration:.2f}ms")

        return result
    return decorated_function


def validate_json(*required_fields):
    """
    Decorator to validate JSON request body contains required fields.

    Args:
        required_fields: Field names that must be present in JSON

    Example:
        @validate_json('username', 'password')
        def login():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return jsonify({'error': 'Content-Type must be application/json'}), 400

            data = request.get_json()
            missing_fields = [field for field in required_fields if field not in data]

            if missing_fields:
                return jsonify({
                    'error': 'Missing required fields',
                    'missing_fields': missing_fields
                }), 400

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def cache_response(timeout: int):
    """
    Decorator to cache response for specified timeout.
    Uses Flask-Caching if available.

    Args:
        timeout: Cache timeout in seconds

    Example:
        @cache_response(300)  # Cache for 5 minutes
        def get_config():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Simple implementation without Flask-Caching
            # In production, integrate with Redis cache
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def handle_db_errors(f):
    """
    Decorator to handle database errors gracefully.

    Example:
        @handle_db_errors
        def create_user():
            ...
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            # Log detail server-side; never echo exception text to clients.
            logger.exception(f"Database error in {f.__name__}: {str(e)}")
            db = current_app.db
            db.rollback()
            return jsonify({
                'error': 'Database operation failed'
            }), 500
    return decorated_function


def audit_log(action: str):
    """
    Decorator to log actions for audit trail.

    Args:
        action: Description of the action

    Example:
        @audit_log('user_created')
        def create_user():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from app.middleware.auth import get_current_user

            user = get_current_user()
            user_id = user.get('user_id') if user else None
            username = user.get('username') if user else 'anonymous'

            logger.info(f"AUDIT: {action} by {username} (user_id={user_id})")

            result = f(*args, **kwargs)

            return result
        return decorated_function
    return decorator


def cors_preflight(f):
    """
    Decorator to handle CORS preflight requests.
    Only reflects Origin if it is in the ALLOWED_ORIGINS allowlist.

    Example:
        @cors_preflight
        def api_endpoint():
            ...
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'OPTIONS':
            response = jsonify({'status': 'ok'})

            # Check if Origin is in allowlist
            allowed_origins_str: str = os.getenv('ALLOWED_ORIGINS', '')
            allowed_origins: list[str] = [
                origin.strip() for origin in allowed_origins_str.split(',') if origin.strip()
            ] if allowed_origins_str else []

            origin: str | None = request.headers.get('Origin')
            if origin and allowed_origins and origin in allowed_origins:
                response.headers['Access-Control-Allow-Origin'] = origin

            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
            return response

        return f(*args, **kwargs)
    return decorated_function
