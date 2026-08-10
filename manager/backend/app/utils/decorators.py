"""
Utility decorators for Squawk DNS Manager.
"""

from functools import wraps
from flask import jsonify, current_app, request
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


def audit_log(action: str, resource_type: str | None = None):
    """
    Decorator to log actions for durable audit trail.

    Writes audit events to the database and emits structured JSON logs.
    Never emits PII (no username, email, etc.) — only user_id.
    Audit write failures are logged but never fail the request (fail-open).

    Args:
        action: Action name (e.g., 'user_created', 'token_deleted')
        resource_type: Optional resource type (auto-extracted from route kwargs if not provided)

    Example:
        @audit_log('user_created', resource_type='user')
        def create_user(user_id):
            ...

        @audit_log('token_deleted')  # resource_type inferred from context
        def delete_token(token_id):
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            import json
            from datetime import datetime
            from app.middleware.auth import get_current_user

            user = get_current_user()
            actor_id = user.get('user_id') if user else None
            tenant = user.get('tenant') if user else None
            source_ip = request.remote_addr

            # Attempt to infer resource_id from route kwargs
            resource_id = None
            inferred_resource_type = resource_type
            for key_pattern in ['_id', 'id']:
                for key in kwargs:
                    if key.endswith(key_pattern):
                        resource_id = kwargs[key]
                        if not inferred_resource_type:
                            # Extract type from key: 'token_id' -> 'token', 'server_id' -> 'server'
                            inferred_resource_type = key.rsplit('_id' if key.endswith('_id') else 'id', 1)[0]
                        break

            try:
                # Execute the wrapped function
                result = f(*args, **kwargs)

                # Extract outcome from result
                outcome = 'success'
                status_code = 200
                if isinstance(result, tuple) and len(result) >= 2:
                    # Flask route returned (response, status_code)
                    _, status_code = result[0:2]
                    outcome = 'success' if status_code < 400 else 'failure'
                elif isinstance(result, dict):
                    status_code = 200

                # Extract request_id if present in headers or response
                request_id = request.headers.get('X-Request-ID')

            except Exception:
                # Audit the failure, log the error, re-raise
                outcome = 'failure'
                status_code = 500
                request_id = request.headers.get('X-Request-ID')

                # Attempt to write failure audit record
                try:
                    db = current_app.db
                    db.audit_event.insert(
                        action=action,
                        actor_id=actor_id,
                        tenant=tenant,
                        resource_type=inferred_resource_type,
                        resource_id=resource_id,
                        outcome=outcome,
                        status_code=status_code,
                        request_id=request_id,
                        source_ip=source_ip,
                    )
                    db.commit()
                except Exception as audit_err:
                    # Log audit write failure but don't fail the request
                    logger.error(f"Audit write failed for {action}: {audit_err}")

                # Emit structured JSON log (no PII)
                log_entry = {
                    'event_type': 'audit',
                    'action': action,
                    'actor_id': actor_id,
                    'resource_type': inferred_resource_type,
                    'resource_id': resource_id,
                    'outcome': outcome,
                    'status_code': status_code,
                    'request_id': request_id,
                    'source_ip': source_ip,
                    'timestamp': datetime.utcnow().isoformat(),
                }
                logger.error(f"AUDIT_EVENT {json.dumps(log_entry)}")

                raise

            # Write audit event to database
            try:
                db = current_app.db
                db.audit_event.insert(
                    action=action,
                    actor_id=actor_id,
                    tenant=tenant,
                    resource_type=inferred_resource_type,
                    resource_id=resource_id,
                    outcome=outcome,
                    status_code=status_code,
                    request_id=request_id,
                    source_ip=source_ip,
                )
                db.commit()
            except Exception as e:
                # Log audit write failure but don't fail the request
                logger.error(f"Audit write failed for {action}: {e}")

            # Emit structured JSON log (no PII — only user_id, no username/email)
            log_entry = {
                'event_type': 'audit',
                'action': action,
                'actor_id': actor_id,
                'resource_type': inferred_resource_type,
                'resource_id': resource_id,
                'outcome': outcome,
                'status_code': status_code,
                'request_id': request_id,
                'source_ip': source_ip,
                'timestamp': datetime.utcnow().isoformat(),
            }
            logger.info(f"AUDIT_EVENT {json.dumps(log_entry)}")

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
