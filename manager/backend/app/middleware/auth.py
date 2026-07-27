"""
Authentication middleware for JWT token validation.
"""

import logging
from functools import wraps
from flask import request, jsonify, current_app, g
from app.services.auth_service import AuthService

logger = logging.getLogger(__name__)


def token_required(f):
    """
    Decorator to require valid JWT token.
    Extracts user information from token and stores in g.current_user.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                token = auth_header.split(' ')[1]  # Bearer <token>
            except IndexError:
                return jsonify({'error': 'Invalid authorization header format'}), 401

        if not token:
            return jsonify({'error': 'Authentication token required'}), 401

        # Decode and validate token
        payload = AuthService.decode_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401

        # Check token type
        if payload.get('type') not in ['access', 'server']:
            return jsonify({'error': 'Invalid token type'}), 401

        # Store user info in g for access in route
        g.current_user = {
            'user_id': payload.get('user_id'),
            'server_id': payload.get('server_id'),
            'username': payload.get('username'),
            'scope': payload.get('scope', ''),
            'global_role': payload.get('global_role'),
            'team_roles': payload.get('team_roles', {}),
            'token_type': payload.get('type'),
            'tenant': payload.get('tenant'),  # For audit trail tenant scoping
        }

        return f(*args, **kwargs)

    return decorated


def _authenticate_server_via_spiffe():
    """Authenticate a DNS server by its mesh-forwarded SPIFFE identity.

    Preferred over the legacy static-secret JWT. Returns the server row on a
    valid SPIFFE identity in the configured trust domain, else None (caller
    falls back to the JWT path).
    """
    if not current_app.config.get('SPIFFE_ENABLED', False):
        return None

    from app.services.spiffe import resolve_dns_server_identity

    header_name = current_app.config.get('SPIFFE_XFCC_HEADER', 'X-Forwarded-Client-Cert')
    trust_domain = current_app.config.get('SPIFFE_TRUST_DOMAIN', 'penguintech.io')
    identity = resolve_dns_server_identity(request.headers.get(header_name), trust_domain)
    if not identity:
        return None

    server = current_app.db.dns_server[identity.server_id]
    if not server:
        logger.warning("SPIFFE identity %s references unknown server", identity.spiffe_id)
        return None

    logger.info("Server authenticated via SPIFFE: %s", identity.spiffe_id)
    return server


def server_token_required(f):
    """
    Decorator to require an authenticated DNS server.

    Prefers SPIFFE/mTLS identity (mesh-forwarded XFCC); falls back to the
    legacy per-server JWT (static shared secret) when no SPIFFE identity is
    presented.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # Preferred: SPIFFE/mTLS peer identity.
        spiffe_server = _authenticate_server_via_spiffe()
        if spiffe_server is not None:
            g.current_server = {
                'server_id': spiffe_server.id,
                'name': spiffe_server.name,
                'region': spiffe_server.region,
                'auth_method': 'spiffe',
            }
            return f(*args, **kwargs)

        token = None

        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                token = auth_header.split(' ')[1]
            except IndexError:
                return jsonify({'error': 'Invalid authorization header format'}), 401

        if not token:
            return jsonify({'error': 'Server authentication token required'}), 401

        # Decode token without verification first to get server_id
        try:
            import jwt
            unverified = jwt.decode(token, options={"verify_signature": False})
            server_id = unverified.get('server_id')
            token_type = unverified.get('type')

            if not server_id or token_type != 'server':
                return jsonify({'error': 'Invalid server token'}), 401

            # Get server's JWT secret
            db = current_app.db
            server = db.dns_server[server_id]
            if not server:
                return jsonify({'error': 'Server not found'}), 401

            # Validate with server-specific secret
            payload = AuthService.decode_token(token, server.jwt_secret)
            if not payload:
                return jsonify({'error': 'Invalid or expired server token'}), 401

            # Store server info in g
            logger.info(
                "Server %s authenticated via legacy static-secret JWT "
                "(SPIFFE/mTLS preferred)", server_id
            )
            g.current_server = {
                'server_id': server_id,
                'name': server.name,
                'region': server.region,
                'auth_method': 'jwt',
            }

            return f(*args, **kwargs)

        except Exception as e:
            # Log the detail; never echo internal exception text to clients.
            logger.warning("Server token validation failed: %s", e)
            return jsonify({'error': 'Token validation failed'}), 401

    return decorated


def optional_token(f):
    """
    Decorator that allows optional token authentication.
    If token is present, validates it and sets g.current_user.
    If token is absent, continues without authentication.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                token = auth_header.split(' ')[1]
            except IndexError:
                pass

        if token:
            # Validate token if present
            payload = AuthService.decode_token(token)
            if payload:
                g.current_user = {
                    'user_id': payload.get('user_id'),
                    'username': payload.get('username'),
                    'scope': payload.get('scope', ''),
                    'global_role': payload.get('global_role'),
                    'team_roles': payload.get('team_roles', {}),
                    'token_type': payload.get('type')
                }
        else:
            g.current_user = None

        return f(*args, **kwargs)

    return decorated


def get_current_user():
    """Get current user from g context."""
    return getattr(g, 'current_user', None)


def get_current_server():
    """Get current server from g context."""
    return getattr(g, 'current_server', None)


def dpop_bound_token(f):
    """
    Decorator to enforce DPoP sender-constraint on tokens with cnf claim.

    Per RFC 9449, if an access token carries a cnf.jkt claim, the client MUST
    present a valid DPoP proof whose JWK thumbprint matches cnf.jkt for each
    request. The proof's htm and htu must match the current request.

    Tokens without cnf claim (bearer tokens) bypass this check — they continue
    to work as before (backward compatible).

    Applied after @token_required, which sets g.current_user.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        from app.services.dpop_service import DPoPService

        user = get_current_user()
        if not user:
            return jsonify({'error': 'Authentication required'}), 401

        # Get the original token payload from auth middleware
        token = None
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                token = auth_header.split(' ')[1]
            except IndexError:
                pass

        if not token:
            return jsonify({'error': 'Token required'}), 401

        payload = AuthService.decode_token(token)
        if not payload:
            return jsonify({'error': 'Invalid token'}), 401

        # Check if token is DPoP-bound (has cnf claim)
        cnf = payload.get('cnf')
        if not cnf or not isinstance(cnf, dict):
            # No DPoP binding; token is bearer, allow through
            return f(*args, **kwargs)

        required_jkt = cnf.get('jkt')
        if not required_jkt:
            # Malformed cnf claim
            return jsonify({'error': 'Invalid token'}), 401

        # Token is DPoP-bound; validate proof on this request
        dpop_header = request.headers.get('DPoP', '').strip()
        if not dpop_header:
            return jsonify({
                'error': 'invalid_token',
                'error_description': 'DPoP proof required for this token'
            }), 401

        dpop_proof = DPoPService.validate_proof(
            dpop_header,
            http_method=request.method,
            http_uri=request.base_url + (f'?{request.query_string.decode()}' if request.query_string else '')
        )
        if not dpop_proof:
            return jsonify({
                'error': 'invalid_token',
                'error_description': 'Invalid or expired DPoP proof'
            }), 401

        # Verify jkt matches (binding)
        if dpop_proof.jkt != required_jkt:
            return jsonify({
                'error': 'invalid_token',
                'error_description': 'DPoP proof does not match token binding'
            }), 401

        # All checks passed; continue
        return f(*args, **kwargs)

    return decorated
