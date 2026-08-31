"""
gRPC server for Manager service.
Handles DNS server communication via gRPC/HTTP2.
"""

import grpc
from concurrent import futures
import logging
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.services.auth_service import AuthService
from app.services.join_key_service import JoinKeyService
from app.services.config_service import ConfigService

logger = logging.getLogger(__name__)


# Note: gRPC implementation requires protoc compilation first
# Run: python -m grpc_tools.protoc -I./app/protos --python_out=./app/protos --grpc_python_out=./app/protos app/protos/manager_service.proto

try:
    from app.protos import manager_service_pb2, manager_service_pb2_grpc
except ImportError:
    logger.warning("gRPC proto files not compiled. Run: python -m grpc_tools.protoc -I./app/protos --python_out=./app/protos --grpc_python_out=./app/protos app/protos/manager_service.proto")
    manager_service_pb2 = None
    manager_service_pb2_grpc = None


# RPCs that authenticate the caller by means OTHER than an existing server
# JWT (they run before a server has one, or are proving they should get a
# fresh one). Every other RPC on this service requires a valid, current
# server JWT in call metadata -- default-deny, not an allowlist of the
# "sensitive" ones, so nothing new added to the service is accidentally
# left unauthenticated.
_INTERCEPTOR_EXEMPT_METHODS = frozenset({
    '/squawkdns.manager.ManagerService/RegisterServer',
    '/squawkdns.manager.ManagerService/RefreshToken',
})


def _extract_bearer_token(metadata) -> str:
    """Pull a bearer token out of gRPC call metadata.

    Accepts either a standard `authorization: Bearer <token>` entry or a
    bare `server-jwt: <token>` entry (for clients that can't set
    `authorization` easily). Returns '' if neither is present.
    """
    md = dict(metadata or ())
    auth_header = md.get('authorization', '') or ''
    if auth_header.lower().startswith('bearer '):
        return auth_header[7:].strip()
    return (md.get('server-jwt', '') or '').strip()


class ServerAuthInterceptor(grpc.ServerInterceptor):
    """Requires a valid, current per-server JWT (via call metadata) for
    every RPC except RegisterServer and RefreshToken.

    Before this interceptor existed, GetConfig/SendHeartbeat/ValidateToken
    (and anything else added to the service) were reachable by *any* caller
    with no authentication at all -- gRPC does not enforce auth by default,
    unlike the REST blueprints which go through `server_token_required`.
    """

    def __init__(self, app):
        """Store the Flask app so handlers can reach `app.db` for lookups."""
        self._app = app

    def intercept_service(self, continuation, handler_call_details):
        """Pass exempt methods straight through; otherwise verify the
        caller's server JWT before invoking the real handler, replacing it
        with an UNAUTHENTICATED-aborting stand-in on failure."""
        handler = continuation(handler_call_details)
        if handler is None or handler_call_details.method in _INTERCEPTOR_EXEMPT_METHODS:
            return handler

        token = _extract_bearer_token(handler_call_details.invocation_metadata)
        server_id = None
        if token:
            with self._app.app_context():
                server_id = AuthService.verify_server_jwt_from_db(self._app.db, token)

        if server_id is not None:
            return handler

        logger.warning(
            "Rejected unauthenticated gRPC call to %s (no valid server JWT in metadata)",
            handler_call_details.method,
        )

        def _deny(ignored_request, context):
            context.abort(
                grpc.StatusCode.UNAUTHENTICATED,
                "Valid server JWT required in 'authorization' metadata",
            )

        # Match the real handler's streaming cardinality -- this service
        # mixes unary-unary, unary-stream, and stream-stream RPCs, and
        # grpc.*_rpc_method_handler factories are cardinality-specific.
        if handler.request_streaming and handler.response_streaming:
            return grpc.stream_stream_rpc_method_handler(_deny)
        if handler.request_streaming:
            return grpc.stream_unary_rpc_method_handler(_deny)
        if handler.response_streaming:
            return grpc.unary_stream_rpc_method_handler(_deny)
        return grpc.unary_unary_rpc_method_handler(_deny)


class ManagerServicer:
    """gRPC servicer for Manager service."""

    def __init__(self, app):
        """
        Initialize servicer with Flask app context.

        Args:
            app: Flask application instance
        """
        self.app = app

    def RegisterServer(self, request, context):
        """
        Register DNS server with join key.

        Args:
            request: RegisterRequest with join_key, hostname, version
            context: gRPC context

        Returns:
            RegisterResponse with JWT and server config
        """
        with self.app.app_context():
            # Register server
            server_info = JoinKeyService.register_server(
                join_key=request.join_key,
                hostname=request.hostname,
                version=request.version
            )

            if not server_info:
                context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid join key")
                return

            # Generate server JWT
            jwt_token = AuthService.create_server_jwt(
                server_id=server_info['id'],
                jwt_secret=server_info['jwt_secret']
            )

            # Get initial configuration
            config = ConfigService.get_server_config(server_info['id'])

            # Build response
            response = manager_service_pb2.RegisterResponse(
                jwt=jwt_token,
                server_id=str(server_info['id']),
                config=self._build_config_message(config)
            )

            return response

    def RefreshToken(self, request, context):
        """
        Refresh DNS server JWT token.

        Requires the caller to prove it already controls this exact
        server_id before a new JWT is minted -- either:
          (a) a current/near-expiry server JWT for this server_id, or
          (b) this server's join key.
        Without this check, any caller who could guess/enumerate a
        server_id could mint a fresh, fully-valid JWT for it with zero
        proof of identity.

        Args:
            request: RefreshTokenRequest with server_id, jwt, join_key
            context: gRPC context

        Returns:
            RefreshTokenResponse with new JWT
        """
        with self.app.app_context():
            try:
                server_id = int(request.server_id)
            except (TypeError, ValueError):
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid server_id")
                return

            db = self.app.db
            server = db.dns_server[server_id]

            if not server:
                context.abort(grpc.StatusCode.NOT_FOUND, "Server not found")
                return

            authenticated = False

            presented_jwt = (request.jwt or '').strip()
            if presented_jwt:
                claims = AuthService.decode_server_jwt_with_grace(
                    presented_jwt, server.jwt_secret
                )
                if claims is not None and claims.get('server_id') == server_id:
                    authenticated = True

            if not authenticated:
                join_key = (getattr(request, 'join_key', '') or '').strip()
                if join_key:
                    key_info = JoinKeyService.validate_join_key(join_key)
                    if key_info and key_info['id'] == server_id:
                        authenticated = True

            if not authenticated:
                logger.warning(
                    "RefreshToken rejected for server_id=%s: no valid server "
                    "JWT or join_key presented", server_id
                )
                context.abort(
                    grpc.StatusCode.UNAUTHENTICATED,
                    "RefreshToken requires a valid current server JWT or "
                    "join_key for this server",
                )
                return

            try:
                # Generate new JWT
                new_jwt = AuthService.create_server_jwt(
                    server_id=server.id,
                    jwt_secret=server.jwt_secret
                )

                return manager_service_pb2.RefreshTokenResponse(jwt=new_jwt)

            except Exception as e:
                logger.error(f"Token refresh error: {e}")
                context.abort(grpc.StatusCode.INTERNAL, str(e))

    def GetConfig(self, request, context):
        """
        Get DNS server configuration.

        Args:
            request: ConfigRequest with server_id
            context: gRPC context

        Returns:
            ConfigResponse with server configuration
        """
        with self.app.app_context():
            try:
                server_id = int(request.server_id)
                config = ConfigService.get_server_config(server_id)

                response = manager_service_pb2.ConfigResponse(
                    config=self._build_config_message(config),
                    version=config.get('version', 0)
                )

                return response

            except Exception as e:
                logger.error(f"Config retrieval error: {e}")
                context.abort(grpc.StatusCode.INTERNAL, str(e))

    def SendHeartbeat(self, request, context):
        """
        Receive heartbeat from DNS server.

        Args:
            request: HeartbeatRequest with server_id and metrics
            context: gRPC context

        Returns:
            HeartbeatResponse with config version and sync flag
        """
        with self.app.app_context():
            try:
                server_id = int(request.server_id)

                # Extract metrics
                metrics = {
                    'queries_total': request.metrics.queries_total,
                    'cache_hits': request.metrics.cache_hits,
                    'errors': request.metrics.errors,
                    'avg_response_ms': request.metrics.avg_response_ms
                }

                # Record heartbeat
                response_data = ConfigService.record_heartbeat(server_id, metrics)

                return manager_service_pb2.HeartbeatResponse(
                    config_version=response_data['config_version'],
                    should_sync=response_data['should_sync']
                )

            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
                context.abort(grpc.StatusCode.INTERNAL, str(e))

    def ValidateToken(self, request, context):
        """
        Fast token validation for DNS queries.

        Args:
            request: ValidateTokenRequest with token and domain
            context: gRPC context

        Returns:
            ValidateTokenResponse with validation result
        """
        with self.app.app_context():
            try:
                result = AuthService.validate_dns_token(
                    token=request.token,
                    domain=request.domain
                )

                return manager_service_pb2.ValidateTokenResponse(
                    valid=result['valid'],
                    user_id=str(result.get('token_id', '')),
                    teams=[str(t) for t in result.get('team_id', [])],
                    allowed_zones=result.get('allowed_zones', [])
                )

            except Exception as e:
                logger.error(f"Token validation error: {e}")
                return manager_service_pb2.ValidateTokenResponse(valid=False)

    def CheckIOC(self, request, context):
        """
        Check if domain/IP is in IOC feeds.

        Args:
            request: IOCCheckRequest with domain or IP
            context: gRPC context

        Returns:
            IOCCheckResponse with blocked status
        """
        with self.app.app_context():
            # Simplified implementation - would integrate with IOC manager
            # For now, return not blocked
            return manager_service_pb2.IOCCheckResponse(
                blocked=False,
                reason="",
                feed_source=""
            )

    def _build_config_message(self, config):
        """
        Build ServerConfig protobuf message from config dict.

        Args:
            config: Configuration dictionary

        Returns:
            ServerConfig protobuf message
        """
        # Build zones
        zones = []
        for zone_data in config.get('zones', []):
            records = []
            for record_data in zone_data.get('records', []):
                records.append(manager_service_pb2.DNSRecord(
                    name=record_data['name'],
                    type=record_data['type'],
                    value=record_data['value'],
                    ttl=record_data['ttl']
                ))

            zones.append(manager_service_pb2.DNSZone(
                id=str(zone_data['id']),
                name=zone_data['name'],
                visibility=zone_data['visibility'],
                records=records,
                allowed_teams=[str(t) for t in zone_data.get('allowed_teams', [])]
            ))

        # Build IOC feeds
        ioc_feeds = []
        for feed_data in config.get('ioc_feeds', []):
            ioc_feeds.append(manager_service_pb2.IOCFeed(
                id=str(feed_data['id']),
                name=feed_data['name'],
                feed_type=feed_data['feed_type'],
                entries=[]  # Would populate from database
            ))

        # Build cache settings
        cache_settings_data = config.get('cache_settings', {})
        cache_settings = manager_service_pb2.CacheSettings(
            ttl=cache_settings_data.get('ttl', 300),
            enabled=cache_settings_data.get('enabled', True)
        )

        # Build config message
        return manager_service_pb2.ServerConfig(
            zones=zones,
            ioc_feeds=ioc_feeds,
            cache_settings=cache_settings,
            settings=config.get('settings', {})
        )


def _build_server_credentials():
    """Load TLS server credentials for the gRPC listener from env-configured
    cert/key files.

    Returns:
        `grpc.ServerCredentials` if GRPC_TLS_CERT_FILE/GRPC_TLS_KEY_FILE are
        both configured and readable, else None (caller decides whether an
        insecure dev fallback is acceptable).
    """
    cert_path = os.environ.get('GRPC_TLS_CERT_FILE')
    key_path = os.environ.get('GRPC_TLS_KEY_FILE')
    if not cert_path or not key_path:
        return None

    with open(key_path, 'rb') as f:
        private_key = f.read()
    with open(cert_path, 'rb') as f:
        cert_chain = f.read()

    # Optional client-cert (mTLS) verification for defense-in-depth on top
    # of the per-call server-JWT interceptor.
    ca_path = os.environ.get('GRPC_TLS_CA_FILE')
    root_certs = None
    require_client_auth = False
    if ca_path:
        with open(ca_path, 'rb') as f:
            root_certs = f.read()
        require_client_auth = True

    return grpc.ssl_server_credentials(
        [(private_key, cert_chain)],
        root_certificates=root_certs,
        require_client_auth=require_client_auth,
    )


def serve_grpc(app, port=50051):
    """
    Start Manager gRPC server.

    Binds with TLS by default (server credentials loaded from
    GRPC_TLS_CERT_FILE/GRPC_TLS_KEY_FILE). An insecure listener is only
    permitted when SQUAWK_GRPC_INSECURE=true is explicitly set (local dev
    only) -- otherwise this refuses to start rather than silently serving
    plaintext gRPC.

    Args:
        app: Flask application instance
        port: gRPC server port (default: 50051)
    """
    if not manager_service_pb2_grpc:
        logger.error("gRPC proto files not compiled. Cannot start gRPC server.")
        return

    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=10),
        options=[
            ('grpc.max_send_message_length', 50 * 1024 * 1024),
            ('grpc.max_receive_message_length', 50 * 1024 * 1024),
        ],
        interceptors=[ServerAuthInterceptor(app)],
    )

    manager_service_pb2_grpc.add_ManagerServiceServicer_to_server(
        ManagerServicer(app),
        server
    )

    credentials = _build_server_credentials()
    insecure_dev = os.environ.get('SQUAWK_GRPC_INSECURE', 'false').lower() == 'true'

    if credentials is not None:
        server.add_secure_port(f'[::]:{port}', credentials)
        logger.info(f"Manager gRPC server started on port {port} (TLS)")
    elif insecure_dev:
        logger.warning(
            "SQUAWK_GRPC_INSECURE=true: gRPC server listening WITHOUT TLS "
            "on port %s. This must NEVER be set in production.", port
        )
        server.add_insecure_port(f'[::]:{port}')
    else:
        raise RuntimeError(
            "gRPC TLS credentials not configured (set GRPC_TLS_CERT_FILE "
            "and GRPC_TLS_KEY_FILE) and SQUAWK_GRPC_INSECURE is not 'true'. "
            "Refusing to start an unencrypted, unauthenticated-transport "
            "gRPC listener."
        )

    server.start()

    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        logger.info("Shutting down gRPC server...")
        server.stop(0)


if __name__ == '__main__':
    from app import create_app

    app = create_app()
    serve_grpc(app)
