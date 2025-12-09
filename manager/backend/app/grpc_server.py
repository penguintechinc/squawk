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

        Args:
            request: RefreshTokenRequest with server_id
            context: gRPC context

        Returns:
            RefreshTokenResponse with new JWT
        """
        with self.app.app_context():
            try:
                server_id = int(request.server_id)
                db = self.app.db
                server = db.dns_server[server_id]

                if not server:
                    context.abort(grpc.StatusCode.NOT_FOUND, "Server not found")

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


def serve_grpc(app, port=50051):
    """
    Start Manager gRPC server.

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
        ]
    )

    manager_service_pb2_grpc.add_ManagerServiceServicer_to_server(
        ManagerServicer(app),
        server
    )

    server.add_insecure_port(f'[::]:{port}')
    server.start()
    logger.info(f"Manager gRPC server started on port {port}")

    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        logger.info("Shutting down gRPC server...")
        server.stop(0)


if __name__ == '__main__':
    from app import create_app

    app = create_app()
    serve_grpc(app)
