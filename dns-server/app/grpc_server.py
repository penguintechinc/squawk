"""
gRPC DNS Query Server
Provides DNS query service over gRPC/HTTP2.
"""
import grpc
import asyncio
import time
import logging
from concurrent import futures
from typing import AsyncIterator

# Import generated protobuf files (will be generated from .proto)
# These would be generated with: python -m grpc_tools.protoc
# For now, we'll create a placeholder implementation

logger = logging.getLogger(__name__)


class DNSQueryServicer:
    """gRPC servicer for DNS queries."""

    def __init__(self, resolver, cache_manager, ioc_checker, selective_router, manager_client, metrics_reporter):
        self.resolver = resolver
        self.cache = cache_manager
        self.ioc_checker = ioc_checker
        self.selective_router = selective_router
        self.manager_client = manager_client
        self.metrics = metrics_reporter
        self.server_id = manager_client.server_id

    async def Query(self, request, context):
        """
        Handle single DNS query.

        Args:
            request: QueryRequest with name, type, token
            context: gRPC context

        Returns:
            QueryResponse
        """
        domain = request.name
        record_type = request.type
        token = request.token

        start_time = time.time()

        # Validate token if provided
        if token:
            # Check zone permissions
            zone_name = self._find_zone_name(domain)
            if zone_name:
                if not self.selective_router.check_zone_permission(domain, token):
                    context.abort(grpc.StatusCode.PERMISSION_DENIED, "Access denied to zone")

        # Check IOC
        if self.ioc_checker.is_blocked(domain):
            self.metrics.record_ioc_block()
            return self._build_blocked_response(domain, record_type)

        # Check cache
        cached = await self.cache.get(domain, record_type)
        if cached:
            self.metrics.record_cache_hit()
            response_time = (time.time() - start_time) * 1000
            return self._build_grpc_response(cached, response_time, from_cache=True)

        self.metrics.record_cache_miss()

        # Check custom zones
        zone_records = self.selective_router.get_zone_records(domain)
        if zone_records:
            result = self.resolver.resolve_custom_zone(domain, record_type, zone_records)
        else:
            # Use public DNS
            result = await self.resolver.resolve(domain, record_type)

        response_time = (time.time() - start_time) * 1000

        # Cache result
        if result.get('Status') == 0:
            await self.cache.set(domain, record_type, result)

        # Record metrics
        self.metrics.record_query(domain, record_type, 'normal')
        self.metrics.record_response_time(response_time)

        return self._build_grpc_response(result, response_time, from_cache=False)

    async def BatchQuery(self, request, context):
        """
        Handle batch DNS queries.

        Args:
            request: BatchQueryRequest with list of queries
            context: gRPC context

        Returns:
            BatchQueryResponse
        """
        start_time = time.time()
        responses = []

        # Process queries concurrently
        tasks = [
            self.Query(query, context)
            for query in request.queries
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        successful = 0
        failed = 0

        for result in results:
            if isinstance(result, Exception):
                # Create error response
                failed += 1
                # Append a SERVFAIL response
                responses.append(self._build_error_response())
            else:
                responses.append(result)
                if result.status == 0:
                    successful += 1
                else:
                    failed += 1

        total_time = (time.time() - start_time) * 1000

        return {
            'responses': responses,
            'metadata': {
                'total_queries': len(request.queries),
                'successful': successful,
                'failed': failed,
                'total_time_ms': total_time
            }
        }

    async def StreamQuery(self, request_iterator: AsyncIterator, context) -> AsyncIterator:
        """
        Handle streaming DNS queries.

        Args:
            request_iterator: Stream of QueryRequest
            context: gRPC context

        Yields:
            QueryResponse for each query
        """
        async for query_request in request_iterator:
            try:
                response = await self.Query(query_request, context)
                yield response
            except Exception as e:
                logger.error(f"Stream query error: {e}")
                yield self._build_error_response()

    def HealthCheck(self, request, context):
        """
        Health check endpoint.

        Returns:
            HealthCheckResponse with SERVING status
        """
        return {
            'status': 1  # SERVING
        }

    def _build_grpc_response(self, dns_result: dict, response_time: float, from_cache: bool):
        """Build gRPC QueryResponse from DNS result."""
        answers = []

        for answer in dns_result.get('Answer', []):
            answers.append({
                'name': answer['name'],
                'type': answer['type'],
                'ttl': answer.get('TTL', 300),
                'data': answer['data']
            })

        return {
            'status': dns_result.get('Status', 2),
            'answers': answers,
            'authority': [],
            'additional': [],
            'metadata': {
                'timestamp': int(time.time()),
                'response_time_ms': response_time,
                'from_cache': from_cache,
                'ioc_blocked': False,
                'server_id': self.server_id or 'unknown'
            }
        }

    def _build_blocked_response(self, domain: str, record_type: str):
        """Build response for IOC-blocked domain."""
        return {
            'status': 3,  # NXDOMAIN
            'answers': [],
            'authority': [],
            'additional': [],
            'metadata': {
                'timestamp': int(time.time()),
                'response_time_ms': 0,
                'from_cache': False,
                'ioc_blocked': True,
                'server_id': self.server_id or 'unknown'
            }
        }

    def _build_error_response(self):
        """Build error response."""
        return {
            'status': 2,  # SERVFAIL
            'answers': [],
            'authority': [],
            'additional': [],
            'metadata': {
                'timestamp': int(time.time()),
                'response_time_ms': 0,
                'from_cache': False,
                'ioc_blocked': False,
                'server_id': self.server_id or 'unknown'
            }
        }

    def _find_zone_name(self, domain: str):
        """Find zone name for domain."""
        config = self.manager_client.config_cache
        zones = config.get('zones', [])

        for zone in zones:
            zone_name = zone.get('name')
            if domain == zone_name or domain.endswith(f'.{zone_name}'):
                return zone_name

        return None


async def serve_grpc(port=50052, resolver=None, cache_manager=None, ioc_checker=None,
                     selective_router=None, manager_client=None, metrics_reporter=None):
    """
    Start DNS Server gRPC server.

    Args:
        port: gRPC port
        resolver: DNSResolver instance
        cache_manager: CacheManager instance
        ioc_checker: IOCChecker instance
        selective_router: SelectiveRouter instance
        manager_client: ManagerClient instance
        metrics_reporter: MetricsReporter instance
    """
    server = grpc.aio.server(
        futures.ThreadPoolExecutor(max_workers=50),
        options=[
            ('grpc.max_send_message_length', 10 * 1024 * 1024),
            ('grpc.max_receive_message_length', 10 * 1024 * 1024),
            ('grpc.so_reuseport', 1),
            ('grpc.use_local_subchannel_pool', 1),
        ]
    )

    # Create servicer
    servicer = DNSQueryServicer(
        resolver, cache_manager, ioc_checker,
        selective_router, manager_client, metrics_reporter
    )

    # Note: In production, you would add the servicer to the server here
    # using generated protobuf code:
    # dns_query_service_pb2_grpc.add_DNSQueryServiceServicer_to_server(servicer, server)

    server.add_insecure_port(f'[::]:{port}')
    await server.start()
    logger.info(f"DNS Server gRPC server started on port {port}")
    await server.wait_for_termination()
