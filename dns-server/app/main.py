"""
DNS Server Main Application
Quart async application for DNS query handling with HTTP/3 (QUIC) support.
"""
import asyncio
import logging
import time
from quart import Quart, request, jsonify
from typing import Optional

from app.config import DNS_PORT, SYNC_INTERVAL, HEARTBEAT_INTERVAL, LOG_LEVEL
from app.services.manager_client import ManagerClient
from app.services.dns_resolver import DNSResolver
from app.services.cache_manager import CacheManager
from app.services.ioc_checker import IOCChecker
from app.services.selective_router import SelectiveRouter
from app.utils.resilience import ResilienceManager
from app.services.prometheus_metrics import PrometheusMetrics, init_prometheus_metrics
from app.services.http3_serving import build_serving_config

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize services
manager_client = ManagerClient()
dns_resolver = DNSResolver()
cache_manager = CacheManager()
ioc_checker = IOCChecker()
selective_router = SelectiveRouter()
metrics_reporter = init_prometheus_metrics(db_url=None, enable_collection=False)
resilience_manager = ResilienceManager(manager_client)

# Create Quart app
app = Quart(__name__)


@app.before_serving
async def startup():
    """Initialize DNS server on startup."""
    logger.info("DNS Server starting up...")

    # Try to load cached config
    if manager_client.load_from_cache():
        logger.info("Loaded cached configuration")
        # Load cached zones and IOC feeds
        config = manager_client.config_cache
        if config.get('zones'):
            selective_router.load_zones(config['zones'])
        if config.get('ioc_feeds'):
            ioc_checker.load_feeds(config['ioc_feeds'])

    # Try to register/refresh with Manager
    if not manager_client.is_jwt_valid():
        if manager_client.register():
            logger.info("Successfully registered with Manager")
            # Sync config
            if manager_client.sync_config():
                config = manager_client.config_cache
                if config.get('zones'):
                    selective_router.load_zones(config['zones'])
                if config.get('ioc_feeds'):
                    ioc_checker.load_feeds(config['ioc_feeds'])
        else:
            logger.warning("Failed to register with Manager, will retry")

    # Start background tasks
    app.add_background_task(sync_task)
    app.add_background_task(heartbeat_task)

    logger.info(f"DNS Server started on port {DNS_PORT}")


@app.route('/health')
async def health():
    """Health check endpoint."""
    mode = resilience_manager.check_mode()
    return jsonify({
        'status': 'healthy',
        'mode': mode,
        'registered': manager_client.server_id is not None
    })


@app.route('/dns/query', methods=['GET'])
async def dns_query():
    """
    DNS query endpoint (DNS-over-HTTPS compatible).

    Query parameters:
        name: Domain name
        type: Record type (A, AAAA, CNAME, MX, TXT, etc.)

    Headers:
        Authorization: Bearer <token> (optional)
    """
    domain = request.args.get('name')
    record_type = request.args.get('type', 'A')
    token = request.headers.get('Authorization', '').replace('Bearer ', '')

    if not domain:
        return jsonify({'Status': 2, 'error': 'Missing domain name'}), 400

    # Check operational mode
    mode = resilience_manager.check_mode()

    # Check if we should serve this domain based on mode and permissions
    zone_name = _find_zone_name(domain)
    if not resilience_manager.should_serve_zone(zone_name, token):
        logger.info(f"Access denied to {domain} (mode: {mode}, token: {'yes' if token else 'no'})")
        metrics_reporter.record_query(
            domain=domain,
            record_type=record_type,
            status='error',
            response_time=0.0,
            cache_hit=False,
            source=token or 'unknown'
        )
        return jsonify({'Status': 3, 'Question': [{'name': domain, 'type': record_type}], 'Answer': []}), 200

    # Check IOC feeds
    if ioc_checker.is_blocked(domain):
        logger.warning(f"Blocked IOC domain: {domain}")
        metrics_reporter.record_query(
            domain=domain,
            record_type=record_type,
            status='blocked',
            response_time=0.0,
            cache_hit=False,
            blocked=True,
            block_reason='threat_intelligence',
            source=token or 'unknown'
        )
        return jsonify({'Status': 3, 'Question': [{'name': domain, 'type': record_type}], 'Answer': []}), 200

    # Check cache
    start_time = time.time()
    cached_result = await cache_manager.get(domain, record_type)

    if cached_result:
        response_time_sec = (time.time() - start_time)
        metrics_reporter.record_query(
            domain=domain,
            record_type=record_type,
            status='success',
            response_time=response_time_sec,
            cache_hit=True,
            source=token or 'unknown'
        )
        return jsonify(cached_result), 200

    # Check custom zones first
    zone_records = selective_router.get_zone_records(domain)
    if zone_records:
        result = dns_resolver.resolve_custom_zone(domain, record_type, zone_records)
    else:
        # Use public DNS
        result = await dns_resolver.resolve(domain, record_type)

    response_time_sec = (time.time() - start_time)

    # Block resolved answers whose IP is in an IOC feed (A/AAAA data)
    for answer in result.get('Answer', []):
        if ioc_checker.is_ip_blocked(answer.get('data', '')):
            logger.warning(f"Blocked IOC resolved IP {answer.get('data')} for {domain}")
            metrics_reporter.record_query(
                domain=domain,
                record_type=record_type,
                status='blocked',
                response_time=response_time_sec,
                cache_hit=False,
                blocked=True,
                block_reason='threat_intelligence',
                source=token or 'unknown'
            )
            return jsonify({'Status': 3, 'Question': [{'name': domain, 'type': record_type}], 'Answer': []}), 200

    # Cache result if successful
    if result.get('Status') == 0:
        await cache_manager.set(domain, record_type, result)

    # Record metrics
    result_status = 'success' if result.get('Status') == 0 else 'error'
    metrics_reporter.record_query(
        domain=domain,
        record_type=record_type,
        status=result_status,
        response_time=response_time_sec,
        cache_hit=False,
        source=token or 'unknown'
    )

    return jsonify(result), 200


@app.route('/metrics')
async def metrics():
    """Prometheus-compatible metrics endpoint."""
    metrics_output, content_type = metrics_reporter.get_metrics_endpoint()
    return metrics_output, 200, {'Content-Type': content_type}


@app.route('/status')
async def status():
    """Detailed status endpoint."""
    resilience_status = resilience_manager.get_status()
    metrics_data = metrics_reporter.get_current_stats()
    cache_stats = cache_manager.get_stats()
    ioc_stats = ioc_checker.get_stats()
    routing_stats = selective_router.get_stats()

    return jsonify({
        'server_id': manager_client.server_id,
        'resilience': resilience_status,
        'metrics': metrics_data,
        'cache': cache_stats,
        'ioc': ioc_stats,
        'routing': routing_stats
    })


async def sync_task():
    """Background task to sync config from Manager."""
    while True:
        await asyncio.sleep(SYNC_INTERVAL)

        logger.info("Running config sync...")

        if manager_client.sync_config():
            # Reload zones and IOC feeds
            config = manager_client.config_cache

            if config.get('zones'):
                selective_router.load_zones(config['zones'])
                logger.info(f"Reloaded {len(config['zones'])} zones")

            if config.get('ioc_feeds'):
                ioc_checker.load_feeds(config['ioc_feeds'])
                logger.info("Reloaded IOC feeds")


async def heartbeat_task():
    """Background task to send heartbeat to Manager."""
    while True:
        await asyncio.sleep(HEARTBEAT_INTERVAL)

        metrics = metrics_reporter.get_current_stats()
        manager_client.heartbeat(metrics)


def _find_zone_name(domain: str) -> Optional[str]:
    """Find the zone name for a domain."""
    # Check if domain matches any configured zone
    config = manager_client.config_cache
    zones = config.get('zones', [])

    for zone in zones:
        zone_name = zone.get('name')
        if domain == zone_name or domain.endswith(f'.{zone_name}'):
            return zone_name

    return None


if __name__ == '__main__':
    # Use hypercorn for ASGI serving with optional HTTP/3 (QUIC) support
    from hypercorn.asyncio import serve

    # Build hypercorn config with HTTP/3 support if enabled
    config = build_serving_config(app_config=None)

    # Serve the Quart app
    asyncio.run(serve(app, config))
