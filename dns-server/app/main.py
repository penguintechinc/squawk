"""
DNS Server Main Application
Quart async application for DNS query handling with HTTP/3 (QUIC) support.
"""
import asyncio
import hashlib
import logging
import time
from quart import Quart, request, jsonify
from typing import Optional

from app.config import (
    DNS_PORT, SYNC_INTERVAL, HEARTBEAT_INTERVAL, LOG_LEVEL, JWT_PUBLIC_KEY,
    SQUAWK_RATE_LIMIT_ENABLED, SQUAWK_RATE_LIMIT_RPS, SQUAWK_RATE_LIMIT_BURST,
    SQUAWK_RATE_LIMIT_BACKEND
)
from app.services.manager_client import ManagerClient
from app.services.dns_resolver import DNSResolver
from app.services.cache_manager import CacheManager
from app.services.ioc_checker import IOCChecker
from app.services.selective_router import SelectiveRouter
from app.utils.resilience import ResilienceManager
from app.services.prometheus_metrics import init_prometheus_metrics
from app.services.http3_serving import build_serving_config
from app.utils.domain_policy import matches_policy
from app.utils.jwt_verify import verify_squawk_jwt
from app.utils.log_sanitize import sanitize_for_log
from app.services.rate_limiter import RateLimiter

# Fixed allowlist of DNS record types accepted as a Prometheus metric label.
# Anything outside this set is reported as "OTHER" to bound label cardinality
# (an unvalidated, attacker-controlled `type=` query param would otherwise let
# a caller create unbounded time series and exhaust Prometheus memory).
VALID_DNS_RECORD_TYPES = frozenset({
    'A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'PTR', 'CAA',
    'DS', 'DNSKEY', 'NAPTR', 'TLSA', 'SSHFP', 'CERT', 'HTTPS', 'SVCB', 'ANY',
})


def _metric_record_type(record_type: Optional[str]) -> str:
    """Map a record type to a bounded label value (allowlist or 'OTHER')."""
    if not record_type:
        return 'A'
    upper = record_type.strip().upper()
    return upper if upper in VALID_DNS_RECORD_TYPES else 'OTHER'


def _metrics_source(token: Optional[str], token_identity: Optional[str] = None) -> str:
    """Derive a safe, non-identifying source label for metrics.

    Never expose the raw bearer token as a Prometheus label value: use the
    verified JWT subject when available, otherwise a short SHA-256 hash of
    the token, otherwise 'anonymous'.
    """
    if token_identity:
        return token_identity
    if token:
        return hashlib.sha256(token.encode()).hexdigest()[:8]
    return 'anonymous'


def _extract_bearer_token() -> str:
    """Extract the raw bearer token (if any) from the Authorization header."""
    return request.headers.get('Authorization', '').replace('Bearer ', '')


def _require_valid_token() -> Optional[dict]:
    """Verify the request's bearer token; return its payload or None.

    Used to gate /metrics and /status, which otherwise expose internal
    state (and previously, raw token values via metric labels) to anyone
    who can reach the endpoint. A valid Squawk JWT (e.g. a scrape token
    issued for Prometheus) is required, same verification as /dns/query.
    """
    token = _extract_bearer_token()
    if not token:
        return None
    return verify_squawk_jwt(token, JWT_PUBLIC_KEY)


# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
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

# Initialize rate limiter with optional Valkey backend
use_valkey_backend = (
    SQUAWK_RATE_LIMIT_BACKEND.lower() == 'valkey' and cache_manager.redis
)
rate_limiter = RateLimiter(
    enabled=SQUAWK_RATE_LIMIT_ENABLED,
    rps=SQUAWK_RATE_LIMIT_RPS,
    burst=SQUAWK_RATE_LIMIT_BURST,
    redis_client=cache_manager.redis if use_valkey_backend else None,
    use_valkey=use_valkey_backend
)

# Create Quart app
app = Quart(__name__)

# Initialize OpenTelemetry tracing (opt-in via OTEL_EXPORTER_OTLP_ENDPOINT)
from app.observability import init_tracing
init_tracing(app)


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
@app.route('/dns-query', methods=['GET'])
async def dns_query():
    """
    DNS query endpoint (DNS-over-HTTPS compatible).

    Registered at both /dns/query (native) and /dns-query (RFC 8484 DoH
    convention used by most DoH clients) so RFC-compliant clients don't 404.

    Query parameters:
        name: Domain name
        type: Record type (A, AAAA, CNAME, MX, TXT, etc.)

    Headers:
        Authorization: Bearer <token> (optional)
    """
    domain = request.args.get('name')
    record_type = request.args.get('type', 'A')
    metric_record_type = _metric_record_type(record_type)
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    client_ip = request.remote_addr

    if not domain:
        return jsonify({'Status': 2, 'error': 'Missing domain name'}), 400

    # Verify JWT and extract identity for rate limiting (if token provided)
    token_identity = None
    if token:
        payload = verify_squawk_jwt(token, JWT_PUBLIC_KEY)
        if payload:
            token_identity = payload.get('sub')  # Use subject (user ID) as identity

    # Determine identity type for metrics
    identity_type = 'token' if token_identity else 'ip'

    # Check rate limit (identity priority: token > client IP)
    allowed, retry_after = await rate_limiter.check_limit(
        token_identity=token_identity,
        client_ip=client_ip
    )

    if not allowed:
        metrics_reporter.record_rate_limited_query(
            domain=domain,
            record_type=metric_record_type,
            identity_type=identity_type,
            source=_metrics_source(token, token_identity)
        )
        return (
            jsonify({'Status': 2, 'error': 'Rate limit exceeded'}),
            429,
            {'Retry-After': str(int(retry_after) + 1)}  # Round up to next second
        )

    # Check operational mode
    mode = resilience_manager.check_mode()

    # Check if we should serve this domain based on mode and permissions
    zone_name = _find_zone_name(domain)
    if not resilience_manager.should_serve_zone(zone_name, token):
        logger.info(
            f"Access denied to {sanitize_for_log(domain)} "
            f"(mode: {mode}, token: {'yes' if token else 'no'})"
        )
        metrics_reporter.record_query(
            domain=domain,
            record_type=metric_record_type,
            status='error',
            response_time=0.0,
            cache_hit=False,
            source=_metrics_source(token, token_identity),
            identity_type=identity_type
        )
        return jsonify({'Status': 3, 'Question': [{'name': domain, 'type': record_type}], 'Answer': []}), 200

    # Check DNS domain policy (per-identity allowlist)
    if token:
        payload = verify_squawk_jwt(token, JWT_PUBLIC_KEY)
        if payload:
            allowed_domains = payload.get('dns_domains')
            if not matches_policy(domain, allowed_domains):
                logger.info(
                    f"Domain policy denial for {sanitize_for_log(domain)}: "
                    f"dns_domains={allowed_domains}"
                )
                metrics_reporter.record_policy_denial('policy_denied')
                metrics_reporter.record_query(
                    domain=domain,
                    record_type=metric_record_type,
                    status='policy_denied',
                    response_time=0.0,
                    cache_hit=False,
                    source=_metrics_source(token, token_identity)
                )
                return jsonify({'Status': 3, 'Question': [{'name': domain, 'type': record_type}], 'Answer': []}), 200

    # Check IOC feeds
    if ioc_checker.is_blocked(domain):
        logger.warning(f"Blocked IOC domain: {sanitize_for_log(domain)}")
        metrics_reporter.record_query(
            domain=domain,
            record_type=metric_record_type,
            status='blocked',
            response_time=0.0,
            cache_hit=False,
            blocked=True,
            block_reason='threat_intelligence',
            source=_metrics_source(token, token_identity),
            identity_type=identity_type
        )
        return jsonify({'Status': 3, 'Question': [{'name': domain, 'type': record_type}], 'Answer': []}), 200

    # Check cache
    start_time = time.time()
    cached_result = await cache_manager.get(domain, record_type)

    if cached_result:
        response_time_sec = (time.time() - start_time)
        metrics_reporter.record_query(
            domain=domain,
            record_type=metric_record_type,
            status='success',
            response_time=response_time_sec,
            cache_hit=True,
            source=_metrics_source(token, token_identity),
            identity_type=identity_type
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
            logger.warning(
                f"Blocked IOC resolved IP {sanitize_for_log(answer.get('data'))} "
                f"for {sanitize_for_log(domain)}"
            )
            metrics_reporter.record_query(
                domain=domain,
                record_type=metric_record_type,
                status='blocked',
                response_time=response_time_sec,
                cache_hit=False,
                blocked=True,
                block_reason='threat_intelligence',
                source=_metrics_source(token, token_identity),
                identity_type=identity_type
            )
            return jsonify({'Status': 3, 'Question': [{'name': domain, 'type': record_type}], 'Answer': []}), 200

    # Cache result if successful
    if result.get('Status') == 0:
        await cache_manager.set(domain, record_type, result)

    # Record metrics
    result_status = 'success' if result.get('Status') == 0 else 'error'
    metrics_reporter.record_query(
        domain=domain,
        record_type=metric_record_type,
        status=result_status,
        response_time=response_time_sec,
        cache_hit=False,
        source=_metrics_source(token, token_identity),
        identity_type=identity_type
    )

    return jsonify(result), 200


@app.route('/metrics')
async def metrics():
    """Prometheus-compatible metrics endpoint.

    Requires a valid bearer JWT (same verification as /dns/query) — this
    endpoint exposes per-source query counters and internal state, so it
    must not be reachable anonymously. Prometheus can scrape it by
    configuring a bearer_token in its scrape config with any valid token.
    """
    if not _require_valid_token():
        return jsonify({'error': 'Unauthorized'}), 401
    metrics_output, content_type = metrics_reporter.get_metrics_endpoint()
    return metrics_output, 200, {'Content-Type': content_type}


@app.route('/status')
async def status():
    """Detailed status endpoint (requires a valid bearer JWT, see /metrics)."""
    if not _require_valid_token():
        return jsonify({'error': 'Unauthorized'}), 401
    resilience_status = resilience_manager.get_status()
    metrics_data = metrics_reporter.get_current_stats()
    cache_stats = cache_manager.get_stats()
    ioc_stats = ioc_checker.get_stats()
    routing_stats = selective_router.get_stats()
    rate_limit_stats = rate_limiter.get_stats()

    return jsonify({
        'server_id': manager_client.server_id,
        'resilience': resilience_status,
        'metrics': metrics_data,
        'cache': cache_stats,
        'ioc': ioc_stats,
        'routing': routing_stats,
        'rate_limit': rate_limit_stats
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
