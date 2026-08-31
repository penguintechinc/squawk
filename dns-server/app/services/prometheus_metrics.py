#!/usr/bin/env python3
"""
Prometheus Metrics Integration for Squawk DNS
Implements Issue #14: DNS Stats for Prometheus and Grafana
"""

import hashlib
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional
from collections import Counter, defaultdict, deque
import threading
from pydal import DAL
from prometheus_client import (
    Counter,
    Histogram,
    Gauge,
    Info,
    generate_latest,
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
)

logger = logging.getLogger(__name__)


class PrometheusMetrics:
    """
    Prometheus metrics collector for Squawk DNS.
    Provides comprehensive DNS statistics for monitoring and alerting.
    """

    # Upper bound on tracked distinct domains, to prevent unbounded memory
    # growth from a caller sending many distinct (or attacker-controlled)
    # domain names — trimmed back to this size once exceeded.
    _MAX_TOP_DOMAINS = 1000

    def __init__(self, db_url: str = None):
        self.db_url = db_url
        self.lock = threading.Lock()

        # Use custom registry to avoid conflicts in tests
        self.registry = CollectorRegistry()

        # Initialize Prometheus metrics
        self._init_metrics()

        # In-memory stats for performance
        self.query_stats = defaultdict(int)
        self.response_times = deque(maxlen=1000)  # Last 1000 queries
        self.top_domains = defaultdict(int)
        self.error_counts = defaultdict(int)

        # Cache for database queries
        self.cache_hit_rate = 0.0
        self.last_stats_update = 0

    def _init_metrics(self):
        """Initialize Prometheus metric objects"""

        # DNS Query Counters
        self.dns_queries_total = Counter(
            "squawk_dns_queries_total",
            "Total number of DNS queries processed",
            ["record_type", "status", "source"],
            registry=self.registry,
        )

        self.dns_cache_hits_total = Counter(
            "squawk_dns_cache_hits_total", "Total number of cache hits", ["record_type"],
            registry=self.registry,
        )

        self.dns_cache_misses_total = Counter(
            "squawk_dns_cache_misses_total",
            "Total number of cache misses",
            ["record_type"],
            registry=self.registry,
        )

        self.dns_blocked_queries_total = Counter(
            "squawk_dns_blocked_queries_total",
            "Total number of blocked queries",
            ["reason"],
            registry=self.registry,
        )

        # Response Time Histograms
        self.dns_query_duration_seconds = Histogram(
            "squawk_dns_query_duration_seconds",
            "DNS query processing time in seconds",
            ["record_type", "cache_status"],
            buckets=[
                0.001,
                0.005,
                0.01,
                0.025,
                0.05,
                0.1,
                0.25,
                0.5,
                1.0,
                2.5,
                5.0,
                10.0,
            ],
            registry=self.registry,
        )

        self.dns_upstream_duration_seconds = Histogram(
            "squawk_dns_upstream_duration_seconds",
            "Upstream DNS resolution time in seconds",
            ["upstream_server"],
            buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
            registry=self.registry,
        )

        # Current State Gauges
        self.dns_active_connections = Gauge(
            "squawk_dns_active_connections", "Number of active client connections",
            registry=self.registry,
        )

        self.dns_cache_entries = Gauge(
            "squawk_dns_cache_entries", "Number of entries in DNS cache",
            registry=self.registry,
        )

        self.dns_cache_hit_rate = Gauge(
            "squawk_dns_cache_hit_rate", "DNS cache hit rate (0-1)",
            registry=self.registry,
        )

        self.dns_ioc_entries = Gauge(
            "squawk_dns_ioc_entries",
            "Number of IOC/threat intelligence entries",
            ["feed_name"],
            registry=self.registry,
        )

        self.dns_server_health = Gauge(
            "squawk_dns_server_health",
            "DNS server health status (1=healthy, 0=unhealthy)",
            registry=self.registry,
        )

        # Top Queried Domains
        self.dns_top_domains = Gauge(
            "squawk_dns_top_domains_queries",
            "Query count for top domains",
            ["domain", "rank"],
            registry=self.registry,
        )

        # User/Token Metrics
        self.dns_user_queries_total = Counter(
            "squawk_dns_user_queries_total",
            "Total queries per user token",
            ["token_hash", "user_type"],
            registry=self.registry,
        )

        self.dns_authentication_failures = Counter(
            "squawk_dns_authentication_failures_total",
            "Total authentication failures",
            ["failure_type"],
            registry=self.registry,
        )

        self.dns_policy_denials = Counter(
            "squawk_dns_policy_denials_total",
            "Total DNS queries denied by domain policy",
            ["outcome"],
            registry=self.registry,
        )

        # System Resource Metrics
        self.dns_memory_usage_bytes = Gauge(
            "squawk_dns_memory_usage_bytes", "Memory usage in bytes",
            registry=self.registry,
        )

        self.dns_open_files = Gauge(
            "squawk_dns_open_files", "Number of open file descriptors",
            registry=self.registry,
        )

        # Server Info
        self.dns_server_info = Info(
            "squawk_dns_server_info", "Static server information",
            registry=self.registry,
        )

        # Set initial server info
        self.dns_server_info.info(
            {
                "version": "2.0",
                "product": "squawk_dns",
                "vendor": "penguin_technologies",
            }
        )

        # Rate limiting metrics
        self.rate_limit_requests_total = Counter(
            "squawk_rate_limit_requests_total",
            "Total requests checked for rate limiting",
            ["result", "identity_type"],
            registry=self.registry,
        )

        self.rate_limit_exceeded_total = Counter(
            "squawk_rate_limit_exceeded_total",
            "Total requests exceeding rate limit",
            ["identity_type"],
            registry=self.registry,
        )

    def record_query(
        self,
        domain: str,
        record_type: str,
        status: str,
        response_time: float,
        cache_hit: bool,
        token_hash: str = None,
        source: str = "client",
        blocked: bool = False,
        block_reason: str = None,
        identity_type: str = None,
    ):
        """Record a DNS query with all relevant metrics"""

        with self.lock:
            try:
                # Track rate limit allowed (identity_type indicates it was checked)
                if identity_type:
                    self.rate_limit_requests_total.labels(
                        result="allowed", identity_type=identity_type
                    ).inc()

                # Defense-in-depth: never let a raw bearer token (or any
                # overly long/JWT-shaped value) reach a metric label,
                # regardless of what a caller passes in. Callers should
                # already pass a verified subject, short hash, or
                # 'anonymous' — this is a safety net, not the primary fix.
                safe_source = self._sanitize_source(source)

                # Basic query counter
                self.dns_queries_total.labels(
                    record_type=record_type, status=status, source=safe_source
                ).inc()

                # Cache metrics
                if cache_hit:
                    self.dns_cache_hits_total.labels(record_type=record_type).inc()
                    cache_status = "hit"
                else:
                    self.dns_cache_misses_total.labels(record_type=record_type).inc()
                    cache_status = "miss"

                # Response time
                self.dns_query_duration_seconds.labels(
                    record_type=record_type, cache_status=cache_status
                ).observe(response_time)

                # Blocked queries
                if blocked:
                    self.dns_blocked_queries_total.labels(
                        reason=block_reason or "unknown"
                    ).inc()

                # User metrics (hash the token for privacy)
                if token_hash:
                    user_type = self._get_user_type_from_token(token_hash)
                    self.dns_user_queries_total.labels(
                        token_hash=token_hash[:8],  # Only first 8 chars for privacy
                        user_type=user_type,
                    ).inc()

                # Update in-memory stats
                self.query_stats[f"{record_type}_{status}"] += 1
                self.response_times.append(response_time)
                self.top_domains[domain] += 1

                # Bound cardinality: an unbounded per-domain counter is a
                # memory-exhaustion vector (every distinct queried domain,
                # including attacker-controlled ones, grows this dict
                # forever). Trim to the most-queried domains once we
                # exceed the cap.
                if len(self.top_domains) > self._MAX_TOP_DOMAINS:
                    trimmed = Counter(self.top_domains).most_common(
                        self._MAX_TOP_DOMAINS
                    )
                    self.top_domains = defaultdict(int, trimmed)

                if status != "success":
                    self.error_counts[status] += 1

            except Exception as e:
                logger.error(f"Failed to record metrics: {e}")

    @staticmethod
    def _sanitize_source(source: str) -> str:
        """Ensure a metric 'source' label value can never be a raw token.

        Hashes any value that is unexpectedly long or JWT-shaped
        (header.payload.signature) instead of using it verbatim.
        """
        if not source:
            return "unknown"
        if len(source) > 64 or source.count(".") >= 2:
            return hashlib.sha256(source.encode()).hexdigest()[:8]
        return source

    def record_authentication_failure(self, failure_type: str):
        """Record authentication failure"""
        self.dns_authentication_failures.labels(failure_type=failure_type).inc()

    def record_policy_denial(self, outcome: str):
        """Record DNS query denied by domain policy.

        Args:
            outcome: Denial reason (e.g., 'policy_denied', 'empty_policy')
        """
        self.dns_policy_denials.labels(outcome=outcome).inc()

    def record_rate_limited_query(
        self,
        domain: str,
        record_type: str,
        identity_type: str = "ip",
        source: str = "unknown"
    ):
        """Record a rate-limited query (identity_type: 'token' or 'ip')"""
        try:
            with self.lock:
                self.rate_limit_requests_total.labels(
                    result="limited", identity_type=identity_type
                ).inc()
                self.rate_limit_exceeded_total.labels(
                    identity_type=identity_type
                ).inc()
        except Exception as e:
            logger.error(f"Failed to record rate limit metrics: {e}")

    def record_upstream_query(self, upstream_server: str, response_time: float):
        """Record upstream DNS query timing"""
        self.dns_upstream_duration_seconds.labels(
            upstream_server=upstream_server
        ).observe(response_time)

    def update_cache_stats(self, total_entries: int, hit_rate: float):
        """Update cache-related metrics"""
        self.dns_cache_entries.set(total_entries)
        self.dns_cache_hit_rate.set(hit_rate)
        self.cache_hit_rate = hit_rate

    def update_ioc_stats(self, ioc_stats: Dict):
        """Update IOC/threat intelligence metrics"""
        try:
            if "feeds" in ioc_stats and "feed_details" in ioc_stats["feeds"]:
                for feed in ioc_stats["feeds"]["feed_details"]:
                    self.dns_ioc_entries.labels(feed_name=feed["name"]).set(
                        feed["indicators"]
                    )
        except Exception as e:
            logger.error(f"Failed to update IOC metrics: {e}")

    def update_server_health(self, is_healthy: bool):
        """Update server health status"""
        self.dns_server_health.set(1.0 if is_healthy else 0.0)

    def update_system_metrics(self):
        """Update system resource metrics"""
        try:
            import psutil
            import os

            # Memory usage
            process = psutil.Process(os.getpid())
            memory_info = process.memory_info()
            self.dns_memory_usage_bytes.set(memory_info.rss)

            # Open files
            try:
                open_files = len(process.open_files())
                self.dns_open_files.set(open_files)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

        except ImportError:
            # psutil not available
            pass
        except Exception as e:
            logger.error(f"Failed to update system metrics: {e}")

    def update_top_domains(self, limit: int = 10):
        """Update top domains metrics"""
        try:
            with self.lock:
                # Get top domains
                sorted_domains = sorted(
                    self.top_domains.items(), key=lambda x: x[1], reverse=True
                )[:limit]

                # Clear existing metrics
                self.dns_top_domains.clear()

                # Set new values
                for rank, (domain, count) in enumerate(sorted_domains, 1):
                    # Sanitize domain name for metric label
                    safe_domain = domain.replace(".", "_").replace("-", "_")[:50]
                    self.dns_top_domains.labels(domain=safe_domain, rank=str(rank)).set(
                        count
                    )

        except Exception as e:
            logger.error(f"Failed to update top domains: {e}")

    def get_current_stats(self) -> Dict:
        """Get current statistics summary"""
        with self.lock:
            total_queries = sum(self.query_stats.values())
            avg_response_time = (
                sum(self.response_times) / len(self.response_times)
                if self.response_times
                else 0
            )

            return {
                "total_queries": total_queries,
                "average_response_time_ms": avg_response_time * 1000,
                "cache_hit_rate": self.cache_hit_rate,
                "error_rate": sum(self.error_counts.values()) / max(total_queries, 1),
                "top_domains": dict(
                    sorted(self.top_domains.items(), key=lambda x: x[1], reverse=True)[
                        :10
                    ]
                ),
            }

    def reset_periodic_stats(self):
        """Reset statistics that should be calculated periodically"""
        with self.lock:
            # Keep running totals but reset rate calculations
            self.response_times.clear()

    def _get_user_type_from_token(self, token_hash: str) -> str:
        """Determine user type from token (simplified)"""
        # This would typically look up in database
        # For now, use simple heuristics
        if "enterprise" in token_hash.lower():
            return "enterprise"
        elif "premium" in token_hash.lower():
            return "premium"
        else:
            return "community"

    def get_metrics_endpoint(self) -> tuple:
        """Get metrics in Prometheus format for HTTP endpoint"""
        try:
            # Update dynamic metrics
            self.update_top_domains()
            self.update_system_metrics()

            # Generate Prometheus format using custom registry
            metrics_output = generate_latest(self.registry)
            return metrics_output, CONTENT_TYPE_LATEST

        except Exception as e:
            logger.error(f"Failed to generate metrics: {e}")
            return "# Error generating metrics\n", "text/plain"

    async def collect_database_stats(self):
        """Collect statistics from database periodically"""
        if not self.db_url:
            return

        try:
            # Only update every 60 seconds to avoid database load
            if time.time() - self.last_stats_update < 60:
                return

            db = DAL(self.db_url)

            # Query log statistics
            yesterday = datetime.now() - timedelta(days=1)

            if "query_logs" in db.tables:
                recent_queries = db(db.query_logs.timestamp >= yesterday).count()
                cache_hits = db(
                    (db.query_logs.timestamp >= yesterday)
                    & (db.query_logs.cache_hit == True)
                ).count()

                hit_rate = cache_hits / max(recent_queries, 1)
                self.update_cache_stats(0, hit_rate)  # Entry count updated elsewhere

            self.last_stats_update = time.time()
            db.close()

        except Exception as e:
            logger.error(f"Failed to collect database stats: {e}")


class MetricsCollector:
    """
    Background collector that runs metrics collection periodically.
    Integrates with existing Squawk DNS components.
    """

    def __init__(self, metrics: PrometheusMetrics, collection_interval: int = 30):
        self.metrics = metrics
        self.collection_interval = collection_interval
        self.running = False
        self.thread = None

    def start(self):
        """Start metrics collection in background thread"""
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self._collect_loop, daemon=True)
            self.thread.start()
            logger.info("Metrics collection started")

    def stop(self):
        """Stop metrics collection"""
        self.running = False
        if self.thread:
            self.thread.join()
        logger.info("Metrics collection stopped")

    def _collect_loop(self):
        """Main collection loop"""
        while self.running:
            try:
                # Collect database statistics
                import asyncio

                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(self.metrics.collect_database_stats())
                loop.close()

                # Update server health (simplified check)
                self.metrics.update_server_health(True)

                time.sleep(self.collection_interval)

            except Exception as e:
                logger.error(f"Metrics collection error: {e}")
                time.sleep(self.collection_interval)


# Global metrics instance
prometheus_metrics = None


def init_prometheus_metrics(
    db_url: str = None, enable_collection: bool = True
) -> PrometheusMetrics:
    """Initialize Prometheus metrics collection"""
    global prometheus_metrics

    prometheus_metrics = PrometheusMetrics(db_url)

    if enable_collection:
        collector = MetricsCollector(prometheus_metrics)
        collector.start()

    logger.info("Prometheus metrics initialized")
    return prometheus_metrics


def get_metrics_instance() -> Optional[PrometheusMetrics]:
    """Get the global metrics instance"""
    return prometheus_metrics
