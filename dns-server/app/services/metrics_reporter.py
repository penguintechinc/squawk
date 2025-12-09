"""
Metrics Reporter Service
Tracks and reports DNS server metrics.
"""
import logging
from typing import Dict
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger(__name__)


class MetricsReporter:
    """Tracks DNS server metrics for reporting to Manager."""

    def __init__(self):
        self.queries_total = 0
        self.queries_by_type = defaultdict(int)
        self.queries_by_mode = defaultdict(int)
        self.cache_hits = 0
        self.cache_misses = 0
        self.errors = 0
        self.ioc_blocked = 0
        self.response_times = []
        self.start_time = datetime.now()

    def record_query(self, domain: str, record_type: str, mode: str):
        """
        Record a DNS query.

        Args:
            domain: Domain queried
            record_type: DNS record type
            mode: Operational mode (normal, cached, degraded)
        """
        self.queries_total += 1
        self.queries_by_type[record_type] += 1
        self.queries_by_mode[mode] += 1

    def record_cache_hit(self):
        """Record a cache hit."""
        self.cache_hits += 1

    def record_cache_miss(self):
        """Record a cache miss."""
        self.cache_misses += 1

    def record_error(self):
        """Record an error."""
        self.errors += 1

    def record_ioc_block(self):
        """Record an IOC block."""
        self.ioc_blocked += 1

    def record_response_time(self, response_time_ms: float):
        """
        Record query response time.

        Args:
            response_time_ms: Response time in milliseconds
        """
        self.response_times.append(response_time_ms)

        # Keep only last 1000 response times
        if len(self.response_times) > 1000:
            self.response_times = self.response_times[-1000:]

    def get_metrics(self) -> Dict:
        """
        Get current metrics for heartbeat.

        Returns:
            Metrics dictionary
        """
        avg_response_ms = (
            sum(self.response_times) / len(self.response_times)
            if self.response_times else 0
        )

        uptime = (datetime.now() - self.start_time).total_seconds()

        cache_hit_rate = (
            self.cache_hits / (self.cache_hits + self.cache_misses)
            if (self.cache_hits + self.cache_misses) > 0 else 0
        )

        return {
            'queries_total': self.queries_total,
            'cache_hits': self.cache_hits,
            'cache_misses': self.cache_misses,
            'cache_hit_rate': cache_hit_rate,
            'errors': self.errors,
            'ioc_blocked': self.ioc_blocked,
            'avg_response_ms': avg_response_ms,
            'queries_by_type': dict(self.queries_by_type),
            'queries_by_mode': dict(self.queries_by_mode),
            'uptime_seconds': uptime
        }

    def reset(self):
        """Reset all metrics."""
        self.queries_total = 0
        self.queries_by_type.clear()
        self.queries_by_mode.clear()
        self.cache_hits = 0
        self.cache_misses = 0
        self.errors = 0
        self.ioc_blocked = 0
        self.response_times.clear()
        logger.info("Metrics reset")
