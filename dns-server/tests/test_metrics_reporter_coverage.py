"""
Coverage tests for app.services.metrics_reporter.MetricsReporter.

Exercises every record/get/reset method, including the bounded
response-time deque (trimmed to the last 1000 entries) and both
branches of the cache-hit-rate / avg-response-time division guards.
"""
from datetime import datetime

import pytest

from app.services.metrics_reporter import MetricsReporter


@pytest.fixture
def reporter() -> MetricsReporter:
    """Fresh MetricsReporter instance, isolated per test."""
    return MetricsReporter()


class TestInit:
    def test_initial_state_is_zeroed(self, reporter: MetricsReporter) -> None:
        assert reporter.queries_total == 0
        assert dict(reporter.queries_by_type) == {}
        assert dict(reporter.queries_by_mode) == {}
        assert reporter.cache_hits == 0
        assert reporter.cache_misses == 0
        assert reporter.errors == 0
        assert reporter.ioc_blocked == 0
        assert reporter.response_times == []
        assert isinstance(reporter.start_time, datetime)


class TestRecordQuery:
    def test_record_query_increments_counters(self, reporter: MetricsReporter) -> None:
        reporter.record_query("example.com", "A", "normal")
        reporter.record_query("example.com", "A", "normal")
        reporter.record_query("example.com", "AAAA", "cached")

        assert reporter.queries_total == 3
        assert reporter.queries_by_type["A"] == 2
        assert reporter.queries_by_type["AAAA"] == 1
        assert reporter.queries_by_mode["normal"] == 2
        assert reporter.queries_by_mode["cached"] == 1

    def test_record_query_tracks_degraded_mode(self, reporter: MetricsReporter) -> None:
        reporter.record_query("example.com", "MX", "degraded")
        assert reporter.queries_by_mode["degraded"] == 1


class TestCacheAndErrorCounters:
    def test_record_cache_hit(self, reporter: MetricsReporter) -> None:
        reporter.record_cache_hit()
        reporter.record_cache_hit()
        assert reporter.cache_hits == 2

    def test_record_cache_miss(self, reporter: MetricsReporter) -> None:
        reporter.record_cache_miss()
        assert reporter.cache_misses == 1

    def test_record_error(self, reporter: MetricsReporter) -> None:
        reporter.record_error()
        reporter.record_error()
        reporter.record_error()
        assert reporter.errors == 3

    def test_record_ioc_block(self, reporter: MetricsReporter) -> None:
        reporter.record_ioc_block()
        assert reporter.ioc_blocked == 1


class TestRecordResponseTime:
    def test_appends_response_time(self, reporter: MetricsReporter) -> None:
        reporter.record_response_time(12.5)
        reporter.record_response_time(7.25)
        assert reporter.response_times == [12.5, 7.25]

    def test_response_times_bounded_to_last_1000(self, reporter: MetricsReporter) -> None:
        for i in range(1005):
            reporter.record_response_time(float(i))

        assert len(reporter.response_times) == 1000
        # The oldest 5 entries (0.0-4.0) must have been trimmed; the tail
        # must be exactly the most recent 1000 values in order.
        assert reporter.response_times[0] == 5.0
        assert reporter.response_times[-1] == 1004.0


class TestGetMetrics:
    def test_get_metrics_with_no_data_avoids_division_by_zero(
        self, reporter: MetricsReporter
    ) -> None:
        metrics = reporter.get_metrics()

        assert metrics["queries_total"] == 0
        assert metrics["cache_hits"] == 0
        assert metrics["cache_misses"] == 0
        assert metrics["cache_hit_rate"] == 0
        assert metrics["errors"] == 0
        assert metrics["ioc_blocked"] == 0
        assert metrics["avg_response_ms"] == 0
        assert metrics["queries_by_type"] == {}
        assert metrics["queries_by_mode"] == {}
        assert metrics["uptime_seconds"] >= 0

    def test_get_metrics_with_populated_data(self, reporter: MetricsReporter) -> None:
        reporter.record_query("example.com", "A", "normal")
        reporter.record_query("example.org", "AAAA", "cached")
        reporter.record_cache_hit()
        reporter.record_cache_hit()
        reporter.record_cache_miss()
        reporter.record_error()
        reporter.record_ioc_block()
        reporter.record_response_time(10.0)
        reporter.record_response_time(20.0)

        metrics = reporter.get_metrics()

        assert metrics["queries_total"] == 2
        assert metrics["cache_hits"] == 2
        assert metrics["cache_misses"] == 1
        assert metrics["cache_hit_rate"] == pytest.approx(2 / 3)
        assert metrics["errors"] == 1
        assert metrics["ioc_blocked"] == 1
        assert metrics["avg_response_ms"] == pytest.approx(15.0)
        assert metrics["queries_by_type"] == {"A": 1, "AAAA": 1}
        assert metrics["queries_by_mode"] == {"normal": 1, "cached": 1}
        assert metrics["uptime_seconds"] >= 0

    def test_get_metrics_returns_plain_dicts_for_type_and_mode(
        self, reporter: MetricsReporter
    ) -> None:
        reporter.record_query("example.com", "A", "normal")
        metrics = reporter.get_metrics()

        assert isinstance(metrics["queries_by_type"], dict)
        assert isinstance(metrics["queries_by_mode"], dict)
        assert not hasattr(metrics["queries_by_type"], "default_factory")


class TestReset:
    def test_reset_clears_all_state(self, reporter: MetricsReporter) -> None:
        reporter.record_query("example.com", "A", "normal")
        reporter.record_cache_hit()
        reporter.record_cache_miss()
        reporter.record_error()
        reporter.record_ioc_block()
        reporter.record_response_time(42.0)

        reporter.reset()

        assert reporter.queries_total == 0
        assert dict(reporter.queries_by_type) == {}
        assert dict(reporter.queries_by_mode) == {}
        assert reporter.cache_hits == 0
        assert reporter.cache_misses == 0
        assert reporter.errors == 0
        assert reporter.ioc_blocked == 0
        assert reporter.response_times == []

    def test_reset_does_not_touch_start_time(self, reporter: MetricsReporter) -> None:
        original_start = reporter.start_time
        reporter.reset()
        assert reporter.start_time == original_start
