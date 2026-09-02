"""
Coverage tests for app.services.prometheus_metrics.

test_security_hardening.py already covers the metric-source /
label-sanitization defense-in-depth path (_sanitize_source and the
type= cardinality guard) using the app.main global instance. This
file covers everything else on PrometheusMetrics and MetricsCollector:
record/report/reset methods, label paths, error handling, the bounded
top_domains cap, and the background collector loop -- all against
fresh, isolated PrometheusMetrics() instances (own CollectorRegistry)
so nothing here touches global state used by other test modules.
"""
import collections
import time
from unittest.mock import MagicMock, Mock

import pytest

import app.services.prometheus_metrics as pm_module
from app.services.prometheus_metrics import (
    MetricsCollector,
    PrometheusMetrics,
    get_metrics_instance,
    init_prometheus_metrics,
)


@pytest.fixture
def metrics() -> PrometheusMetrics:
    """Fresh PrometheusMetrics with its own CollectorRegistry."""
    return PrometheusMetrics()


def _decode(output) -> str:
    return output.decode() if isinstance(output, bytes) else output


class TestInitMetrics:
    def test_constructor_sets_defaults(self, metrics: PrometheusMetrics) -> None:
        assert metrics.db_url is None
        assert metrics.cache_hit_rate == 0.0
        assert metrics.last_stats_update == 0
        assert dict(metrics.query_stats) == {}
        assert len(metrics.response_times) == 0
        assert dict(metrics.top_domains) == {}
        assert dict(metrics.error_counts) == {}

    def test_constructor_accepts_db_url(self) -> None:
        m = PrometheusMetrics(db_url="sqlite://test.db")
        assert m.db_url == "sqlite://test.db"

    def test_server_info_metric_set(self, metrics: PrometheusMetrics) -> None:
        output = _decode(generate := metrics.get_metrics_endpoint()[0])
        assert "squawk_dns_server_info" in output
        assert 'version="2.0"' in output


class TestRecordQuery:
    def test_basic_success_recorded(self, metrics: PrometheusMetrics) -> None:
        metrics.record_query(
            domain="example.com",
            record_type="A",
            status="success",
            response_time=0.05,
            cache_hit=False,
        )
        assert metrics.query_stats["A_success"] == 1
        assert metrics.top_domains["example.com"] == 1
        assert list(metrics.response_times) == [0.05]
        assert metrics.error_counts == {}

    def test_cache_hit_path(self, metrics: PrometheusMetrics) -> None:
        metrics.record_query(
            domain="example.com",
            record_type="A",
            status="success",
            response_time=0.01,
            cache_hit=True,
        )
        output = _decode(metrics.get_metrics_endpoint()[0])
        assert "squawk_dns_cache_hits_total" in output

    def test_cache_miss_path(self, metrics: PrometheusMetrics) -> None:
        metrics.record_query(
            domain="example.com",
            record_type="A",
            status="success",
            response_time=0.01,
            cache_hit=False,
        )
        output = _decode(metrics.get_metrics_endpoint()[0])
        assert "squawk_dns_cache_misses_total" in output

    def test_error_status_increments_error_counts(self, metrics: PrometheusMetrics) -> None:
        metrics.record_query(
            domain="bad.example.com",
            record_type="A",
            status="nxdomain",
            response_time=0.01,
            cache_hit=False,
        )
        assert metrics.error_counts["nxdomain"] == 1

    def test_blocked_with_reason(self, metrics: PrometheusMetrics) -> None:
        metrics.record_query(
            domain="blocked.example.com",
            record_type="A",
            status="blocked",
            response_time=0.0,
            cache_hit=False,
            blocked=True,
            block_reason="threat_intelligence",
        )
        output = _decode(metrics.get_metrics_endpoint()[0])
        assert 'reason="threat_intelligence"' in output

    def test_blocked_without_reason_defaults_unknown(self, metrics: PrometheusMetrics) -> None:
        metrics.record_query(
            domain="blocked.example.com",
            record_type="A",
            status="blocked",
            response_time=0.0,
            cache_hit=False,
            blocked=True,
        )
        output = _decode(metrics.get_metrics_endpoint()[0])
        assert 'reason="unknown"' in output

    def test_token_hash_records_user_metrics(self, metrics: PrometheusMetrics) -> None:
        metrics.record_query(
            domain="example.com",
            record_type="A",
            status="success",
            response_time=0.01,
            cache_hit=False,
            token_hash="enterprise0123456789abcdef",  # gitleaks:allow (fake test fixture, not a secret)
        )
        output = _decode(metrics.get_metrics_endpoint()[0])
        assert "squawk_dns_user_queries_total" in output
        assert 'user_type="enterprise"' in output
        # Only first 8 chars of the token hash are used as a label value.
        assert 'token_hash="enterpri"' in output

    def test_identity_type_tracks_rate_limit_allowed(self, metrics: PrometheusMetrics) -> None:
        metrics.record_query(
            domain="example.com",
            record_type="A",
            status="success",
            response_time=0.01,
            cache_hit=False,
            identity_type="token",
        )
        output = _decode(metrics.get_metrics_endpoint()[0])
        assert 'result="allowed"' in output
        assert 'identity_type="token"' in output

    def test_record_query_swallows_internal_exceptions(
        self, metrics: PrometheusMetrics, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Force an internal failure and verify record_query never raises."""
        metrics.dns_queries_total.labels = Mock(side_effect=RuntimeError("boom"))
        with caplog.at_level("ERROR"):
            metrics.record_query(
                domain="example.com",
                record_type="A",
                status="success",
                response_time=0.01,
                cache_hit=False,
            )
        assert "Failed to record metrics" in caplog.text


class TestTopDomainsCap:
    def test_over_cap_domains_do_not_crash_record_query(
        self, metrics: PrometheusMetrics, caplog: pytest.LogCaptureFixture
    ) -> None:
        """
        Regression test for the top_domains DoS cap. `collections.Counter`
        was previously shadowed by `prometheus_client.Counter` (same import
        name), so the trim at record_query() raised internally and the dict
        grew unbounded (the cap was inoperative). The trim now uses an
        aliased `CollectionsCounter`, so exceeding the cap trims the dict
        down to _MAX_TOP_DOMAINS most-common entries — without record_query
        ever raising.
        """
        for i in range(PrometheusMetrics._MAX_TOP_DOMAINS + 5):
            with caplog.at_level("ERROR"):
                metrics.record_query(
                    domain=f"domain-{i}.example.com",
                    record_type="A",
                    status="success",
                    response_time=0.001,
                    cache_hit=False,
                )

        # record_query never raises, and the cap is now actually enforced.
        assert len(metrics.top_domains) == PrometheusMetrics._MAX_TOP_DOMAINS
        assert "Failed to record metrics" not in caplog.text

    def test_trim_logic_when_name_shadow_is_corrected(
        self, metrics: PrometheusMetrics, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """
        Prove the *intended* trimming logic is otherwise correct: with the
        module's `Counter` name patched back to collections.Counter (i.e.
        as if the import-shadow bug above were fixed), pushing past the cap
        does trim top_domains down to _MAX_TOP_DOMAINS most-common entries.
        """
        monkeypatch.setattr(pm_module, "Counter", collections.Counter)

        for i in range(PrometheusMetrics._MAX_TOP_DOMAINS + 5):
            metrics.record_query(
                domain=f"domain-{i}.example.com",
                record_type="A",
                status="success",
                response_time=0.001,
                cache_hit=False,
            )

        assert len(metrics.top_domains) == PrometheusMetrics._MAX_TOP_DOMAINS


class TestAuthAndPolicyAndRateLimit:
    def test_record_authentication_failure(self, metrics: PrometheusMetrics) -> None:
        metrics.record_authentication_failure("invalid_signature")
        output = _decode(metrics.get_metrics_endpoint()[0])
        assert 'failure_type="invalid_signature"' in output

    def test_record_policy_denial(self, metrics: PrometheusMetrics) -> None:
        metrics.record_policy_denial("policy_denied")
        output = _decode(metrics.get_metrics_endpoint()[0])
        assert 'outcome="policy_denied"' in output

    def test_record_rate_limited_query(self, metrics: PrometheusMetrics) -> None:
        metrics.record_rate_limited_query(
            domain="example.com", record_type="A", identity_type="ip"
        )
        output = _decode(metrics.get_metrics_endpoint()[0])
        assert 'result="limited"' in output
        assert 'identity_type="ip"' in output

    def test_record_rate_limited_query_default_identity_type(
        self, metrics: PrometheusMetrics
    ) -> None:
        metrics.record_rate_limited_query(domain="example.com", record_type="A")
        output = _decode(metrics.get_metrics_endpoint()[0])
        assert 'identity_type="ip"' in output

    def test_record_rate_limited_query_swallows_exceptions(
        self, metrics: PrometheusMetrics, caplog: pytest.LogCaptureFixture
    ) -> None:
        metrics.rate_limit_requests_total.labels = Mock(side_effect=RuntimeError("boom"))
        with caplog.at_level("ERROR"):
            metrics.record_rate_limited_query(domain="example.com", record_type="A")
        assert "Failed to record rate limit metrics" in caplog.text

    def test_record_upstream_query(self, metrics: PrometheusMetrics) -> None:
        metrics.record_upstream_query(upstream_server="1.1.1.1", response_time=0.02)
        output = _decode(metrics.get_metrics_endpoint()[0])
        assert "squawk_dns_upstream_duration_seconds" in output
        assert 'upstream_server="1.1.1.1"' in output


class TestCacheAndIocAndHealthGauges:
    def test_update_cache_stats(self, metrics: PrometheusMetrics) -> None:
        metrics.update_cache_stats(total_entries=42, hit_rate=0.75)
        assert metrics.cache_hit_rate == 0.75
        output = _decode(metrics.get_metrics_endpoint()[0])
        assert "squawk_dns_cache_entries 42" in output
        assert "squawk_dns_cache_hit_rate 0.75" in output

    def test_update_ioc_stats_normal(self, metrics: PrometheusMetrics) -> None:
        ioc_stats = {
            "feeds": {
                "feed_details": [
                    {"name": "feed_one", "indicators": 10},
                    {"name": "feed_two", "indicators": 20},
                ]
            }
        }
        metrics.update_ioc_stats(ioc_stats)
        output = _decode(metrics.get_metrics_endpoint()[0])
        assert 'feed_name="feed_one"' in output
        assert 'feed_name="feed_two"' in output

    def test_update_ioc_stats_missing_feeds_key_is_noop(
        self, metrics: PrometheusMetrics
    ) -> None:
        # Should not raise even though "feeds" is absent.
        metrics.update_ioc_stats({})

    def test_update_ioc_stats_swallows_exceptions(
        self, metrics: PrometheusMetrics, caplog: pytest.LogCaptureFixture
    ) -> None:
        bad_stats = {"feeds": {"feed_details": [{"name": "feed_missing_indicators"}]}}
        with caplog.at_level("ERROR"):
            metrics.update_ioc_stats(bad_stats)
        assert "Failed to update IOC metrics" in caplog.text

    def test_update_server_health(self, metrics: PrometheusMetrics) -> None:
        metrics.update_server_health(True)
        output = _decode(metrics.get_metrics_endpoint()[0])
        assert "squawk_dns_server_health 1.0" in output

        metrics.update_server_health(False)
        output = _decode(metrics.get_metrics_endpoint()[0])
        assert "squawk_dns_server_health 0.0" in output


class TestSystemMetrics:
    def test_update_system_metrics_normal_path(self, metrics: PrometheusMetrics) -> None:
        # psutil is installed in this environment; exercise the real path.
        metrics.update_system_metrics()
        output = _decode(metrics.get_metrics_endpoint()[0])
        assert "squawk_dns_memory_usage_bytes" in output

    def test_update_system_metrics_import_error(
        self, metrics: PrometheusMetrics, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import sys

        monkeypatch.setitem(sys.modules, "psutil", None)
        # Should not raise -- ImportError is caught and swallowed.
        metrics.update_system_metrics()

    def test_update_system_metrics_access_denied_on_open_files(
        self, metrics: PrometheusMetrics, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import psutil

        fake_process = Mock()
        fake_process.memory_info.return_value = Mock(rss=123456)
        fake_process.open_files.side_effect = psutil.AccessDenied(pid=1)
        monkeypatch.setattr(psutil, "Process", Mock(return_value=fake_process))

        # Should not raise -- AccessDenied on open_files() is caught locally.
        metrics.update_system_metrics()
        output = _decode(metrics.get_metrics_endpoint()[0])
        assert "squawk_dns_memory_usage_bytes 123456" in output

    def test_update_system_metrics_generic_exception(
        self, metrics: PrometheusMetrics, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        import psutil

        monkeypatch.setattr(psutil, "Process", Mock(side_effect=RuntimeError("boom")))
        with caplog.at_level("ERROR"):
            metrics.update_system_metrics()
        assert "Failed to update system metrics" in caplog.text


class TestUpdateTopDomains:
    def test_sanitizes_domain_labels(self, metrics: PrometheusMetrics) -> None:
        from prometheus_client import generate_latest

        metrics.top_domains["a.b-c.example.com"] = 5
        metrics.top_domains["z.example.org"] = 1
        metrics.update_top_domains(limit=10)

        # Read the registry directly -- get_metrics_endpoint() would call
        # update_top_domains() again with its own default limit and
        # overwrite the limit under test.
        output = _decode(generate_latest(metrics.registry))
        assert 'domain="a_b_c_example_com"' in output
        assert 'rank="1"' in output

    def test_respects_limit(self, metrics: PrometheusMetrics) -> None:
        from prometheus_client import generate_latest

        for i in range(5):
            metrics.top_domains[f"domain{i}.example.com"] = 5 - i
        metrics.update_top_domains(limit=2)

        output = _decode(generate_latest(metrics.registry))
        assert 'rank="1"' in output
        assert 'rank="2"' in output
        assert 'rank="3"' not in output

    def test_swallows_exceptions(
        self, metrics: PrometheusMetrics, caplog: pytest.LogCaptureFixture
    ) -> None:
        metrics.dns_top_domains.clear = Mock(side_effect=RuntimeError("boom"))
        with caplog.at_level("ERROR"):
            metrics.update_top_domains()
        assert "Failed to update top domains" in caplog.text


class TestGetCurrentStats:
    def test_empty_stats(self, metrics: PrometheusMetrics) -> None:
        stats = metrics.get_current_stats()
        assert stats["total_queries"] == 0
        assert stats["average_response_time_ms"] == 0
        assert stats["cache_hit_rate"] == 0.0
        assert stats["error_rate"] == 0
        assert stats["top_domains"] == {}

    def test_populated_stats(self, metrics: PrometheusMetrics) -> None:
        metrics.record_query(
            domain="example.com",
            record_type="A",
            status="success",
            response_time=0.1,
            cache_hit=False,
        )
        metrics.record_query(
            domain="example.com",
            record_type="A",
            status="timeout",
            response_time=0.2,
            cache_hit=False,
        )

        stats = metrics.get_current_stats()
        assert stats["total_queries"] == 2
        assert stats["average_response_time_ms"] == pytest.approx(150.0)
        assert stats["error_rate"] == pytest.approx(0.5)
        assert stats["top_domains"] == {"example.com": 2}


class TestResetPeriodicStats:
    def test_clears_response_times_but_keeps_totals(self, metrics: PrometheusMetrics) -> None:
        metrics.record_query(
            domain="example.com",
            record_type="A",
            status="success",
            response_time=0.1,
            cache_hit=False,
        )
        assert len(metrics.response_times) == 1

        metrics.reset_periodic_stats()

        assert len(metrics.response_times) == 0
        # Running totals are untouched by design.
        assert metrics.query_stats["A_success"] == 1


class TestGetUserTypeFromToken:
    @pytest.mark.parametrize(
        "token_hash,expected",
        [
            ("ENTERPRISE-abc123", "enterprise"),
            ("premium-xyz", "premium"),
            ("community-000", "community"),
            ("randomvalue", "community"),
        ],
    )
    def test_heuristics(self, metrics: PrometheusMetrics, token_hash: str, expected: str) -> None:
        assert metrics._get_user_type_from_token(token_hash) == expected


class TestGetMetricsEndpoint:
    def test_returns_bytes_and_content_type(self, metrics: PrometheusMetrics) -> None:
        from prometheus_client import CONTENT_TYPE_LATEST

        output, content_type = metrics.get_metrics_endpoint()
        assert isinstance(output, (bytes, str))
        assert content_type == CONTENT_TYPE_LATEST

    def test_error_path_returns_plain_text(
        self, metrics: PrometheusMetrics, caplog: pytest.LogCaptureFixture
    ) -> None:
        metrics.update_top_domains = Mock(side_effect=RuntimeError("boom"))
        with caplog.at_level("ERROR"):
            output, content_type = metrics.get_metrics_endpoint()
        assert output == "# Error generating metrics\n"
        assert content_type == "text/plain"
        assert "Failed to generate metrics" in caplog.text


class TestCollectDatabaseStats:
    @pytest.mark.asyncio
    async def test_noop_when_no_db_url(self, metrics: PrometheusMetrics) -> None:
        assert metrics.db_url is None
        await metrics.collect_database_stats()  # must not raise

    @pytest.mark.asyncio
    async def test_skips_when_recently_updated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        metrics = PrometheusMetrics(db_url="sqlite://test.db")
        metrics.last_stats_update = time.time()

        sentinel = Mock(side_effect=AssertionError("DAL should not be called"))
        monkeypatch.setattr(pm_module, "DAL", sentinel)

        await metrics.collect_database_stats()  # must not raise, must not call DAL
        sentinel.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_query_logs_table(self, monkeypatch: pytest.MonkeyPatch) -> None:
        metrics = PrometheusMetrics(db_url="sqlite://test.db")

        fake_db = MagicMock()
        fake_db.tables = []
        monkeypatch.setattr(pm_module, "DAL", Mock(return_value=fake_db))

        await metrics.collect_database_stats()

        fake_db.close.assert_called_once()
        assert metrics.last_stats_update > 0

    @pytest.mark.asyncio
    async def test_with_query_logs_table(self, monkeypatch: pytest.MonkeyPatch) -> None:
        metrics = PrometheusMetrics(db_url="sqlite://test.db")

        fake_db = MagicMock()
        fake_db.tables = ["query_logs"]
        # `db.query_logs.timestamp >= yesterday` and `... cache_hit == True`
        # invoke MagicMock's rich-comparison dunders, which default to
        # NotImplemented (raising TypeError against a real datetime) unless
        # explicitly given a return value.
        condition = MagicMock()
        condition.__and__.return_value = condition
        fake_db.query_logs.timestamp.__ge__.return_value = condition
        fake_db.query_logs.cache_hit.__eq__.return_value = condition
        fake_db.return_value.count.return_value = 5
        monkeypatch.setattr(pm_module, "DAL", Mock(return_value=fake_db))

        await metrics.collect_database_stats()

        assert metrics.cache_hit_rate == pytest.approx(1.0)
        fake_db.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_swallows_exceptions(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        metrics = PrometheusMetrics(db_url="sqlite://test.db")
        monkeypatch.setattr(pm_module, "DAL", Mock(side_effect=RuntimeError("boom")))

        with caplog.at_level("ERROR"):
            await metrics.collect_database_stats()  # must not raise

        assert "Failed to collect database stats" in caplog.text


class TestMetricsCollector:
    def test_collect_loop_single_iteration(
        self, metrics: PrometheusMetrics, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        collector = MetricsCollector(metrics, collection_interval=0)
        collector.running = True
        calls = {"n": 0}

        def fake_sleep(_interval: float) -> None:
            calls["n"] += 1
            collector.running = False

        monkeypatch.setattr(pm_module.time, "sleep", fake_sleep)
        collector._collect_loop()

        assert calls["n"] == 1

    def test_collect_loop_handles_exception_and_continues_sleeping(
        self,
        metrics: PrometheusMetrics,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        collector = MetricsCollector(metrics, collection_interval=0)
        collector.running = True
        calls = {"n": 0}

        def fake_sleep(_interval: float) -> None:
            calls["n"] += 1
            collector.running = False

        monkeypatch.setattr(pm_module.time, "sleep", fake_sleep)
        monkeypatch.setattr(
            metrics, "collect_database_stats", Mock(side_effect=RuntimeError("boom"))
        )

        with caplog.at_level("ERROR"):
            collector._collect_loop()

        assert calls["n"] == 1
        assert "Metrics collection error" in caplog.text

    def test_start_and_stop_real_thread(self, metrics: PrometheusMetrics) -> None:
        collector = MetricsCollector(metrics, collection_interval=0.01)
        assert collector.running is False

        collector.start()
        assert collector.running is True
        assert collector.thread is not None
        assert collector.thread.is_alive()

        # Calling start() again while already running must be a no-op.
        existing_thread = collector.thread
        collector.start()
        assert collector.thread is existing_thread

        time.sleep(0.05)
        collector.stop()
        assert collector.running is False

    def test_stop_without_start_is_safe(self, metrics: PrometheusMetrics) -> None:
        collector = MetricsCollector(metrics)
        assert collector.thread is None
        collector.stop()  # must not raise
        assert collector.running is False


class TestModuleLevelGlobals:
    def test_init_prometheus_metrics_without_collection(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        original = pm_module.prometheus_metrics
        try:
            instance = init_prometheus_metrics(db_url=None, enable_collection=False)
            assert isinstance(instance, PrometheusMetrics)
            assert get_metrics_instance() is instance
        finally:
            pm_module.prometheus_metrics = original

    def test_init_prometheus_metrics_starts_collection_when_enabled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        original = pm_module.prometheus_metrics
        start_mock = Mock()
        monkeypatch.setattr(pm_module.MetricsCollector, "start", start_mock)
        try:
            instance = init_prometheus_metrics(db_url=None, enable_collection=True)
            assert isinstance(instance, PrometheusMetrics)
            start_mock.assert_called_once()
        finally:
            pm_module.prometheus_metrics = original

    def test_get_metrics_instance_returns_none_before_init(self) -> None:
        original = pm_module.prometheus_metrics
        try:
            pm_module.prometheus_metrics = None
            assert get_metrics_instance() is None
        finally:
            pm_module.prometheus_metrics = original
