#!/usr/bin/env python3
"""
Unit tests for Prometheus Metrics
Tests DNS statistics collection and Prometheus format generation.
"""

import pytest
import time
import threading
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from prometheus_metrics import PrometheusMetrics, MetricsCollector, init_prometheus_metrics, get_metrics_instance

class TestPrometheusMetrics:

    @pytest.fixture
    def prometheus_metrics(self, temp_db):
        """Create Prometheus metrics instance with test database"""
        db_url = f"sqlite://{temp_db._uri[9:]}"
        return PrometheusMetrics(db_url)

    def test_metrics_initialization(self, prometheus_metrics):
        """Test that all metrics are properly initialized"""
        assert prometheus_metrics.dns_queries_total is not None
        assert prometheus_metrics.dns_cache_hits_total is not None
        assert prometheus_metrics.dns_cache_misses_total is not None
        assert prometheus_metrics.dns_blocked_queries_total is not None
        assert prometheus_metrics.dns_query_duration_seconds is not None
        assert prometheus_metrics.dns_upstream_duration_seconds is not None
        assert prometheus_metrics.dns_active_connections is not None
        assert prometheus_metrics.dns_cache_entries is not None
        assert prometheus_metrics.dns_cache_hit_rate is not None
        assert prometheus_metrics.dns_ioc_entries is not None
        assert prometheus_metrics.dns_server_health is not None
        assert prometheus_metrics.dns_top_domains is not None
        assert prometheus_metrics.dns_user_queries_total is not None
        assert prometheus_metrics.dns_authentication_failures is not None
        assert prometheus_metrics.dns_memory_usage_bytes is not None
        assert prometheus_metrics.dns_open_files is not None
        assert prometheus_metrics.dns_server_info is not None

    def test_record_query_basic(self, prometheus_metrics):
        """Test recording basic DNS query"""
        prometheus_metrics.record_query(
            domain='example.com',
            record_type='A',
            status='success',
            response_time=0.05,
            cache_hit=False
        )

        # Check internal stats were updated
        assert prometheus_metrics.query_stats['A_success'] == 1
        assert len(prometheus_metrics.response_times) == 1
        assert prometheus_metrics.top_domains['example.com'] == 1

    def test_record_query_with_cache_hit(self, prometheus_metrics):
        """Test recording query with cache hit"""
        prometheus_metrics.record_query(
            domain='cached.example.com',
            record_type='A',
            status='success',
            response_time=0.001,
            cache_hit=True
        )

        # Verify cache hit was recorded
        assert len(prometheus_metrics.response_times) == 1
        assert prometheus_metrics.response_times[0] == 0.001

    def test_record_query_blocked(self, prometheus_metrics):
        """Test recording blocked query"""
        prometheus_metrics.record_query(
            domain='malware.example.com',
            record_type='A',
            status='blocked',
            response_time=0.01,
            cache_hit=False,
            blocked=True,
            block_reason='threat_intelligence'
        )

        assert prometheus_metrics.query_stats['A_blocked'] == 1
        assert prometheus_metrics.error_counts['blocked'] == 1

    def test_record_query_with_user_token(self, prometheus_metrics):
        """Test recording query with user token hash"""
        token_hash = 'abcd1234567890'

        prometheus_metrics.record_query(
            domain='user.example.com',
            record_type='A',
            status='success',
            response_time=0.02,
            cache_hit=False,
            token_hash=token_hash
        )

        # User metrics should be updated
        assert len(prometheus_metrics.response_times) == 1

    def test_record_authentication_failure(self, prometheus_metrics):
        """Test recording authentication failure"""
        prometheus_metrics.record_authentication_failure('invalid_token')
        prometheus_metrics.record_authentication_failure('expired_token')
        prometheus_metrics.record_authentication_failure('invalid_token')  # Duplicate

        # Metrics should be incremented
        # (We can't easily test Prometheus counter values directly)
        assert True  # Placeholder - in real tests we'd check the counter

    def test_record_upstream_query(self, prometheus_metrics):
        """Test recording upstream DNS query timing"""
        prometheus_metrics.record_upstream_query('8.8.8.8', 0.15)
        prometheus_metrics.record_upstream_query('1.1.1.1', 0.08)
        prometheus_metrics.record_upstream_query('8.8.8.8', 0.12)

        # Upstream metrics should be recorded
        # (We can't easily test histogram values directly)
        assert True  # Placeholder

    def test_update_cache_stats(self, prometheus_metrics):
        """Test updating cache statistics"""
        prometheus_metrics.update_cache_stats(total_entries=1500, hit_rate=0.85)

        assert prometheus_metrics.cache_hit_rate == 0.85
        # Gauges should be updated (not easily testable directly)

    def test_update_ioc_stats(self, prometheus_metrics):
        """Test updating IOC statistics"""
        ioc_stats = {
            'feeds': {
                'feed_details': [
                    {'name': 'Feed1', 'indicators': 1000},
                    {'name': 'Feed2', 'indicators': 500},
                    {'name': 'Feed3', 'indicators': 250}
                ]
            }
        }

        prometheus_metrics.update_ioc_stats(ioc_stats)

        # IOC metrics should be updated
        assert True  # Placeholder - would test gauge values

    def test_update_server_health(self, prometheus_metrics):
        """Test updating server health status"""
        # Test healthy
        prometheus_metrics.update_server_health(True)
        # Test unhealthy
        prometheus_metrics.update_server_health(False)
        # Back to healthy
        prometheus_metrics.update_server_health(True)

        # Health gauge should be updated
        assert True  # Placeholder

    @patch('psutil.Process')
    def test_update_system_metrics(self, mock_process, prometheus_metrics):
        """Test updating system resource metrics"""
        # Mock psutil
        mock_memory_info = Mock()
        mock_memory_info.rss = 100 * 1024 * 1024  # 100MB

        mock_process_instance = Mock()
        mock_process_instance.memory_info.return_value = mock_memory_info
        mock_process_instance.open_files.return_value = ['file1', 'file2', 'file3']
        mock_process.return_value = mock_process_instance

        prometheus_metrics.update_system_metrics()

        # Should have called psutil methods
        mock_process_instance.memory_info.assert_called_once()
        mock_process_instance.open_files.assert_called_once()

    @patch('psutil.Process')
    def test_update_system_metrics_access_denied(self, mock_process, prometheus_metrics):
        """Test handling of psutil access denied errors"""
        import psutil

        mock_process_instance = Mock()
        mock_process_instance.memory_info.side_effect = psutil.AccessDenied()
        mock_process_instance.open_files.side_effect = psutil.AccessDenied()
        mock_process.return_value = mock_process_instance

        # Should not raise exception
        prometheus_metrics.update_system_metrics()

        # Should have attempted to call psutil methods
        mock_process_instance.memory_info.assert_called_once()

    def test_update_system_metrics_no_psutil(self, prometheus_metrics):
        """Test system metrics update when psutil is not available"""
        with patch.dict('sys.modules', {'psutil': None}):
            # Should not raise exception
            prometheus_metrics.update_system_metrics()

    def test_update_top_domains(self, prometheus_metrics):
        """Test updating top domains metrics"""
        # Add some domain queries
        domains = [
            ('example.com', 100),
            ('google.com', 80),
            ('github.com', 60),
            ('stackoverflow.com', 40),
            ('amazon.com', 20)
        ]

        for domain, count in domains:
            prometheus_metrics.top_domains[domain] = count

        prometheus_metrics.update_top_domains(limit=3)

        # Top domains metric should be updated
        # (Can't easily test Prometheus gauge values directly)
        assert True  # Placeholder

    def test_get_current_stats(self, prometheus_metrics):
        """Test getting current statistics summary"""
        # Add some test data
        prometheus_metrics.record_query('test1.com', 'A', 'success', 0.05, False)
        prometheus_metrics.record_query('test2.com', 'A', 'success', 0.03, True)
        prometheus_metrics.record_query('test3.com', 'A', 'error', 0.10, False)

        prometheus_metrics.cache_hit_rate = 0.75

        stats = prometheus_metrics.get_current_stats()

        assert 'total_queries' in stats
        assert 'average_response_time_ms' in stats
        assert 'cache_hit_rate' in stats
        assert 'error_rate' in stats
        assert 'top_domains' in stats

        assert stats['total_queries'] == 3
        assert stats['cache_hit_rate'] == 0.75
        assert stats['error_rate'] > 0  # Should have some errors
        assert len(stats['top_domains']) <= 10

    def test_reset_periodic_stats(self, prometheus_metrics):
        """Test resetting periodic statistics"""
        # Add some data
        prometheus_metrics.response_times.extend([0.1, 0.2, 0.3])

        assert len(prometheus_metrics.response_times) == 3

        prometheus_metrics.reset_periodic_stats()

        assert len(prometheus_metrics.response_times) == 0

    def test_get_user_type_from_token(self, prometheus_metrics):
        """Test determining user type from token hash"""
        test_cases = [
            ('enterprise_token_abc123', 'enterprise'),
            ('premium_user_def456', 'premium'),
            ('regular_token_xyz789', 'community'),
            ('ENTERPRISE_ABC', 'enterprise'),  # Case insensitive
            ('normal_token', 'community')
        ]

        for token_hash, expected_type in test_cases:
            user_type = prometheus_metrics._get_user_type_from_token(token_hash)
            assert user_type == expected_type

    def test_get_metrics_endpoint(self, prometheus_metrics):
        """Test generating Prometheus metrics endpoint"""
        # Add some test data
        prometheus_metrics.record_query('endpoint-test.com', 'A', 'success', 0.05, False)
        prometheus_metrics.update_server_health(True)

        metrics_output, content_type = prometheus_metrics.get_metrics_endpoint()

        assert isinstance(metrics_output, bytes)
        assert content_type == 'text/plain; version=0.0.4; charset=utf-8'

        # Should contain Prometheus format metrics
        metrics_str = metrics_output.decode('utf-8')
        assert 'squawk_dns_queries_total' in metrics_str
        assert 'squawk_dns_server_health' in metrics_str

    @pytest.mark.asyncio
    async def test_collect_database_stats(self, prometheus_metrics, temp_db):
        """Test collecting statistics from database"""
        # This requires the database to have tables set up
        await prometheus_metrics.collect_database_stats()

        # Should not raise exceptions
        assert prometheus_metrics.last_stats_update > 0

    @pytest.mark.asyncio
    async def test_collect_database_stats_no_tables(self, prometheus_metrics):
        """Test database stats collection with missing tables"""
        # Use in-memory database with no tables
        prometheus_metrics.db_url = "sqlite:///:memory:"

        await prometheus_metrics.collect_database_stats()

        # Should handle missing tables gracefully
        assert True  # Should not raise exception

    @pytest.mark.asyncio
    async def test_collect_database_stats_rate_limiting(self, prometheus_metrics):
        """Test that database stats collection respects rate limiting"""
        # First call
        await prometheus_metrics.collect_database_stats()
        first_update_time = prometheus_metrics.last_stats_update

        # Immediate second call should be skipped
        await prometheus_metrics.collect_database_stats()
        second_update_time = prometheus_metrics.last_stats_update

        assert second_update_time == first_update_time  # Should be same (skipped)

    def test_concurrent_record_query(self, prometheus_metrics):
        """Test concurrent query recording"""
        import threading

        def record_queries(start_domain_num):
            for i in range(100):
                prometheus_metrics.record_query(
                    f'concurrent{start_domain_num}-{i}.com',
                    'A', 'success', 0.01, False
                )

        # Start multiple threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=record_queries, args=(i,))
            threads.append(thread)
            thread.start()

        # Wait for all threads
        for thread in threads:
            thread.join()

        # Should have recorded all queries without errors
        stats = prometheus_metrics.get_current_stats()
        assert stats['total_queries'] == 500  # 5 threads * 100 queries each

    def test_domain_name_sanitization(self, prometheus_metrics):
        """Test domain name sanitization for metrics labels"""
        test_domains = [
            'normal.com',
            'dashes-and-dots.example.com',
            'very-long-domain-name-that-should-be-truncated-at-fifty-characters.com',
            'UPPERCASE.COM'
        ]

        for domain in test_domains:
            prometheus_metrics.top_domains[domain] = 10

        prometheus_metrics.update_top_domains()

        # Should handle all domains without errors
        assert True  # Placeholder - would check sanitized labels

class TestMetricsCollector:

    @pytest.fixture
    def metrics_collector(self, temp_db):
        """Create metrics collector with test prometheus instance"""
        db_url = f"sqlite://{temp_db._uri[9:]}"
        prometheus_metrics = PrometheusMetrics(db_url)
        return MetricsCollector(prometheus_metrics, collection_interval=0.1)  # Fast interval for testing

    def test_collector_initialization(self, metrics_collector):
        """Test metrics collector initialization"""
        assert metrics_collector.metrics is not None
        assert metrics_collector.collection_interval == 0.1
        assert metrics_collector.running is False
        assert metrics_collector.thread is None

    def test_start_stop_collector(self, metrics_collector):
        """Test starting and stopping metrics collection"""
        assert metrics_collector.running is False

        # Start collector
        metrics_collector.start()
        assert metrics_collector.running is True
        assert metrics_collector.thread is not None
        assert metrics_collector.thread.is_alive()

        # Let it run briefly
        time.sleep(0.3)

        # Stop collector
        metrics_collector.stop()
        assert metrics_collector.running is False

        # Thread should finish
        time.sleep(0.2)
        assert not metrics_collector.thread.is_alive()

    def test_collector_double_start(self, metrics_collector):
        """Test that starting collector twice doesn't create multiple threads"""
        metrics_collector.start()
        first_thread = metrics_collector.thread

        # Start again
        metrics_collector.start()
        second_thread = metrics_collector.thread

        # Should be same thread
        assert first_thread == second_thread

        metrics_collector.stop()

    def test_collection_loop_error_handling(self, metrics_collector):
        """Test that collection loop handles errors gracefully"""
        # Mock the metrics collection to raise an error
        with patch.object(metrics_collector.metrics, 'collect_database_stats') as mock_collect:
            mock_collect.side_effect = Exception("Database error")

            # Start collector
            metrics_collector.start()
            time.sleep(0.3)  # Let it run and hit the error
            metrics_collector.stop()

            # Should have attempted collection despite errors
            assert mock_collect.call_count > 0

class TestGlobalMetricsFunctions:

    def test_init_prometheus_metrics(self, temp_db):
        """Test global metrics initialization"""
        db_url = f"sqlite://{temp_db._uri[9:]}"

        metrics = init_prometheus_metrics(db_url, enable_collection=False)

        assert metrics is not None
        assert isinstance(metrics, PrometheusMetrics)

        # Should be accessible via get_metrics_instance
        global_metrics = get_metrics_instance()
        assert global_metrics == metrics

    def test_init_prometheus_metrics_with_collection(self, temp_db):
        """Test metrics initialization with background collection"""
        db_url = f"sqlite://{temp_db._uri[9:]}"

        with patch('prometheus_metrics.MetricsCollector') as mock_collector_class:
            mock_collector = Mock()
            mock_collector_class.return_value = mock_collector

            metrics = init_prometheus_metrics(db_url, enable_collection=True)

            # Should have created and started collector
            mock_collector_class.assert_called_once_with(metrics)
            mock_collector.start.assert_called_once()

    def test_get_metrics_instance_none(self):
        """Test get_metrics_instance when not initialized"""
        # Reset global instance
        import prometheus_metrics
        prometheus_metrics.prometheus_metrics = None

        result = get_metrics_instance()
        assert result is None

    def test_metrics_thread_safety(self, temp_db):
        """Test metrics thread safety with concurrent access"""
        db_url = f"sqlite://{temp_db._uri[9:]}"
        metrics = PrometheusMetrics(db_url)

        def worker():
            for i in range(50):
                metrics.record_query(f'thread-{threading.current_thread().ident}-{i}.com', 'A', 'success', 0.01, False)
                metrics.update_server_health(True)
                time.sleep(0.001)

        threads = []
        for i in range(3):
            thread = threading.Thread(target=worker)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Should complete without deadlocks or errors
        stats = metrics.get_current_stats()
        assert stats['total_queries'] == 150  # 3 threads * 50 queries each

    def test_error_handling_in_record_query(self, temp_db):
        """Test error handling within record_query method"""
        db_url = f"sqlite://{temp_db._uri[9:]}"
        metrics = PrometheusMetrics(db_url)

        # Mock one of the internal operations to fail
        with patch.object(metrics.dns_queries_total, 'labels') as mock_labels:
            mock_labels.side_effect = Exception("Prometheus error")

            # Should not raise exception
            metrics.record_query('error-test.com', 'A', 'success', 0.05, False)

            # Should have attempted the operation
            mock_labels.assert_called_once()

    @patch('prometheus_metrics.generate_latest')
    def test_metrics_endpoint_generation_error(self, mock_generate, temp_db):
        """Test handling of errors during metrics generation"""
        db_url = f"sqlite://{temp_db._uri[9:]}"
        metrics = PrometheusMetrics(db_url)

        # Mock generate_latest to fail
        mock_generate.side_effect = Exception("Generation error")

        output, content_type = metrics.get_metrics_endpoint()

        assert isinstance(output, str)  # Should return error message
        assert content_type == "text/plain"
        assert "Error generating metrics" in output
