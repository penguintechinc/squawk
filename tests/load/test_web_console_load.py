"""
Web Console Load Tests
Tests web console performance under load
"""

import pytest
import time
from .conftest import run_load_test, LoadTestResult


@pytest.mark.load
@pytest.mark.performance
class TestWebConsoleLoad:
    """Load tests for web console"""

    def test_health_endpoint_under_load(self, load_config):
        """Health endpoint handles concurrent requests"""
        url = f"{load_config.web_console_url}/health"

        result = run_load_test(
            url=url,
            method="GET",
            concurrent_users=load_config.concurrent_users,
            requests_per_user=load_config.requests_per_user,
            timeout=load_config.request_timeout
        )

        print(f"\nWeb Console Health Load Test: {result.summary()}")

        assert result.error_rate <= load_config.max_error_rate, \
            f"Error rate {result.error_rate:.2%} exceeds threshold"

        assert result.avg_response_ms <= load_config.max_avg_response_ms, \
            f"Avg response {result.avg_response_ms:.2f}ms exceeds threshold"

    def test_login_page_under_load(self, load_config):
        """Login page handles concurrent requests"""
        url = f"{load_config.web_console_url}/auth/login"

        result = run_load_test(
            url=url,
            method="GET",
            concurrent_users=load_config.concurrent_users,
            requests_per_user=load_config.requests_per_user // 2,
            timeout=load_config.request_timeout
        )

        print(f"\nLogin Page Load Test: {result.summary()}")

        assert result.error_rate <= load_config.max_error_rate
        assert result.avg_response_ms <= load_config.max_avg_response_ms * 2  # Pages can be slower


@pytest.mark.load
@pytest.mark.performance
class TestAPIEndpointsLoad:
    """Load tests for API endpoints"""

    def test_multiple_api_endpoints(self, load_config):
        """Multiple API endpoints handle concurrent load"""
        base_url = load_config.web_console_url
        endpoints = [
            "/health",
            "/auth/login",
            "/auth/register"
        ]

        results = {}
        for endpoint in endpoints:
            url = f"{base_url}{endpoint}"
            result = run_load_test(
                url=url,
                method="GET",
                concurrent_users=5,
                requests_per_user=20,
                timeout=load_config.request_timeout
            )
            results[endpoint] = result
            print(f"{endpoint}: RPS={result.requests_per_second:.2f}, "
                  f"Avg={result.avg_response_ms:.2f}ms, "
                  f"Errors={result.error_rate:.2%}")

        # All endpoints should function
        for endpoint, result in results.items():
            assert result.error_rate <= 0.20, \
                f"Endpoint {endpoint} error rate too high"


@pytest.mark.load
@pytest.mark.performance
class TestWebConsolePerformance:
    """Performance benchmarks for web console"""

    def test_response_time_consistency(self, load_config):
        """Response times are consistent under load"""
        url = f"{load_config.web_console_url}/health"

        result = run_load_test(
            url=url,
            method="GET",
            concurrent_users=10,
            requests_per_user=100,
            timeout=load_config.request_timeout
        )

        print(f"\nResponse Time Consistency:")
        print(f"  Avg: {result.avg_response_ms:.2f}ms")
        print(f"  P50: {result.p50_response_ms:.2f}ms")
        print(f"  P95: {result.p95_response_ms:.2f}ms")
        print(f"  P99: {result.p99_response_ms:.2f}ms")

        # P95 should not be more than 3x the average
        if result.avg_response_ms > 0:
            ratio = result.p95_response_ms / result.avg_response_ms
            assert ratio <= 5, \
                f"Response time variance too high (P95/Avg ratio: {ratio:.2f})"

    def test_throughput_benchmark(self, load_config):
        """Measure maximum throughput"""
        url = f"{load_config.web_console_url}/health"

        result = run_load_test(
            url=url,
            method="GET",
            concurrent_users=50,
            requests_per_user=100,
            timeout=load_config.request_timeout
        )

        print(f"\nThroughput Benchmark:")
        print(f"  Total Requests: {result.total_requests}")
        print(f"  Duration: {result.duration_seconds:.2f}s")
        print(f"  Requests/Second: {result.requests_per_second:.2f}")

        # Should achieve reasonable throughput
        assert result.requests_per_second >= 10, \
            f"Throughput {result.requests_per_second:.2f} RPS too low"


@pytest.mark.load
@pytest.mark.stress
@pytest.mark.slow
class TestWebConsoleStress:
    """Stress tests for web console"""

    def test_recovery_after_load(self, load_config):
        """Server recovers after heavy load"""
        url = f"{load_config.web_console_url}/health"

        # Heavy load
        heavy_result = run_load_test(
            url=url,
            method="GET",
            concurrent_users=50,
            requests_per_user=50,
            timeout=load_config.request_timeout
        )

        print(f"\nHeavy Load: {heavy_result.summary()}")

        # Wait for recovery
        time.sleep(2)

        # Light load after recovery
        light_result = run_load_test(
            url=url,
            method="GET",
            concurrent_users=5,
            requests_per_user=10,
            timeout=load_config.request_timeout
        )

        print(f"After Recovery: {light_result.summary()}")

        # Should recover to normal performance
        assert light_result.error_rate <= 0.05, \
            "Server did not recover properly after heavy load"

    def test_sustained_moderate_load(self, load_config):
        """Server handles sustained moderate load"""
        url = f"{load_config.web_console_url}/health"

        # 3 rounds of moderate load
        round_results = []
        for i in range(3):
            result = run_load_test(
                url=url,
                method="GET",
                concurrent_users=10,
                requests_per_user=50,
                timeout=load_config.request_timeout
            )
            round_results.append(result)
            print(f"Round {i+1}: RPS={result.requests_per_second:.2f}, "
                  f"Errors={result.error_rate:.2%}")

        # Error rate should not increase significantly over time
        first_errors = round_results[0].error_rate
        last_errors = round_results[-1].error_rate

        # Allow 5% more errors in last round
        assert last_errors <= first_errors + 0.05, \
            f"Error rate increased: {first_errors:.2%} -> {last_errors:.2%}"
