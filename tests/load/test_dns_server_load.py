"""
DNS Server Load Tests
Tests DNS server performance under load
"""

import pytest
import time
from .conftest import run_load_test, LoadTestResult


@pytest.mark.load
@pytest.mark.performance
class TestDNSServerLoad:
    """Load tests for DNS server"""

    def test_health_endpoint_under_load(self, load_config):
        """Health endpoint handles concurrent requests"""
        url = f"{load_config.dns_server_url}/health"

        result = run_load_test(
            url=url,
            method="GET",
            concurrent_users=load_config.concurrent_users,
            requests_per_user=load_config.requests_per_user,
            timeout=load_config.request_timeout
        )

        print(f"\nLoad Test Results: {result.summary()}")

        # Assertions
        assert result.error_rate <= load_config.max_error_rate, \
            f"Error rate {result.error_rate:.2%} exceeds {load_config.max_error_rate:.2%}"

        assert result.avg_response_ms <= load_config.max_avg_response_ms, \
            f"Avg response {result.avg_response_ms:.2f}ms exceeds {load_config.max_avg_response_ms}ms"

    def test_dns_query_under_load(self, load_config):
        """DNS query endpoint handles concurrent requests"""
        url = f"{load_config.dns_server_url}/dns-query"

        result = run_load_test(
            url=url,
            method="GET",
            concurrent_users=load_config.concurrent_users,
            requests_per_user=load_config.requests_per_user // 2,  # Fewer requests
            timeout=load_config.request_timeout,
            params={"name": "google.com", "type": "A"}
        )

        print(f"\nDNS Query Load Test Results: {result.summary()}")

        # DNS queries may fail auth but should not error
        # Allow higher error rate for auth failures
        assert result.error_rate <= 0.10, \
            f"Error rate {result.error_rate:.2%} exceeds 10%"

    def test_concurrent_different_domains(self, load_config):
        """Server handles queries for different domains concurrently"""
        url = f"{load_config.dns_server_url}/dns-query"
        domains = [
            "google.com", "facebook.com", "amazon.com",
            "microsoft.com", "apple.com", "netflix.com",
            "cloudflare.com", "github.com", "stackoverflow.com"
        ]

        results = []
        for domain in domains:
            result = run_load_test(
                url=url,
                method="GET",
                concurrent_users=2,
                requests_per_user=10,
                timeout=load_config.request_timeout,
                params={"name": domain, "type": "A"}
            )
            results.append((domain, result))

        # All domains should be handled
        for domain, result in results:
            print(f"{domain}: {result.summary()}")

        total_success = sum(r.successful_requests for _, r in results)
        total_requests = sum(r.total_requests for _, r in results)

        # Overall success rate should be reasonable
        success_rate = total_success / total_requests if total_requests > 0 else 0
        assert success_rate >= 0.5, f"Success rate {success_rate:.2%} too low"


@pytest.mark.load
@pytest.mark.performance
class TestDNSServerPerformance:
    """Performance tests for DNS server"""

    def test_response_time_percentiles(self, load_config):
        """Response time percentiles are within limits"""
        url = f"{load_config.dns_server_url}/health"

        result = run_load_test(
            url=url,
            method="GET",
            concurrent_users=20,
            requests_per_user=50,
            timeout=load_config.request_timeout
        )

        print(f"\nPercentile Results:")
        print(f"  P50: {result.p50_response_ms:.2f}ms")
        print(f"  P95: {result.p95_response_ms:.2f}ms")
        print(f"  P99: {result.p99_response_ms:.2f}ms")

        assert result.p95_response_ms <= load_config.max_p95_response_ms, \
            f"P95 {result.p95_response_ms:.2f}ms exceeds {load_config.max_p95_response_ms}ms"

    def test_sustained_load(self, load_config):
        """Server maintains performance under sustained load"""
        url = f"{load_config.dns_server_url}/health"

        # Run multiple rounds
        rounds = 3
        round_results = []

        for i in range(rounds):
            result = run_load_test(
                url=url,
                method="GET",
                concurrent_users=load_config.concurrent_users,
                requests_per_user=load_config.requests_per_user // 2,
                timeout=load_config.request_timeout
            )
            round_results.append(result)
            print(f"Round {i+1}: {result.summary()}")
            time.sleep(1)  # Brief pause between rounds

        # Performance should not degrade significantly
        first_avg = round_results[0].avg_response_ms
        last_avg = round_results[-1].avg_response_ms

        # Allow 50% degradation max
        assert last_avg <= first_avg * 1.5, \
            f"Performance degraded: {first_avg:.2f}ms -> {last_avg:.2f}ms"


@pytest.mark.load
@pytest.mark.stress
@pytest.mark.slow
class TestDNSServerStress:
    """Stress tests for DNS server"""

    def test_high_concurrency(self, load_config):
        """Server handles high concurrency"""
        url = f"{load_config.dns_server_url}/health"

        # Double the normal concurrency
        result = run_load_test(
            url=url,
            method="GET",
            concurrent_users=load_config.concurrent_users * 2,
            requests_per_user=50,
            timeout=load_config.request_timeout
        )

        print(f"\nHigh Concurrency Results: {result.summary()}")

        # Should still function with some errors acceptable
        assert result.error_rate <= 0.20, \
            f"Error rate {result.error_rate:.2%} too high under stress"

    def test_burst_traffic(self, load_config):
        """Server handles burst traffic"""
        url = f"{load_config.dns_server_url}/health"

        # Short burst with many requests
        result = run_load_test(
            url=url,
            method="GET",
            concurrent_users=50,
            requests_per_user=20,
            timeout=load_config.request_timeout
        )

        print(f"\nBurst Traffic Results: {result.summary()}")
        print(f"Requests per second: {result.requests_per_second:.2f}")

        # Should handle burst without complete failure
        assert result.successful_requests > result.total_requests * 0.5, \
            "Less than 50% of requests succeeded during burst"
