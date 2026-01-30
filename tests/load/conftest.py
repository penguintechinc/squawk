"""
Load Test Configuration and Fixtures
Provides fixtures for load and performance testing
"""

import os
import pytest
import requests
import time
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class LoadTestConfig:
    """Load test configuration"""
    dns_server_url: str = os.getenv("DNS_SERVER_URL", "http://localhost:8080")
    web_console_url: str = os.getenv("WEB_CONSOLE_URL", "http://localhost:8005")

    # Load test parameters
    concurrent_users: int = int(os.getenv("LOAD_CONCURRENT_USERS", "10"))
    requests_per_user: int = int(os.getenv("LOAD_REQUESTS_PER_USER", "100"))
    ramp_up_seconds: int = int(os.getenv("LOAD_RAMP_UP_SECONDS", "5"))

    # Performance thresholds
    max_avg_response_ms: float = float(os.getenv("LOAD_MAX_AVG_RESPONSE_MS", "500"))
    max_p95_response_ms: float = float(os.getenv("LOAD_MAX_P95_RESPONSE_MS", "1000"))
    max_error_rate: float = float(os.getenv("LOAD_MAX_ERROR_RATE", "0.05"))  # 5%

    request_timeout: int = int(os.getenv("REQUEST_TIMEOUT", "30"))


@dataclass
class LoadTestResult:
    """Results from a load test"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    response_times: List[float] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    start_time: float = 0
    end_time: float = 0

    @property
    def duration_seconds(self) -> float:
        return self.end_time - self.start_time

    @property
    def requests_per_second(self) -> float:
        if self.duration_seconds > 0:
            return self.total_requests / self.duration_seconds
        return 0

    @property
    def error_rate(self) -> float:
        if self.total_requests > 0:
            return self.failed_requests / self.total_requests
        return 0

    @property
    def avg_response_ms(self) -> float:
        if self.response_times:
            return statistics.mean(self.response_times) * 1000
        return 0

    @property
    def p50_response_ms(self) -> float:
        if self.response_times:
            return statistics.median(self.response_times) * 1000
        return 0

    @property
    def p95_response_ms(self) -> float:
        if len(self.response_times) >= 20:
            sorted_times = sorted(self.response_times)
            p95_index = int(len(sorted_times) * 0.95)
            return sorted_times[p95_index] * 1000
        return self.avg_response_ms

    @property
    def p99_response_ms(self) -> float:
        if len(self.response_times) >= 100:
            sorted_times = sorted(self.response_times)
            p99_index = int(len(sorted_times) * 0.99)
            return sorted_times[p99_index] * 1000
        return self.p95_response_ms

    def summary(self) -> Dict:
        return {
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "duration_seconds": round(self.duration_seconds, 2),
            "requests_per_second": round(self.requests_per_second, 2),
            "error_rate": round(self.error_rate * 100, 2),
            "avg_response_ms": round(self.avg_response_ms, 2),
            "p50_response_ms": round(self.p50_response_ms, 2),
            "p95_response_ms": round(self.p95_response_ms, 2),
            "p99_response_ms": round(self.p99_response_ms, 2)
        }


@pytest.fixture(scope="session")
def load_config() -> LoadTestConfig:
    """Provide load test configuration"""
    return LoadTestConfig()


@pytest.fixture(scope="session")
def http_session() -> requests.Session:
    """Provide HTTP session for load tests"""
    session = requests.Session()

    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    # Configure for high concurrency
    adapter = HTTPAdapter(
        pool_connections=100,
        pool_maxsize=100,
        max_retries=Retry(total=0)  # No retries for load tests
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    return session


def run_load_test(
    url: str,
    method: str = "GET",
    concurrent_users: int = 10,
    requests_per_user: int = 100,
    timeout: int = 30,
    params: dict = None,
    json_data: dict = None
) -> LoadTestResult:
    """Execute a load test and return results"""
    result = LoadTestResult()
    result.start_time = time.time()

    def make_request(request_id: int) -> tuple:
        """Make a single request and return (success, response_time, error)"""
        session = requests.Session()
        start = time.time()
        try:
            if method == "GET":
                response = session.get(url, params=params, timeout=timeout)
            else:
                response = session.post(url, json=json_data, timeout=timeout)

            elapsed = time.time() - start
            success = response.status_code in [200, 201, 401, 403]
            return (success, elapsed, None if success else f"Status {response.status_code}")
        except Exception as e:
            elapsed = time.time() - start
            return (False, elapsed, str(e))
        finally:
            session.close()

    # Run concurrent requests
    total_requests = concurrent_users * requests_per_user

    with ThreadPoolExecutor(max_workers=concurrent_users) as executor:
        futures = [
            executor.submit(make_request, i)
            for i in range(total_requests)
        ]

        for future in as_completed(futures):
            success, response_time, error = future.result()
            result.total_requests += 1
            result.response_times.append(response_time)

            if success:
                result.successful_requests += 1
            else:
                result.failed_requests += 1
                if error:
                    result.errors.append(error)

    result.end_time = time.time()
    return result


# Markers
def pytest_configure(config):
    """Configure custom pytest markers"""
    config.addinivalue_line("markers", "load: mark test as load test")
    config.addinivalue_line("markers", "performance: mark test as performance test")
    config.addinivalue_line("markers", "stress: mark test as stress test")
    config.addinivalue_line("markers", "slow: mark test as slow running")
