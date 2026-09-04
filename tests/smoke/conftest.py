"""
Smoke Test Configuration and Fixtures
Provides shared fixtures for all smoke tests
"""

import os
import pytest
import requests
import time
from typing import Dict, Optional, Generator
from dataclasses import dataclass


# Service configuration from environment or defaults
@dataclass
class ServiceConfig:
    """Service endpoint configuration"""
    dns_server_url: str = os.getenv("DNS_SERVER_URL", "http://localhost:8080")
    web_console_url: str = os.getenv("WEB_CONSOLE_URL", "http://localhost:8005")
    manager_backend_url: str = os.getenv("MANAGER_BACKEND_URL", "http://localhost:5000")
    dns_client_url: str = os.getenv("DNS_CLIENT_URL", "localhost:5353")

    # Test credentials
    admin_email: str = os.getenv("TEST_ADMIN_EMAIL", "admin@localhost")
    admin_password: str = os.getenv("TEST_ADMIN_PASSWORD", "admin123")

    # Manager credentials
    manager_admin_user: str = os.getenv("MANAGER_ADMIN_USER", "admin")
    manager_admin_pass: str = os.getenv("MANAGER_ADMIN_PASS", "admin123")

    # Timeouts
    request_timeout: int = int(os.getenv("REQUEST_TIMEOUT", "10"))
    startup_timeout: int = int(os.getenv("STARTUP_TIMEOUT", "60"))


@pytest.fixture(scope="session")
def config() -> ServiceConfig:
    """Provide service configuration"""
    return ServiceConfig()


def _create_session_with_retries() -> requests.Session:
    """Create a new session with retry configuration"""
    session = requests.Session()

    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    retry_strategy = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    return session


@pytest.fixture(scope="session")
def http_session() -> Generator[requests.Session, None, None]:
    """Provide a shared HTTP session with retries (may have auth cookies)"""
    session = _create_session_with_retries()
    yield session
    session.close()


@pytest.fixture
def fresh_http_session() -> Generator[requests.Session, None, None]:
    """
    Provide a fresh HTTP session WITHOUT any cookies.
    Use this for testing unauthenticated access.
    """
    session = _create_session_with_retries()
    yield session
    session.close()


@pytest.fixture(scope="session")
def wait_for_services(config: ServiceConfig, http_session: requests.Session) -> bool:
    """Wait for all services to be available"""
    services = [
        (config.dns_server_url + "/health", "DNS Server"),
        (config.web_console_url + "/health", "Web Console"),
    ]

    start_time = time.time()
    all_healthy = True

    for url, name in services:
        healthy = False
        while time.time() - start_time < config.startup_timeout:
            try:
                response = http_session.get(url, timeout=5)
                if response.status_code == 200:
                    healthy = True
                    print(f"{name} is healthy")
                    break
            except requests.exceptions.RequestException:
                pass
            time.sleep(1)

        if not healthy:
            print(f"WARNING: {name} did not become healthy")
            all_healthy = False

    return all_healthy


@pytest.fixture(scope="session")
def web_console_session(
    config: ServiceConfig,
    http_session: requests.Session,
    wait_for_services: bool
) -> Dict[str, str]:
    """
    Authenticate with web console API and return JWT tokens.
    Returns dict with 'access_token' and 'refresh_token' for authenticated requests.
    """
    login_url = f"{config.web_console_url}/api/v1/auth/login"

    # Perform login with JSON credentials
    login_data = {
        "email": config.admin_email,
        "password": config.admin_password
    }

    try:
        response = http_session.post(
            login_url,
            json=login_data,
            timeout=config.request_timeout
        )

        if response.status_code == 200:
            data = response.json()
            if data.get("success"):
                return {
                    "access_token": data.get("access_token", ""),
                    "refresh_token": data.get("refresh_token", "")
                }
            else:
                pytest.skip(f"Login unsuccessful: {data}")
        else:
            pytest.skip(f"Login failed with status {response.status_code}")
    except requests.exceptions.RequestException as e:
        pytest.skip(f"Could not authenticate: {e}")


@pytest.fixture(scope="session")
def manager_auth_token(
    config: ServiceConfig,
    http_session: requests.Session
) -> Optional[str]:
    """
    Authenticate with manager backend and return JWT token.
    """
    login_url = f"{config.manager_backend_url}/api/v1/auth/login"

    login_data = {
        "username": config.manager_admin_user,
        "password": config.manager_admin_pass
    }

    try:
        response = http_session.post(
            login_url,
            json=login_data,
            timeout=config.request_timeout
        )

        if response.status_code == 200:
            data = response.json()
            return data.get("accessToken")
    except requests.exceptions.RequestException:
        pass

    return None


@pytest.fixture
def authenticated_client(
    http_session: requests.Session,
    web_console_session: Dict[str, str],
    config: ServiceConfig
):
    """Provide authenticated HTTP client for web console API with JWT Bearer token"""
    class AuthenticatedClient:
        def __init__(self):
            self.session = http_session
            self.token = web_console_session.get("access_token", "")
            self.base_url = config.web_console_url
            self.timeout = config.request_timeout
            self.headers = {}
            if self.token:
                self.headers["Authorization"] = f"Bearer {self.token}"

        def get(self, path: str, **kwargs) -> requests.Response:
            url = f"{self.base_url}{path}"
            headers = kwargs.pop("headers", {})
            headers.update(self.headers)
            kwargs["headers"] = headers
            kwargs.setdefault("timeout", self.timeout)
            return self.session.get(url, **kwargs)

        def post(self, path: str, **kwargs) -> requests.Response:
            url = f"{self.base_url}{path}"
            headers = kwargs.pop("headers", {})
            headers.update(self.headers)
            kwargs["headers"] = headers
            kwargs.setdefault("timeout", self.timeout)
            return self.session.post(url, **kwargs)

        def put(self, path: str, **kwargs) -> requests.Response:
            url = f"{self.base_url}{path}"
            headers = kwargs.pop("headers", {})
            headers.update(self.headers)
            kwargs["headers"] = headers
            kwargs.setdefault("timeout", self.timeout)
            return self.session.put(url, **kwargs)

        def delete(self, path: str, **kwargs) -> requests.Response:
            url = f"{self.base_url}{path}"
            headers = kwargs.pop("headers", {})
            headers.update(self.headers)
            kwargs["headers"] = headers
            kwargs.setdefault("timeout", self.timeout)
            return self.session.delete(url, **kwargs)

    return AuthenticatedClient()


@pytest.fixture
def manager_client(
    http_session: requests.Session,
    manager_auth_token: Optional[str],
    config: ServiceConfig
):
    """Provide authenticated HTTP client for manager backend"""
    class ManagerClient:
        def __init__(self):
            self.session = http_session
            self.token = manager_auth_token
            self.base_url = config.manager_backend_url
            self.timeout = config.request_timeout
            self.headers = {}
            if self.token:
                self.headers["Authorization"] = f"Bearer {self.token}"

        def get(self, path: str, **kwargs) -> requests.Response:
            url = f"{self.base_url}{path}"
            headers = kwargs.pop("headers", {})
            headers.update(self.headers)
            kwargs["headers"] = headers
            kwargs.setdefault("timeout", self.timeout)
            return self.session.get(url, **kwargs)

        def post(self, path: str, **kwargs) -> requests.Response:
            url = f"{self.base_url}{path}"
            headers = kwargs.pop("headers", {})
            headers.update(self.headers)
            kwargs["headers"] = headers
            kwargs.setdefault("timeout", self.timeout)
            return self.session.post(url, **kwargs)

        def put(self, path: str, **kwargs) -> requests.Response:
            url = f"{self.base_url}{path}"
            headers = kwargs.pop("headers", {})
            headers.update(self.headers)
            kwargs["headers"] = headers
            kwargs.setdefault("timeout", self.timeout)
            return self.session.put(url, **kwargs)

        def delete(self, path: str, **kwargs) -> requests.Response:
            url = f"{self.base_url}{path}"
            headers = kwargs.pop("headers", {})
            headers.update(self.headers)
            kwargs["headers"] = headers
            kwargs.setdefault("timeout", self.timeout)
            return self.session.delete(url, **kwargs)

    return ManagerClient()


# Markers for test categorization
def pytest_configure(config):
    """Configure custom pytest markers"""
    config.addinivalue_line("markers", "smoke: mark test as smoke test")
    config.addinivalue_line("markers", "health: mark test as health check")
    config.addinivalue_line("markers", "page: mark test as page load test")
    config.addinivalue_line("markers", "api: mark test as API test")
    config.addinivalue_line("markers", "auth: mark test as authentication test")
    config.addinivalue_line("markers", "slow: mark test as slow running")
