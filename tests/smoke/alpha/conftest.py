"""
Alpha (Local Development) Smoke Test Configuration
Full comprehensive testing against local Docker Compose environment
"""

import os
import pytest
import requests
import time
from typing import Dict, Optional, Generator
from dataclasses import dataclass


@dataclass
class AlphaConfig:
    """Alpha environment configuration - Local Docker Compose"""

    # Service URLs - Local development
    dns_server_url: str = os.getenv("ALPHA_DNS_SERVER_URL", "http://localhost:8080")
    web_console_url: str = os.getenv("ALPHA_WEB_CONSOLE_URL", "http://localhost:8005")
    manager_backend_url: str = os.getenv("ALPHA_MANAGER_URL", "http://localhost:5000")
    dns_client_host: str = os.getenv("ALPHA_DNS_CLIENT_HOST", "localhost")
    dns_client_port: int = int(os.getenv("ALPHA_DNS_CLIENT_PORT", "5353"))

    # Valkey/Redis (local)
    valkey_url: str = os.getenv("ALPHA_VALKEY_URL", "redis://localhost:6379")

    # Test credentials - Local development
    admin_email: str = os.getenv("ALPHA_ADMIN_EMAIL", "admin@localhost")
    admin_password: str = os.getenv("ALPHA_ADMIN_PASSWORD", "admin123")
    manager_admin_user: str = os.getenv("ALPHA_MANAGER_USER", "admin")
    manager_admin_pass: str = os.getenv("ALPHA_MANAGER_PASS", "admin123")

    # Timeouts - Shorter for local
    request_timeout: int = int(os.getenv("ALPHA_REQUEST_TIMEOUT", "10"))
    startup_timeout: int = int(os.getenv("ALPHA_STARTUP_TIMEOUT", "60"))

    # Test intensity - Full gambit for alpha
    run_full_tests: bool = True
    run_load_tests: bool = True
    run_stress_tests: bool = True

    # Environment identifier
    environment: str = "alpha"
    environment_name: str = "Local Development"


@pytest.fixture(scope="session")
def config() -> AlphaConfig:
    """Provide alpha environment configuration"""
    return AlphaConfig()


@pytest.fixture(scope="session")
def http_session() -> Generator[requests.Session, None, None]:
    """Provide HTTP session optimized for local testing"""
    session = requests.Session()

    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    # Local environment - fewer retries, faster timeout
    retry_strategy = Retry(
        total=2,
        backoff_factor=0.3,
        status_forcelist=[500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    yield session
    session.close()


@pytest.fixture(scope="session")
def wait_for_services(config: AlphaConfig, http_session: requests.Session) -> Dict[str, bool]:
    """Wait for all local services to be available"""
    services = {
        "dns_server": (f"{config.dns_server_url}/health", "DNS Server"),
        "web_console": (f"{config.web_console_url}/health", "Web Console"),
    }

    results = {}
    start_time = time.time()

    for key, (url, name) in services.items():
        healthy = False
        while time.time() - start_time < config.startup_timeout:
            try:
                response = http_session.get(url, timeout=5)
                if response.status_code == 200:
                    healthy = True
                    print(f"[ALPHA] {name} is healthy at {url}")
                    break
            except requests.exceptions.RequestException:
                pass
            time.sleep(1)

        if not healthy:
            print(f"[ALPHA] WARNING: {name} did not become healthy at {url}")

        results[key] = healthy

    return results


@pytest.fixture(scope="session")
def web_console_session(
    config: AlphaConfig,
    http_session: requests.Session,
    wait_for_services: Dict[str, bool]
) -> Dict[str, str]:
    """Authenticate with local web console via JWT"""
    if not wait_for_services.get("web_console"):
        pytest.skip("Web console not available in alpha environment")

    login_url = f"{config.web_console_url}/api/v1/auth/login"

    try:
        response = http_session.post(
            login_url,
            json={
                "email": config.admin_email,
                "password": config.admin_password
            },
            timeout=config.request_timeout,
        )

        if response.status_code == 200:
            data = response.json()
            if data.get("success") and data.get("access_token"):
                return {
                    "authenticated": True,
                    "access_token": data["access_token"],
                    "refresh_token": data.get("refresh_token", ""),
                }
    except requests.exceptions.RequestException as e:
        print(f"[ALPHA] Auth failed: {e}")

    return {"authenticated": False, "access_token": "", "refresh_token": ""}


@pytest.fixture(scope="session")
def manager_auth_token(
    config: AlphaConfig,
    http_session: requests.Session
) -> Optional[str]:
    """Authenticate with local manager backend"""
    login_url = f"{config.manager_backend_url}/api/v1/auth/login"

    try:
        response = http_session.post(
            login_url,
            json={
                "username": config.manager_admin_user,
                "password": config.manager_admin_pass
            },
            timeout=config.request_timeout
        )

        if response.status_code == 200:
            return response.json().get("accessToken")
    except requests.exceptions.RequestException:
        pass

    return None


@pytest.fixture
def authenticated_client(http_session, web_console_session, config):
    """Authenticated client for web console using JWT Bearer token"""
    class AuthenticatedClient:
        def __init__(self):
            self.session = http_session
            self.token = web_console_session.get("access_token", "")
            self.base_url = config.web_console_url
            self.timeout = config.request_timeout
            self.environment = "alpha"
            self.headers = {}
            if self.token:
                self.headers["Authorization"] = f"Bearer {self.token}"

        def get(self, path: str, **kwargs) -> requests.Response:
            headers = kwargs.pop("headers", {})
            headers.update(self.headers)
            kwargs["headers"] = headers
            kwargs.setdefault("timeout", self.timeout)
            return self.session.get(f"{self.base_url}{path}", **kwargs)

        def post(self, path: str, **kwargs) -> requests.Response:
            headers = kwargs.pop("headers", {})
            headers.update(self.headers)
            kwargs["headers"] = headers
            kwargs.setdefault("timeout", self.timeout)
            return self.session.post(f"{self.base_url}{path}", **kwargs)

        def put(self, path: str, **kwargs) -> requests.Response:
            headers = kwargs.pop("headers", {})
            headers.update(self.headers)
            kwargs["headers"] = headers
            kwargs.setdefault("timeout", self.timeout)
            return self.session.put(f"{self.base_url}{path}", **kwargs)

        def delete(self, path: str, **kwargs) -> requests.Response:
            headers = kwargs.pop("headers", {})
            headers.update(self.headers)
            kwargs["headers"] = headers
            kwargs.setdefault("timeout", self.timeout)
            return self.session.delete(f"{self.base_url}{path}", **kwargs)

    return AuthenticatedClient()


@pytest.fixture
def manager_client(http_session, manager_auth_token, config):
    """Authenticated client for manager backend"""
    class ManagerClient:
        def __init__(self):
            self.session = http_session
            self.token = manager_auth_token
            self.base_url = config.manager_backend_url
            self.timeout = config.request_timeout
            self.headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
            self.environment = "alpha"

        def get(self, path: str, **kwargs) -> requests.Response:
            headers = kwargs.pop("headers", {})
            headers.update(self.headers)
            kwargs["headers"] = headers
            kwargs.setdefault("timeout", self.timeout)
            return self.session.get(f"{self.base_url}{path}", **kwargs)

        def post(self, path: str, **kwargs) -> requests.Response:
            headers = kwargs.pop("headers", {})
            headers.update(self.headers)
            kwargs["headers"] = headers
            kwargs.setdefault("timeout", self.timeout)
            return self.session.post(f"{self.base_url}{path}", **kwargs)

        def put(self, path: str, **kwargs) -> requests.Response:
            headers = kwargs.pop("headers", {})
            headers.update(self.headers)
            kwargs["headers"] = headers
            kwargs.setdefault("timeout", self.timeout)
            return self.session.put(f"{self.base_url}{path}", **kwargs)

        def delete(self, path: str, **kwargs) -> requests.Response:
            headers = kwargs.pop("headers", {})
            headers.update(self.headers)
            kwargs["headers"] = headers
            kwargs.setdefault("timeout", self.timeout)
            return self.session.delete(f"{self.base_url}{path}", **kwargs)

    return ManagerClient()


def pytest_configure(config):
    """Configure alpha test markers"""
    config.addinivalue_line("markers", "alpha: Alpha (local) environment tests")
    config.addinivalue_line("markers", "full: Full comprehensive tests")
    config.addinivalue_line("markers", "local: Local-only tests")
