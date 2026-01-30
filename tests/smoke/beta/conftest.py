"""
Beta (dal2.penguintech.io K8s Cluster) Smoke Test Configuration
Post-deployment verification against internal Kubernetes cluster
"""

import os
import pytest
import requests
import time
from typing import Dict, Optional, Generator
from dataclasses import dataclass


@dataclass
class BetaConfig:
    """Beta environment configuration - dal2.penguintech.io K8s cluster"""

    # Service URLs - K8s cluster endpoints
    # Format: https://<service>.squawk.dal2.penguintech.io
    base_domain: str = os.getenv("BETA_BASE_DOMAIN", "squawk.dal2.penguintech.io")

    dns_server_url: str = os.getenv(
        "BETA_DNS_SERVER_URL",
        "https://dns.squawk.dal2.penguintech.io"
    )
    web_console_url: str = os.getenv(
        "BETA_WEB_CONSOLE_URL",
        "https://console.squawk.dal2.penguintech.io"
    )
    manager_backend_url: str = os.getenv(
        "BETA_MANAGER_URL",
        "https://api.squawk.dal2.penguintech.io"
    )

    # Test credentials - Beta environment
    admin_email: str = os.getenv("BETA_ADMIN_EMAIL", "admin@penguintech.io")
    admin_password: str = os.getenv("BETA_ADMIN_PASSWORD", "")  # From secrets
    manager_admin_user: str = os.getenv("BETA_MANAGER_USER", "admin")
    manager_admin_pass: str = os.getenv("BETA_MANAGER_PASS", "")  # From secrets

    # Timeouts - Longer for network latency
    request_timeout: int = int(os.getenv("BETA_REQUEST_TIMEOUT", "30"))
    startup_timeout: int = int(os.getenv("BETA_STARTUP_TIMEOUT", "120"))

    # Test intensity - Lighter for deployed environment
    run_full_tests: bool = False
    run_load_tests: bool = False  # Don't stress production-like env
    run_stress_tests: bool = False

    # SSL verification
    verify_ssl: bool = os.getenv("BETA_VERIFY_SSL", "true").lower() == "true"

    # Environment identifier
    environment: str = "beta"
    environment_name: str = "dal2.penguintech.io K8s Cluster"


@pytest.fixture(scope="session")
def config() -> BetaConfig:
    """Provide beta environment configuration"""
    cfg = BetaConfig()

    # Warn if credentials not set
    if not cfg.admin_password:
        print("[BETA] WARNING: BETA_ADMIN_PASSWORD not set")
    if not cfg.manager_admin_pass:
        print("[BETA] WARNING: BETA_MANAGER_PASS not set")

    return cfg


@pytest.fixture(scope="session")
def http_session(config: BetaConfig) -> Generator[requests.Session, None, None]:
    """Provide HTTP session configured for K8s cluster"""
    session = requests.Session()

    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    # K8s environment - more retries for potential pod restarts
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    # SSL verification
    session.verify = config.verify_ssl

    yield session
    session.close()


@pytest.fixture(scope="session")
def wait_for_services(config: BetaConfig, http_session: requests.Session) -> Dict[str, bool]:
    """Wait for K8s services to be available"""
    services = {
        "dns_server": (f"{config.dns_server_url}/health", "DNS Server"),
        "web_console": (f"{config.web_console_url}/health", "Web Console"),
    }

    results = {}
    start_time = time.time()

    print(f"\n[BETA] Checking services on {config.environment_name}...")

    for key, (url, name) in services.items():
        healthy = False
        attempts = 0
        max_attempts = 5

        while attempts < max_attempts and time.time() - start_time < config.startup_timeout:
            attempts += 1
            try:
                response = http_session.get(url, timeout=10)
                if response.status_code == 200:
                    healthy = True
                    print(f"[BETA] {name} is healthy at {url}")
                    break
                else:
                    print(f"[BETA] {name} returned {response.status_code}")
            except requests.exceptions.SSLError as e:
                print(f"[BETA] {name} SSL error: {e}")
            except requests.exceptions.ConnectionError as e:
                print(f"[BETA] {name} connection error (attempt {attempts}/{max_attempts})")
            except requests.exceptions.RequestException as e:
                print(f"[BETA] {name} error: {e}")

            time.sleep(3)

        if not healthy:
            print(f"[BETA] WARNING: {name} not available at {url}")

        results[key] = healthy

    return results


@pytest.fixture(scope="session")
def web_console_session(
    config: BetaConfig,
    http_session: requests.Session,
    wait_for_services: Dict[str, bool]
) -> Dict[str, str]:
    """Authenticate with K8s-deployed web console"""
    if not wait_for_services.get("web_console"):
        pytest.skip("Web console not available in beta environment")

    if not config.admin_password:
        pytest.skip("BETA_ADMIN_PASSWORD not configured")

    login_url = f"{config.web_console_url}/auth/login"

    try:
        http_session.get(login_url, timeout=config.request_timeout)
        response = http_session.post(
            login_url,
            data={
                "email": config.admin_email,
                "password": config.admin_password
            },
            timeout=config.request_timeout,
            allow_redirects=False
        )

        if response.status_code in [302, 303]:
            print(f"[BETA] Authenticated as {config.admin_email}")
            return {"authenticated": True, "cookies": dict(http_session.cookies)}
        else:
            print(f"[BETA] Auth returned {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[BETA] Auth failed: {e}")

    return {"authenticated": False, "cookies": {}}


@pytest.fixture(scope="session")
def manager_auth_token(
    config: BetaConfig,
    http_session: requests.Session
) -> Optional[str]:
    """Authenticate with K8s-deployed manager backend"""
    if not config.manager_admin_pass:
        return None

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
            token = response.json().get("accessToken")
            print(f"[BETA] Manager authenticated as {config.manager_admin_user}")
            return token
    except requests.exceptions.RequestException as e:
        print(f"[BETA] Manager auth failed: {e}")

    return None


@pytest.fixture
def authenticated_client(http_session, web_console_session, config):
    """Authenticated client for K8s web console"""
    class AuthenticatedClient:
        def __init__(self):
            self.session = http_session
            self.cookies = web_console_session.get("cookies", {})
            self.base_url = config.web_console_url
            self.timeout = config.request_timeout
            self.environment = "beta"

        def get(self, path: str, **kwargs) -> requests.Response:
            kwargs.setdefault("cookies", self.cookies)
            kwargs.setdefault("timeout", self.timeout)
            return self.session.get(f"{self.base_url}{path}", **kwargs)

        def post(self, path: str, **kwargs) -> requests.Response:
            kwargs.setdefault("cookies", self.cookies)
            kwargs.setdefault("timeout", self.timeout)
            return self.session.post(f"{self.base_url}{path}", **kwargs)

        def put(self, path: str, **kwargs) -> requests.Response:
            kwargs.setdefault("cookies", self.cookies)
            kwargs.setdefault("timeout", self.timeout)
            return self.session.put(f"{self.base_url}{path}", **kwargs)

        def delete(self, path: str, **kwargs) -> requests.Response:
            kwargs.setdefault("cookies", self.cookies)
            kwargs.setdefault("timeout", self.timeout)
            return self.session.delete(f"{self.base_url}{path}", **kwargs)

    return AuthenticatedClient()


@pytest.fixture
def manager_client(http_session, manager_auth_token, config):
    """Authenticated client for K8s manager backend"""
    class ManagerClient:
        def __init__(self):
            self.session = http_session
            self.token = manager_auth_token
            self.base_url = config.manager_backend_url
            self.timeout = config.request_timeout
            self.headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
            self.environment = "beta"

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
    """Configure beta test markers"""
    config.addinivalue_line("markers", "beta: Beta (K8s cluster) environment tests")
    config.addinivalue_line("markers", "k8s: Kubernetes-specific tests")
    config.addinivalue_line("markers", "deployed: Post-deployment verification tests")
