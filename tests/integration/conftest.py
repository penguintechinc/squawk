"""
Integration Test Configuration and Fixtures
Provides fixtures for testing component interactions
"""

import os
import sys
import pytest
import requests
import tempfile
import shutil
from typing import Generator


# Service configuration
DNS_SERVER_URL = os.getenv("DNS_SERVER_URL", "http://localhost:8080")
WEB_CONSOLE_URL = os.getenv("WEB_CONSOLE_URL", "http://localhost:8005")
MANAGER_URL = os.getenv("MANAGER_BACKEND_URL", "http://localhost:5000")
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))


@pytest.fixture(scope="session")
def http_session() -> Generator[requests.Session, None, None]:
    """Provide a shared HTTP session"""
    session = requests.Session()

    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    yield session
    session.close()


@pytest.fixture(scope="session")
def temp_directory() -> Generator[str, None, None]:
    """Provide a temporary directory for test files"""
    temp_dir = tempfile.mkdtemp(prefix="squawk_test_")
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture(scope="session")
def web_console_auth(http_session) -> dict:
    """Authenticate with web console and return session"""
    login_url = f"{WEB_CONSOLE_URL}/auth/login"

    try:
        # Get login page
        http_session.get(login_url, timeout=REQUEST_TIMEOUT)

        # Login
        response = http_session.post(
            login_url,
            data={
                "email": "admin@localhost",
                "password": "admin123"
            },
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False
        )

        if response.status_code in [302, 303]:
            return {"authenticated": True, "cookies": dict(http_session.cookies)}

    except requests.exceptions.RequestException:
        pass

    return {"authenticated": False, "cookies": {}}


@pytest.fixture(scope="session")
def manager_auth(http_session) -> dict:
    """Authenticate with manager and return token"""
    login_url = f"{MANAGER_URL}/api/v1/auth/login"

    try:
        response = http_session.post(
            login_url,
            json={
                "username": "admin",
                "password": "admin123"
            },
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code == 200:
            data = response.json()
            return {
                "authenticated": True,
                "access_token": data.get("accessToken"),
                "refresh_token": data.get("refreshToken")
            }

    except requests.exceptions.RequestException:
        pass

    return {"authenticated": False}


# Markers
def pytest_configure(config):
    """Configure custom pytest markers"""
    config.addinivalue_line("markers", "integration: mark test as integration test")
    config.addinivalue_line("markers", "slow: mark test as slow running")
    config.addinivalue_line("markers", "database: mark test as requiring database")
    config.addinivalue_line("markers", "network: mark test as requiring network")
