"""Coverage tests for app.services.manager_client.ManagerClient.

Exercises registration, JWT refresh, config sync (including the 401 retry
loop), heartbeats, token validation, disk cache persistence, and JWT expiry
self-checks -- success paths, error status codes, and network-exception
fallbacks for each.
"""
import json
from datetime import datetime, timedelta, timezone

import jwt
import pytest
import requests

from app.services.manager_client import ManagerClient

MANAGER_URL = "http://manager.test"


@pytest.fixture
def client(tmp_path) -> ManagerClient:
    """A ManagerClient pointed at a fake manager URL with an isolated cache file.

    The cache file is redirected to a per-test tmp_path so concurrent test
    modules writing their own ManagerClient caches never collide.
    """
    c = ManagerClient(manager_url=MANAGER_URL, join_key="a" * 64)
    c.cache_file = tmp_path / "manager_cache.json"
    return c


class TestRegister:
    def test_no_join_key_returns_false(self) -> None:
        c = ManagerClient(manager_url=MANAGER_URL, join_key="")
        assert c.register() is False

    def test_success(self, client: ManagerClient, requests_mock) -> None:
        requests_mock.post(
            f"{MANAGER_URL}/api/v1/dns-servers/register",
            json={"jwt": "tok123", "serverId": "srv1", "config": {"zones": []}},
            status_code=200,
        )
        assert client.register() is True
        assert client.jwt_token == "tok123"
        assert client.server_id == "srv1"
        assert client.config_cache == {"zones": []}
        assert client.cached_at is not None
        assert client.cache_file.exists()

    def test_success_missing_config_defaults_empty(self, client: ManagerClient, requests_mock) -> None:
        requests_mock.post(
            f"{MANAGER_URL}/api/v1/dns-servers/register",
            json={"jwt": "tok123", "serverId": "srv1"},
            status_code=200,
        )
        assert client.register() is True
        assert client.config_cache == {}

    def test_failure_status_returns_false(self, client: ManagerClient, requests_mock) -> None:
        requests_mock.post(
            f"{MANAGER_URL}/api/v1/dns-servers/register",
            text="bad request",
            status_code=400,
        )
        assert client.register() is False

    def test_request_exception_returns_false(self, client: ManagerClient, requests_mock) -> None:
        requests_mock.post(
            f"{MANAGER_URL}/api/v1/dns-servers/register",
            exc=requests.exceptions.ConnectTimeout,
        )
        assert client.register() is False


class TestRefreshJwt:
    def test_no_token_triggers_register(
        self, client: ManagerClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client.jwt_token = None
        monkeypatch.setattr(client, "register", lambda: True)
        assert client.refresh_jwt() is True

    def test_success_updates_token_and_caches(self, client: ManagerClient, requests_mock) -> None:
        client.jwt_token = "old"
        client.server_id = "srv1"
        requests_mock.post(
            f"{MANAGER_URL}/api/v1/dns-servers/srv1/refresh",
            json={"jwt": "newtok"},
            status_code=200,
        )
        assert client.refresh_jwt() is True
        assert client.jwt_token == "newtok"
        assert client.cache_file.exists()

    def test_failure_status_triggers_reregister(
        self, client: ManagerClient, requests_mock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client.jwt_token = "old"
        client.server_id = "srv1"
        requests_mock.post(
            f"{MANAGER_URL}/api/v1/dns-servers/srv1/refresh",
            status_code=401,
        )
        monkeypatch.setattr(client, "register", lambda: True)
        assert client.refresh_jwt() is True

    def test_request_exception_returns_false(self, client: ManagerClient, requests_mock) -> None:
        client.jwt_token = "old"
        client.server_id = "srv1"
        requests_mock.post(
            f"{MANAGER_URL}/api/v1/dns-servers/srv1/refresh",
            exc=requests.exceptions.ConnectionError,
        )
        assert client.refresh_jwt() is False


class TestSyncConfig:
    def test_not_registered_returns_false(self, client: ManagerClient) -> None:
        client.jwt_token = None
        client.server_id = None
        assert client.sync_config() is False

    def test_success_updates_cache(self, client: ManagerClient, requests_mock) -> None:
        client.jwt_token = "tok"
        client.server_id = "srv1"
        requests_mock.get(
            f"{MANAGER_URL}/api/v1/dns-servers/srv1/config",
            json={"zones": [{"name": "a.com"}]},
            status_code=200,
        )
        assert client.sync_config() is True
        assert client.config_cache == {"zones": [{"name": "a.com"}]}
        assert client.cache_file.exists()

    def test_401_then_refresh_succeeds_retries_and_syncs(
        self, client: ManagerClient, requests_mock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client.jwt_token = "tok"
        client.server_id = "srv1"
        requests_mock.get(
            f"{MANAGER_URL}/api/v1/dns-servers/srv1/config",
            [
                {"status_code": 401},
                {"status_code": 200, "json": {"zones": []}},
            ],
        )
        monkeypatch.setattr(client, "refresh_jwt", lambda: True)
        assert client.sync_config() is True
        assert client.config_cache == {"zones": []}

    def test_401_then_refresh_fails_returns_false(
        self, client: ManagerClient, requests_mock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client.jwt_token = "tok"
        client.server_id = "srv1"
        requests_mock.get(
            f"{MANAGER_URL}/api/v1/dns-servers/srv1/config",
            status_code=401,
        )
        monkeypatch.setattr(client, "refresh_jwt", lambda: False)
        assert client.sync_config() is False

    def test_other_status_returns_false(self, client: ManagerClient, requests_mock) -> None:
        client.jwt_token = "tok"
        client.server_id = "srv1"
        requests_mock.get(
            f"{MANAGER_URL}/api/v1/dns-servers/srv1/config",
            status_code=500,
        )
        assert client.sync_config() is False

    def test_request_exception_returns_false(self, client: ManagerClient, requests_mock) -> None:
        client.jwt_token = "tok"
        client.server_id = "srv1"
        requests_mock.get(
            f"{MANAGER_URL}/api/v1/dns-servers/srv1/config",
            exc=requests.exceptions.Timeout,
        )
        assert client.sync_config() is False


class TestHeartbeat:
    def test_not_registered_returns_false(self, client: ManagerClient) -> None:
        client.jwt_token = None
        client.server_id = None
        assert client.heartbeat({"qps": 1}) is False

    def test_success_no_sync_requested(self, client: ManagerClient, requests_mock) -> None:
        client.jwt_token = "tok"
        client.server_id = "srv1"
        requests_mock.post(
            f"{MANAGER_URL}/api/v1/dns-servers/srv1/heartbeat",
            json={"shouldSync": False},
            status_code=200,
        )
        assert client.heartbeat({"qps": 1}) is True

    def test_success_triggers_sync_when_requested(
        self, client: ManagerClient, requests_mock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client.jwt_token = "tok"
        client.server_id = "srv1"
        requests_mock.post(
            f"{MANAGER_URL}/api/v1/dns-servers/srv1/heartbeat",
            json={"shouldSync": True},
            status_code=200,
        )
        called = {"sync": False}

        def fake_sync() -> bool:
            called["sync"] = True
            return True

        monkeypatch.setattr(client, "sync_config", fake_sync)
        assert client.heartbeat({"qps": 1}) is True
        assert called["sync"] is True

    def test_401_triggers_refresh_and_returns_false(
        self, client: ManagerClient, requests_mock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client.jwt_token = "tok"
        client.server_id = "srv1"
        requests_mock.post(
            f"{MANAGER_URL}/api/v1/dns-servers/srv1/heartbeat",
            status_code=401,
        )
        called = {"refresh": False}

        def fake_refresh() -> bool:
            called["refresh"] = True
            return True

        monkeypatch.setattr(client, "refresh_jwt", fake_refresh)
        assert client.heartbeat({"qps": 1}) is False
        assert called["refresh"] is True

    def test_other_status_returns_false(self, client: ManagerClient, requests_mock) -> None:
        client.jwt_token = "tok"
        client.server_id = "srv1"
        requests_mock.post(
            f"{MANAGER_URL}/api/v1/dns-servers/srv1/heartbeat",
            status_code=500,
        )
        assert client.heartbeat({"qps": 1}) is False

    def test_request_exception_returns_false(self, client: ManagerClient, requests_mock) -> None:
        client.jwt_token = "tok"
        client.server_id = "srv1"
        requests_mock.post(
            f"{MANAGER_URL}/api/v1/dns-servers/srv1/heartbeat",
            exc=requests.exceptions.ConnectionError,
        )
        assert client.heartbeat({"qps": 1}) is False


class TestValidateToken:
    def test_not_registered_returns_invalid(self, client: ManagerClient) -> None:
        client.jwt_token = None
        client.server_id = None
        assert client.validate_token("usertok", "example.com") == {"valid": False}

    def test_success_returns_manager_payload(self, client: ManagerClient, requests_mock) -> None:
        client.jwt_token = "tok"
        client.server_id = "srv1"
        requests_mock.post(
            f"{MANAGER_URL}/api/v1/tokens/validate",
            json={"valid": True, "teams": ["a"]},
            status_code=200,
        )
        assert client.validate_token("usertok", "example.com") == {"valid": True, "teams": ["a"]}

    def test_non_200_returns_invalid(self, client: ManagerClient, requests_mock) -> None:
        client.jwt_token = "tok"
        client.server_id = "srv1"
        requests_mock.post(
            f"{MANAGER_URL}/api/v1/tokens/validate",
            status_code=403,
        )
        assert client.validate_token("usertok", "example.com") == {"valid": False}

    def test_request_exception_returns_invalid(self, client: ManagerClient, requests_mock) -> None:
        client.jwt_token = "tok"
        client.server_id = "srv1"
        requests_mock.post(
            f"{MANAGER_URL}/api/v1/tokens/validate",
            exc=requests.exceptions.Timeout,
        )
        assert client.validate_token("usertok", "example.com") == {"valid": False}


class TestCachePersistence:
    def test_save_and_load_roundtrip(self, client: ManagerClient) -> None:
        client.jwt_token = "tok"
        client.server_id = "srv1"
        client.config_cache = {"zones": []}
        client.cached_at = datetime.now()
        client.save_to_cache()

        new_client = ManagerClient(manager_url=MANAGER_URL, join_key="b" * 64)
        new_client.cache_file = client.cache_file
        assert new_client.load_from_cache() is True
        assert new_client.jwt_token == "tok"
        assert new_client.server_id == "srv1"
        assert new_client.config_cache == {"zones": []}
        assert new_client.cached_at is not None

    def test_save_with_no_cached_at_writes_null(self, client: ManagerClient) -> None:
        client.jwt_token = "tok"
        client.cached_at = None
        client.save_to_cache()
        data = json.loads(client.cache_file.read_text())
        assert data["cached_at"] is None

    def test_save_handles_write_exception_without_raising(
        self, client: ManagerClient, tmp_path
    ) -> None:
        # Point the cache "file" at a directory so open(..., 'w') raises.
        client.cache_file = tmp_path
        client.save_to_cache()  # must not raise

    def test_load_missing_file_returns_false(self, client: ManagerClient, tmp_path) -> None:
        client.cache_file = tmp_path / "does_not_exist.json"
        assert client.load_from_cache() is False

    def test_load_missing_cached_at_field_sets_none(self, client: ManagerClient) -> None:
        client.cache_file.write_text(
            json.dumps({"jwt_token": "t", "server_id": "s", "config": {}})
        )
        assert client.load_from_cache() is True
        assert client.cached_at is None

    def test_load_corrupted_json_returns_false(self, client: ManagerClient) -> None:
        client.cache_file.write_text("not valid json{{{")
        assert client.load_from_cache() is False


class TestIsJwtValid:
    def test_no_token_returns_false(self, client: ManagerClient) -> None:
        client.jwt_token = None
        assert client.is_jwt_valid() is False

    def test_far_future_expiry_returns_true(self, client: ManagerClient) -> None:
        # PyJWT converts a tz-aware exp via utctimetuple(); is_jwt_valid() compares
        # the decoded epoch against local time, so the exp must be genuinely UTC.
        exp = datetime.now(timezone.utc) + timedelta(hours=1)
        client.jwt_token = jwt.encode({"exp": exp}, "secret", algorithm="HS256")
        assert client.is_jwt_valid() is True

    def test_expiring_within_five_minutes_returns_false(self, client: ManagerClient) -> None:
        exp = datetime.now(timezone.utc) + timedelta(minutes=1)
        client.jwt_token = jwt.encode({"exp": exp}, "secret", algorithm="HS256")
        assert client.is_jwt_valid() is False

    def test_already_expired_returns_false(self, client: ManagerClient) -> None:
        exp = datetime.now(timezone.utc) - timedelta(minutes=5)
        client.jwt_token = jwt.encode({"exp": exp}, "secret", algorithm="HS256")
        assert client.is_jwt_valid() is False

    def test_malformed_token_returns_false(self, client: ManagerClient) -> None:
        client.jwt_token = "not-a-jwt-at-all"
        assert client.is_jwt_valid() is False
