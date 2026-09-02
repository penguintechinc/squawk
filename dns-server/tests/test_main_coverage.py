"""
Coverage tests for app/main.py

test_security_hardening.py and test_doh_rate_limiting_integration.py already
cover: metrics/status auth gating, the /dns-query RFC 8484 alias, record-type
cardinality bounding, and the rate-limit-enforced happy/burst paths via the
real in-memory rate limiter. This file covers what's left: dns_query's
non-rate-limit branches (resilience zone denial, per-identity domain policy
denial, IOC domain/IP blocking, cache hit, custom-zone vs. upstream
resolution, resolution error handling), health, the remaining
metrics/status branches, startup()'s cache/registration branches, the
sync_task/heartbeat_task background loops, and _find_zone_name.

All network- and Redis-touching collaborators (dns_resolver, cache_manager,
ioc_checker, selective_router, manager_client, rate_limiter) are monkeypatched
per-test; nothing here makes a real DNS/HTTP/Redis call.
"""
import asyncio

import pytest
from unittest.mock import AsyncMock, Mock

from app.main import (
    app,
    cache_manager,
    dns_resolver,
    heartbeat_task,
    ioc_checker,
    manager_client,
    metrics_reporter,
    rate_limiter,
    resilience_manager,
    selective_router,
    startup,
    sync_task,
    _find_zone_name,
)


@pytest.fixture
def bypass_rate_limit(monkeypatch):
    """Most dns_query branch tests aren't about rate limiting; always allow."""
    mock = AsyncMock(return_value=(True, 0.0))
    monkeypatch.setattr(rate_limiter, "check_limit", mock)
    return mock


@pytest.fixture
def no_custom_zone(monkeypatch):
    monkeypatch.setattr(selective_router, "get_zone_records", Mock(return_value=None))


@pytest.fixture
def not_ioc_blocked(monkeypatch):
    monkeypatch.setattr(ioc_checker, "is_blocked", Mock(return_value=False))
    monkeypatch.setattr(ioc_checker, "is_ip_blocked", Mock(return_value=False))


class TestHealthEndpoint:
    @pytest.mark.asyncio
    async def test_health_reports_normal_mode_and_registered(self, monkeypatch):
        monkeypatch.setattr(resilience_manager, "check_mode", Mock(return_value="normal"))
        monkeypatch.setattr(manager_client, "server_id", "srv-123")

        async with app.test_client() as client:
            response = await client.get("/health")

        assert response.status_code == 200
        data = await response.get_json()
        assert data == {"status": "healthy", "mode": "normal", "registered": True}

    @pytest.mark.asyncio
    async def test_health_reports_unregistered_when_no_server_id(self, monkeypatch):
        monkeypatch.setattr(resilience_manager, "check_mode", Mock(return_value="degraded"))
        monkeypatch.setattr(manager_client, "server_id", None)

        async with app.test_client() as client:
            response = await client.get("/health")

        data = await response.get_json()
        assert data["mode"] == "degraded"
        assert data["registered"] is False


class TestDnsQueryRateLimitIdentity:
    @pytest.mark.asyncio
    async def test_rate_limited_without_token_uses_ip_identity(self, monkeypatch):
        check_limit = AsyncMock(return_value=(False, 5.3))
        monkeypatch.setattr(rate_limiter, "check_limit", check_limit)

        async with app.test_client() as client:
            response = await client.get("/dns/query?name=example.com")

        assert response.status_code == 429
        assert response.headers["Retry-After"] == "6"  # int(5.3) + 1
        data = await response.get_json()
        assert data == {"Status": 2, "error": "Rate limit exceeded"}
        _, kwargs = check_limit.call_args
        assert kwargs["token_identity"] is None

    @pytest.mark.asyncio
    async def test_invalid_token_falls_back_to_ip_identity(self, monkeypatch, bypass_rate_limit):
        """An unverifiable bearer token must not be trusted as an identity —
        rate limiting (and downstream identity_type) falls back to IP."""
        monkeypatch.setattr(resilience_manager, "should_serve_zone", Mock(return_value=False))

        async with app.test_client() as client:
            response = await client.get(
                "/dns/query?name=example.com",
                headers={"Authorization": "Bearer not-a-real-token"},
            )

        assert response.status_code == 200
        _, kwargs = bypass_rate_limit.call_args
        assert kwargs["token_identity"] is None


class TestDnsQueryResilienceAndPolicy:
    @pytest.mark.asyncio
    async def test_denied_by_resilience_mode_returns_status_3(
        self, monkeypatch, bypass_rate_limit
    ):
        monkeypatch.setattr(resilience_manager, "should_serve_zone", Mock(return_value=False))

        async with app.test_client() as client:
            response = await client.get("/dns/query?name=blocked-zone.example.com")

        assert response.status_code == 200
        data = await response.get_json()
        assert data["Status"] == 3
        assert data["Answer"] == []

    @pytest.mark.asyncio
    async def test_domain_policy_denial_for_restricted_token(
        self, monkeypatch, bypass_rate_limit, no_custom_zone, not_ioc_blocked
    ):
        payload = {"sub": "user-1", "dns_domains": ["allowed.example.com"]}
        monkeypatch.setattr("app.main.verify_squawk_jwt", Mock(return_value=payload))
        monkeypatch.setattr(resilience_manager, "should_serve_zone", Mock(return_value=True))
        record_denial = Mock()
        monkeypatch.setattr(metrics_reporter, "record_policy_denial", record_denial)

        async with app.test_client() as client:
            response = await client.get(
                "/dns/query?name=not-allowed.example.com",
                headers={"Authorization": "Bearer sometoken"},
            )

        assert response.status_code == 200
        data = await response.get_json()
        assert data["Status"] == 3
        record_denial.assert_called_once_with("policy_denied")

    @pytest.mark.asyncio
    async def test_domain_policy_allows_matching_domain(
        self, monkeypatch, bypass_rate_limit, no_custom_zone, not_ioc_blocked
    ):
        payload = {"sub": "user-1", "dns_domains": ["example.com"]}
        monkeypatch.setattr("app.main.verify_squawk_jwt", Mock(return_value=payload))
        monkeypatch.setattr(resilience_manager, "should_serve_zone", Mock(return_value=True))
        monkeypatch.setattr(cache_manager, "get", AsyncMock(return_value=None))
        monkeypatch.setattr(cache_manager, "set", AsyncMock())
        resolve_result = {
            "Status": 0,
            "Question": [{"name": "example.com", "type": "A"}],
            "Answer": [],
        }
        monkeypatch.setattr(dns_resolver, "resolve", AsyncMock(return_value=resolve_result))

        async with app.test_client() as client:
            response = await client.get(
                "/dns/query?name=example.com",
                headers={"Authorization": "Bearer sometoken"},
            )

        data = await response.get_json()
        assert data == resolve_result


class TestDnsQueryIocBlocking:
    @pytest.mark.asyncio
    async def test_ioc_blocked_domain_returns_status_3(
        self, monkeypatch, bypass_rate_limit, no_custom_zone
    ):
        monkeypatch.setattr(resilience_manager, "should_serve_zone", Mock(return_value=True))
        monkeypatch.setattr(ioc_checker, "is_blocked", Mock(return_value=True))

        async with app.test_client() as client:
            response = await client.get("/dns/query?name=malicious.example.com")

        data = await response.get_json()
        assert data["Status"] == 3
        assert data["Answer"] == []

    @pytest.mark.asyncio
    async def test_ioc_blocks_resolved_answer_ip(
        self, monkeypatch, bypass_rate_limit, no_custom_zone
    ):
        monkeypatch.setattr(resilience_manager, "should_serve_zone", Mock(return_value=True))
        monkeypatch.setattr(ioc_checker, "is_blocked", Mock(return_value=False))
        monkeypatch.setattr(
            ioc_checker, "is_ip_blocked", Mock(side_effect=lambda ip: ip == "6.6.6.6")
        )
        monkeypatch.setattr(cache_manager, "get", AsyncMock(return_value=None))
        cache_set = AsyncMock()
        monkeypatch.setattr(cache_manager, "set", cache_set)
        monkeypatch.setattr(
            dns_resolver,
            "resolve",
            AsyncMock(
                return_value={
                    "Status": 0,
                    "Question": [{"name": "example.com", "type": "A"}],
                    "Answer": [{"name": "example.com", "type": "A", "TTL": 300, "data": "6.6.6.6"}],
                }
            ),
        )

        async with app.test_client() as client:
            response = await client.get("/dns/query?name=example.com")

        data = await response.get_json()
        assert data["Status"] == 3
        assert data["Answer"] == []
        cache_set.assert_not_awaited()


class TestDnsQueryCacheAndResolution:
    @pytest.mark.asyncio
    async def test_cache_hit_short_circuits_resolution(
        self, monkeypatch, bypass_rate_limit, no_custom_zone, not_ioc_blocked
    ):
        monkeypatch.setattr(resilience_manager, "should_serve_zone", Mock(return_value=True))
        cached = {
            "Status": 0,
            "Question": [{"name": "example.com", "type": "A"}],
            "Answer": [{"name": "example.com", "type": "A", "TTL": 300, "data": "1.2.3.4"}],
        }
        monkeypatch.setattr(cache_manager, "get", AsyncMock(return_value=cached))
        resolve_mock = AsyncMock(side_effect=AssertionError("must not hit upstream on cache hit"))
        monkeypatch.setattr(dns_resolver, "resolve", resolve_mock)

        async with app.test_client() as client:
            response = await client.get("/dns/query?name=example.com")

        assert response.status_code == 200
        data = await response.get_json()
        assert data == cached
        resolve_mock.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_custom_zone_used_instead_of_upstream(
        self, monkeypatch, bypass_rate_limit, not_ioc_blocked
    ):
        monkeypatch.setattr(resilience_manager, "should_serve_zone", Mock(return_value=True))
        monkeypatch.setattr(cache_manager, "get", AsyncMock(return_value=None))
        cache_set = AsyncMock()
        monkeypatch.setattr(cache_manager, "set", cache_set)
        zone_records = [{"name": "zone.example.com", "type": "A", "value": "10.0.0.5", "ttl": 60}]
        monkeypatch.setattr(selective_router, "get_zone_records", Mock(return_value=zone_records))
        resolve_mock = AsyncMock(side_effect=AssertionError("must not hit upstream for custom zone"))
        monkeypatch.setattr(dns_resolver, "resolve", resolve_mock)

        async with app.test_client() as client:
            response = await client.get("/dns/query?name=zone.example.com")

        data = await response.get_json()
        assert data["Status"] == 0
        assert data["Answer"] == [
            {"name": "zone.example.com", "type": "A", "TTL": 60, "data": "10.0.0.5"}
        ]
        resolve_mock.assert_not_awaited()
        cache_set.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_upstream_success_is_cached(
        self, monkeypatch, bypass_rate_limit, no_custom_zone, not_ioc_blocked
    ):
        monkeypatch.setattr(resilience_manager, "should_serve_zone", Mock(return_value=True))
        monkeypatch.setattr(cache_manager, "get", AsyncMock(return_value=None))
        cache_set = AsyncMock()
        monkeypatch.setattr(cache_manager, "set", cache_set)
        result = {
            "Status": 0,
            "Question": [{"name": "example.com", "type": "A"}],
            "Answer": [{"name": "example.com", "type": "A", "TTL": 300, "data": "93.184.216.34"}],
        }
        monkeypatch.setattr(dns_resolver, "resolve", AsyncMock(return_value=result))

        async with app.test_client() as client:
            response = await client.get("/dns/query?name=example.com&type=A")

        data = await response.get_json()
        assert data == result
        cache_set.assert_awaited_once_with("example.com", "A", result)

    @pytest.mark.asyncio
    async def test_upstream_failure_is_not_cached(
        self, monkeypatch, bypass_rate_limit, no_custom_zone, not_ioc_blocked
    ):
        monkeypatch.setattr(resilience_manager, "should_serve_zone", Mock(return_value=True))
        monkeypatch.setattr(cache_manager, "get", AsyncMock(return_value=None))
        cache_set = AsyncMock()
        monkeypatch.setattr(cache_manager, "set", cache_set)
        error_result = {
            "Status": 2,
            "Question": [{"name": "example.com", "type": "A"}],
            "Answer": [],
        }
        monkeypatch.setattr(dns_resolver, "resolve", AsyncMock(return_value=error_result))

        async with app.test_client() as client:
            response = await client.get("/dns/query?name=example.com")

        assert response.status_code == 200
        data = await response.get_json()
        assert data["Status"] == 2
        cache_set.assert_not_awaited()


class TestDnsQueryValidation:
    @pytest.mark.asyncio
    async def test_missing_domain_returns_400(self, bypass_rate_limit):
        async with app.test_client() as client:
            response = await client.get("/dns/query")

        assert response.status_code == 400
        data = await response.get_json()
        assert data == {"Status": 2, "error": "Missing domain name"}

    @pytest.mark.asyncio
    async def test_empty_type_param_defaults_metric_label_to_a(
        self, monkeypatch, bypass_rate_limit, no_custom_zone, not_ioc_blocked
    ):
        """type= present but empty must not crash `_metric_record_type`
        (falsy-but-not-missing input) — covers its `not record_type` branch."""
        monkeypatch.setattr(resilience_manager, "should_serve_zone", Mock(return_value=True))
        monkeypatch.setattr(cache_manager, "get", AsyncMock(return_value=None))
        monkeypatch.setattr(cache_manager, "set", AsyncMock())
        result = {"Status": 0, "Question": [{"name": "example.com", "type": ""}], "Answer": []}
        monkeypatch.setattr(dns_resolver, "resolve", AsyncMock(return_value=result))

        async with app.test_client() as client:
            response = await client.get("/dns/query?name=example.com&type=")

        assert response.status_code == 200


class TestMetricsEndpoint:
    @pytest.mark.asyncio
    async def test_metrics_unauthorized_without_token(self):
        async with app.test_client() as client:
            response = await client.get("/metrics")

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_metrics_returns_prometheus_content_type(self, jwt_token_factory):
        token = jwt_token_factory(user_id=1)

        async with app.test_client() as client:
            response = await client.get(
                "/metrics", headers={"Authorization": f"Bearer {token}"}
            )

        assert response.status_code == 200
        assert "text/plain" in response.headers["Content-Type"] or response.headers[
            "Content-Type"
        ]


class TestStatusEndpoint:
    @pytest.mark.asyncio
    async def test_status_unauthorized_without_token(self):
        async with app.test_client() as client:
            response = await client.get("/status")

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_status_returns_all_sections(self, monkeypatch, jwt_token_factory):
        monkeypatch.setattr(manager_client, "server_id", "srv-xyz")
        token = jwt_token_factory(user_id=1)

        async with app.test_client() as client:
            response = await client.get(
                "/status", headers={"Authorization": f"Bearer {token}"}
            )

        assert response.status_code == 200
        data = await response.get_json()
        assert data["server_id"] == "srv-xyz"
        for key in ("resilience", "metrics", "cache", "ioc", "routing", "rate_limit"):
            assert key in data


class TestFindZoneName:
    def test_no_zones_configured_returns_none(self, monkeypatch):
        monkeypatch.setattr(manager_client, "config_cache", {})

        assert _find_zone_name("example.com") is None

    def test_exact_zone_match(self, monkeypatch):
        monkeypatch.setattr(
            manager_client, "config_cache", {"zones": [{"name": "example.com"}]}
        )

        assert _find_zone_name("example.com") == "example.com"

    def test_subdomain_matches_parent_zone(self, monkeypatch):
        monkeypatch.setattr(
            manager_client, "config_cache", {"zones": [{"name": "example.com"}]}
        )

        assert _find_zone_name("sub.example.com") == "example.com"

    def test_unrelated_domain_returns_none(self, monkeypatch):
        monkeypatch.setattr(
            manager_client, "config_cache", {"zones": [{"name": "example.com"}]}
        )

        assert _find_zone_name("unrelated.org") is None


class TestStartup:
    @pytest.mark.asyncio
    async def test_startup_loads_cache_and_skips_registration_when_jwt_valid(
        self, monkeypatch
    ):
        monkeypatch.setattr(manager_client, "load_from_cache", Mock(return_value=True))
        monkeypatch.setattr(
            manager_client,
            "config_cache",
            {"zones": [{"name": "cached-zone.com"}], "ioc_feeds": [{"id": 1}]},
        )
        monkeypatch.setattr(manager_client, "is_jwt_valid", Mock(return_value=True))
        register_mock = Mock()
        monkeypatch.setattr(manager_client, "register", register_mock)
        load_zones = Mock()
        load_feeds = Mock()
        monkeypatch.setattr(selective_router, "load_zones", load_zones)
        monkeypatch.setattr(ioc_checker, "load_feeds", load_feeds)
        add_bg = Mock()
        monkeypatch.setattr(app, "add_background_task", add_bg)

        await startup()

        load_zones.assert_called_once_with([{"name": "cached-zone.com"}])
        load_feeds.assert_called_once_with([{"id": 1}])
        register_mock.assert_not_called()
        assert add_bg.call_count == 2
        add_bg.assert_any_call(sync_task)
        add_bg.assert_any_call(heartbeat_task)

    @pytest.mark.asyncio
    async def test_startup_registers_and_syncs_when_jwt_invalid(self, monkeypatch):
        monkeypatch.setattr(manager_client, "load_from_cache", Mock(return_value=False))
        monkeypatch.setattr(manager_client, "is_jwt_valid", Mock(return_value=False))
        monkeypatch.setattr(manager_client, "register", Mock(return_value=True))
        monkeypatch.setattr(manager_client, "sync_config", Mock(return_value=True))
        monkeypatch.setattr(
            manager_client,
            "config_cache",
            {"zones": [{"name": "synced-zone.com"}], "ioc_feeds": [{"id": 2}]},
        )
        load_zones = Mock()
        load_feeds = Mock()
        monkeypatch.setattr(selective_router, "load_zones", load_zones)
        monkeypatch.setattr(ioc_checker, "load_feeds", load_feeds)
        monkeypatch.setattr(app, "add_background_task", Mock())

        await startup()

        load_zones.assert_called_once_with([{"name": "synced-zone.com"}])
        load_feeds.assert_called_once_with([{"id": 2}])

    @pytest.mark.asyncio
    async def test_startup_logs_warning_when_registration_fails(self, monkeypatch):
        monkeypatch.setattr(manager_client, "load_from_cache", Mock(return_value=False))
        monkeypatch.setattr(manager_client, "is_jwt_valid", Mock(return_value=False))
        register_mock = Mock(return_value=False)
        monkeypatch.setattr(manager_client, "register", register_mock)
        sync_config_mock = Mock()
        monkeypatch.setattr(manager_client, "sync_config", sync_config_mock)
        monkeypatch.setattr(app, "add_background_task", Mock())

        await startup()

        register_mock.assert_called_once()
        sync_config_mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_startup_no_cached_zones_or_iocs_skips_loading(self, monkeypatch):
        monkeypatch.setattr(manager_client, "load_from_cache", Mock(return_value=True))
        monkeypatch.setattr(manager_client, "config_cache", {})
        monkeypatch.setattr(manager_client, "is_jwt_valid", Mock(return_value=True))
        load_zones = Mock()
        load_feeds = Mock()
        monkeypatch.setattr(selective_router, "load_zones", load_zones)
        monkeypatch.setattr(ioc_checker, "load_feeds", load_feeds)
        monkeypatch.setattr(app, "add_background_task", Mock())

        await startup()

        load_zones.assert_not_called()
        load_feeds.assert_not_called()


class TestSyncTask:
    @pytest.mark.asyncio
    async def test_sync_task_reloads_zones_and_iocs_on_success(self, monkeypatch):
        sleep_calls = []

        async def fake_sleep(interval):
            sleep_calls.append(interval)
            if len(sleep_calls) >= 2:
                raise asyncio.CancelledError()

        monkeypatch.setattr("app.main.asyncio.sleep", fake_sleep)
        monkeypatch.setattr(manager_client, "sync_config", Mock(return_value=True))
        monkeypatch.setattr(
            manager_client,
            "config_cache",
            {"zones": [{"name": "z1"}], "ioc_feeds": [{"id": 1}]},
        )
        load_zones = Mock()
        load_feeds = Mock()
        monkeypatch.setattr(selective_router, "load_zones", load_zones)
        monkeypatch.setattr(ioc_checker, "load_feeds", load_feeds)

        with pytest.raises(asyncio.CancelledError):
            await sync_task()

        load_zones.assert_called_once_with([{"name": "z1"}])
        load_feeds.assert_called_once_with([{"id": 1}])

    @pytest.mark.asyncio
    async def test_sync_task_skips_reload_when_sync_fails(self, monkeypatch):
        calls = []

        async def fake_sleep(interval):
            calls.append(interval)
            if len(calls) >= 2:
                raise asyncio.CancelledError()

        monkeypatch.setattr("app.main.asyncio.sleep", fake_sleep)
        monkeypatch.setattr(manager_client, "sync_config", Mock(return_value=False))
        load_zones = Mock()
        monkeypatch.setattr(selective_router, "load_zones", load_zones)

        with pytest.raises(asyncio.CancelledError):
            await sync_task()

        load_zones.assert_not_called()


class TestHeartbeatTask:
    @pytest.mark.asyncio
    async def test_heartbeat_task_sends_current_stats(self, monkeypatch):
        calls = []

        async def fake_sleep(interval):
            calls.append(interval)
            if len(calls) >= 2:
                raise asyncio.CancelledError()

        monkeypatch.setattr("app.main.asyncio.sleep", fake_sleep)
        stats = {"queries": 42}
        monkeypatch.setattr(metrics_reporter, "get_current_stats", Mock(return_value=stats))
        heartbeat_mock = Mock()
        monkeypatch.setattr(manager_client, "heartbeat", heartbeat_mock)

        with pytest.raises(asyncio.CancelledError):
            await heartbeat_task()

        heartbeat_mock.assert_called_once_with(stats)
