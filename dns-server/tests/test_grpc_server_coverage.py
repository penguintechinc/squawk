"""
Coverage tests for app.grpc_server (DNSQueryServicer + serve_grpc).

NOTE: The task target listed `app/services/grpc_server.py`, but that path
does not exist in this repo -- the gRPC servicer actually lives at
`app/grpc_server.py`. That is the module tested here.

app/grpc_server.py does NOT import any protoc-generated stubs
(manager_service_pb2 or similar) -- per its own top-of-file comment, the
generated protobuf wiring was never added ("For now, we'll create a
placeholder implementation"). DNSQueryServicer works with plain duck-typed
request objects (attribute access only: .name/.type/.token/.queries) and
returns plain dicts, and serve_grpc() never registers the servicer with
grpc's generated `add_*Servicer_to_server` call. That means the module
imports and the servicer instantiates cleanly with no stubs at all, so the
full unit-testable surface is covered directly below using Mock/AsyncMock
dependencies and SimpleNamespace request stand-ins -- no protobuf stubs
were required or faked.
"""
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import grpc
import pytest

import app.grpc_server as grpc_server_module
from app.grpc_server import DNSQueryServicer, serve_grpc


def make_servicer(**overrides) -> DNSQueryServicer:
    """Build a DNSQueryServicer with fully mocked collaborators.

    Any collaborator explicitly passed in `overrides` is used verbatim
    (including whatever mock configuration the caller already applied to
    it) -- only collaborators NOT overridden get the sane async-safe
    defaults below.
    """
    defaults = dict(
        resolver=Mock(),
        cache_manager=Mock(),
        ioc_checker=Mock(),
        selective_router=Mock(),
        manager_client=Mock(server_id="server-1", config_cache={"zones": []}),
        metrics_reporter=Mock(),
    )
    merged = {**defaults, **overrides}

    servicer = DNSQueryServicer(
        resolver=merged["resolver"],
        cache_manager=merged["cache_manager"],
        ioc_checker=merged["ioc_checker"],
        selective_router=merged["selective_router"],
        manager_client=merged["manager_client"],
        metrics_reporter=merged["metrics_reporter"],
    )

    if "cache_manager" not in overrides:
        servicer.cache.get = AsyncMock(return_value=None)
        servicer.cache.set = AsyncMock(return_value=None)
    if "resolver" not in overrides:
        servicer.resolver.resolve = AsyncMock(
            return_value={
                "Status": 0,
                "Answer": [{"name": "example.com", "type": 1, "data": "1.2.3.4"}],
            }
        )
    if "ioc_checker" not in overrides:
        servicer.ioc_checker.is_blocked = Mock(return_value=False)
    return servicer


class TestServicerInit:
    def test_init_stores_collaborators_and_server_id(self) -> None:
        manager_client = Mock(server_id="srv-42")
        servicer = make_servicer(manager_client=manager_client)
        assert servicer.server_id == "srv-42"
        assert servicer.manager_client is manager_client


class TestFindZoneName:
    def test_no_zones_returns_none(self) -> None:
        servicer = make_servicer(manager_client=Mock(server_id="s", config_cache={"zones": []}))
        assert servicer._find_zone_name("example.com") is None

    def test_missing_zones_key_returns_none(self) -> None:
        servicer = make_servicer(manager_client=Mock(server_id="s", config_cache={}))
        assert servicer._find_zone_name("example.com") is None

    def test_exact_match(self) -> None:
        servicer = make_servicer(
            manager_client=Mock(
                server_id="s", config_cache={"zones": [{"name": "example.com"}]}
            )
        )
        assert servicer._find_zone_name("example.com") == "example.com"

    def test_subdomain_match(self) -> None:
        servicer = make_servicer(
            manager_client=Mock(
                server_id="s", config_cache={"zones": [{"name": "example.com"}]}
            )
        )
        assert servicer._find_zone_name("host.example.com") == "example.com"

    def test_no_match(self) -> None:
        servicer = make_servicer(
            manager_client=Mock(
                server_id="s", config_cache={"zones": [{"name": "other.com"}]}
            )
        )
        assert servicer._find_zone_name("example.com") is None


class TestBuildResponses:
    def test_build_grpc_response_shapes_answers(self) -> None:
        servicer = make_servicer()
        dns_result = {
            "Status": 0,
            "Answer": [
                {"name": "example.com", "type": 1, "TTL": 120, "data": "1.2.3.4"},
                {"name": "example.com", "type": 1, "data": "5.6.7.8"},  # default TTL
            ],
        }
        response = servicer._build_grpc_response(dns_result, 12.5, from_cache=True)

        assert response["status"] == 0
        assert len(response["answers"]) == 2
        assert response["answers"][0]["ttl"] == 120
        assert response["answers"][1]["ttl"] == 300  # default applied
        assert response["metadata"]["from_cache"] is True
        assert response["metadata"]["response_time_ms"] == 12.5
        assert response["metadata"]["ioc_blocked"] is False
        assert response["metadata"]["server_id"] == servicer.server_id

    def test_build_grpc_response_defaults_missing_fields(self) -> None:
        servicer = make_servicer()
        response = servicer._build_grpc_response({}, 0.0, from_cache=False)
        assert response["status"] == 2  # default SERVFAIL-ish status
        assert response["answers"] == []

    def test_build_grpc_response_falls_back_server_id(self) -> None:
        servicer = make_servicer(manager_client=Mock(server_id=None, config_cache={}))
        response = servicer._build_grpc_response({}, 0.0, from_cache=False)
        assert response["metadata"]["server_id"] == "unknown"

    def test_build_blocked_response(self) -> None:
        servicer = make_servicer()
        response = servicer._build_blocked_response("blocked.example.com", "A")
        assert response["status"] == 3
        assert response["metadata"]["ioc_blocked"] is True
        assert response["answers"] == []

    def test_build_error_response(self) -> None:
        servicer = make_servicer()
        response = servicer._build_error_response()
        assert response["status"] == 2
        assert response["metadata"]["ioc_blocked"] is False


class TestHealthCheck:
    def test_health_check_returns_serving(self) -> None:
        servicer = make_servicer()
        response = servicer.HealthCheck(request=Mock(), context=Mock())
        assert response == {"status": 1}


class TestQuery:
    @pytest.mark.asyncio
    async def test_permission_denied_aborts(self) -> None:
        selective_router = Mock()
        selective_router.check_zone_permission = Mock(return_value=False)
        manager_client = Mock(
            server_id="s", config_cache={"zones": [{"name": "example.com"}]}
        )
        servicer = make_servicer(
            selective_router=selective_router, manager_client=manager_client
        )

        class _Aborted(Exception):
            pass

        context = Mock()
        context.abort = Mock(side_effect=_Aborted())
        request = SimpleNamespace(name="host.example.com", type="A", token="tok-123")

        with pytest.raises(_Aborted):
            await servicer.Query(request, context)

        context.abort.assert_called_once_with(
            grpc.StatusCode.PERMISSION_DENIED, "Access denied to zone"
        )

    @pytest.mark.asyncio
    async def test_permission_allowed_continues(self) -> None:
        selective_router = Mock()
        selective_router.check_zone_permission = Mock(return_value=True)
        selective_router.get_zone_records = Mock(return_value=None)
        manager_client = Mock(
            server_id="s", config_cache={"zones": [{"name": "example.com"}]}
        )
        servicer = make_servicer(
            selective_router=selective_router, manager_client=manager_client
        )
        context = Mock()
        request = SimpleNamespace(name="host.example.com", type="A", token="tok-123")

        response = await servicer.Query(request, context)

        context.abort.assert_not_called()
        assert response["status"] == 0
        servicer.metrics.record_query.assert_called_once()
        assert servicer.metrics.record_query.call_args.kwargs["source"] == "tok-123"

    @pytest.mark.asyncio
    async def test_no_token_skips_zone_check_entirely(self) -> None:
        selective_router = Mock()
        selective_router.get_zone_records = Mock(return_value=None)
        servicer = make_servicer(selective_router=selective_router)
        context = Mock()
        request = SimpleNamespace(name="example.com", type="A", token="")

        response = await servicer.Query(request, context)

        selective_router.check_zone_permission.assert_not_called()
        assert response["status"] == 0
        assert servicer.metrics.record_query.call_args.kwargs["source"] == "grpc"

    @pytest.mark.asyncio
    async def test_token_but_zone_not_found_skips_permission_check(self) -> None:
        selective_router = Mock()
        selective_router.get_zone_records = Mock(return_value=None)
        manager_client = Mock(server_id="s", config_cache={"zones": []})
        servicer = make_servicer(
            selective_router=selective_router, manager_client=manager_client
        )
        context = Mock()
        request = SimpleNamespace(name="example.com", type="A", token="tok-1")

        await servicer.Query(request, context)

        selective_router.check_zone_permission.assert_not_called()

    @pytest.mark.asyncio
    async def test_ioc_blocked_short_circuits(self) -> None:
        ioc_checker = Mock()
        ioc_checker.is_blocked = Mock(return_value=True)
        servicer = make_servicer(ioc_checker=ioc_checker)
        context = Mock()
        request = SimpleNamespace(name="bad.example.com", type="A", token=None)

        response = await servicer.Query(request, context)

        assert response["status"] == 3
        assert response["metadata"]["ioc_blocked"] is True
        servicer.metrics.record_query.assert_called_once()
        kwargs = servicer.metrics.record_query.call_args.kwargs
        assert kwargs["blocked"] is True
        assert kwargs["block_reason"] == "threat_intelligence"
        assert kwargs["source"] == "grpc"
        servicer.cache.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_cache_hit_returns_cached_response(self) -> None:
        servicer = make_servicer()
        cached_result = {"Status": 0, "Answer": [{"name": "example.com", "type": 1, "data": "9.9.9.9"}]}
        servicer.cache.get = AsyncMock(return_value=cached_result)
        context = Mock()
        request = SimpleNamespace(name="example.com", type="A", token=None)

        response = await servicer.Query(request, context)

        assert response["metadata"]["from_cache"] is True
        servicer.resolver.resolve.assert_not_called()
        kwargs = servicer.metrics.record_query.call_args.kwargs
        assert kwargs["cache_hit"] is True
        assert kwargs["status"] == "success"

    @pytest.mark.asyncio
    async def test_cache_miss_uses_custom_zone_records(self) -> None:
        selective_router = Mock()
        selective_router.get_zone_records = Mock(return_value=[{"type": "A", "data": "1.1.1.1"}])
        servicer = make_servicer(selective_router=selective_router)
        servicer.resolver.resolve_custom_zone = Mock(
            return_value={"Status": 0, "Answer": []}
        )
        context = Mock()
        request = SimpleNamespace(name="custom.example.com", type="A", token=None)

        response = await servicer.Query(request, context)

        servicer.resolver.resolve_custom_zone.assert_called_once_with(
            "custom.example.com", "A", [{"type": "A", "data": "1.1.1.1"}]
        )
        servicer.resolver.resolve.assert_not_called()
        servicer.cache.set.assert_awaited_once()
        assert response["status"] == 0

    @pytest.mark.asyncio
    async def test_cache_miss_uses_public_resolver_on_success(self) -> None:
        servicer = make_servicer()
        servicer.selective_router.get_zone_records = Mock(return_value=None)
        context = Mock()
        request = SimpleNamespace(name="public.example.com", type="A", token=None)

        response = await servicer.Query(request, context)

        servicer.resolver.resolve.assert_awaited_once_with("public.example.com", "A")
        servicer.cache.set.assert_awaited_once()
        kwargs = servicer.metrics.record_query.call_args.kwargs
        assert kwargs["status"] == "success"
        assert response["status"] == 0

    @pytest.mark.asyncio
    async def test_resolver_error_status_skips_cache_write(self) -> None:
        servicer = make_servicer()
        servicer.selective_router.get_zone_records = Mock(return_value=None)
        servicer.resolver.resolve = AsyncMock(return_value={"Status": 2, "Answer": []})
        context = Mock()
        request = SimpleNamespace(name="fail.example.com", type="A", token=None)

        response = await servicer.Query(request, context)

        servicer.cache.set.assert_not_called()
        kwargs = servicer.metrics.record_query.call_args.kwargs
        assert kwargs["status"] == "error"
        assert response["status"] == 2


class TestBatchQuery:
    @pytest.mark.asyncio
    async def test_all_successful(self) -> None:
        servicer = make_servicer()
        servicer.Query = AsyncMock(
            side_effect=[
                SimpleNamespace(status=0),
                SimpleNamespace(status=0),
            ]
        )
        request = SimpleNamespace(queries=[SimpleNamespace(name="a.com"), SimpleNamespace(name="b.com")])
        context = Mock()

        result = await servicer.BatchQuery(request, context)

        assert result["metadata"]["total_queries"] == 2
        assert result["metadata"]["successful"] == 2
        assert result["metadata"]["failed"] == 0
        assert len(result["responses"]) == 2
        assert result["metadata"]["total_time_ms"] >= 0

    @pytest.mark.asyncio
    async def test_mixed_success_failure_and_exception(self) -> None:
        servicer = make_servicer()
        servicer.Query = AsyncMock(
            side_effect=[
                SimpleNamespace(status=0),
                SimpleNamespace(status=2),
                RuntimeError("boom"),
            ]
        )
        request = SimpleNamespace(
            queries=[SimpleNamespace(name="a.com"), SimpleNamespace(name="b.com"), SimpleNamespace(name="c.com")]
        )
        context = Mock()

        result = await servicer.BatchQuery(request, context)

        assert result["metadata"]["total_queries"] == 3
        assert result["metadata"]["successful"] == 1
        assert result["metadata"]["failed"] == 2
        assert len(result["responses"]) == 3


class TestStreamQuery:
    @pytest.mark.asyncio
    async def test_yields_response_per_query(self) -> None:
        servicer = make_servicer()
        servicer.Query = AsyncMock(return_value=SimpleNamespace(status=0))

        async def request_iterator():
            yield SimpleNamespace(name="a.com")
            yield SimpleNamespace(name="b.com")

        context = Mock()
        responses = []
        async for resp in servicer.StreamQuery(request_iterator(), context):
            responses.append(resp)

        assert len(responses) == 2
        assert servicer.Query.await_count == 2

    @pytest.mark.asyncio
    async def test_yields_error_response_on_exception(self) -> None:
        servicer = make_servicer()
        servicer.Query = AsyncMock(side_effect=RuntimeError("boom"))

        async def request_iterator():
            yield SimpleNamespace(name="a.com")

        context = Mock()
        responses = []
        async for resp in servicer.StreamQuery(request_iterator(), context):
            responses.append(resp)

        assert len(responses) == 1
        assert responses[0]["status"] == 2  # _build_error_response()


class TestServeGrpc:
    @pytest.mark.asyncio
    async def test_serve_grpc_starts_and_waits(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake_server = Mock()
        fake_server.add_insecure_port = Mock()
        fake_server.start = AsyncMock()
        fake_server.wait_for_termination = AsyncMock()
        monkeypatch.setattr(
            grpc_server_module.grpc.aio, "server", Mock(return_value=fake_server)
        )

        await serve_grpc(
            port=60999,
            resolver=Mock(),
            cache_manager=Mock(),
            ioc_checker=Mock(),
            selective_router=Mock(),
            manager_client=Mock(server_id="srv-1", config_cache={}),
            metrics_reporter=Mock(),
        )

        fake_server.add_insecure_port.assert_called_once_with("[::]:60999")
        fake_server.start.assert_awaited_once()
        fake_server.wait_for_termination.assert_awaited_once()
