"""Tests for gRPC server auth: ServerAuthInterceptor and RefreshToken
proof-of-identity.

Prior implementation: GetConfig/SendHeartbeat/ValidateToken/CheckIOC had no
authentication at all (any caller reaching the listener could call them),
and RefreshToken minted a fresh, fully-valid server JWT for *any*
`server_id` with zero proof the caller controlled that server.

These tests exercise app.grpc_server directly (unit-level) rather than
starting a real gRPC server + client, per the harness note in the task:
"unit-test the interceptor directly if the full server can't start." A full
end-to-end test additionally requires compiled `manager_service_pb2`/`_grpc`
stubs (protoc-generated, not committed to this repo -- see the module
docstring in app/grpc_server.py) *and* a protobuf runtime version matching
whatever `grpcio-tools` bundles; this sandbox's installed `protobuf==6.33.6`
is older than the gencode grpcio-tools 1.82.1 emits, so real message
construction isn't exercised here. `manager_service_pb2` is monkeypatched
with a tiny fake for the two RefreshToken success-path assertions that need
to build a `RefreshTokenResponse`; the rejection paths (the security-
relevant behavior) don't touch it at all.
"""

from __future__ import annotations

import types
from datetime import timedelta

import grpc
import pytest

from app import grpc_server as gs
from app.services.auth_service import AuthService


class _FakeContext:
    """Real grpc.ServicerContext.abort() raises to terminate the RPC; this
    fake reproduces that so post-abort code paths are exercised faithfully."""

    class Aborted(Exception):
        def __init__(self, code, details):
            super().__init__(details)
            self.code = code
            self.details = details

    def abort(self, code, details):
        raise self.Aborted(code, details)


class _HandlerCallDetails:
    def __init__(self, method, metadata=()):
        self.method = method
        self.invocation_metadata = metadata


def _continuation(handler):
    def _cont(_details):
        return handler
    return _cont


# ---------------------------------------------------------------------------
# ServerAuthInterceptor
# ---------------------------------------------------------------------------

def test_exempt_methods_pass_through_unauthenticated(app):
    """RegisterServer/RefreshToken are exempt -- they perform their own
    caller-identity checks since a fresh server JWT doesn't exist yet."""
    interceptor = gs.ServerAuthInterceptor(app)
    handler = grpc.unary_unary_rpc_method_handler(lambda req, ctx: "ok")

    for method in gs._INTERCEPTOR_EXEMPT_METHODS:
        details = _HandlerCallDetails(method)
        result = interceptor.intercept_service(_continuation(handler), details)
        assert result is handler


def test_missing_token_rejected_unary_unary(app):
    """A protected unary-unary RPC (e.g. GetConfig) with no metadata at all
    is replaced with an UNAUTHENTICATED-aborting handler."""
    interceptor = gs.ServerAuthInterceptor(app)
    handler = grpc.unary_unary_rpc_method_handler(lambda req, ctx: "ok")
    details = _HandlerCallDetails(
        "/squawkdns.manager.ManagerService/GetConfig", metadata=()
    )

    result = interceptor.intercept_service(_continuation(handler), details)
    assert result is not handler

    ctx = _FakeContext()
    with pytest.raises(_FakeContext.Aborted) as exc_info:
        result.unary_unary(None, ctx)
    assert exc_info.value.code == grpc.StatusCode.UNAUTHENTICATED


def test_missing_token_rejected_stream_stream(app):
    """SendHeartbeat is stream-stream -- the denial handler must match that
    cardinality or gRPC itself would reject the substituted handler."""
    interceptor = gs.ServerAuthInterceptor(app)
    handler = grpc.stream_stream_rpc_method_handler(lambda req_iter, ctx: iter(["ok"]))
    details = _HandlerCallDetails(
        "/squawkdns.manager.ManagerService/SendHeartbeat", metadata=()
    )

    result = interceptor.intercept_service(_continuation(handler), details)
    assert result is not handler

    ctx = _FakeContext()
    with pytest.raises(_FakeContext.Aborted) as exc_info:
        result.stream_stream(iter([]), ctx)
    assert exc_info.value.code == grpc.StatusCode.UNAUTHENTICATED


def test_invalid_token_rejected(app):
    """A syntactically-present but garbage bearer token is rejected the
    same as no token at all."""
    interceptor = gs.ServerAuthInterceptor(app)
    handler = grpc.unary_unary_rpc_method_handler(lambda req, ctx: "ok")
    details = _HandlerCallDetails(
        "/squawkdns.manager.ManagerService/ValidateToken",
        metadata=(("authorization", "Bearer not-a-real-token"),),
    )

    result = interceptor.intercept_service(_continuation(handler), details)
    assert result is not handler


def test_valid_server_jwt_allows_through(app, db):
    """A caller presenting a genuine, current server JWT for a real
    dns_server row reaches the real handler unchanged."""
    with app.app_context():
        server_id = db.dns_server.insert(
            name='grpc-test-server',
            join_key='k' * 64,
            jwt_secret='s' * 40,
            region='us-east',
            status='online',
        )
        db.commit()
        server = db.dns_server[server_id]
        token = AuthService.create_server_jwt(server_id=server.id, jwt_secret=server.jwt_secret)

    interceptor = gs.ServerAuthInterceptor(app)
    handler = grpc.unary_unary_rpc_method_handler(lambda req, ctx: "ok")
    details = _HandlerCallDetails(
        "/squawkdns.manager.ManagerService/GetConfig",
        metadata=(("authorization", f"Bearer {token}"),),
    )

    result = interceptor.intercept_service(_continuation(handler), details)
    assert result is handler


def test_server_jwt_for_different_server_still_authenticates_call(app, db):
    """The interceptor only proves *a* valid server identity exists (any
    known server_id) -- authorization for the specific resource requested
    is each RPC's own responsibility, same as the REST server_token_required
    path. This test documents that boundary rather than asserting a
    resource-level check the interceptor itself doesn't perform."""
    with app.app_context():
        server_id = db.dns_server.insert(
            name='grpc-test-server-2',
            join_key='k' * 64,
            jwt_secret='s' * 40,
            region='us-east',
            status='online',
        )
        db.commit()
        server = db.dns_server[server_id]
        token = AuthService.create_server_jwt(server_id=server.id, jwt_secret=server.jwt_secret)

    interceptor = gs.ServerAuthInterceptor(app)
    handler = grpc.unary_unary_rpc_method_handler(lambda req, ctx: "ok")
    details = _HandlerCallDetails(
        "/squawkdns.manager.ManagerService/GetConfig",
        metadata=(("authorization", f"Bearer {token}"),),
    )

    result = interceptor.intercept_service(_continuation(handler), details)
    assert result is handler


# ---------------------------------------------------------------------------
# RefreshToken proof-of-identity
# ---------------------------------------------------------------------------

class _RefreshRequest:
    """Duck-typed stand-in for the protobuf RefreshTokenRequest message --
    ManagerServicer.RefreshToken only reads .server_id/.jwt/.join_key."""

    def __init__(self, server_id="", jwt="", join_key=""):
        self.server_id = server_id
        self.jwt = jwt
        self.join_key = join_key


@pytest.fixture
def dns_server_row(app, db):
    with app.app_context():
        server_id = db.dns_server.insert(
            name='refresh-test-server',
            join_key='j' * 64,
            jwt_secret='r' * 40,
            region='us-east',
            status='online',
        )
        db.commit()
        return server_id


def test_refresh_token_rejects_with_no_proof(app, dns_server_row):
    with app.app_context():
        servicer = gs.ManagerServicer(app)
        ctx = _FakeContext()
        request = _RefreshRequest(server_id=str(dns_server_row))

        with pytest.raises(_FakeContext.Aborted) as exc_info:
            servicer.RefreshToken(request, ctx)
        assert exc_info.value.code == grpc.StatusCode.UNAUTHENTICATED


def test_refresh_token_rejects_jwt_for_wrong_server(app, db, dns_server_row):
    with app.app_context():
        other_id = db.dns_server.insert(
            name='other-server', join_key='o' * 64, jwt_secret='o' * 40,
            region='us-west', status='online',
        )
        db.commit()
        other = db.dns_server[other_id]
        wrong_token = AuthService.create_server_jwt(server_id=other.id, jwt_secret=other.jwt_secret)

        servicer = gs.ManagerServicer(app)
        ctx = _FakeContext()
        request = _RefreshRequest(server_id=str(dns_server_row), jwt=wrong_token)

        with pytest.raises(_FakeContext.Aborted) as exc_info:
            servicer.RefreshToken(request, ctx)
        assert exc_info.value.code == grpc.StatusCode.UNAUTHENTICATED


def test_refresh_token_rejects_wrong_join_key(app, dns_server_row):
    with app.app_context():
        servicer = gs.ManagerServicer(app)
        ctx = _FakeContext()
        request = _RefreshRequest(server_id=str(dns_server_row), join_key='wrong-key')

        with pytest.raises(_FakeContext.Aborted) as exc_info:
            servicer.RefreshToken(request, ctx)
        assert exc_info.value.code == grpc.StatusCode.UNAUTHENTICATED


def test_refresh_token_accepts_valid_current_jwt(app, db, dns_server_row, monkeypatch):
    with app.app_context():
        server = db.dns_server[dns_server_row]
        current_token = AuthService.create_server_jwt(server_id=server.id, jwt_secret=server.jwt_secret)

        fake_pb2 = types.SimpleNamespace(
            RefreshTokenResponse=lambda jwt: types.SimpleNamespace(jwt=jwt)
        )
        monkeypatch.setattr(gs, 'manager_service_pb2', fake_pb2)

        servicer = gs.ManagerServicer(app)
        ctx = _FakeContext()
        request = _RefreshRequest(server_id=str(dns_server_row), jwt=current_token)

        response = servicer.RefreshToken(request, ctx)
        assert response.jwt
        # A server JWT has second-granularity exp/iat and no jti, so two
        # calls within the same second are legitimately byte-identical --
        # assert it's a valid, re-verifiable token rather than "different".
        assert AuthService.decode_token(response.jwt, server.jwt_secret) is not None


def test_refresh_token_accepts_valid_join_key(app, db, dns_server_row, monkeypatch):
    with app.app_context():
        server = db.dns_server[dns_server_row]

        fake_pb2 = types.SimpleNamespace(
            RefreshTokenResponse=lambda jwt: types.SimpleNamespace(jwt=jwt)
        )
        monkeypatch.setattr(gs, 'manager_service_pb2', fake_pb2)

        servicer = gs.ManagerServicer(app)
        ctx = _FakeContext()
        request = _RefreshRequest(server_id=str(dns_server_row), join_key=server.join_key)

        response = servicer.RefreshToken(request, ctx)
        assert response.jwt


def test_refresh_token_accepts_near_expiry_jwt_within_grace(app, db, dns_server_row, monkeypatch):
    """A server JWT that expired moments ago (within the grace window) is
    still accepted as proof of identity, so servers can refresh shortly
    after their token lapses without being locked out entirely."""
    import jwt as pyjwt
    from datetime import datetime

    with app.app_context():
        server = db.dns_server[dns_server_row]
        payload = {
            'server_id': server.id,
            'type': 'server',
            'exp': datetime.utcnow() - timedelta(seconds=10),
            'iat': datetime.utcnow() - timedelta(hours=24),
        }
        just_expired = pyjwt.encode(payload, server.jwt_secret, algorithm='HS256')

        fake_pb2 = types.SimpleNamespace(
            RefreshTokenResponse=lambda jwt: types.SimpleNamespace(jwt=jwt)
        )
        monkeypatch.setattr(gs, 'manager_service_pb2', fake_pb2)

        servicer = gs.ManagerServicer(app)
        ctx = _FakeContext()
        request = _RefreshRequest(server_id=str(dns_server_row), jwt=just_expired)

        response = servicer.RefreshToken(request, ctx)
        assert response.jwt


def test_refresh_token_unknown_server_not_found(app):
    with app.app_context():
        servicer = gs.ManagerServicer(app)
        ctx = _FakeContext()
        request = _RefreshRequest(server_id="999999")

        with pytest.raises(_FakeContext.Aborted) as exc_info:
            servicer.RefreshToken(request, ctx)
        assert exc_info.value.code == grpc.StatusCode.NOT_FOUND
