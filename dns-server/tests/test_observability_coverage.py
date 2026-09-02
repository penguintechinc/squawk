"""
Additional coverage tests for app.observability.init_tracing / _get_service_version.

tests/test_observability.py already covers the "no endpoint, no exporter"
no-op path and a happy-path call with an injected exporter. This file
fills in the remaining branches:

- The ImportError guard around the OpenTelemetry imports (the
  "not available" branch) is forced deliberately here rather than relying
  on environment happenstance.
- In THIS environment, `opentelemetry.instrumentation.asgi` is not
  installed, which means test_observability.py's "enabled" tests never
  actually reach past that import (they silently hit the except-ImportError
  branch and return early) -- this is the known env-only gap the task
  description references. To genuinely exercise the "available" branch
  (resource creation, TracerProvider, both exporter branches, ASGI/requests
  instrumentation, final log), we inject a stub module for the missing
  optional dependency via sys.modules so the import guard's try block can
  actually complete, and use the *real* remaining OTel SDK components.
- _get_service_version()'s exists/absent/exception branches.
"""
import importlib
import os
import sys
import types
from unittest.mock import Mock, patch

import pytest


MISSING_OTEL_MODULE = "opentelemetry.instrumentation.asgi"


def _otel_asgi_available() -> bool:
    try:
        importlib.import_module(MISSING_OTEL_MODULE)
        return True
    except ImportError:
        return False


@pytest.fixture
def stub_asgi_instrumentation(monkeypatch: pytest.MonkeyPatch):
    """
    Ensure `opentelemetry.instrumentation.asgi.OpenTelemetryMiddleware` is
    importable, regardless of whether the real optional dependency is
    installed in this environment. Yields the middleware class used.
    """
    if _otel_asgi_available():
        from opentelemetry.instrumentation.asgi import OpenTelemetryMiddleware

        yield OpenTelemetryMiddleware
        return

    class _StubOpenTelemetryMiddleware:
        """Minimal stand-in: wraps an ASGI app callable, records the wrap."""

        def __init__(self, asgi_app):
            self.asgi_app = asgi_app

        async def __call__(self, scope, receive, send):
            return await self.asgi_app(scope, receive, send)

    stub_module = types.ModuleType(MISSING_OTEL_MODULE)
    stub_module.OpenTelemetryMiddleware = _StubOpenTelemetryMiddleware
    monkeypatch.setitem(sys.modules, MISSING_OTEL_MODULE, stub_module)

    yield _StubOpenTelemetryMiddleware


class TestDisabledByDefault:
    """Self-contained duplicate of test_observability.py's disabled-path
    check, kept here so this file's own coverage run (per this task's
    verification command) closes the early-return branch too."""

    def test_no_exporter_no_endpoint_is_a_noop(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        from quart import Quart

        from app.observability import init_tracing

        monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
        test_app = Quart(__name__)

        with caplog.at_level("DEBUG"):
            result = init_tracing(test_app)

        assert result is None
        assert "OTEL_EXPORTER_OTLP_ENDPOINT not set; tracing disabled" in caplog.text


class TestImportGuardNotAvailable:
    """Deliberately force the ImportError branch (lines ~32-44)."""

    def test_missing_dependency_disables_tracing_gracefully(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
            InMemorySpanExporter,
        )
        from quart import Quart

        from app.observability import init_tracing

        # Poison a submodule that init_tracing imports inside its try block --
        # a None entry in sys.modules forces `import`/`from ... import` to
        # raise ImportError, exactly like the dependency being absent.
        monkeypatch.setitem(sys.modules, "opentelemetry.instrumentation.requests", None)

        test_app = Quart(__name__)
        exporter = InMemorySpanExporter()

        with caplog.at_level("WARNING"):
            result = init_tracing(test_app, exporter=exporter)

        assert result is None
        assert "OpenTelemetry packages not available" in caplog.text
        # Quart's `asgi_app` is a bound method recomputed on every access, so
        # identity can't be compared directly -- instead confirm it is still
        # the framework's own unwrapped method (never reassigned to a
        # middleware instance), proving the early-return happened before any
        # wrapping occurred.
        assert test_app.asgi_app.__func__ is Quart.asgi_app

    def test_missing_dependency_with_endpoint_only(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Same guard, reached via the env-var endpoint path instead of an
        injected exporter."""
        from quart import Quart

        from app.observability import init_tracing

        monkeypatch.setitem(sys.modules, "opentelemetry.instrumentation.requests", None)
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector.example:4318")

        test_app = Quart(__name__)

        with caplog.at_level("WARNING"):
            result = init_tracing(test_app)

        assert result is None
        assert "OpenTelemetry packages not available" in caplog.text


class TestImportGuardAvailable:
    """Force the try block to fully succeed (lines ~47-79)."""

    def test_injected_exporter_wraps_app_and_instruments(
        self, stub_asgi_instrumentation, caplog: pytest.LogCaptureFixture
    ) -> None:
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
            InMemorySpanExporter,
        )
        from quart import Quart

        from app.observability import init_tracing

        test_app = Quart(__name__)
        original_asgi_app = test_app.asgi_app
        exporter = InMemorySpanExporter()

        with caplog.at_level("INFO"):
            init_tracing(test_app, exporter=exporter)

        # asgi_app was reassigned (wrapped by the ASGI middleware).
        assert test_app.asgi_app is not original_asgi_app
        assert isinstance(test_app.asgi_app, stub_asgi_instrumentation)
        assert "OpenTelemetry tracing initialized for squawk-dns-server" in caplog.text

    def test_otlp_endpoint_branch_constructs_real_exporter(
        self,
        stub_asgi_instrumentation,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """No injected exporter: exercises the `elif otel_endpoint:` branch,
        constructing a real OTLPSpanExporter (no network call at init time)."""
        from quart import Quart

        from app.observability import init_tracing

        monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector.example:4318")
        test_app = Quart(__name__)
        original_asgi_app = test_app.asgi_app

        with caplog.at_level("INFO"):
            init_tracing(test_app)

        assert test_app.asgi_app is not original_asgi_app
        assert "OpenTelemetry tracing enabled: http://collector.example:4318" in caplog.text
        assert "OpenTelemetry tracing initialized for squawk-dns-server" in caplog.text

    def test_resource_service_name_uses_helper(
        self, stub_asgi_instrumentation
    ) -> None:
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
            InMemorySpanExporter,
        )
        from quart import Quart

        from app.observability import _get_service_version, init_tracing

        test_app = Quart(__name__)
        exporter = InMemorySpanExporter()
        init_tracing(test_app, exporter=exporter)

        # Sanity: the helper used to build the resource is independently
        # callable and returns a real value (exercised fully below too).
        assert _get_service_version() != ""


class TestGetServiceVersion:
    def test_reads_real_version_file(self) -> None:
        from app.observability import _get_service_version

        version_file = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "..", ".version"
        )
        version_file = os.path.normpath(version_file)

        result = _get_service_version()

        if os.path.exists(version_file):
            with open(version_file) as f:
                expected = f.read().strip()
            assert result == expected
        else:
            assert result == "unknown"

    def test_returns_unknown_when_file_absent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.observability import _get_service_version

        monkeypatch.setattr(os.path, "exists", Mock(return_value=False))
        assert _get_service_version() == "unknown"

    def test_returns_unknown_on_read_exception(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.observability import _get_service_version

        monkeypatch.setattr(os.path, "exists", Mock(return_value=True))
        with patch("builtins.open", side_effect=OSError("permission denied")):
            assert _get_service_version() == "unknown"

    def test_strips_whitespace_from_version_file(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from unittest.mock import mock_open

        from app.observability import _get_service_version

        monkeypatch.setattr(os.path, "exists", Mock(return_value=True))
        with patch("builtins.open", mock_open(read_data="v9.9.9\n")):
            assert _get_service_version() == "v9.9.9"
