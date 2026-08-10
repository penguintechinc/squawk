"""
OpenTelemetry tracing initialization for Squawk DNS Server.

Opt-in tracing via OTEL_EXPORTER_OTLP_ENDPOINT environment variable.
When not set, no tracing infrastructure is initialized (zero overhead).
"""

import os
import logging

logger = logging.getLogger(__name__)


def init_tracing(app, exporter=None) -> None:
    """
    Initialize OpenTelemetry tracing for Quart/ASGI application.

    Args:
        app: Quart application instance.
        exporter: Optional custom exporter (InMemorySpanExporter for testing).
                 If None, reads OTEL_EXPORTER_OTLP_ENDPOINT env var.
                 If env var not set, tracing is disabled (no overhead).
    """
    otel_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")

    # If no custom exporter and no env endpoint, skip initialization
    if exporter is None and not otel_endpoint:
        logger.debug("OTEL_EXPORTER_OTLP_ENDPOINT not set; tracing disabled")
        return

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.instrumentation.asgi import OpenTelemetryMiddleware
        from opentelemetry.instrumentation.requests import RequestsInstrumentor
    except ImportError as e:
        logger.warning(f"OpenTelemetry packages not available: {e}")
        return

    # Create resource with service metadata
    resource = Resource.create(
        {
            "service.name": "squawk-dns-server",
            "service.version": _get_service_version(),
        }
    )

    # Create TracerProvider
    tracer_provider = TracerProvider(resource=resource)

    # Add span exporter
    if exporter is not None:
        # Test mode: use injected exporter (InMemorySpanExporter)
        # Wrap in SimpleSpanProcessor for testing
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor

        tracer_provider.add_span_processor(SimpleSpanProcessor(exporter))
        logger.debug("Using injected span exporter for testing")
    elif otel_endpoint:
        # Production mode: use OTLP HTTP exporter
        otlp_exporter = OTLPSpanExporter(endpoint=otel_endpoint)
        tracer_provider.add_span_processor(BatchSpanProcessor(otlp_exporter))
        logger.info(f"OpenTelemetry tracing enabled: {otel_endpoint}")

    # Set global tracer provider
    trace.set_tracer_provider(tracer_provider)

    # Instrument ASGI (Quart) and Requests
    # OpenTelemetryMiddleware needs to wrap the app
    app.asgi_app = OpenTelemetryMiddleware(app.asgi_app)
    RequestsInstrumentor().instrument()

    logger.info("OpenTelemetry tracing initialized for squawk-dns-server")


def _get_service_version() -> str:
    """
    Retrieve service version from repository version file.

    Returns current version or 'unknown' if not available.
    """
    try:
        # Try to read version from .version file in repo root
        version_file = os.path.join(
            os.path.dirname(__file__), "..", "..", ".version"
        )
        if os.path.exists(version_file):
            with open(version_file) as f:
                return f.read().strip()
    except Exception:
        pass

    return "unknown"
