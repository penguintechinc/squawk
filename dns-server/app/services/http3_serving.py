"""
HTTP/3 (QUIC) Serving Support for Squawk DNS-over-HTTPS
Manages hypercorn configuration with optional HTTP/3 support.
Feature-gated via PostHog flag 'squawkdns.http3' with graceful degradation.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from hypercorn.config import Config

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class Http3Config:
    """HTTP/3 (QUIC) serving configuration."""
    enabled: bool
    bind_address: str
    bind_port: int
    tls_cert_file: Optional[str] = None
    tls_key_file: Optional[str] = None


class Http3ServerBuilder:
    """
    Builder for hypercorn Config with HTTP/3 (QUIC) support.
    Feature-gated via PostHog flag 'squawkdns.http3' (default OFF).
    Gracefully degrades if flag server unreachable (safe fail to TCP-only).
    """

    def __init__(
        self,
        http3_enabled: bool = False,
        quic_bind: str = "0.0.0.0:8443",
        tcp_bind: str = "0.0.0.0:8080",
        tls_cert_file: Optional[str] = None,
        tls_key_file: Optional[str] = None,
        cert_manager: Optional[object] = None,
    ) -> None:
        """
        Initialize HTTP/3 server builder.

        Args:
            http3_enabled: Whether HTTP/3 is enabled (before feature flag check)
            quic_bind: Address to bind QUIC server (default: 0.0.0.0:8443)
            tcp_bind: Address to bind TCP server (default: 0.0.0.0:8080)
            tls_cert_file: Path to TLS certificate file (required for HTTP/3)
            tls_key_file: Path to TLS key file (required for HTTP/3)
            cert_manager: Optional CertManager instance for auto-cert generation
        """
        self.http3_enabled = http3_enabled
        self.quic_bind = quic_bind
        self.tcp_bind = tcp_bind
        self.tls_cert_file = tls_cert_file
        self.tls_key_file = tls_key_file
        self.cert_manager = cert_manager

    def _check_http3_feature_flag(self) -> bool:
        """
        Check PostHog feature flag 'squawkdns.http3' with graceful degradation.
        Returns False if flag server unreachable (safe fail to TCP-only).
        """
        try:
            # Try to import and use PostHog if available
            try:
                from manager.backend.app.services.posthog_client import PostHogClient
            except ImportError:
                logger.debug("PostHogClient not available, using default HTTP3=False")
                return False

            client = PostHogClient()
            # Deployment-wide distinct_id for HTTP/3 feature flag
            distinct_id = os.getenv("DEPLOYMENT_ID", "default")
            return client.feature_enabled("squawkdns.http3", distinct_id, default=False)
        except Exception as e:
            logger.warning(
                f"Failed to check HTTP/3 feature flag, defaulting to False: {e}"
            )
            return False

    def _get_cert_material(self) -> tuple[Optional[str], Optional[str]]:
        """
        Get TLS certificate and key file paths.
        Tries explicit paths first, then CertManager if available.
        Returns (cert_file, key_file) or (None, None) if unavailable.
        """
        # Explicit paths take precedence
        if self.tls_cert_file and self.tls_key_file:
            # Verify files exist
            if Path(self.tls_cert_file).exists() and Path(self.tls_key_file).exists():
                logger.info(
                    f"Using TLS cert from explicit paths: {self.tls_cert_file}"
                )
                return self.tls_cert_file, self.tls_key_file
            else:
                logger.warning(
                    f"Explicit TLS cert/key paths not found: "
                    f"{self.tls_cert_file}, {self.tls_key_file}"
                )

        # Try CertManager
        if self.cert_manager:
            try:
                # Ensure server cert exists (creates if needed)
                self.cert_manager.create_server_cert()

                cert_path = str(self.cert_manager.server_cert_path)
                key_path = str(self.cert_manager.server_key_path)

                if (
                    Path(cert_path).exists()
                    and Path(key_path).exists()
                ):
                    logger.info(f"Using TLS cert from CertManager: {cert_path}")
                    return cert_path, key_path
            except Exception as e:
                logger.warning(f"Failed to obtain cert from CertManager: {e}")

        return None, None

    def build_config(self) -> Config:
        """
        Build hypercorn Config with HTTP/3 support if enabled and available.

        Returns:
            hypercorn.config.Config configured for TCP (always) and QUIC (if enabled)
        """
        config = Config()

        # Always start with TCP bind (HTTP/1.1, HTTP/2)
        config.bind = [self.tcp_bind]

        # Check feature flag with exception handling for graceful degradation
        try:
            http3_flag_enabled = self._check_http3_feature_flag()
        except Exception as e:
            logger.warning(
                f"Exception checking HTTP/3 feature flag, "
                f"falling back to TCP-only: {e}"
            )
            http3_flag_enabled = False

        http3_active = self.http3_enabled and http3_flag_enabled

        if http3_active:
            # Get TLS material
            cert_file, key_file = self._get_cert_material()

            if cert_file and key_file:
                # Configure for HTTP/3
                config.certfile = cert_file
                config.keyfile = key_file

                # Add QUIC bind on top of TCP
                quic_address = self.quic_bind
                config.bind = [self.tcp_bind, quic_address]

                # Set ALPN protocols: HTTP/3, HTTP/2, HTTP/1.1
                config.alpn_protocols = ["h3", "h2", "http/1.1"]

                logger.info(
                    f"HTTP/3 (QUIC) enabled: "
                    f"TCP={self.tcp_bind}, QUIC={quic_address}, "
                    f"cert={cert_file}"
                )
            else:
                # HTTP/3 enabled but no TLS material -> fail closed
                logger.error(
                    "HTTP/3 enabled but TLS certificate/key unavailable. "
                    "Falling back to TCP-only serving. "
                    "Provide TLS_CERT_FILE/TLS_KEY_FILE or enable CertManager."
                )
                # Fall back to TCP-only (no QUIC, no TLS)
                config.alpn_protocols = ["h2", "http/1.1"]
        else:
            # HTTP/3 disabled or flag off -> TCP-only
            if self.http3_enabled and not http3_flag_enabled:
                logger.info("HTTP/3 disabled by feature flag, serving TCP-only")
            else:
                logger.debug("HTTP/3 not enabled, serving TCP-only")
            config.alpn_protocols = ["h2", "http/1.1"]

        return config


def build_serving_config(
    app_config: object,
    cert_manager: Optional[object] = None,
) -> Config:
    """
    Factory function to build hypercorn Config from app settings.

    Args:
        app_config: Config object with HTTP3_ENABLED, QUIC_BIND, TLS_CERT_FILE, TLS_KEY_FILE
        cert_manager: Optional CertManager instance

    Returns:
        hypercorn.config.Config ready for serve()
    """
    from app.config import (
        HTTP3_ENABLED,
        QUIC_BIND,
        TLS_CERT_FILE,
        TLS_KEY_FILE,
        DNS_PORT,
    )

    tcp_bind = f"0.0.0.0:{DNS_PORT}"

    builder = Http3ServerBuilder(
        http3_enabled=HTTP3_ENABLED,
        quic_bind=QUIC_BIND,
        tcp_bind=tcp_bind,
        tls_cert_file=TLS_CERT_FILE,
        tls_key_file=TLS_KEY_FILE,
        cert_manager=cert_manager,
    )

    return builder.build_config()
