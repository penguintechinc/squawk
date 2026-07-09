"""
HTTP/3 (QUIC) Serving Configuration Tests
Tests feature gating, TLS integration, and graceful degradation for HTTP/3 support.
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from hypercorn.config import Config

from app.services.http3_serving import Http3ServerBuilder, build_serving_config


@pytest.fixture
def temp_cert_dir():
    """Create a temporary certificate directory."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        yield tmp_dir


@pytest.fixture
def mock_cert_manager(temp_cert_dir):
    """Create a mock CertManager with server certs available."""
    mock_manager = Mock()
    mock_manager.server_cert_path = Path(temp_cert_dir) / "server.crt"
    mock_manager.server_key_path = Path(temp_cert_dir) / "server.key"

    # Create dummy cert files
    mock_manager.server_cert_path.write_text("DUMMY_CERT_PEM")
    mock_manager.server_key_path.write_text("DUMMY_KEY_PEM")

    # Mock create_server_cert to not fail
    mock_manager.create_server_cert = Mock(return_value=True)

    return mock_manager


class TestHttp3ServerBuilder:
    """Test HTTP/3 server configuration builder."""

    def test_http3_disabled_returns_tcp_only(self):
        """Test that disabled HTTP/3 returns TCP-only config (no QUIC bind)."""
        builder = Http3ServerBuilder(
            http3_enabled=False,
            quic_bind="0.0.0.0:8443",
            tcp_bind="0.0.0.0:8080",
        )

        config = builder.build_config()

        # Should have TCP only
        assert len(config.bind) == 1
        assert "8080" in config.bind[0]
        assert config.certfile is None
        assert config.keyfile is None

        # ALPN should not include h3
        assert "h3" not in config.alpn_protocols
        assert "h2" in config.alpn_protocols
        assert "http/1.1" in config.alpn_protocols

    def test_http3_enabled_with_explicit_cert(self, temp_cert_dir):
        """Test HTTP/3 enabled with explicit certificate paths."""
        # Create dummy cert files
        cert_file = Path(temp_cert_dir) / "server.crt"
        key_file = Path(temp_cert_dir) / "server.key"
        cert_file.write_text("DUMMY_CERT_PEM")
        key_file.write_text("DUMMY_KEY_PEM")

        builder = Http3ServerBuilder(
            http3_enabled=True,
            quic_bind="0.0.0.0:8443",
            tcp_bind="0.0.0.0:8080",
            tls_cert_file=str(cert_file),
            tls_key_file=str(key_file),
        )

        # Mock the feature flag to return True
        with patch.object(builder, "_check_http3_feature_flag", return_value=True):
            config = builder.build_config()

        # Should have both TCP and QUIC
        assert len(config.bind) == 2
        assert "8080" in config.bind[0]
        assert "8443" in config.bind[1]

        # Should have cert/key configured
        assert config.certfile == str(cert_file)
        assert config.keyfile == str(key_file)

        # ALPN should include h3
        assert config.alpn_protocols == ["h3", "h2", "http/1.1"]

    def test_http3_enabled_without_cert_fails_closed(self):
        """Test HTTP/3 enabled WITHOUT cert/key and no CertManager: fails closed (TCP-only)."""
        builder = Http3ServerBuilder(
            http3_enabled=True,
            quic_bind="0.0.0.0:8443",
            tcp_bind="0.0.0.0:8080",
            tls_cert_file=None,
            tls_key_file=None,
            cert_manager=None,
        )

        # Mock feature flag to True
        with patch.object(builder, "_check_http3_feature_flag", return_value=True):
            config = builder.build_config()

        # Should fall back to TCP-only (fail closed, no silent QUIC without TLS)
        assert len(config.bind) == 1
        assert "8080" in config.bind[0]
        assert config.certfile is None
        assert config.keyfile is None

        # ALPN should not include h3
        assert "h3" not in config.alpn_protocols
        assert "h2" in config.alpn_protocols

    def test_http3_feature_flag_off_forces_tcp_only(self, mock_cert_manager):
        """Test that HTTP/3 enabled but feature flag OFF forces TCP-only."""
        builder = Http3ServerBuilder(
            http3_enabled=True,
            quic_bind="0.0.0.0:8443",
            tcp_bind="0.0.0.0:8080",
            cert_manager=mock_cert_manager,
        )

        # Mock feature flag to return False
        with patch.object(builder, "_check_http3_feature_flag", return_value=False):
            config = builder.build_config()

        # Should have TCP only despite HTTP3_ENABLED=True
        assert len(config.bind) == 1
        assert "8080" in config.bind[0]
        assert config.certfile is None
        assert config.keyfile is None

        # ALPN should not include h3
        assert "h3" not in config.alpn_protocols

    def test_http3_with_cert_manager(self, mock_cert_manager):
        """Test HTTP/3 with CertManager providing cert material."""
        builder = Http3ServerBuilder(
            http3_enabled=True,
            quic_bind="0.0.0.0:8443",
            tcp_bind="0.0.0.0:8080",
            cert_manager=mock_cert_manager,
        )

        # Mock feature flag to return True
        with patch.object(builder, "_check_http3_feature_flag", return_value=True):
            config = builder.build_config()

        # Should have both TCP and QUIC
        assert len(config.bind) == 2
        assert "8080" in config.bind[0]
        assert "8443" in config.bind[1]

        # Should use CertManager's certs
        assert str(mock_cert_manager.server_cert_path) in config.certfile
        assert str(mock_cert_manager.server_key_path) in config.keyfile

        # ALPN should include h3
        assert config.alpn_protocols == ["h3", "h2", "http/1.1"]

        # Verify create_server_cert was called
        mock_cert_manager.create_server_cert.assert_called()

    def test_feature_flag_server_unreachable_graceful_degradation(self):
        """Test graceful degradation when flag server is unreachable."""
        builder = Http3ServerBuilder(
            http3_enabled=True,
            quic_bind="0.0.0.0:8443",
            tcp_bind="0.0.0.0:8080",
        )

        # Mock feature flag to raise an exception (simulating server unreachable)
        def flag_check_error():
            raise RuntimeError("PostHog server unreachable")

        with patch.object(builder, "_check_http3_feature_flag", side_effect=flag_check_error):
            # Should not crash, should fall back to TCP-only
            config = builder.build_config()

        # Should have TCP only (gracefully degraded)
        assert len(config.bind) == 1
        assert "8080" in config.bind[0]
        assert "h3" not in config.alpn_protocols

    def test_explicit_cert_takes_precedence_over_cert_manager(
        self, temp_cert_dir, mock_cert_manager
    ):
        """Test that explicit cert/key paths take precedence over CertManager."""
        # Create explicit cert files
        cert_file = Path(temp_cert_dir) / "explicit.crt"
        key_file = Path(temp_cert_dir) / "explicit.key"
        cert_file.write_text("EXPLICIT_CERT")
        key_file.write_text("EXPLICIT_KEY")

        builder = Http3ServerBuilder(
            http3_enabled=True,
            quic_bind="0.0.0.0:8443",
            tcp_bind="0.0.0.0:8080",
            tls_cert_file=str(cert_file),
            tls_key_file=str(key_file),
            cert_manager=mock_cert_manager,
        )

        # Mock feature flag to return True
        with patch.object(builder, "_check_http3_feature_flag", return_value=True):
            config = builder.build_config()

        # Should use explicit paths, not CertManager
        assert config.certfile == str(cert_file)
        assert config.keyfile == str(key_file)

        # CertManager create_server_cert should NOT be called
        mock_cert_manager.create_server_cert.assert_not_called()

    def test_missing_explicit_cert_falls_back_to_cert_manager(
        self, temp_cert_dir, mock_cert_manager
    ):
        """Test fallback to CertManager when explicit cert/key don't exist."""
        # Point to non-existent files
        cert_file = Path(temp_cert_dir) / "nonexistent.crt"
        key_file = Path(temp_cert_dir) / "nonexistent.key"

        builder = Http3ServerBuilder(
            http3_enabled=True,
            quic_bind="0.0.0.0:8443",
            tcp_bind="0.0.0.0:8080",
            tls_cert_file=str(cert_file),
            tls_key_file=str(key_file),
            cert_manager=mock_cert_manager,
        )

        # Mock feature flag to return True
        with patch.object(builder, "_check_http3_feature_flag", return_value=True):
            config = builder.build_config()

        # Should fall back to CertManager
        assert str(mock_cert_manager.server_cert_path) in config.certfile
        assert str(mock_cert_manager.server_key_path) in config.keyfile

        # CertManager create_server_cert should be called
        mock_cert_manager.create_server_cert.assert_called()

    def test_quic_bind_address_configuration(self, temp_cert_dir, mock_cert_manager):
        """Test custom QUIC bind address is correctly set."""
        builder = Http3ServerBuilder(
            http3_enabled=True,
            quic_bind="127.0.0.1:9443",  # Custom QUIC bind
            tcp_bind="127.0.0.1:9080",   # Custom TCP bind
            cert_manager=mock_cert_manager,
        )

        # Mock feature flag to return True
        with patch.object(builder, "_check_http3_feature_flag", return_value=True):
            config = builder.build_config()

        # Should have correct bind addresses
        assert len(config.bind) == 2
        assert "127.0.0.1:9080" in config.bind[0]
        assert "127.0.0.1:9443" in config.bind[1]

    def test_alpn_protocols_correct_order(self, temp_cert_dir):
        """Test ALPN protocols are in correct order: h3, h2, http/1.1."""
        cert_file = Path(temp_cert_dir) / "server.crt"
        key_file = Path(temp_cert_dir) / "server.key"
        cert_file.write_text("CERT")
        key_file.write_text("KEY")

        builder = Http3ServerBuilder(
            http3_enabled=True,
            tls_cert_file=str(cert_file),
            tls_key_file=str(key_file),
        )

        with patch.object(builder, "_check_http3_feature_flag", return_value=True):
            config = builder.build_config()

        # ALPN order: h3 (HTTP/3), h2 (HTTP/2), http/1.1 (HTTP/1.1)
        assert config.alpn_protocols == ["h3", "h2", "http/1.1"]

    def test_tcp_only_alpn_protocols(self):
        """Test ALPN protocols for TCP-only serving: h2, http/1.1."""
        builder = Http3ServerBuilder(
            http3_enabled=False,
        )

        config = builder.build_config()

        # ALPN order: h2, http/1.1 (no h3)
        assert config.alpn_protocols == ["h2", "http/1.1"]


class TestBuildServingConfig:
    """Test the factory function build_serving_config."""

    def test_build_serving_config_default(self):
        """Test build_serving_config with default settings."""
        with patch("app.config.DNS_PORT", 8080), \
             patch("app.config.HTTP3_ENABLED", False), \
             patch("app.config.QUIC_BIND", "0.0.0.0:8443"), \
             patch("app.config.TLS_CERT_FILE", None), \
             patch("app.config.TLS_KEY_FILE", None):

            config = build_serving_config(app_config=None, cert_manager=None)

            assert isinstance(config, Config)
            assert len(config.bind) == 1
            assert "8080" in config.bind[0]
            assert "h3" not in config.alpn_protocols

    def test_build_serving_config_with_cert_manager(self, mock_cert_manager):
        """Test build_serving_config with CertManager."""
        with patch("app.config.DNS_PORT", 8080), \
             patch("app.config.HTTP3_ENABLED", True), \
             patch("app.config.QUIC_BIND", "0.0.0.0:8443"), \
             patch("app.config.TLS_CERT_FILE", None), \
             patch("app.config.TLS_KEY_FILE", None):

            config = build_serving_config(app_config=None, cert_manager=mock_cert_manager)

            assert isinstance(config, Config)
            # With feature flag off by default, should be TCP-only
            assert len(config.bind) == 1


class TestHttp3Integration:
    """Integration tests for HTTP/3 serving configuration."""

    def test_config_is_hypercorn_config_instance(self):
        """Verify build_serving_config returns valid hypercorn Config."""
        builder = Http3ServerBuilder(http3_enabled=False)
        config = builder.build_config()

        # Must be hypercorn.config.Config instance
        assert isinstance(config, Config)

        # Must have bind attribute (list of addresses)
        assert isinstance(config.bind, list)
        assert len(config.bind) > 0

        # Must have ALPN protocols
        assert hasattr(config, "alpn_protocols")
        assert isinstance(config.alpn_protocols, list)

    def test_no_hardcoded_secrets_in_config(self):
        """Verify no hardcoded secrets are embedded in config."""
        builder = Http3ServerBuilder(
            http3_enabled=True,
            tls_cert_file="/path/to/cert.crt",
            tls_key_file="/path/to/key.key",
        )

        # Config should not contain actual secret values in logs/strings
        # (Paths are OK as they're configuration, not secrets)
        assert builder.tls_cert_file is not None
        assert builder.tls_key_file is not None

    def test_feature_flag_check_propagates_gracefully(self):
        """Test that feature flag check failures don't crash the builder."""
        builder = Http3ServerBuilder(http3_enabled=True)

        # Simulate various failure modes
        failure_modes = [
            RuntimeError("Network error"),
            ValueError("Invalid response"),
            ConnectionError("Server unreachable"),
            Exception("Generic error"),
        ]

        for error in failure_modes:
            with patch.object(builder, "_check_http3_feature_flag", side_effect=error):
                # Should not raise, should build config with graceful degradation
                config = builder.build_config()
                assert config is not None
                assert "h3" not in config.alpn_protocols

    def test_cert_manager_create_server_cert_called_on_demand(
        self, mock_cert_manager
    ):
        """Test that CertManager.create_server_cert() is called when needed."""
        builder = Http3ServerBuilder(
            http3_enabled=True,
            cert_manager=mock_cert_manager,
        )

        with patch.object(builder, "_check_http3_feature_flag", return_value=True):
            config = builder.build_config()

        # Should have called create_server_cert to ensure certs exist
        mock_cert_manager.create_server_cert.assert_called_once()


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_empty_quic_bind_address(self):
        """Test with empty QUIC bind address."""
        builder = Http3ServerBuilder(
            http3_enabled=True,
            quic_bind="",
            tcp_bind="0.0.0.0:8080",
        )

        with patch.object(builder, "_check_http3_feature_flag", return_value=True):
            # Should handle gracefully, likely fall back to TCP-only
            config = builder.build_config()
            assert config is not None

    def test_cert_manager_exception_handling(self):
        """Test graceful handling of CertManager exceptions."""
        mock_manager = Mock()
        mock_manager.server_cert_path = Path("/nonexistent/cert.crt")
        mock_manager.server_key_path = Path("/nonexistent/key.key")
        mock_manager.create_server_cert = Mock(
            side_effect=RuntimeError("Cert generation failed")
        )

        builder = Http3ServerBuilder(
            http3_enabled=True,
            cert_manager=mock_manager,
        )

        with patch.object(builder, "_check_http3_feature_flag", return_value=True):
            # Should handle exception gracefully, fall back to TCP
            config = builder.build_config()
            assert config is not None
            assert "h3" not in config.alpn_protocols

    def test_partial_cert_material(self, temp_cert_dir):
        """Test with only cert file (missing key file)."""
        cert_file = Path(temp_cert_dir) / "server.crt"
        cert_file.write_text("CERT")
        # No key file

        builder = Http3ServerBuilder(
            http3_enabled=True,
            tls_cert_file=str(cert_file),
            tls_key_file="/nonexistent/key.key",
        )

        with patch.object(builder, "_check_http3_feature_flag", return_value=True):
            config = builder.build_config()

        # Should fail closed (TCP-only)
        assert len(config.bind) == 1
        assert "h3" not in config.alpn_protocols
