"""
Coverage tests for app/services/http3_serving.py

Exercises the PostHog feature-flag check (import-not-available, available,
raises), TLS cert-material resolution (explicit paths, CertManager
fallback, exceptions), and the full build_config() decision matrix
(disabled, flag-off, enabled-with-cert, enabled-without-cert fail-closed,
flag-check exception). No real network/QUIC socket is exercised — hypercorn's
Config object and PostHogClient are both test doubles.

Note: real QUIC/UDP socket behavior (actual hypercorn HTTP/3 serving) is not
exercised anywhere in this suite -- build_config() only *configures* a
hypercorn Config object, it never binds a socket or drives aioquic, so
there is no additional untestable runtime path here beyond what's covered.
"""
import sys
import types
from unittest.mock import Mock, patch

from hypercorn.config import Config

from app.services.http3_serving import Http3ServerBuilder, build_serving_config


def _inject_fake_posthog_module(
    feature_enabled_return=None,
    feature_enabled_side_effect=None,
    client_init_side_effect=None,
):
    """Insert a fake manager.backend.app.services.posthog_client module chain
    into sys.modules so `from manager...posthog_client import PostHogClient`
    resolves to a controllable test double instead of ImportError-ing."""
    client_cls = Mock()
    if client_init_side_effect is not None:
        client_cls.side_effect = client_init_side_effect
    else:
        instance = Mock()
        if feature_enabled_side_effect is not None:
            instance.feature_enabled = Mock(side_effect=feature_enabled_side_effect)
        else:
            instance.feature_enabled = Mock(return_value=feature_enabled_return)
        client_cls.return_value = instance

    names = [
        "manager",
        "manager.backend",
        "manager.backend.app",
        "manager.backend.app.services",
        "manager.backend.app.services.posthog_client",
    ]
    fake_modules = {name: types.ModuleType(name) for name in names}
    fake_modules["manager.backend.app.services.posthog_client"].PostHogClient = client_cls
    return fake_modules, client_cls


class TestCheckHttp3FeatureFlag:
    """Direct tests of Http3ServerBuilder._check_http3_feature_flag()."""

    def test_posthog_unavailable_defaults_false(self):
        """In this environment `manager.backend...` is not on sys.path from
        dns-server/, so the real ImportError branch fires without any
        mocking needed."""
        builder = Http3ServerBuilder(http3_enabled=True)

        assert builder._check_http3_feature_flag() is False

    def test_posthog_available_and_flag_enabled(self):
        fake_modules, client_cls = _inject_fake_posthog_module(feature_enabled_return=True)
        builder = Http3ServerBuilder(http3_enabled=True)

        with patch.dict(sys.modules, fake_modules):
            result = builder._check_http3_feature_flag()

        assert result is True
        client_cls.return_value.feature_enabled.assert_called_once_with(
            "squawkdns.http3", "default", default=False
        )

    def test_posthog_available_and_flag_disabled(self):
        fake_modules, client_cls = _inject_fake_posthog_module(feature_enabled_return=False)
        builder = Http3ServerBuilder(http3_enabled=True)

        with patch.dict(sys.modules, fake_modules):
            result = builder._check_http3_feature_flag()

        assert result is False

    def test_deployment_id_env_var_used_as_distinct_id(self, monkeypatch):
        fake_modules, client_cls = _inject_fake_posthog_module(feature_enabled_return=True)
        monkeypatch.setenv("DEPLOYMENT_ID", "squawk-dns-01")
        builder = Http3ServerBuilder(http3_enabled=True)

        with patch.dict(sys.modules, fake_modules):
            builder._check_http3_feature_flag()

        client_cls.return_value.feature_enabled.assert_called_once_with(
            "squawkdns.http3", "squawk-dns-01", default=False
        )

    def test_feature_enabled_raising_is_caught_and_returns_false(self):
        fake_modules, _ = _inject_fake_posthog_module(
            feature_enabled_side_effect=RuntimeError("PostHog unreachable")
        )
        builder = Http3ServerBuilder(http3_enabled=True)

        with patch.dict(sys.modules, fake_modules):
            result = builder._check_http3_feature_flag()

        assert result is False

    def test_client_construction_raising_is_caught_and_returns_false(self):
        fake_modules, _ = _inject_fake_posthog_module(
            client_init_side_effect=ConnectionError("cannot reach PostHog")
        )
        builder = Http3ServerBuilder(http3_enabled=True)

        with patch.dict(sys.modules, fake_modules):
            result = builder._check_http3_feature_flag()

        assert result is False


class TestGetCertMaterial:
    """Direct tests of Http3ServerBuilder._get_cert_material()."""

    def test_explicit_paths_used_when_files_exist(self, tmp_path):
        cert = tmp_path / "server.crt"
        key = tmp_path / "server.key"
        cert.write_text("CERT")
        key.write_text("KEY")

        builder = Http3ServerBuilder(
            http3_enabled=True, tls_cert_file=str(cert), tls_key_file=str(key)
        )

        result = builder._get_cert_material()

        assert result == (str(cert), str(key))

    def test_explicit_paths_missing_falls_through_to_none(self):
        builder = Http3ServerBuilder(
            http3_enabled=True,
            tls_cert_file="/nonexistent/server.crt",
            tls_key_file="/nonexistent/server.key",
        )

        result = builder._get_cert_material()

        assert result == (None, None)

    def test_cert_manager_provides_material_when_no_explicit_paths(self, tmp_path):
        cert_manager = Mock()
        cert_manager.server_cert_path = tmp_path / "server.crt"
        cert_manager.server_key_path = tmp_path / "server.key"
        cert_manager.server_cert_path.write_text("CERT")
        cert_manager.server_key_path.write_text("KEY")
        cert_manager.create_server_cert = Mock()

        builder = Http3ServerBuilder(http3_enabled=True, cert_manager=cert_manager)

        result = builder._get_cert_material()

        assert result == (str(cert_manager.server_cert_path), str(cert_manager.server_key_path))
        cert_manager.create_server_cert.assert_called_once()

    def test_cert_manager_files_missing_after_create_returns_none(self, tmp_path):
        cert_manager = Mock()
        cert_manager.server_cert_path = tmp_path / "never-written.crt"
        cert_manager.server_key_path = tmp_path / "never-written.key"
        cert_manager.create_server_cert = Mock()

        builder = Http3ServerBuilder(http3_enabled=True, cert_manager=cert_manager)

        result = builder._get_cert_material()

        assert result == (None, None)

    def test_cert_manager_raising_is_caught_and_returns_none(self):
        cert_manager = Mock()
        cert_manager.create_server_cert = Mock(side_effect=RuntimeError("cert gen failed"))

        builder = Http3ServerBuilder(http3_enabled=True, cert_manager=cert_manager)

        result = builder._get_cert_material()

        assert result == (None, None)

    def test_no_explicit_paths_and_no_cert_manager_returns_none(self):
        builder = Http3ServerBuilder(http3_enabled=True)

        result = builder._get_cert_material()

        assert result == (None, None)


class TestBuildConfig:
    """Tests of Http3ServerBuilder.build_config() decision matrix."""

    def test_http3_disabled_is_tcp_only(self):
        builder = Http3ServerBuilder(http3_enabled=False, tcp_bind="0.0.0.0:8080")

        config = builder.build_config()

        assert config.bind == ["0.0.0.0:8080"]
        assert config.certfile is None
        assert config.alpn_protocols == ["h2", "http/1.1"]

    def test_http3_enabled_but_flag_off_is_tcp_only(self):
        builder = Http3ServerBuilder(http3_enabled=True, tcp_bind="0.0.0.0:8080")

        with patch.object(builder, "_check_http3_feature_flag", return_value=False):
            config = builder.build_config()

        assert config.bind == ["0.0.0.0:8080"]
        assert "h3" not in config.alpn_protocols

    def test_http3_enabled_flag_on_with_cert_adds_quic_bind(self, tmp_path):
        cert = tmp_path / "server.crt"
        key = tmp_path / "server.key"
        cert.write_text("CERT")
        key.write_text("KEY")

        builder = Http3ServerBuilder(
            http3_enabled=True,
            tcp_bind="0.0.0.0:8080",
            quic_bind="0.0.0.0:8443",
            tls_cert_file=str(cert),
            tls_key_file=str(key),
        )

        with patch.object(builder, "_check_http3_feature_flag", return_value=True):
            config = builder.build_config()

        assert config.bind == ["0.0.0.0:8080", "0.0.0.0:8443"]
        assert config.certfile == str(cert)
        assert config.keyfile == str(key)
        assert config.alpn_protocols == ["h3", "h2", "http/1.1"]

    def test_http3_enabled_flag_on_without_cert_fails_closed(self):
        builder = Http3ServerBuilder(http3_enabled=True, tcp_bind="0.0.0.0:8080")

        with patch.object(builder, "_check_http3_feature_flag", return_value=True):
            config = builder.build_config()

        assert config.bind == ["0.0.0.0:8080"]
        assert config.certfile is None
        assert "h3" not in config.alpn_protocols
        assert config.alpn_protocols == ["h2", "http/1.1"]

    def test_feature_flag_check_raising_falls_back_to_tcp_only(self):
        builder = Http3ServerBuilder(http3_enabled=True, tcp_bind="0.0.0.0:8080")

        with patch.object(
            builder, "_check_http3_feature_flag", side_effect=RuntimeError("flag server down")
        ):
            config = builder.build_config()

        assert config.bind == ["0.0.0.0:8080"]
        assert "h3" not in config.alpn_protocols

    def test_returns_hypercorn_config_instance(self):
        builder = Http3ServerBuilder(http3_enabled=False)

        config = builder.build_config()

        assert isinstance(config, Config)


class TestBuildServingConfig:
    """Tests of the build_serving_config() factory function."""

    def test_builds_tcp_only_config_from_app_settings(self):
        with patch("app.config.DNS_PORT", 8080), patch("app.config.HTTP3_ENABLED", False), patch(
            "app.config.QUIC_BIND", "0.0.0.0:8443"
        ), patch("app.config.TLS_CERT_FILE", None), patch("app.config.TLS_KEY_FILE", None):
            config = build_serving_config(app_config=None)

        assert isinstance(config, Config)
        assert config.bind == ["0.0.0.0:8080"]
        assert "h3" not in config.alpn_protocols

    def test_builds_with_cert_manager_but_flag_off_stays_tcp_only(self, tmp_path):
        cert_manager = Mock()
        cert_manager.server_cert_path = tmp_path / "server.crt"
        cert_manager.server_key_path = tmp_path / "server.key"
        cert_manager.create_server_cert = Mock()

        with patch("app.config.DNS_PORT", 9090), patch("app.config.HTTP3_ENABLED", True), patch(
            "app.config.QUIC_BIND", "0.0.0.0:8443"
        ), patch("app.config.TLS_CERT_FILE", None), patch("app.config.TLS_KEY_FILE", None):
            config = build_serving_config(app_config=None, cert_manager=cert_manager)

        # PostHog flag defaults to False in this environment, so TCP-only.
        assert config.bind == ["0.0.0.0:9090"]
        assert "h3" not in config.alpn_protocols
