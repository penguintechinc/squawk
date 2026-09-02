"""Coverage tests for app.config environment parsing and key-loading helpers.

Covers the env-var-or-file key loader, the multi-key PEM directory loader
(including malformed/unreadable-key branches), and the module-level default
vs. env-override parsing for every setting `app.config` exposes.
"""
import importlib
import os

import pytest

import app.config as config_module
from app.config import _load_key_from_env_or_file, _load_multiple_keys_from_directory


@pytest.fixture
def reload_config():
    """Set env vars, reload app.config, then fully restore env + module state.

    Yields a setter function: call it with env var kwargs (None removes the
    var) and it returns the freshly-reloaded app.config module.
    """
    original_environ = dict(os.environ)

    def _reload(**env_overrides: str | None):
        for key, value in env_overrides.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        importlib.reload(config_module)
        return config_module

    yield _reload

    os.environ.clear()
    os.environ.update(original_environ)
    importlib.reload(config_module)


class TestLoadKeyFromEnvOrFile:
    def test_env_var_present_returns_value(self) -> None:
        os.environ["TEST_KEY_ENV"] = "abc123"
        try:
            assert _load_key_from_env_or_file("TEST_KEY_ENV", "TEST_KEY_ENV_FILE") == "abc123"
        finally:
            os.environ.pop("TEST_KEY_ENV", None)

    def test_no_env_no_file_env_returns_none(self) -> None:
        os.environ.pop("TEST_KEY_MISSING", None)
        os.environ.pop("TEST_KEY_MISSING_FILE", None)
        assert _load_key_from_env_or_file("TEST_KEY_MISSING", "TEST_KEY_MISSING_FILE") is None

    def test_file_env_points_to_missing_file_returns_none(self, tmp_path) -> None:
        os.environ.pop("TEST_KEY2", None)
        os.environ["TEST_KEY2_FILE"] = str(tmp_path / "does_not_exist.pem")
        try:
            assert _load_key_from_env_or_file("TEST_KEY2", "TEST_KEY2_FILE") is None
        finally:
            os.environ.pop("TEST_KEY2_FILE", None)

    def test_file_env_points_to_existing_file_reads_stripped_content(self, tmp_path) -> None:
        key_file = tmp_path / "key.pem"
        key_file.write_text("  -----BEGIN KEY-----\nabc\n-----END KEY-----  \n")
        os.environ.pop("TEST_KEY3", None)
        os.environ["TEST_KEY3_FILE"] = str(key_file)
        try:
            result = _load_key_from_env_or_file("TEST_KEY3", "TEST_KEY3_FILE")
            assert result == "-----BEGIN KEY-----\nabc\n-----END KEY-----"
        finally:
            os.environ.pop("TEST_KEY3_FILE", None)


class TestLoadMultipleKeysFromDirectory:
    def test_none_dir_returns_empty(self) -> None:
        assert _load_multiple_keys_from_directory(None) == {}

    def test_empty_string_dir_returns_empty(self) -> None:
        assert _load_multiple_keys_from_directory("") == {}

    def test_nonexistent_dir_returns_empty(self, tmp_path) -> None:
        assert _load_multiple_keys_from_directory(str(tmp_path / "nope")) == {}

    def test_empty_dir_returns_empty(self, tmp_path) -> None:
        assert _load_multiple_keys_from_directory(str(tmp_path)) == {}

    def test_loads_valid_pem_ignores_non_pem_and_subdirs(self, tmp_path, jwt_keypair) -> None:
        (tmp_path / "key1.pem").write_text(jwt_keypair["public"])
        (tmp_path / "readme.txt").write_text("ignore me")
        (tmp_path / "subdir.pem").mkdir()  # ends in .pem but is a directory -> isfile() False

        keys = _load_multiple_keys_from_directory(str(tmp_path))
        assert len(keys) == 1
        (_kid, pem_content) = next(iter(keys.items()))
        assert pem_content == jwt_keypair["public"].strip()

    def test_empty_pem_file_skipped(self, tmp_path) -> None:
        (tmp_path / "empty.pem").write_text("   \n  ")
        assert _load_multiple_keys_from_directory(str(tmp_path)) == {}

    def test_invalid_pem_content_skipped(self, tmp_path) -> None:
        (tmp_path / "bad.pem").write_text("not a real pem key")
        assert _load_multiple_keys_from_directory(str(tmp_path)) == {}

    def test_outer_exception_returns_empty(
        self, tmp_path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _boom(_path: str):
            raise OSError("boom")

        monkeypatch.setattr(os, "listdir", _boom)
        assert _load_multiple_keys_from_directory(str(tmp_path)) == {}


class TestModuleLevelDefaults:
    def test_defaults(self, reload_config) -> None:
        cfg = reload_config(
            MANAGER_URL=None,
            JOIN_KEY=None,
            JWT_ALGORITHM=None,
            JWT_ISSUER=None,
            JWT_AUDIENCE=None,
            JWT_SECRET_KEY=None,
            DNS_PORT=None,
            GRPC_PORT=None,
            CACHE_URL=None,
            CACHE_TTL=None,
            SYNC_INTERVAL=None,
            HEARTBEAT_INTERVAL=None,
            LOG_LEVEL=None,
            HTTP3_ENABLED=None,
            QUIC_BIND=None,
            TLS_CERT_FILE=None,
            TLS_KEY_FILE=None,
            SQUAWK_RATE_LIMIT_ENABLED=None,
            SQUAWK_RATE_LIMIT_RPS=None,
            SQUAWK_RATE_LIMIT_BURST=None,
            SQUAWK_RATE_LIMIT_BACKEND=None,
        )
        assert cfg.MANAGER_URL == "http://localhost:5000"
        assert cfg.JOIN_KEY is None
        assert cfg.JWT_ALGORITHM == "ES256"
        assert cfg.JWT_ISSUER == "squawk-manager"
        assert cfg.JWT_AUDIENCE == "squawk"
        assert cfg.JWT_SECRET_KEY is None
        assert cfg.DNS_PORT == 8080
        assert cfg.GRPC_PORT == 50052
        assert cfg.CACHE_URL == "redis://localhost:6379"
        assert cfg.CACHE_TTL == 86400
        assert cfg.SYNC_INTERVAL == 300
        assert cfg.HEARTBEAT_INTERVAL == 30
        assert cfg.LOG_LEVEL == "INFO"
        assert cfg.HTTP3_ENABLED is False
        assert cfg.QUIC_BIND == "0.0.0.0:8443"
        assert cfg.TLS_CERT_FILE is None
        assert cfg.TLS_KEY_FILE is None
        assert cfg.SQUAWK_RATE_LIMIT_ENABLED is True
        assert cfg.SQUAWK_RATE_LIMIT_RPS == 50.0
        assert cfg.SQUAWK_RATE_LIMIT_BURST == 100.0
        assert cfg.SQUAWK_RATE_LIMIT_BACKEND == "memory"

    def test_overrides(self, reload_config, tmp_path) -> None:
        cfg = reload_config(
            MANAGER_URL="http://manager.example:9000",
            JOIN_KEY="a" * 64,
            JWT_ALGORITHM="RS256",
            JWT_ISSUER="custom-issuer",
            JWT_AUDIENCE="custom-aud",
            JWT_SECRET_KEY="s3cr3t",
            DNS_PORT="9090",
            GRPC_PORT="60000",
            CACHE_URL="redis://cache:6380",
            CACHE_TTL="60",
            SYNC_INTERVAL="120",
            HEARTBEAT_INTERVAL="15",
            CACHE_DIR=str(tmp_path),
            LOG_LEVEL="DEBUG",
            HTTP3_ENABLED="true",
            QUIC_BIND="0.0.0.0:9443",
            TLS_CERT_FILE="/certs/tls.crt",
            TLS_KEY_FILE="/certs/tls.key",
            SQUAWK_RATE_LIMIT_ENABLED="false",
            SQUAWK_RATE_LIMIT_RPS="10.5",
            SQUAWK_RATE_LIMIT_BURST="20.5",
            SQUAWK_RATE_LIMIT_BACKEND="valkey",
        )
        assert cfg.MANAGER_URL == "http://manager.example:9000"
        assert cfg.JOIN_KEY == "a" * 64
        assert cfg.JWT_ALGORITHM == "RS256"
        assert cfg.JWT_ISSUER == "custom-issuer"
        assert cfg.JWT_AUDIENCE == "custom-aud"
        assert cfg.JWT_SECRET_KEY == "s3cr3t"
        assert cfg.DNS_PORT == 9090
        assert cfg.GRPC_PORT == 60000
        assert cfg.CACHE_URL == "redis://cache:6380"
        assert cfg.CACHE_TTL == 60
        assert cfg.SYNC_INTERVAL == 120
        assert cfg.HEARTBEAT_INTERVAL == 15
        assert cfg.CACHE_DIR == str(tmp_path)
        assert cfg.LOG_LEVEL == "DEBUG"
        assert cfg.HTTP3_ENABLED is True
        assert cfg.QUIC_BIND == "0.0.0.0:9443"
        assert cfg.TLS_CERT_FILE == "/certs/tls.crt"
        assert cfg.TLS_KEY_FILE == "/certs/tls.key"
        assert cfg.SQUAWK_RATE_LIMIT_ENABLED is False
        assert cfg.SQUAWK_RATE_LIMIT_RPS == 10.5
        assert cfg.SQUAWK_RATE_LIMIT_BURST == 20.5
        assert cfg.SQUAWK_RATE_LIMIT_BACKEND == "valkey"

    def test_http3_enabled_is_case_insensitive(self, reload_config) -> None:
        cfg = reload_config(HTTP3_ENABLED="TRUE")
        assert cfg.HTTP3_ENABLED is True

    def test_jwt_public_key_loaded_from_env_var(self, reload_config, jwt_keypair) -> None:
        cfg = reload_config(JWT_PUBLIC_KEY=jwt_keypair["public"], JWT_PUBLIC_KEY_FILE=None)
        assert cfg.JWT_PUBLIC_KEY == jwt_keypair["public"]

    def test_jwt_public_key_loaded_from_file(self, reload_config, tmp_path, jwt_keypair) -> None:
        key_file = tmp_path / "pub.pem"
        key_file.write_text(jwt_keypair["public"])
        cfg = reload_config(JWT_PUBLIC_KEY=None, JWT_PUBLIC_KEY_FILE=str(key_file))
        assert cfg.JWT_PUBLIC_KEY == jwt_keypair["public"].strip()

    def test_jwt_public_keys_loaded_from_directory(self, reload_config, tmp_path, jwt_keypair) -> None:
        (tmp_path / "key1.pem").write_text(jwt_keypair["public"])
        cfg = reload_config(JWT_PUBLIC_KEYS_DIR=str(tmp_path))
        assert len(cfg.JWT_PUBLIC_KEYS) == 1

    def test_jwt_public_keys_dir_unset_returns_empty(self, reload_config) -> None:
        cfg = reload_config(JWT_PUBLIC_KEYS_DIR=None)
        assert cfg.JWT_PUBLIC_KEYS == {}
