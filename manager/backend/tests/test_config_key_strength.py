"""
Regression tests: ProductionConfig must enforce a minimum SECRET_KEY
strength, since SECRET_KEY is fed through HKDF to derive the Fernet key
used for MFA/SSO secret encryption (app/services/mfa_service.py).

Config class attributes are evaluated at module import time from
os.environ, so each test reloads app.config against a controlled
environment and restores both afterward.
"""

import importlib
import os
import sys

import pytest

MANAGER_BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..")
if MANAGER_BACKEND_DIR not in sys.path:
    sys.path.insert(0, MANAGER_BACKEND_DIR)


@pytest.fixture
def config_module():
    """Yield a helper to reload app.config; restore env + module after test."""
    import app.config as config_mod

    original_environ = dict(os.environ)

    def _reload():
        return importlib.reload(config_mod)

    yield _reload

    os.environ.clear()
    os.environ.update(original_environ)
    importlib.reload(config_mod)


def test_production_config_rejects_short_secret_key(config_module):
    """A SECRET_KEY under the minimum length must fail startup, not warn."""
    os.environ['SECRET_KEY'] = 'too-short'
    os.environ['JWT_PRIVATE_KEY'] = 'dummy-private-key'
    os.environ['JWT_PUBLIC_KEY'] = 'dummy-public-key'

    config_mod = config_module()

    with pytest.raises(RuntimeError, match='at least'):
        config_mod.ProductionConfig()


def test_production_config_accepts_strong_secret_key(config_module):
    """A 32+ byte SECRET_KEY passes validation."""
    strong_key = 'x' * 32
    os.environ['SECRET_KEY'] = strong_key
    os.environ['JWT_PRIVATE_KEY'] = 'dummy-private-key'
    os.environ['JWT_PUBLIC_KEY'] = 'dummy-public-key'

    config_mod = config_module()

    cfg = config_mod.ProductionConfig()
    assert cfg.SECRET_KEY == strong_key


def test_production_config_missing_secret_key_still_rejected(config_module):
    """Absence of SECRET_KEY entirely must still fail (pre-existing check)."""
    os.environ.pop('SECRET_KEY', None)
    os.environ['JWT_PRIVATE_KEY'] = 'dummy-private-key'
    os.environ['JWT_PUBLIC_KEY'] = 'dummy-public-key'

    config_mod = config_module()

    with pytest.raises(RuntimeError, match='SECRET_KEY environment variable is required'):
        config_mod.ProductionConfig()


def test_dev_and_testing_configs_unaffected_by_min_length(config_module):
    """Dev/test ephemeral secrets (under 32 bytes) must not be weakened."""
    os.environ.pop('SECRET_KEY', None)

    config_mod = config_module()

    dev_cfg = config_mod.DevelopmentConfig()
    assert dev_cfg.SECRET_KEY == 'dev-ephemeral-secret-key-only'

    test_cfg = config_mod.TestingConfig()
    assert test_cfg.SECRET_KEY == 'test-ephemeral-secret-key-only'
