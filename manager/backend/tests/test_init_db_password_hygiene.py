"""
Regression tests for init_db.py admin-password stdout hygiene.

The database bootstrap script must never print the admin password literal
to stdout -- it persists in container/CI logs. Only a masked note is
permitted.
"""

import os
import re
import sys

import pytest


@pytest.fixture
def init_db_module(app, monkeypatch):
    """Import init_db.py with create_app() patched to return the test app."""
    manager_backend_dir = os.path.join(os.path.dirname(__file__), "..")
    if manager_backend_dir not in sys.path:
        sys.path.insert(0, manager_backend_dir)

    sys.modules.pop("init_db", None)
    import init_db as init_db_mod

    monkeypatch.setattr(init_db_mod, "create_app", lambda: app)
    yield init_db_mod
    sys.modules.pop("init_db", None)


def _clear_admin(app):
    with app.app_context():
        db = app.db
        db(db.auth_user.username == "admin").delete()
        db.commit()


def test_init_database_never_prints_generated_password(
    init_db_module, app, capsys, monkeypatch
):
    """Generated admin password must not appear anywhere in stdout."""
    monkeypatch.delenv("SQUAWK_ADMIN_PASSWORD", raising=False)
    _clear_admin(app)

    init_db_module.init_database()

    captured = capsys.readouterr()
    assert "generated -- retrieve via a secure channel" in captured.out
    # No bare high-entropy token (a leaked secrets.token_urlsafe(16) value)
    # appears on a "Password:" line.
    assert not re.search(r"Password:\s+[A-Za-z0-9_-]{16,}", captured.out)

    with app.app_context():
        db = app.db
        admin = db(db.auth_user.username == "admin").select().first()
        assert admin is not None
        assert admin.password_hash is not None


def test_init_database_never_prints_env_password(
    init_db_module, app, capsys, monkeypatch
):
    """Password sourced from env var must also never be echoed to stdout."""
    secret_value = "SuperSecretEnvPassword123!"
    monkeypatch.setenv("SQUAWK_ADMIN_PASSWORD", secret_value)
    _clear_admin(app)

    init_db_module.init_database()

    captured = capsys.readouterr()
    assert secret_value not in captured.out
    assert "set from SQUAWK_ADMIN_PASSWORD env var" in captured.out
