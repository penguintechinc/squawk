"""
Regression test: cert_manager private-key files must be created atomically
at mode 0600 via os.open(), never written first and chmod'd afterward.

The chmod-after-write ordering leaves a race window at the process umask
default (commonly 0644/0664) where the key is briefly group/world
readable between the write() completing and the chmod() call landing.
Asserting os.chmod is never called (permissions come from os.open's mode
argument at creation) plus a permissive-umask check together prove the
window is closed, not just that the final on-disk mode happens to be
0600 (which chmod-after-write would also produce).
"""

import os
import stat
from unittest.mock import patch

from app.services.cert_manager import CertManager


def test_save_private_key_does_not_chmod_after_write(tmp_path):
    """_save_private_key must not rely on a post-write os.chmod() call."""
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    key = mgr._generate_private_key()
    keypath = tmp_path / "regression.key"

    with patch("app.services.cert_manager.os.chmod") as mock_chmod:
        mgr._save_private_key(key, keypath)
        mock_chmod.assert_not_called()

    mode = stat.S_IMODE(os.stat(keypath).st_mode)
    assert mode == 0o600, f"expected 0600, got {oct(mode)}"


def test_save_private_key_is_0600_under_permissive_umask(tmp_path):
    """Even with a permissive process umask, the key file must land at 0600."""
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    key = mgr._generate_private_key()
    keypath = tmp_path / "regression_umask.key"

    old_umask = os.umask(0o000)
    try:
        mgr._save_private_key(key, keypath)
    finally:
        os.umask(old_umask)

    mode = stat.S_IMODE(os.stat(keypath).st_mode)
    assert mode == 0o600, f"expected 0600, got {oct(mode)}"


def test_create_ca_key_file_is_mode_0600(tmp_path):
    """End-to-end: CA key file on disk is 0600 after create_ca()."""
    mgr = CertManager(cert_dir=str(tmp_path), mtls_enabled=True)
    assert mgr.create_ca() is True

    mode = stat.S_IMODE(os.stat(mgr.ca_key_path).st_mode)
    assert mode == 0o600, f"expected 0600, got {oct(mode)}"
