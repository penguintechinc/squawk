"""Tests for scope-bundle authorization.

Verifies that (1) roles expand into the correct concrete scope bundles,
(2) issued access tokens carry a `scope` claim, (3) the `requires_scope`
decorator gates on scopes only, and (4) the pre-refactor access matrix is
preserved (SystemAdmin ⊇ OrgAdmin/UserManager privileges; Viewer read-only).
"""

from __future__ import annotations

import jwt
import pytest

from app.middleware import rbac
from app.services.scopes import (
    ROLE_SCOPES,
    SUPERADMIN_SCOPE,
    expand_scopes,
    scope_string,
)


# ---------------------------------------------------------------------------
# Role → scope-bundle expansion
# ---------------------------------------------------------------------------
def test_only_systemadmin_holds_superadmin_scope():
    assert SUPERADMIN_SCOPE in expand_scopes("SystemAdmin")
    for role in ("OrgAdmin", "UserManager", "Viewer"):
        assert SUPERADMIN_SCOPE not in expand_scopes(role)


def test_systemadmin_is_superset_of_all_roles():
    sysadmin = set(expand_scopes("SystemAdmin"))
    for role in ("OrgAdmin", "UserManager", "Viewer"):
        assert set(expand_scopes(role)).issubset(sysadmin)


@pytest.mark.parametrize(
    "role,present,absent",
    [
        ("OrgAdmin", {"servers:write", "teams:write", "time:write", "dhcp:write"},
         {"users:write", "servers:admin", "ioc:admin", SUPERADMIN_SCOPE}),
        ("UserManager", {"users:write"},
         {"users:admin", "servers:write", "dhcp:write", "ioc:admin"}),
        ("Viewer", {"users:read", "servers:read"},
         {"users:write", "servers:write", "teams:write", "ioc:admin"}),
    ],
)
def test_role_bundles_preserve_access_matrix(role, present, absent):
    scopes = set(expand_scopes(role))
    assert present.issubset(scopes)
    assert scopes.isdisjoint(absent)


def test_unknown_role_gets_no_scopes():
    assert expand_scopes(None) == []
    assert expand_scopes("Nonexistent") == []


def test_scope_string_is_space_delimited_and_sorted():
    s = scope_string("OrgAdmin")
    assert s == " ".join(sorted(ROLE_SCOPES["OrgAdmin"]))


# ---------------------------------------------------------------------------
# Token issuance carries the scope claim
# ---------------------------------------------------------------------------
def test_issued_access_token_carries_scope_claim(app, jwt_keypair):
    from app.services.auth_service import AuthService

    with app.app_context():
        token = AuthService.create_access_token(
            user_id=7, username="admin", global_role="SystemAdmin"
        )
    payload = jwt.decode(
        token, jwt_keypair["public"], algorithms=["ES256"],
        audience="squawk", issuer="squawk-manager",
    )
    assert "scope" in payload
    scopes = set(payload["scope"].split())
    assert scopes == set(expand_scopes("SystemAdmin"))
    # global_role retained for audit only.
    assert payload["global_role"] == "SystemAdmin"


# ---------------------------------------------------------------------------
# requires_scope decorator behavior
# ---------------------------------------------------------------------------
def _decorate(scopes):
    @rbac.requires_scope(*scopes)
    def view():
        return "ok", 200
    return view


def test_requires_scope_401_when_unauthenticated(app, monkeypatch):
    monkeypatch.setattr(rbac, "get_current_user", lambda: None)
    with app.test_request_context():
        _body, status = _decorate(["servers:write"])()
    assert status == 401


def test_requires_scope_403_when_scope_missing(app, monkeypatch):
    monkeypatch.setattr(rbac, "get_current_user", lambda: {"scope": "servers:read"})
    with app.test_request_context():
        _body, status = _decorate(["servers:write"])()
    assert status == 403


def test_requires_scope_200_when_scope_present(app, monkeypatch):
    monkeypatch.setattr(
        rbac, "get_current_user",
        lambda: {"scope": "servers:read servers:write"},
    )
    with app.test_request_context():
        body, status = _decorate(["servers:write"])()
    assert (body, status) == ("ok", 200)


def test_requires_scope_any_of_semantics(app, monkeypatch):
    """Endpoint grants access if the user holds ANY one of the listed scopes."""
    monkeypatch.setattr(rbac, "get_current_user", lambda: {"scope": "dhcp:admin"})
    with app.test_request_context():
        body, status = _decorate(["dhcp:write", "dhcp:admin"])()
    assert status == 200


# ---------------------------------------------------------------------------
# Scope-based helpers (no role-name branching)
# ---------------------------------------------------------------------------
def test_is_superadmin_only_for_superadmin_scope():
    assert rbac._is_superadmin({"scope": scope_string("SystemAdmin")}) is True
    assert rbac._is_superadmin({"scope": scope_string("OrgAdmin")}) is False
    assert rbac._is_superadmin(None) is False


def test_can_manage_users_matches_old_matrix(app, monkeypatch):
    for role, expected in [("SystemAdmin", True), ("UserManager", True),
                           ("OrgAdmin", False), ("Viewer", False)]:
        monkeypatch.setattr(
            rbac, "get_current_user", lambda r=role: {"scope": scope_string(r)}
        )
        assert rbac.can_manage_users() is expected


def test_can_manage_teams_matches_old_matrix(app, monkeypatch):
    for role, expected in [("SystemAdmin", True), ("OrgAdmin", True),
                           ("UserManager", False), ("Viewer", False)]:
        monkeypatch.setattr(
            rbac, "get_current_user", lambda r=role: {"scope": scope_string(r)}
        )
        assert rbac.can_manage_teams() is expected
