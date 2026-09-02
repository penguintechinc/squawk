"""Coverage tests for app.services.selective_dns_routing.SelectiveDNSRouter.

Exercises real routing decisions (can_resolve_domain / filter_dns_response)
across zone visibility levels, group membership, and explicit zone grants,
plus the group/zone/assignment CRUD helpers and their error branches.

Note: `_get_user_id_from_token`'s hash-lookup contract is already covered by
test_selective_dns_routing_token_hash.py -- this file exercises the rest of
the module via the real SQLite-backed penguin_dal DB (session `db` /
`db_engine` fixtures from conftest.py), using the token table only as a
means to drive can_resolve_domain's authenticated paths. DB-layer exception
branches (the `except Exception` handlers in every CRUD method) are
exercised with a mocked `_get_db()` -- real SQLite doesn't cleanly surface
those failure modes, and the task calls for mocking the DB for such paths.
"""
import hashlib
import os
from unittest.mock import MagicMock

import pytest
from sqlalchemy import Boolean, Column, DateTime, Integer, MetaData, String, Table

from app.services.selective_dns_routing import SelectiveDNSRouter


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@pytest.fixture
def token_table(db_engine):
    """Minimal `token` table (token_hash only -- see
    test_selective_dns_routing_token_hash.py for the full rationale).
    idempotent + self-cleaning, safe alongside the real schema import."""
    metadata = MetaData()
    table = Table(
        "token", metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("token_hash", String(64), unique=True, nullable=False),
        Column("name", String(100), nullable=False),
        Column("team_id", Integer, nullable=True),
        Column("created_by", Integer, nullable=True),
        Column("active", Boolean, nullable=False, default=True),
        Column("expires_at", DateTime, nullable=True),
        Column("last_used", DateTime, nullable=True),
        Column("created_at", DateTime, nullable=True),
        Column("updated_at", DateTime, nullable=True),
    )
    table.create(db_engine, checkfirst=True)
    yield table
    with db_engine.begin() as conn:
        conn.execute(table.delete())


def _insert_token(db_engine, table, *, plaintext: str, name: str = "test-token") -> int:
    with db_engine.begin() as conn:
        result = conn.execute(
            table.insert().values(token_hash=_sha256_hex(plaintext), name=name, active=True)
        )
        return result.inserted_primary_key[0]


@pytest.fixture
def router() -> SelectiveDNSRouter:
    return SelectiveDNSRouter(db_url=os.environ["DATABASE_URI"])


def _failing_db(select_first=None):
    """A MagicMock standing in for penguin_dal.DB whose commit() blows up --
    covers every CRUD method's `except Exception` branch uniformly, since
    each does its "already exists"/"existing" read before commit()."""
    mock_db = MagicMock()
    mock_db.return_value.select.return_value.first.return_value = select_first
    mock_db.commit.side_effect = RuntimeError("boom")
    return mock_db


# ---------------------------------------------------------------------------
# create_group
# ---------------------------------------------------------------------------

class TestCreateGroup:
    def test_creates_new_group(self, router: SelectiveDNSRouter):
        result = router.create_group("engineering", "Eng team", ["internal"])
        assert result["success"] is True
        assert isinstance(result["group_id"], int)

    def test_rejects_duplicate_name(self, router: SelectiveDNSRouter):
        router.create_group("engineering", "Eng team", ["internal"])
        result = router.create_group("engineering", "Dup", ["public"])
        assert result == {"success": False, "error": "Group 'engineering' already exists"}

    def test_exception_path_returns_error_message(self, router: SelectiveDNSRouter, monkeypatch):
        monkeypatch.setattr(router, "_get_db", lambda: _failing_db())
        result = router.create_group("broken", "desc", ["public"])
        assert result == {"success": False, "error": "boom"}


# ---------------------------------------------------------------------------
# assign_user_to_group
# ---------------------------------------------------------------------------

class TestAssignUserToGroup:
    def test_creates_new_assignment(self, router: SelectiveDNSRouter):
        group = router.create_group("eng", "desc", ["internal"])
        result = router.assign_user_to_group(user_id=1, group_id=group["group_id"], role="member")
        assert result == {"success": True}

    def test_updates_existing_assignment_role(self, router: SelectiveDNSRouter):
        group = router.create_group("eng", "desc", ["internal"])
        router.assign_user_to_group(user_id=1, group_id=group["group_id"], role="member")
        result = router.assign_user_to_group(user_id=1, group_id=group["group_id"], role="owner")
        assert result == {"success": True}

        groups = router.get_user_groups(1)
        assert len(groups) == 1  # updated in place, not duplicated

    def test_exception_path_returns_failure(self, router: SelectiveDNSRouter, monkeypatch):
        monkeypatch.setattr(router, "_get_db", lambda: _failing_db())
        result = router.assign_user_to_group(user_id=1, group_id=1, role="member")
        assert result == {"success": False}


# ---------------------------------------------------------------------------
# create_dns_zone
# ---------------------------------------------------------------------------

class TestCreateDnsZone:
    def test_creates_new_zone(self, router: SelectiveDNSRouter):
        result = router.create_dns_zone("internal.company.com", "internal", "desc", "admin")
        assert result["success"] is True
        assert isinstance(result["zone_id"], int)

    def test_rejects_duplicate_zone_name(self, router: SelectiveDNSRouter):
        router.create_dns_zone("internal.company.com", "internal", "desc", "admin")
        result = router.create_dns_zone("internal.company.com", "restricted", "desc2", "admin")
        assert result["success"] is False
        assert "already exists" in result["error"]
        assert "zone_id" in result

    def test_rejects_invalid_visibility_level(self, router: SelectiveDNSRouter):
        result = router.create_dns_zone("weird.company.com", "supersecret", "desc", "admin")
        assert result == {"success": False, "error": "Invalid visibility level: supersecret"}

    def test_exception_path_returns_error_message(self, router: SelectiveDNSRouter, monkeypatch):
        monkeypatch.setattr(router, "_get_db", lambda: _failing_db())
        result = router.create_dns_zone("broken.company.com", "public", "desc", "admin")
        assert result == {"success": False, "error": "boom"}


# ---------------------------------------------------------------------------
# _is_valid_domain
# ---------------------------------------------------------------------------

class TestIsValidDomain:
    @pytest.mark.parametrize(
        "domain",
        ["example.com", "sub.example.com", "*.example.com", "localhost"],
    )
    def test_valid_domains(self, router: SelectiveDNSRouter, domain):
        assert router._is_valid_domain(domain) is True

    def test_rejects_empty_string(self, router: SelectiveDNSRouter):
        assert router._is_valid_domain("") is False

    def test_rejects_non_string(self, router: SelectiveDNSRouter):
        assert router._is_valid_domain(None) is False  # type: ignore[arg-type]

    def test_rejects_double_dots(self, router: SelectiveDNSRouter):
        assert router._is_valid_domain("invalid..domain.com") is False

    def test_rejects_leading_hyphen(self, router: SelectiveDNSRouter):
        assert router._is_valid_domain("-domain.com") is False

    def test_rejects_trailing_hyphen(self, router: SelectiveDNSRouter):
        assert router._is_valid_domain("domain-") is False

    def test_rejects_overlong_domain(self, router: SelectiveDNSRouter):
        overlong = ("a" * 250) + ".com"
        assert len(overlong) > 253
        assert router._is_valid_domain(overlong) is False


# ---------------------------------------------------------------------------
# _find_zone_for_domain
# ---------------------------------------------------------------------------

class TestFindZoneForDomain:
    def test_exact_match(self, router: SelectiveDNSRouter):
        router.create_dns_zone("exact.company.com", "internal", "desc", "admin")
        db = router._get_db()
        try:
            zone = router._find_zone_for_domain("exact.company.com", db)
            assert zone.name == "exact.company.com"
        finally:
            db.close()

    def test_wildcard_catch_all(self, router: SelectiveDNSRouter):
        router.create_dns_zone("*", "restricted", "catch-all", "admin")
        db = router._get_db()
        try:
            zone = router._find_zone_for_domain("anything-at-all.example.org", db)
            assert zone.name == "*"
        finally:
            db.close()

    def test_parent_domain_match(self, router: SelectiveDNSRouter):
        router.create_dns_zone("company.com", "internal", "desc", "admin")
        db = router._get_db()
        try:
            zone = router._find_zone_for_domain("deep.sub.company.com", db)
            assert zone.name == "company.com"
        finally:
            db.close()

    def test_wildcard_parent_match(self, router: SelectiveDNSRouter):
        router.create_dns_zone("*.internal.company.com", "restricted", "desc", "admin")
        db = router._get_db()
        try:
            zone = router._find_zone_for_domain("host.internal.company.com", db)
            assert zone.name == "*.internal.company.com"
        finally:
            db.close()

    def test_no_match_returns_none(self, router: SelectiveDNSRouter):
        db = router._get_db()
        try:
            assert router._find_zone_for_domain("totally-unmapped.org", db) is None
        finally:
            db.close()


# ---------------------------------------------------------------------------
# can_resolve_domain / filter_dns_response (the core routing decisions)
# ---------------------------------------------------------------------------

class TestCanResolveDomain:
    def test_empty_domain_denied(self, router: SelectiveDNSRouter):
        assert router.can_resolve_domain(None, "") is False

    def test_none_domain_denied(self, router: SelectiveDNSRouter):
        assert router.can_resolve_domain(None, None) is False  # type: ignore[arg-type]

    def test_malformed_domain_denied(self, router: SelectiveDNSRouter):
        assert router.can_resolve_domain(None, "invalid..domain.com") is False

    def test_no_custom_zone_allows_public_dns(self, router: SelectiveDNSRouter):
        assert router.can_resolve_domain(None, "unmapped.example.com") is True

    def test_public_zone_allows_without_token(self, router: SelectiveDNSRouter):
        router.create_dns_zone("public.company.com", "public", "desc", "admin")
        assert router.can_resolve_domain(None, "public.company.com") is True

    def test_nonpublic_zone_without_token_denied(self, router: SelectiveDNSRouter):
        router.create_dns_zone("internal.company.com", "internal", "desc", "admin")
        assert router.can_resolve_domain(None, "internal.company.com") is False

    def test_nonpublic_zone_unknown_token_denied(self, router: SelectiveDNSRouter):
        router.create_dns_zone("internal.company.com", "internal", "desc", "admin")
        assert router.can_resolve_domain("no-such-token", "internal.company.com") is False

    def test_authenticated_user_with_no_group_assignments_denied(
        self, router: SelectiveDNSRouter, db_engine, token_table
    ):
        router.create_dns_zone("internal.company.com", "internal", "desc", "admin")
        _insert_token(db_engine, token_table, plaintext="lone-user-token")

        assert router.can_resolve_domain("lone-user-token", "internal.company.com") is False

    def test_group_visibility_level_grants_access(self, router: SelectiveDNSRouter, db_engine, token_table):
        zone = router.create_dns_zone("internal.company.com", "internal", "desc", "admin")
        group = router.create_group("eng", "Eng team", ["internal"])
        user_id = _insert_token(db_engine, token_table, plaintext="eng-user-token")
        router.assign_user_to_group(user_id, group["group_id"], "member")

        assert router.can_resolve_domain("eng-user-token", "internal.company.com") is True
        assert zone["success"] is True

    def test_group_without_matching_visibility_and_no_grant_denied(
        self, router: SelectiveDNSRouter, db_engine, token_table
    ):
        router.create_dns_zone("restricted.company.com", "restricted", "desc", "admin")
        group = router.create_group("sales", "Sales team", ["public"])
        user_id = _insert_token(db_engine, token_table, plaintext="sales-user-token")
        router.assign_user_to_group(user_id, group["group_id"], "member")

        assert router.can_resolve_domain("sales-user-token", "restricted.company.com") is False

    def test_explicit_zone_grant_overrides_missing_visibility_level(
        self, router: SelectiveDNSRouter, db_engine, token_table
    ):
        """Group lacks the zone's visibility level in its bundle, but has an
        explicit group_zone_access grant for this specific zone -- allowed."""
        zone = router.create_dns_zone("restricted.company.com", "restricted", "desc", "admin")
        group = router.create_group("partners", "Partner team", ["public"])
        user_id = _insert_token(db_engine, token_table, plaintext="partner-user-token")
        router.assign_user_to_group(user_id, group["group_id"], "member")
        router.grant_zone_access_to_group(zone["zone_id"], group["group_id"], "admin")

        assert router.can_resolve_domain("partner-user-token", "restricted.company.com") is True

    def test_multiple_group_memberships_second_group_grants_access(
        self, router: SelectiveDNSRouter, db_engine, token_table
    ):
        """First group's visibility bundle doesn't match; second group's does --
        exercises the multi-assignment loop finding a later match."""
        router.create_dns_zone("internal.company.com", "internal", "desc", "admin")
        group_a = router.create_group("no-access", "desc", ["public"])
        group_b = router.create_group("has-access", "desc", ["internal"])
        user_id = _insert_token(db_engine, token_table, plaintext="multi-group-token")
        router.assign_user_to_group(user_id, group_a["group_id"], "member")
        router.assign_user_to_group(user_id, group_b["group_id"], "member")

        assert router.can_resolve_domain("multi-group-token", "internal.company.com") is True

    def test_revoked_grant_denies_access(self, router: SelectiveDNSRouter, db_engine, token_table):
        zone = router.create_dns_zone("restricted.company.com", "restricted", "desc", "admin")
        group = router.create_group("partners", "Partner team", ["public"])
        user_id = _insert_token(db_engine, token_table, plaintext="revoke-user-token")
        router.assign_user_to_group(user_id, group["group_id"], "member")
        router.grant_zone_access_to_group(zone["zone_id"], group["group_id"], "admin")
        assert router.can_resolve_domain("revoke-user-token", "restricted.company.com") is True

        router.revoke_zone_access_from_group(zone["zone_id"], group["group_id"], "admin")
        assert router.can_resolve_domain("revoke-user-token", "restricted.company.com") is False

    def test_removed_user_denied(self, router: SelectiveDNSRouter, db_engine, token_table):
        router.create_dns_zone("internal.company.com", "internal", "desc", "admin")
        group = router.create_group("eng", "desc", ["internal"])
        user_id = _insert_token(db_engine, token_table, plaintext="removable-user-token")
        router.assign_user_to_group(user_id, group["group_id"], "member")
        assert router.can_resolve_domain("removable-user-token", "internal.company.com") is True

        router.remove_user_from_group(user_id, group["group_id"], "admin")
        assert router.can_resolve_domain("removable-user-token", "internal.company.com") is False

    def test_deleted_group_denies_previously_authorized_user(
        self, router: SelectiveDNSRouter, db_engine, token_table
    ):
        router.create_dns_zone("internal.company.com", "internal", "desc", "admin")
        group = router.create_group("eng", "desc", ["internal"])
        user_id = _insert_token(db_engine, token_table, plaintext="deleted-group-user-token")
        router.assign_user_to_group(user_id, group["group_id"], "member")
        assert router.can_resolve_domain("deleted-group-user-token", "internal.company.com") is True

        router.delete_group(group["group_id"], "admin")
        assert router.can_resolve_domain("deleted-group-user-token", "internal.company.com") is False


class TestFilterDnsResponse:
    def test_authorized_domain_returns_original_response(self, router: SelectiveDNSRouter):
        original = {"Status": 0, "Answer": [{"name": "example.com", "type": 1, "data": "1.2.3.4"}]}
        result = router.filter_dns_response(None, "example.com", original)
        assert result is original

    def test_unauthorized_domain_returns_nxdomain(self, router: SelectiveDNSRouter):
        router.create_dns_zone("internal.company.com", "internal", "desc", "admin")
        original = {"Status": 0, "Answer": [{"name": "internal.company.com", "type": 1}]}

        result = router.filter_dns_response(None, "internal.company.com", original)

        assert result["Status"] == 3
        assert result["Answer"] == []
        assert result["Question"] == [{"name": "internal.company.com", "type": 1}]


# ---------------------------------------------------------------------------
# get_user_groups
# ---------------------------------------------------------------------------

class TestGetUserGroups:
    def test_no_assignments_returns_empty_list(self, router: SelectiveDNSRouter):
        assert router.get_user_groups(999) == []

    def test_returns_group_details_for_each_assignment(self, router: SelectiveDNSRouter, db_engine, token_table):
        group = router.create_group("eng", "Eng team", ["internal", "restricted"])
        user_id = _insert_token(db_engine, token_table, plaintext="group-list-token")
        router.assign_user_to_group(user_id, group["group_id"], "member")

        groups = router.get_user_groups(user_id)

        assert groups == [
            {
                "id": group["group_id"],
                "name": "eng",
                "description": "Eng team",
                "visibility_levels": ["internal", "restricted"],
            }
        ]


# ---------------------------------------------------------------------------
# get_zone_access_level
# ---------------------------------------------------------------------------

class TestGetZoneAccessLevel:
    def test_known_zone_returns_its_visibility(self, router: SelectiveDNSRouter):
        router.create_dns_zone("restricted.company.com", "restricted", "desc", "admin")
        assert router.get_zone_access_level("restricted.company.com") == "restricted"

    def test_unknown_zone_defaults_to_public(self, router: SelectiveDNSRouter):
        assert router.get_zone_access_level("unmapped.example.com") == "public"


# ---------------------------------------------------------------------------
# grant / revoke zone access
# ---------------------------------------------------------------------------

class TestGrantZoneAccessToGroup:
    def test_creates_new_grant(self, router: SelectiveDNSRouter):
        zone = router.create_dns_zone("z.company.com", "restricted", "desc", "admin")
        group = router.create_group("g", "desc", ["public"])
        result = router.grant_zone_access_to_group(zone["zone_id"], group["group_id"], "admin")
        assert result == {"success": True}

    def test_existing_grant_is_idempotent(self, router: SelectiveDNSRouter):
        zone = router.create_dns_zone("z.company.com", "restricted", "desc", "admin")
        group = router.create_group("g", "desc", ["public"])
        router.grant_zone_access_to_group(zone["zone_id"], group["group_id"], "admin")
        result = router.grant_zone_access_to_group(zone["zone_id"], group["group_id"], "admin")
        assert result == {"success": True}

    def test_exception_path_returns_failure(self, router: SelectiveDNSRouter, monkeypatch):
        monkeypatch.setattr(router, "_get_db", lambda: _failing_db())
        result = router.grant_zone_access_to_group(1, 1, "admin")
        assert result == {"success": False}


class TestRevokeZoneAccessFromGroup:
    def test_revokes_existing_grant(self, router: SelectiveDNSRouter):
        zone = router.create_dns_zone("z.company.com", "restricted", "desc", "admin")
        group = router.create_group("g", "desc", ["public"])
        router.grant_zone_access_to_group(zone["zone_id"], group["group_id"], "admin")

        result = router.revoke_zone_access_from_group(zone["zone_id"], group["group_id"], "admin")
        assert result == {"success": True}

    def test_revoke_nonexistent_grant_still_succeeds(self, router: SelectiveDNSRouter):
        result = router.revoke_zone_access_from_group(999, 999, "admin")
        assert result == {"success": True}

    def test_exception_path_returns_failure(self, router: SelectiveDNSRouter, monkeypatch):
        monkeypatch.setattr(router, "_get_db", lambda: _failing_db())
        result = router.revoke_zone_access_from_group(1, 1, "admin")
        assert result == {"success": False}


# ---------------------------------------------------------------------------
# remove_user_from_group
# ---------------------------------------------------------------------------

class TestRemoveUserFromGroup:
    def test_removes_existing_assignment(self, router: SelectiveDNSRouter):
        group = router.create_group("g", "desc", ["public"])
        router.assign_user_to_group(1, group["group_id"], "member")
        result = router.remove_user_from_group(1, group["group_id"], "admin")
        assert result == {"success": True}
        assert router.get_user_groups(1) == []

    def test_remove_nonexistent_assignment_still_succeeds(self, router: SelectiveDNSRouter):
        result = router.remove_user_from_group(999, 999, "admin")
        assert result == {"success": True}

    def test_exception_path_returns_failure(self, router: SelectiveDNSRouter, monkeypatch):
        monkeypatch.setattr(router, "_get_db", lambda: _failing_db())
        result = router.remove_user_from_group(1, 1, "admin")
        assert result == {"success": False}


# ---------------------------------------------------------------------------
# delete_group
# ---------------------------------------------------------------------------

class TestDeleteGroup:
    def test_deletes_existing_group(self, router: SelectiveDNSRouter):
        group = router.create_group("g", "desc", ["public"])
        result = router.delete_group(group["group_id"], "admin")
        assert result == {"success": True}

    def test_delete_nonexistent_group_still_succeeds(self, router: SelectiveDNSRouter):
        result = router.delete_group(999, "admin")
        assert result == {"success": True}

    def test_exception_path_returns_failure(self, router: SelectiveDNSRouter, monkeypatch):
        monkeypatch.setattr(router, "_get_db", lambda: _failing_db())
        result = router.delete_group(1, "admin")
        assert result == {"success": False}


# ---------------------------------------------------------------------------
# get_routing_stats
# ---------------------------------------------------------------------------

class TestGetRoutingStats:
    def test_zero_state(self, router: SelectiveDNSRouter):
        assert router.get_routing_stats() == {
            "groups": {"total": 0},
            "zones": {"total": 0},
            "user_assignments": {"total": 0},
            "zone_access_grants": {"total": 0},
        }

    def test_counts_reflect_created_records(self, router: SelectiveDNSRouter):
        zone = router.create_dns_zone("z.company.com", "restricted", "desc", "admin")
        group = router.create_group("g", "desc", ["public"])
        router.assign_user_to_group(1, group["group_id"], "member")
        router.grant_zone_access_to_group(zone["zone_id"], group["group_id"], "admin")

        stats = router.get_routing_stats()

        assert stats == {
            "groups": {"total": 1},
            "zones": {"total": 1},
            "user_assignments": {"total": 1},
            "zone_access_grants": {"total": 1},
        }
