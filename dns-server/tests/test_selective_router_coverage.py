"""Coverage tests for app.services.selective_router.SelectiveRouter.

Exercises real routing decisions (allow/deny) across zone visibility levels
(public/internal/restricted/private/unknown), JWT-gated authorization via
the shared verify_squawk_jwt verifier, operational-mode fallback
(normal/cached/degraded/unknown), and zone lookup/statistics helpers.

No DB involved -- SelectiveRouter is purely in-memory + JWT verification,
so tests build zones directly and sign real ES256 tokens with the
session-scoped `jwt_keypair` fixture from conftest.py.
"""
from datetime import datetime, timedelta

import jwt as pyjwt
import pytest

from app.services.selective_router import SelectiveRouter


def _make_token(
    jwt_keypair,
    *,
    team_roles: dict | None = None,
    role: str | None = None,
    tenant: str | None = "default",
    expired: bool = False,
    issuer: str = "squawk-manager",
    audience: str = "squawk",
):
    """Sign a real ES256 JWT with the given claims (fail-closed verifier
    requires exp/iat/tenant; role/team_roles are optional authz inputs
    consumed by SelectiveRouter.check_zone_permission)."""
    now = datetime.utcnow()
    payload = {
        "sub": "1",
        "iss": issuer,
        "aud": audience,
        "exp": now + (timedelta(hours=-1) if expired else timedelta(hours=1)),
        "iat": now,
    }
    if tenant is not None:
        payload["tenant"] = tenant
    if team_roles is not None:
        payload["team_roles"] = team_roles
    if role is not None:
        payload["role"] = role
    return pyjwt.encode(payload, jwt_keypair["private"], algorithm="ES256")


@pytest.fixture
def router() -> SelectiveRouter:
    return SelectiveRouter()


class TestLoadZones:
    def test_load_zones_applies_defaults(self, router: SelectiveRouter):
        """Zone dicts missing visibility/allowed_teams/records get sane defaults."""
        router.load_zones([{"name": "bare.example.com"}])

        zone = router.zones["bare.example.com"]
        assert zone == {
            "name": "bare.example.com",
            "visibility": "public",
            "allowed_teams": [],
            "records": [],
        }

    def test_load_zones_replaces_previous_state(self, router: SelectiveRouter):
        """A second load_zones call clears prior zones rather than merging."""
        router.load_zones([{"name": "first.example.com"}])
        assert "first.example.com" in router.zones

        router.load_zones([{"name": "second.example.com", "visibility": "internal"}])

        assert "first.example.com" not in router.zones
        assert router.zones["second.example.com"]["visibility"] == "internal"


class TestCheckZonePermission:
    def test_no_matching_zone_allows(self, router: SelectiveRouter):
        """No custom zone rule -- fall through to public DNS resolution."""
        assert router.check_zone_permission("nowhere.example.com", token=None) is True

    def test_public_zone_always_allowed(self, router: SelectiveRouter):
        router.load_zones([{"name": "public.example.com", "visibility": "public"}])
        assert router.check_zone_permission("public.example.com", token=None) is True

    def test_nonpublic_zone_without_token_denied(self, router: SelectiveRouter):
        router.load_zones([{"name": "internal.example.com", "visibility": "internal"}])
        assert router.check_zone_permission("internal.example.com", token=None) is False

    def test_nonpublic_zone_with_unverifiable_token_denied(self, router: SelectiveRouter):
        """A garbage token fails verify_squawk_jwt (fail-closed) -> denied."""
        router.load_zones([{"name": "internal.example.com", "visibility": "internal"}])
        assert router.check_zone_permission("internal.example.com", token="not-a-jwt") is False

    def test_internal_zone_no_allowed_teams_configured_allows_any_authenticated(
        self, router: SelectiveRouter, jwt_keypair
    ):
        """Internal zone with no allowed_teams list is open to any valid token."""
        router.load_zones([{"name": "internal.example.com", "visibility": "internal"}])
        token = _make_token(jwt_keypair, team_roles={"eng": "member"})
        assert router.check_zone_permission("internal.example.com", token=token) is True

    def test_internal_zone_member_of_allowed_team_allowed(self, router: SelectiveRouter, jwt_keypair):
        router.load_zones(
            [{"name": "internal.example.com", "visibility": "internal", "allowed_teams": ["eng"]}]
        )
        token = _make_token(jwt_keypair, team_roles={"eng": "member"})
        assert router.check_zone_permission("internal.example.com", token=token) is True

    def test_internal_zone_non_member_denied(self, router: SelectiveRouter, jwt_keypair):
        router.load_zones(
            [{"name": "internal.example.com", "visibility": "internal", "allowed_teams": ["eng"]}]
        )
        token = _make_token(jwt_keypair, team_roles={"sales": "member"})
        assert router.check_zone_permission("internal.example.com", token=token) is False

    def test_restricted_zone_member_allowed(self, router: SelectiveRouter, jwt_keypair):
        router.load_zones(
            [{"name": "restricted.example.com", "visibility": "restricted", "allowed_teams": ["secops"]}]
        )
        token = _make_token(jwt_keypair, team_roles={"secops": "member"})
        assert router.check_zone_permission("restricted.example.com", token=token) is True

    def test_restricted_zone_non_member_denied(self, router: SelectiveRouter, jwt_keypair):
        router.load_zones(
            [{"name": "restricted.example.com", "visibility": "restricted", "allowed_teams": ["secops"]}]
        )
        token = _make_token(jwt_keypair, team_roles={"eng": "member"})
        assert router.check_zone_permission("restricted.example.com", token=token) is False

    def test_restricted_zone_no_allowed_teams_denies_everyone(self, router: SelectiveRouter, jwt_keypair):
        """Unlike internal, restricted with an empty allow-list denies (any() over [] is False)."""
        router.load_zones([{"name": "restricted.example.com", "visibility": "restricted"}])
        token = _make_token(jwt_keypair, team_roles={"eng": "member"})
        assert router.check_zone_permission("restricted.example.com", token=token) is False

    def test_private_zone_admin_allowed(self, router: SelectiveRouter, jwt_keypair):
        router.load_zones([{"name": "private.example.com", "visibility": "private"}])
        token = _make_token(jwt_keypair, role="admin")
        assert router.check_zone_permission("private.example.com", token=token) is True

    def test_private_zone_non_admin_denied(self, router: SelectiveRouter, jwt_keypair):
        router.load_zones([{"name": "private.example.com", "visibility": "private"}])
        token = _make_token(jwt_keypair, role="viewer")
        assert router.check_zone_permission("private.example.com", token=token) is False

    def test_private_zone_missing_role_claim_denied(self, router: SelectiveRouter, jwt_keypair):
        router.load_zones([{"name": "private.example.com", "visibility": "private"}])
        token = _make_token(jwt_keypair)
        assert router.check_zone_permission("private.example.com", token=token) is False

    def test_unknown_visibility_denies(self, router: SelectiveRouter, jwt_keypair):
        """Visibility values outside the known set fail closed."""
        router.load_zones([{"name": "weird.example.com", "visibility": "quantum"}])
        token = _make_token(jwt_keypair, role="admin")
        assert router.check_zone_permission("weird.example.com", token=token) is False

    def test_expired_token_denied(self, router: SelectiveRouter, jwt_keypair):
        router.load_zones([{"name": "internal.example.com", "visibility": "internal"}])
        token = _make_token(jwt_keypair, expired=True)
        assert router.check_zone_permission("internal.example.com", token=token) is False

    def test_missing_tenant_claim_denied(self, router: SelectiveRouter, jwt_keypair):
        """verify_squawk_jwt fails closed when tenant is absent."""
        router.load_zones([{"name": "internal.example.com", "visibility": "internal"}])
        token = _make_token(jwt_keypair, tenant=None)
        assert router.check_zone_permission("internal.example.com", token=token) is False

    def test_subdomain_matches_parent_zone(self, router: SelectiveRouter):
        router.load_zones([{"name": "example.com", "visibility": "public"}])
        assert router.check_zone_permission("deep.sub.example.com", token=None) is True


class TestGetZoneRecords:
    def test_returns_records_for_known_zone(self, router: SelectiveRouter):
        router.load_zones(
            [{"name": "example.com", "visibility": "public", "records": [{"type": "A", "value": "1.2.3.4"}]}]
        )
        assert router.get_zone_records("example.com") == [{"type": "A", "value": "1.2.3.4"}]

    def test_returns_none_for_unknown_zone(self, router: SelectiveRouter):
        assert router.get_zone_records("nowhere.example.com") is None

    def test_returns_empty_list_when_zone_has_no_records(self, router: SelectiveRouter):
        router.load_zones([{"name": "empty.example.com"}])
        assert router.get_zone_records("empty.example.com") == []


class TestFindZoneForDomain:
    def test_exact_match(self, router: SelectiveRouter):
        router.load_zones([{"name": "exact.example.com"}])
        assert router._find_zone_for_domain("exact.example.com")["name"] == "exact.example.com"

    def test_parent_domain_match(self, router: SelectiveRouter):
        router.load_zones([{"name": "example.com"}])
        zone = router._find_zone_for_domain("a.b.example.com")
        assert zone["name"] == "example.com"

    def test_no_match_returns_none(self, router: SelectiveRouter):
        router.load_zones([{"name": "example.com"}])
        assert router._find_zone_for_domain("totally-different.org") is None


class TestShouldServeZone:
    def test_no_custom_zone_always_serves(self, router: SelectiveRouter):
        assert router.should_serve_zone("nowhere.example.com", None, "normal") is True

    def test_normal_mode_delegates_to_permission_check(self, router: SelectiveRouter):
        router.load_zones([{"name": "internal.example.com", "visibility": "internal", "allowed_teams": ["eng"]}])
        assert router.should_serve_zone("internal.example.com", None, "normal") is False

    def test_cached_mode_delegates_to_permission_check(self, router: SelectiveRouter, jwt_keypair):
        router.load_zones([{"name": "internal.example.com", "visibility": "internal", "allowed_teams": ["eng"]}])
        token = _make_token(jwt_keypair, team_roles={"eng": "member"})
        assert router.should_serve_zone("internal.example.com", token, "cached") is True

    def test_degraded_mode_serves_public_only(self, router: SelectiveRouter):
        router.load_zones([{"name": "public.example.com", "visibility": "public"}])
        assert router.should_serve_zone("public.example.com", None, "degraded") is True

    def test_degraded_mode_blocks_nonpublic_even_with_valid_token(self, router: SelectiveRouter, jwt_keypair):
        router.load_zones([{"name": "internal.example.com", "visibility": "internal"}])
        token = _make_token(jwt_keypair, team_roles={"eng": "member"})
        assert router.should_serve_zone("internal.example.com", token, "degraded") is False

    def test_unknown_mode_denies(self, router: SelectiveRouter):
        router.load_zones([{"name": "internal.example.com", "visibility": "internal"}])
        assert router.should_serve_zone("internal.example.com", None, "bogus-mode") is False


class TestGetStats:
    def test_empty_router_has_zero_stats(self, router: SelectiveRouter):
        assert router.get_stats() == {"total_zones": 0, "visibility_breakdown": {}}

    def test_stats_breakdown_by_visibility(self, router: SelectiveRouter):
        router.load_zones(
            [
                {"name": "a.example.com", "visibility": "public"},
                {"name": "b.example.com", "visibility": "public"},
                {"name": "c.example.com", "visibility": "internal"},
            ]
        )
        stats = router.get_stats()
        assert stats["total_zones"] == 3
        assert stats["visibility_breakdown"] == {"public": 2, "internal": 1}
