"""Coverage tests for app.utils.resilience.ResilienceManager.

Exercises mode transitions (normal/cached/degraded), zone-serving decisions
across each mode, team-based permission checks, and status reporting.
"""
from datetime import datetime, timedelta
from unittest.mock import Mock

import pytest

from app.services.manager_client import ManagerClient
from app.utils.resilience import ResilienceManager


@pytest.fixture
def mock_client() -> Mock:
    """A mocked ManagerClient with a fresh, valid JWT and no cached config."""
    mock = Mock(spec=ManagerClient)
    mock.is_jwt_valid.return_value = True
    mock.refresh_jwt.return_value = False
    mock.cached_at = None
    mock.config_cache = {}
    return mock


@pytest.fixture
def manager(mock_client: Mock) -> ResilienceManager:
    """A ResilienceManager wired to the mocked client with a 1-hour cache TTL."""
    return ResilienceManager(mock_client, cache_ttl_hours=1)


class TestCheckMode:
    """Covers all branches of ResilienceManager.check_mode."""

    def test_valid_jwt_returns_normal(self, manager: ResilienceManager, mock_client: Mock) -> None:
        mock_client.is_jwt_valid.return_value = True
        assert manager.check_mode() == "normal"

    def test_invalid_jwt_refresh_succeeds_returns_normal(
        self, manager: ResilienceManager, mock_client: Mock
    ) -> None:
        mock_client.is_jwt_valid.return_value = False
        mock_client.refresh_jwt.return_value = True
        assert manager.check_mode() == "normal"

    def test_refresh_fails_cache_within_ttl_returns_cached(
        self, manager: ResilienceManager, mock_client: Mock
    ) -> None:
        mock_client.is_jwt_valid.return_value = False
        mock_client.refresh_jwt.return_value = False
        mock_client.cached_at = datetime.now() - timedelta(minutes=5)
        assert manager.check_mode() == "cached"

    def test_cached_mode_repeat_call_does_not_change_result(
        self, manager: ResilienceManager, mock_client: Mock
    ) -> None:
        """First call transitions normal->cached (logs); second stays cached (skips log branch)."""
        mock_client.is_jwt_valid.return_value = False
        mock_client.refresh_jwt.return_value = False
        mock_client.cached_at = datetime.now() - timedelta(minutes=5)
        assert manager.mode == "normal"
        assert manager.check_mode() == "cached"
        assert manager.check_mode() == "cached"

    def test_no_cache_returns_degraded(self, manager: ResilienceManager, mock_client: Mock) -> None:
        mock_client.is_jwt_valid.return_value = False
        mock_client.refresh_jwt.return_value = False
        mock_client.cached_at = None
        assert manager.check_mode() == "degraded"

    def test_cache_expired_returns_degraded(self, manager: ResilienceManager, mock_client: Mock) -> None:
        mock_client.is_jwt_valid.return_value = False
        mock_client.refresh_jwt.return_value = False
        mock_client.cached_at = datetime.now() - timedelta(hours=2)  # ttl is 1h
        assert manager.check_mode() == "degraded"

    def test_degraded_mode_repeat_call_does_not_change_result(
        self, manager: ResilienceManager, mock_client: Mock
    ) -> None:
        """First call transitions normal->degraded (logs); second stays degraded (skips log branch)."""
        mock_client.is_jwt_valid.return_value = False
        mock_client.refresh_jwt.return_value = False
        mock_client.cached_at = None
        assert manager.mode == "normal"
        assert manager.check_mode() == "degraded"
        assert manager.check_mode() == "degraded"


class TestShouldServeZone:
    """Covers should_serve_zone across zone lookup and each operational mode."""

    def test_no_zone_name_always_serves(self, manager: ResilienceManager, mock_client: Mock) -> None:
        mock_client.is_jwt_valid.return_value = True
        assert manager.should_serve_zone(None, None) is True

    def test_zone_not_found_serves(self, manager: ResilienceManager, mock_client: Mock) -> None:
        mock_client.is_jwt_valid.return_value = True
        mock_client.config_cache = {"zones": [{"name": "other.com", "visibility": "public"}]}
        assert manager.should_serve_zone("missing.com", None) is True

    def test_normal_mode_public_zone_no_token(self, manager: ResilienceManager, mock_client: Mock) -> None:
        mock_client.is_jwt_valid.return_value = True
        mock_client.config_cache = {"zones": [{"name": "pub.com", "visibility": "public"}]}
        assert manager.should_serve_zone("pub.com", None) is True

    def test_normal_mode_private_zone_no_token_denied(
        self, manager: ResilienceManager, mock_client: Mock
    ) -> None:
        mock_client.is_jwt_valid.return_value = True
        mock_client.config_cache = {
            "zones": [{"name": "priv.com", "visibility": "internal", "allowed_teams": []}]
        }
        assert manager.should_serve_zone("priv.com", None) is False

    def test_cached_mode_permission_enforced(self, manager: ResilienceManager, mock_client: Mock) -> None:
        mock_client.is_jwt_valid.return_value = False
        mock_client.refresh_jwt.return_value = False
        mock_client.cached_at = datetime.now()
        mock_client.config_cache = {"zones": [{"name": "pub.com", "visibility": "public"}]}
        assert manager.should_serve_zone("pub.com", None) is True

    def test_degraded_mode_public_zone_served(self, manager: ResilienceManager, mock_client: Mock) -> None:
        mock_client.is_jwt_valid.return_value = False
        mock_client.refresh_jwt.return_value = False
        mock_client.cached_at = None
        mock_client.config_cache = {"zones": [{"name": "pub.com", "visibility": "public"}]}
        assert manager.should_serve_zone("pub.com", None) is True

    def test_degraded_mode_private_zone_denied(self, manager: ResilienceManager, mock_client: Mock) -> None:
        mock_client.is_jwt_valid.return_value = False
        mock_client.refresh_jwt.return_value = False
        mock_client.cached_at = None
        mock_client.config_cache = {"zones": [{"name": "priv.com", "visibility": "internal"}]}
        assert manager.should_serve_zone("priv.com", "sometoken") is False

    def test_unknown_mode_falls_through_to_false(
        self, manager: ResilienceManager, mock_client: Mock
    ) -> None:
        """Defensive fallback branch: an unrecognized mode value denies service."""
        mock_client.config_cache = {"zones": [{"name": "z.com", "visibility": "public"}]}
        manager.check_mode = lambda: "weird"  # type: ignore[method-assign]
        assert manager.should_serve_zone("z.com", None) is False


class TestCheckZonePermission:
    """Covers _check_zone_permission: public bypass, missing token, JWT verification, team checks."""

    def test_public_zone_always_true(self, manager: ResilienceManager) -> None:
        zone = {"visibility": "public"}
        assert manager._check_zone_permission(zone, None) is True

    def test_private_zone_no_token_false(self, manager: ResilienceManager) -> None:
        zone = {"visibility": "internal"}
        assert manager._check_zone_permission(zone, None) is False

    def test_private_zone_invalid_token_false(
        self, manager: ResilienceManager, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("app.utils.resilience.JWT_PUBLIC_KEY", "not-a-valid-pem-key")
        zone = {"visibility": "internal"}
        assert manager._check_zone_permission(zone, "garbage-token") is False

    def test_private_zone_no_allowed_teams_true(
        self,
        manager: ResilienceManager,
        monkeypatch: pytest.MonkeyPatch,
        jwt_keypair: dict,
        jwt_token_factory,
    ) -> None:
        monkeypatch.setattr("app.utils.resilience.JWT_PUBLIC_KEY", jwt_keypair["public"])
        token = jwt_token_factory(team_roles={"teamA": "member"})
        zone = {"visibility": "internal", "allowed_teams": []}
        assert manager._check_zone_permission(zone, token) is True

    def test_private_zone_user_in_allowed_team_true(
        self,
        manager: ResilienceManager,
        monkeypatch: pytest.MonkeyPatch,
        jwt_keypair: dict,
        jwt_token_factory,
    ) -> None:
        monkeypatch.setattr("app.utils.resilience.JWT_PUBLIC_KEY", jwt_keypair["public"])
        token = jwt_token_factory(team_roles={"teamA": "member"})
        zone = {"visibility": "internal", "allowed_teams": ["teamA"]}
        assert manager._check_zone_permission(zone, token) is True

    def test_private_zone_user_not_in_allowed_team_false(
        self,
        manager: ResilienceManager,
        monkeypatch: pytest.MonkeyPatch,
        jwt_keypair: dict,
        jwt_token_factory,
    ) -> None:
        monkeypatch.setattr("app.utils.resilience.JWT_PUBLIC_KEY", jwt_keypair["public"])
        token = jwt_token_factory(team_roles={"teamB": "member"})
        zone = {"visibility": "internal", "allowed_teams": ["teamA"]}
        assert manager._check_zone_permission(zone, token) is False

    def test_private_zone_no_team_roles_claim_denied(
        self,
        manager: ResilienceManager,
        monkeypatch: pytest.MonkeyPatch,
        jwt_keypair: dict,
        jwt_token_factory,
    ) -> None:
        monkeypatch.setattr("app.utils.resilience.JWT_PUBLIC_KEY", jwt_keypair["public"])
        token = jwt_token_factory(team_roles={})
        zone = {"visibility": "internal", "allowed_teams": ["teamA"]}
        assert manager._check_zone_permission(zone, token) is False


class TestGetModeAndStatus:
    """Covers get_mode and get_status, with and without an active cache."""

    def test_get_mode_returns_current_mode(self, manager: ResilienceManager) -> None:
        manager.mode = "cached"
        assert manager.get_mode() == "cached"

    def test_get_status_with_cache(self, manager: ResilienceManager, mock_client: Mock) -> None:
        mock_client.is_jwt_valid.return_value = True
        mock_client.cached_at = datetime.now() - timedelta(minutes=1)
        status = manager.get_status()
        assert status["mode"] == "normal"
        assert status["jwt_valid"] is True
        assert status["has_cache"] is True
        assert "cache_age_seconds" in status
        assert "cache_ttl_seconds" in status
        assert "cache_expires_in_seconds" in status

    def test_get_status_without_cache(self, manager: ResilienceManager, mock_client: Mock) -> None:
        mock_client.is_jwt_valid.return_value = False
        mock_client.refresh_jwt.return_value = False
        mock_client.cached_at = None
        status = manager.get_status()
        assert status["mode"] == "degraded"
        assert status["has_cache"] is False
        assert "cache_age_seconds" not in status
