"""
JWT Signature Verification Regression Tests
Tests for CVE-style authentication bypass vulnerability in DNS zone authorization.
Ensures JWT signatures are properly verified before granting zone access.

regression: JWT signature verification (auth bypass)
"""

import pytest
import jwt as pyjwt
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch
from app.services.selective_router import SelectiveRouter
from app.utils.resilience import ResilienceManager
from app.services.manager_client import ManagerClient


# Test constants
VALID_SECRET = "super-secret-key-for-testing"
INVALID_SECRET = "wrong-secret-key"
TEST_USER_ID = "user-123"
TEST_TEAM = "engineering"
TEST_TEAM_2 = "finance"


def create_jwt_token(
    secret: str,
    teams: list[str] = None,
    user_id: str = TEST_USER_ID,
    role: str = "viewer",
    exp_delta_minutes: int = 60,
) -> str:
    """Create a signed JWT token for testing."""
    if teams is None:
        teams = [TEST_TEAM]

    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=exp_delta_minutes)

    payload = {
        "user_id": user_id,
        "teams": teams,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }

    return pyjwt.encode(payload, secret, algorithm="HS256")


class TestSelectiveRouterJWTVerification:
    """Test JWT signature verification in SelectiveRouter.check_zone_permission"""

    @pytest.fixture
    def router(self) -> SelectiveRouter:
        """Create a SelectiveRouter instance."""
        return SelectiveRouter()

    @pytest.fixture
    def internal_zone(self) -> dict:
        """Create a test internal zone."""
        return {
            "name": "internal.example.com",
            "visibility": "internal",
            "allowed_teams": [TEST_TEAM],
            "records": [],
        }

    @pytest.fixture
    def restricted_zone(self) -> dict:
        """Create a test restricted zone."""
        return {
            "name": "restricted.example.com",
            "visibility": "restricted",
            "allowed_teams": [TEST_TEAM],
            "records": [],
        }

    @pytest.fixture
    def private_zone(self) -> dict:
        """Create a test private zone."""
        return {
            "name": "private.example.com",
            "visibility": "private",
            "allowed_teams": [],
            "records": [],
        }

    @pytest.fixture
    def public_zone(self) -> dict:
        """Create a test public zone."""
        return {
            "name": "public.example.com",
            "visibility": "public",
            "allowed_teams": [],
            "records": [],
        }

    @patch("app.services.selective_router.JWT_SECRET_KEY", VALID_SECRET)
    def test_valid_signature_grants_access_internal(
        self, router: SelectiveRouter, internal_zone: dict
    ):
        """A token with VALID signature and matching team grants access to internal zone."""
        router.load_zones([internal_zone])
        token = create_jwt_token(VALID_SECRET, teams=[TEST_TEAM])

        result = router.check_zone_permission("internal.example.com", token)

        assert result is True

    @patch("app.services.selective_router.JWT_SECRET_KEY", VALID_SECRET)
    def test_forged_signature_denies_access_internal(
        self, router: SelectiveRouter, internal_zone: dict
    ):
        """A forged token (signed with wrong key) is DENIED even with correct team claim."""
        router.load_zones([internal_zone])
        # Sign with INVALID_SECRET, but server expects VALID_SECRET
        forged_token = create_jwt_token(INVALID_SECRET, teams=[TEST_TEAM])

        result = router.check_zone_permission("internal.example.com", forged_token)

        assert result is False

    @patch("app.services.selective_router.JWT_SECRET_KEY", VALID_SECRET)
    def test_unsigned_token_denies_access_internal(
        self, router: SelectiveRouter, internal_zone: dict
    ):
        """An unsigned token (signature stripped) is DENIED."""
        router.load_zones([internal_zone])
        # Create a payload and manually construct unsigned token
        payload = {
            "user_id": TEST_USER_ID,
            "teams": [TEST_TEAM],
            "role": "viewer",
        }
        # Split and remove signature
        signed_token = pyjwt.encode(payload, VALID_SECRET, algorithm="HS256")
        parts = signed_token.split(".")
        unsigned_token = f"{parts[0]}.{parts[1]}."  # No signature

        result = router.check_zone_permission("internal.example.com", unsigned_token)

        assert result is False

    @patch("app.services.selective_router.JWT_SECRET_KEY", VALID_SECRET)
    def test_valid_signature_denies_wrong_team_internal(
        self, router: SelectiveRouter, internal_zone: dict
    ):
        """A validly-signed token with WRONG team is DENIED."""
        router.load_zones([internal_zone])
        token = create_jwt_token(VALID_SECRET, teams=[TEST_TEAM_2])

        result = router.check_zone_permission("internal.example.com", token)

        assert result is False

    @patch("app.services.selective_router.JWT_SECRET_KEY", VALID_SECRET)
    def test_expired_token_denies_access_internal(
        self, router: SelectiveRouter, internal_zone: dict
    ):
        """An expired but validly-signed token is DENIED."""
        router.load_zones([internal_zone])
        # Create token that expires 5 minutes ago
        token = create_jwt_token(VALID_SECRET, teams=[TEST_TEAM], exp_delta_minutes=-5)

        result = router.check_zone_permission("internal.example.com", token)

        assert result is False

    @patch("app.services.selective_router.JWT_SECRET_KEY", VALID_SECRET)
    def test_valid_signature_grants_access_restricted(
        self, router: SelectiveRouter, restricted_zone: dict
    ):
        """A validly-signed token with matching team grants access to restricted zone."""
        router.load_zones([restricted_zone])
        token = create_jwt_token(VALID_SECRET, teams=[TEST_TEAM])

        result = router.check_zone_permission("restricted.example.com", token)

        assert result is True

    @patch("app.services.selective_router.JWT_SECRET_KEY", VALID_SECRET)
    def test_forged_signature_denies_access_restricted(
        self, router: SelectiveRouter, restricted_zone: dict
    ):
        """A forged token is DENIED for restricted zone."""
        router.load_zones([restricted_zone])
        forged_token = create_jwt_token(INVALID_SECRET, teams=[TEST_TEAM])

        result = router.check_zone_permission("restricted.example.com", forged_token)

        assert result is False

    @patch("app.services.selective_router.JWT_SECRET_KEY", VALID_SECRET)
    def test_valid_signature_admin_grants_access_private(
        self, router: SelectiveRouter, private_zone: dict
    ):
        """A validly-signed token with admin role grants access to private zone."""
        router.load_zones([private_zone])
        token = create_jwt_token(VALID_SECRET, role="admin")

        result = router.check_zone_permission("private.example.com", token)

        assert result is True

    @patch("app.services.selective_router.JWT_SECRET_KEY", VALID_SECRET)
    def test_forged_signature_admin_denies_access_private(
        self, router: SelectiveRouter, private_zone: dict
    ):
        """A forged token with admin claim is DENIED for private zone."""
        router.load_zones([private_zone])
        forged_token = create_jwt_token(INVALID_SECRET, role="admin")

        result = router.check_zone_permission("private.example.com", forged_token)

        assert result is False

    @patch("app.services.selective_router.JWT_SECRET_KEY", VALID_SECRET)
    def test_valid_signature_non_admin_denies_access_private(
        self, router: SelectiveRouter, private_zone: dict
    ):
        """A validly-signed token without admin role is DENIED for private zone."""
        router.load_zones([private_zone])
        token = create_jwt_token(VALID_SECRET, role="viewer")

        result = router.check_zone_permission("private.example.com", token)

        assert result is False

    @patch("app.services.selective_router.JWT_SECRET_KEY", None)
    def test_no_jwt_secret_denies_non_public_access(
        self, router: SelectiveRouter, internal_zone: dict
    ):
        """When JWT_SECRET_KEY is None, non-public zones are DENIED (fail-closed)."""
        router.load_zones([internal_zone])
        token = create_jwt_token(VALID_SECRET, teams=[TEST_TEAM])

        result = router.check_zone_permission("internal.example.com", token)

        assert result is False

    @patch("app.services.selective_router.JWT_SECRET_KEY", VALID_SECRET)
    def test_public_zone_no_token_allowed(
        self, router: SelectiveRouter, public_zone: dict
    ):
        """Public zones are always accessible without token (unchanged behavior)."""
        router.load_zones([public_zone])

        result = router.check_zone_permission("public.example.com", None)

        assert result is True

    @patch("app.services.selective_router.JWT_SECRET_KEY", VALID_SECRET)
    def test_public_zone_with_invalid_token_allowed(
        self, router: SelectiveRouter, public_zone: dict
    ):
        """Public zones are accessible even with invalid token."""
        router.load_zones([public_zone])
        forged_token = create_jwt_token(INVALID_SECRET)

        result = router.check_zone_permission("public.example.com", forged_token)

        assert result is True


class TestResilienceManagerJWTVerification:
    """Test JWT signature verification in ResilienceManager._check_zone_permission"""

    @pytest.fixture
    def mock_manager_client(self) -> Mock:
        """Create a mock ManagerClient."""
        mock = Mock(spec=ManagerClient)
        mock.is_jwt_valid.return_value = True
        mock.refresh_jwt.return_value = False
        mock.cached_at = datetime.now()
        mock.config_cache = {"zones": []}
        return mock

    @pytest.fixture
    def resilience_mgr(self, mock_manager_client: Mock) -> ResilienceManager:
        """Create a ResilienceManager instance."""
        return ResilienceManager(mock_manager_client)

    @pytest.fixture
    def internal_zone(self) -> dict:
        """Create a test internal zone."""
        return {
            "name": "internal.example.com",
            "visibility": "internal",
            "allowed_teams": [TEST_TEAM],
        }

    @pytest.fixture
    def public_zone(self) -> dict:
        """Create a test public zone."""
        return {
            "name": "public.example.com",
            "visibility": "public",
            "allowed_teams": [],
        }

    @patch("app.utils.resilience.JWT_SECRET_KEY", VALID_SECRET)
    def test_valid_signature_grants_access_internal(
        self, resilience_mgr: ResilienceManager, internal_zone: dict, mock_manager_client: Mock
    ):
        """A token with VALID signature and matching team grants access to internal zone."""
        mock_manager_client.config_cache = {"zones": [internal_zone]}
        token = create_jwt_token(VALID_SECRET, teams=[TEST_TEAM])

        result = resilience_mgr.should_serve_zone("internal.example.com", token)

        assert result is True

    @patch("app.utils.resilience.JWT_SECRET_KEY", VALID_SECRET)
    def test_forged_signature_denies_access_internal(
        self, resilience_mgr: ResilienceManager, internal_zone: dict, mock_manager_client: Mock
    ):
        """A forged token (signed with wrong key) is DENIED."""
        mock_manager_client.config_cache = {"zones": [internal_zone]}
        forged_token = create_jwt_token(INVALID_SECRET, teams=[TEST_TEAM])

        result = resilience_mgr.should_serve_zone("internal.example.com", forged_token)

        assert result is False

    @patch("app.utils.resilience.JWT_SECRET_KEY", VALID_SECRET)
    def test_expired_token_denies_access_internal(
        self, resilience_mgr: ResilienceManager, internal_zone: dict, mock_manager_client: Mock
    ):
        """An expired but validly-signed token is DENIED."""
        mock_manager_client.config_cache = {"zones": [internal_zone]}
        token = create_jwt_token(VALID_SECRET, teams=[TEST_TEAM], exp_delta_minutes=-5)

        result = resilience_mgr.should_serve_zone("internal.example.com", token)

        assert result is False

    @patch("app.utils.resilience.JWT_SECRET_KEY", None)
    def test_no_jwt_secret_denies_non_public_access(
        self, resilience_mgr: ResilienceManager, internal_zone: dict, mock_manager_client: Mock
    ):
        """When JWT_SECRET_KEY is None, non-public zones are DENIED (fail-closed)."""
        mock_manager_client.config_cache = {"zones": [internal_zone]}
        token = create_jwt_token(VALID_SECRET, teams=[TEST_TEAM])

        result = resilience_mgr.should_serve_zone("internal.example.com", token)

        assert result is False

    @patch("app.utils.resilience.JWT_SECRET_KEY", VALID_SECRET)
    def test_public_zone_no_token_allowed(
        self, resilience_mgr: ResilienceManager, public_zone: dict, mock_manager_client: Mock
    ):
        """Public zones are always accessible without token."""
        mock_manager_client.config_cache = {"zones": [public_zone]}

        result = resilience_mgr.should_serve_zone("public.example.com", None)

        assert result is True

    @patch("app.utils.resilience.JWT_SECRET_KEY", VALID_SECRET)
    def test_valid_signature_denies_wrong_team_internal(
        self, resilience_mgr: ResilienceManager, internal_zone: dict, mock_manager_client: Mock
    ):
        """A validly-signed token with WRONG team is DENIED."""
        mock_manager_client.config_cache = {"zones": [internal_zone]}
        token = create_jwt_token(VALID_SECRET, teams=[TEST_TEAM_2])

        result = resilience_mgr.should_serve_zone("internal.example.com", token)

        assert result is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
