"""
Tests for IOC refresh job (app.jobs.ioc_refresh).
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, patch, MagicMock

import pytest


@pytest.mark.asyncio
async def test_ioc_refresh_main_success(capsys: pytest.CaptureFixture[str]) -> None:
    """Test main() returns 0 when update_all_feeds succeeds."""
    from app.jobs.ioc_refresh import main

    mock_result = {
        "success": True,
        "feeds_updated": 3,
        "skipped": 1,
    }

    with patch("app.services.posthog_client.PostHogClient") as MockPostHog:
        mock_posthog = MagicMock()
        mock_posthog.feature_enabled.return_value = True
        MockPostHog.return_value = mock_posthog

        with patch("app.services.ioc_ingestion_service.IOCManager") as MockIOCManager:
            mock_manager = MagicMock()
            mock_manager.update_all_feeds = AsyncMock(return_value=mock_result)
            MockIOCManager.return_value = mock_manager

            exit_code = await main()

    assert exit_code == 0
    captured = capsys.readouterr()
    output = json.loads(captured.out)
    assert output["job"] == "ioc_refresh"
    assert output["feeds_updated"] == 3
    assert output["skipped"] == 1


@pytest.mark.asyncio
async def test_ioc_refresh_main_failure(capsys: pytest.CaptureFixture[str]) -> None:
    """Test main() returns non-zero when update_all_feeds reports failure."""
    from app.jobs.ioc_refresh import main

    mock_result = {
        "success": False,
        "feeds_updated": 1,
        "error": "Network timeout on feed update",
    }

    with patch("app.services.posthog_client.PostHogClient") as MockPostHog:
        mock_posthog = MagicMock()
        mock_posthog.feature_enabled.return_value = True
        MockPostHog.return_value = mock_posthog

        with patch("app.services.ioc_ingestion_service.IOCManager") as MockIOCManager:
            mock_manager = MagicMock()
            mock_manager.update_all_feeds = AsyncMock(return_value=mock_result)
            MockIOCManager.return_value = mock_manager

            exit_code = await main()

    assert exit_code != 0
    captured = capsys.readouterr()
    output = json.loads(captured.out)
    assert output["job"] == "ioc_refresh"
    assert output["feeds_updated"] == 1
    assert "error" in output


@pytest.mark.asyncio
async def test_ioc_refresh_main_exception(capsys: pytest.CaptureFixture[str]) -> None:
    """Test main() returns non-zero on exception."""
    from app.jobs.ioc_refresh import main

    with patch("app.services.posthog_client.PostHogClient") as MockPostHog:
        mock_posthog = MagicMock()
        mock_posthog.feature_enabled.return_value = True
        MockPostHog.return_value = mock_posthog

        with patch("app.services.ioc_ingestion_service.IOCManager") as MockIOCManager:
            MockIOCManager.side_effect = RuntimeError("Database connection failed")

            exit_code = await main()

    assert exit_code != 0
    captured = capsys.readouterr()
    output = json.loads(captured.out)
    assert output["success"] is False
    assert "Database connection failed" in output["error"]


def test_ioc_refresh_db_url_from_env() -> None:
    """Test _get_db_url reads from DB_URL env var."""
    from app.jobs.ioc_refresh import _get_db_url
    import os

    original_db_url = os.environ.get("DB_URL")
    try:
        os.environ["DB_URL"] = "postgresql://testhost/testdb"
        result = _get_db_url()
        assert result == "postgresql://testhost/testdb"
    finally:
        if original_db_url:
            os.environ["DB_URL"] = original_db_url
        else:
            os.environ.pop("DB_URL", None)


def test_ioc_refresh_db_url_fallback() -> None:
    """Test _get_db_url falls back to config default when DB_URL unset."""
    from app.jobs.ioc_refresh import _get_db_url
    import os

    original_db_url = os.environ.get("DB_URL")
    try:
        os.environ.pop("DB_URL", None)
        result = _get_db_url()
        # Should be the config default or hardcoded fallback
        assert result is not None
        assert isinstance(result, str)
    finally:
        if original_db_url:
            os.environ["DB_URL"] = original_db_url
