"""
IOC (Indicators of Compromise) feed refresh job.

Runnable as: python3 -m app.jobs.ioc_refresh

Fetches all enabled IOC feeds, respects per-feed update frequency,
and logs a structured summary to stdout for supercronic capture.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from typing import Any

# Configure structured logging to stdout for supercronic
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
)
logger = logging.getLogger(__name__)


def _get_db_url() -> str:
    """Get database URL from environment or config default."""
    db_url = os.getenv("DB_URL")
    if db_url:
        return db_url
    # Fall back to config default
    try:
        from app.config import Config
        return Config.DB_URL
    except ImportError:
        return "sqlite://storage.db"


async def main() -> int:
    """
    Run IOC feed refresh job.

    Returns 0 on success, 1 on failure.
    Logs structured summary to stdout.
    """
    try:
        from app.services.ioc_ingestion_service import IOCManager

        db_url = _get_db_url()
        manager = IOCManager(db_url)

        # TODO(ioc-gating): skip refresh when PostHog flag 'squawkdns.ioc-ingestion' disabled

        result = await manager.update_all_feeds()

        # Log structured summary
        summary: dict[str, Any] = {
            "job": "ioc_refresh",
            "feeds_updated": result.get("feeds_updated", 0),
        }

        if "skipped" in result:
            summary["skipped"] = result["skipped"]

        if "error" in result:
            summary["error"] = result["error"]

        # Output as JSON for structured log capture
        print(json.dumps(summary))

        # Return appropriate exit code
        return 0 if result.get("success", False) else 1

    except Exception as e:
        error_summary = {
            "job": "ioc_refresh",
            "success": False,
            "error": str(e),
        }
        print(json.dumps(error_summary))
        logger.exception("IOC refresh job failed")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
