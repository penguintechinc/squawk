"""
WHOIS cache cleanup job.

Runnable as: python3 -m app.jobs.whois_cleanup

Removes old WHOIS data based on retention policy,
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
    Run WHOIS cache cleanup job.

    Returns 0 on success, 1 on failure.
    Logs structured summary to stdout.
    """
    try:
        from app.services.whois_service import WHOISManager
        from app.services.posthog_client import PostHogClient

        db_url = _get_db_url()
        manager = WHOISManager(db_url)

        # Check PostHog feature flag for WHOIS lookup
        posthog = PostHogClient()
        distinct_id = os.getenv('HOSTNAME', 'squawk-manager')
        flag_enabled = posthog.feature_enabled(
            'squawkdns.whois-lookup',
            distinct_id,
            default=False,
        )

        if not flag_enabled:
            # Feature flag disabled; skip cleanup
            summary = {
                'job': 'whois_cleanup',
                'skipped': True,
                'reason': 'Feature flag squawkdns.whois-lookup is disabled',
            }
            print(json.dumps(summary))
            logger.info('WHOIS cleanup skipped: feature flag disabled')
            return 0

        deleted_count = await manager.cleanup_old_data()

        # Log structured summary
        summary: dict[str, Any] = {
            "job": "whois_cleanup",
            "deleted_entries": deleted_count,
            "success": True,
        }

        # Output as JSON for structured log capture
        print(json.dumps(summary))

        return 0

    except Exception as e:
        error_summary = {
            "job": "whois_cleanup",
            "success": False,
            "error": str(e),
        }
        print(json.dumps(error_summary))
        logger.exception("WHOIS cleanup job failed")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
