"""
PostHog feature flag client for Squawk DNS Manager.

Provides graceful feature flag evaluation with fallback caching.
If PostHog is unreachable or unconfigured, falls back to default values.
"""

from __future__ import annotations

import logging
import os
import socket
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class PostHogConfig:
    """PostHog configuration."""
    api_key: Optional[str]
    host: Optional[str]
    project_key: Optional[str]
    enabled: bool


class PostHogClient:
    """
    PostHog feature flag client with graceful degradation.

    If PostHog is unconfigured or unreachable, falls back to last-known
    cached values or defaults. Never raises exceptions; always returns
    a boolean.
    """

    def __init__(self) -> None:
        """Initialize PostHog client from environment variables."""
        self.api_key = os.getenv("POSTHOG_API_KEY")
        self.host = os.getenv("POSTHOG_HOST")
        self.project_key = os.getenv("POSTHOG_PROJECT_KEY")

        self.enabled = bool(self.api_key and self.host and self.project_key)

        # In-memory cache: (flag_key, distinct_id) -> bool
        self._flag_cache: dict[tuple[str, str], bool] = {}

        if self.enabled:
            self._init_posthog()
        else:
            logger.info(
                "PostHog not configured (POSTHOG_API_KEY, POSTHOG_HOST, "
                "POSTHOG_PROJECT_KEY not set). Feature flags will use defaults."
            )

    def _init_posthog(self) -> None:
        """Initialize PostHog SDK if available."""
        try:
            import posthog

            posthog.api_key = self.api_key
            posthog.host = self.host

            # Verify connectivity with a test call
            try:
                posthog.capture(
                    distinct_id="system",
                    event="squawk_posthog_initialized",
                    properties={"source": "posthog_client"},
                    timeout=2,
                )
                logger.info(f"PostHog initialized: host={self.host}")
            except (socket.error, TimeoutError) as e:
                logger.warning(f"PostHog initial connectivity check failed: {e}")

        except ImportError:
            logger.error(
                "posthog package not installed. Install it with: pip install posthog"
            )
            self.enabled = False

    def feature_enabled(
        self,
        flag_key: str,
        distinct_id: str,
        default: bool = False,
    ) -> bool:
        """
        Check if a feature flag is enabled for a distinct ID.

        Args:
            flag_key: Feature flag key (e.g., 'squawkdns.ioc-ingestion')
            distinct_id: User/deployment identifier
            default: Default value if flag evaluation fails or PostHog unavailable

        Returns:
            True if feature is enabled, False otherwise.
            On any error, returns last-known cached value if present, else default.
        """
        cache_key = (flag_key, distinct_id)

        # Try PostHog if enabled
        if self.enabled:
            try:
                import posthog

                result = posthog.get_feature_flag(
                    flag_key,
                    distinct_id,
                    send_feature_flag_events=False,
                )

                if result is not None:
                    enabled = bool(result)
                    self._flag_cache[cache_key] = enabled
                    logger.debug(
                        f"PostHog flag '{flag_key}' for '{distinct_id}': {enabled}"
                    )
                    return enabled

            except socket.error as e:
                logger.warning(
                    f"PostHog connectivity error for flag '{flag_key}': {e}. "
                    "Using cache/default."
                )
            except TimeoutError as e:
                logger.warning(
                    f"PostHog timeout for flag '{flag_key}': {e}. "
                    "Using cache/default."
                )
            except Exception as e:
                logger.error(
                    f"PostHog error evaluating flag '{flag_key}': {e}. "
                    "Using cache/default."
                )

        # Return cached value if available, else default
        if cache_key in self._flag_cache:
            cached = self._flag_cache[cache_key]
            logger.debug(
                f"Using cached value for flag '{flag_key}': {cached}"
            )
            return cached

        logger.debug(
            f"No PostHog or cached value for flag '{flag_key}', "
            f"returning default: {default}"
        )
        return default

    def clear_cache(self) -> None:
        """Clear all cached flag values."""
        self._flag_cache.clear()
        logger.debug("PostHog flag cache cleared")

    def get_cache_size(self) -> int:
        """Get number of cached entries."""
        return len(self._flag_cache)
