"""
Cache Manager Service
Handles Redis/Valkey caching for DNS results.
"""
import redis
import json
import logging
from typing import Optional, Dict, Any
from app.config import CACHE_URL, CACHE_TTL

logger = logging.getLogger(__name__)


class CacheManager:
    """Redis/Valkey cache manager for DNS results."""

    def __init__(self, cache_url: str = CACHE_URL):
        try:
            self.redis = redis.from_url(cache_url, decode_responses=True)
            self.redis.ping()
            logger.info(f"Connected to cache at {cache_url}")
        except Exception as e:
            logger.error(f"Failed to connect to cache: {e}")
            self.redis = None

        self.cache_hits = 0
        self.cache_misses = 0

    async def get(self, domain: str, record_type: str) -> Optional[Dict[str, Any]]:
        """
        Get cached DNS result.

        Args:
            domain: Domain name
            record_type: Record type

        Returns:
            Cached DNS response or None
        """
        if not self.redis:
            return None

        cache_key = f"dns:{domain}:{record_type}"

        try:
            cached_data = self.redis.get(cache_key)

            if cached_data:
                self.cache_hits += 1
                logger.debug(f"Cache hit: {cache_key}")
                return json.loads(cached_data)
            else:
                self.cache_misses += 1
                logger.debug(f"Cache miss: {cache_key}")
                return None

        except Exception as e:
            logger.error(f"Cache get error: {e}")
            return None

    async def set(self, domain: str, record_type: str, result: Dict[str, Any], ttl: int = CACHE_TTL):
        """
        Cache DNS result.

        Args:
            domain: Domain name
            record_type: Record type
            result: DNS response to cache
            ttl: Time to live in seconds
        """
        if not self.redis:
            return

        cache_key = f"dns:{domain}:{record_type}"

        try:
            self.redis.setex(
                cache_key,
                ttl,
                json.dumps(result)
            )
            logger.debug(f"Cached: {cache_key} (TTL: {ttl}s)")

        except Exception as e:
            logger.error(f"Cache set error: {e}")

    def get_stats(self) -> Dict[str, int]:
        """Get cache statistics."""
        return {
            'cache_hits': self.cache_hits,
            'cache_misses': self.cache_misses,
            'hit_rate': (self.cache_hits / (self.cache_hits + self.cache_misses)
                        if (self.cache_hits + self.cache_misses) > 0 else 0)
        }

    def clear(self):
        """Clear all DNS cache entries."""
        if not self.redis:
            return

        try:
            keys = self.redis.keys("dns:*")
            if keys:
                self.redis.delete(*keys)
                logger.info(f"Cleared {len(keys)} cache entries")
        except Exception as e:
            logger.error(f"Cache clear error: {e}")
