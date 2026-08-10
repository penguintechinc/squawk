"""
Rate Limiter Service
Provides per-identity rate limiting for DoH query endpoints using token bucket algorithm.
"""
import time
import logging
from dataclasses import dataclass
from typing import Optional, Dict, Tuple
from abc import ABC, abstractmethod
from collections import OrderedDict
import redis

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class TokenBucket:
    """Token bucket for rate limiting."""
    capacity: float
    tokens: float
    refill_rate: float
    last_refill: float

    def allow(self, now: Optional[float] = None) -> bool:
        """Check if a token is available and consume it."""
        if now is None:
            now = time.time()

        # Refill tokens since last refill
        time_passed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + time_passed * self.refill_rate)
        self.last_refill = now

        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

    def tokens_available(self, now: Optional[float] = None) -> float:
        """Get current available tokens (for testing/metrics)."""
        if now is None:
            now = time.time()
        time_passed = now - self.last_refill
        return min(self.capacity, self.tokens + time_passed * self.refill_rate)


class RateLimitBackend(ABC):
    """Abstract base class for rate limit backends."""

    @abstractmethod
    async def check_and_consume(self, key: str, now: Optional[float] = None) -> bool:
        """Check if request is allowed; consume a token if so."""
        pass

    @abstractmethod
    async def get_retry_after(self, key: str) -> float:
        """Get seconds until next token available."""
        pass


class InMemoryBackend(RateLimitBackend):
    """In-memory token bucket backend with LRU eviction."""

    def __init__(self, rps: float, burst: float, max_keys: int = 10000):
        """
        Initialize in-memory backend.

        Args:
            rps: Requests per second (refill rate)
            burst: Burst capacity (max tokens)
            max_keys: Maximum number of tracked identities (LRU eviction if exceeded)
        """
        self.rps = rps
        self.burst = burst
        self.max_keys = max_keys
        self.buckets: OrderedDict[str, TokenBucket] = OrderedDict()

    async def check_and_consume(self, key: str, now: Optional[float] = None) -> bool:
        """Check and consume a token from the bucket."""
        if now is None:
            now = time.time()

        # LRU eviction if at capacity
        if key not in self.buckets and len(self.buckets) >= self.max_keys:
            # Remove oldest (first) entry
            self.buckets.popitem(last=False)

        # Get or create bucket
        if key not in self.buckets:
            self.buckets[key] = TokenBucket(
                capacity=self.burst,
                tokens=self.burst,  # Start with full capacity
                refill_rate=self.rps,
                last_refill=now
            )
        else:
            # Move to end for LRU ordering
            self.buckets.move_to_end(key)

        bucket = self.buckets[key]
        return bucket.allow(now)

    async def get_retry_after(self, key: str) -> float:
        """Get seconds until next token is available."""
        if key not in self.buckets:
            return 0.0

        bucket = self.buckets[key]
        now = time.time()

        # If bucket has tokens, retry immediately
        if bucket.tokens_available(now) >= 1.0:
            return 0.0

        # Time to refill one token
        tokens_needed = 1.0 - bucket.tokens_available(now)
        return tokens_needed / self.rps if self.rps > 0 else 60.0


class ValKeyBackend(RateLimitBackend):
    """Valkey/Redis token bucket backend using fixed-window counters."""

    def __init__(self, redis_client: redis.Redis, rps: float, burst: float, window_size: int = 1):
        """
        Initialize Valkey backend.

        Args:
            redis_client: Redis/Valkey client
            rps: Requests per second (requests per window)
            burst: Burst capacity (not strictly enforced in fixed-window, but used for context)
            window_size: Window size in seconds (default 1s for per-second rate limit)
        """
        self.redis = redis_client
        self.rps = rps
        self.burst = burst
        self.window_size = window_size
        self.max_requests = max(1, int(rps * window_size))

    async def check_and_consume(self, key: str, now: Optional[float] = None) -> bool:
        """Check and consume request from fixed-window counter."""
        if now is None:
            now = time.time()

        window_key = f"rate_limit:{key}:{int(now / self.window_size)}"

        try:
            # INCR is atomic; EXPIRE sets TTL
            count = self.redis.incr(window_key)
            if count == 1:
                # First request in this window; set expiration
                self.redis.expire(window_key, self.window_size + 1)

            return count <= self.max_requests
        except Exception as e:
            logger.error(f"ValKey rate limit check error: {e}")
            # Fail open on backend error
            return True

    async def get_retry_after(self, key: str) -> float:
        """Get seconds until next window."""
        if not self.redis:
            return 0.0

        try:
            now = time.time()
            current_window_key = f"rate_limit:{key}:{int(now / self.window_size)}"
            count = self.redis.get(current_window_key)

            if count is None or int(count) < self.max_requests:
                return 0.0

            # Return time until next window
            return self.window_size - (now % self.window_size) + 0.1
        except Exception as e:
            logger.error(f"ValKey retry_after error: {e}")
            return 0.0


class RateLimiter:
    """
    Per-identity rate limiter for DoH queries.
    Supports both in-memory and Valkey backends.
    """

    def __init__(
        self,
        enabled: bool = False,
        rps: float = 50.0,
        burst: float = 100.0,
        redis_client: Optional[redis.Redis] = None,
        use_valkey: bool = False,
        max_in_memory_keys: int = 10000
    ):
        """
        Initialize rate limiter.

        Args:
            enabled: Enable rate limiting (default False for safe defaults)
            rps: Requests per second per identity
            burst: Burst capacity (token bucket max)
            redis_client: Optional Redis/Valkey client for distributed backend
            use_valkey: Use Valkey backend if redis_client provided
            max_in_memory_keys: Max identities to track in memory (LRU eviction)
        """
        self.enabled = enabled
        self.rps = max(1.0, float(rps))  # Minimum 1 RPS
        self.burst = max(1.0, float(burst))  # Minimum burst=1

        if use_valkey and redis_client:
            self.backend: RateLimitBackend = ValKeyBackend(
                redis_client, self.rps, self.burst
            )
            logger.info(f"Rate limiter initialized (Valkey backend, {self.rps} RPS)")
        else:
            self.backend: RateLimitBackend = InMemoryBackend(
                self.rps, self.burst, max_in_memory_keys
            )
            logger.info(
                f"Rate limiter initialized (in-memory backend, {self.rps} RPS, "
                f"max {max_in_memory_keys} identities)"
            )

        self.request_counter = 0
        self.limited_counter = 0

    async def check_limit(
        self,
        identity: Optional[str] = None,
        token_identity: Optional[str] = None,
        spiffe_id: Optional[str] = None,
        client_ip: Optional[str] = None
    ) -> Tuple[bool, float]:
        """
        Check if request is rate-limited.

        Args:
            identity: Explicit identity override (for testing)
            token_identity: JWT token identity (sub claim or similar)
            spiffe_id: SPIFFE identity (mTLS)
            client_ip: Client IP address (fallback)

        Returns:
            Tuple of (allowed: bool, retry_after_seconds: float)
        """
        if not self.enabled:
            return True, 0.0

        # Resolve identity with priority: explicit > token > SPIFFE > IP
        key = identity or token_identity or spiffe_id or client_ip or "unknown"

        self.request_counter += 1
        allowed = await self.backend.check_and_consume(key)

        if not allowed:
            self.limited_counter += 1
            retry_after = await self.backend.get_retry_after(key)
            logger.debug(f"Rate limit exceeded for {key}, retry_after={retry_after:.2f}s")
            return False, retry_after

        return True, 0.0

    def get_stats(self) -> Dict[str, any]:
        """Get rate limiting statistics."""
        return {
            "enabled": self.enabled,
            "rps": self.rps,
            "burst": self.burst,
            "total_requests": self.request_counter,
            "limited_requests": self.limited_counter,
            "limit_rate": (
                self.limited_counter / self.request_counter
                if self.request_counter > 0 else 0.0
            )
        }
