"""
Rate Limiting Tests
Tests for per-identity rate limiting on DoH query endpoints.
"""
import pytest
import asyncio
import time
from unittest.mock import Mock, AsyncMock, patch
from app.services.rate_limiter import (
    RateLimiter, InMemoryBackend, ValKeyBackend, TokenBucket
)


class TestTokenBucket:
    """Test the token bucket data structure."""

    def test_initial_state(self):
        """Test bucket starts at capacity."""
        bucket = TokenBucket(
            capacity=100.0,
            tokens=100.0,
            refill_rate=10.0,
            last_refill=time.time()
        )
        assert bucket.tokens == 100.0
        assert bucket.capacity == 100.0

    def test_allow_consumes_token(self):
        """Test allow() consumes a token."""
        now = time.time()
        bucket = TokenBucket(
            capacity=100.0,
            tokens=100.0,
            refill_rate=10.0,
            last_refill=now
        )
        assert bucket.allow(now) is True
        assert bucket.tokens == 99.0

    def test_allow_when_empty(self):
        """Test allow() returns False when out of tokens."""
        now = time.time()
        bucket = TokenBucket(
            capacity=100.0,
            tokens=0.0,
            refill_rate=10.0,
            last_refill=now
        )
        assert bucket.allow(now) is False
        assert bucket.tokens == 0.0

    def test_refill_over_time(self):
        """Test tokens refill at the correct rate."""
        now = time.time()
        bucket = TokenBucket(
            capacity=100.0,
            tokens=50.0,
            refill_rate=10.0,  # 10 tokens per second
            last_refill=now
        )
        # After 2 seconds, 20 tokens should be added
        later = now + 2.0
        tokens = bucket.tokens_available(later)
        assert 69.0 < tokens < 71.0  # Allow small float errors

    def test_refill_capped_at_capacity(self):
        """Test tokens don't exceed capacity."""
        now = time.time()
        bucket = TokenBucket(
            capacity=100.0,
            tokens=90.0,
            refill_rate=100.0,  # Refill very fast
            last_refill=now
        )
        # After 1 second, would refill 100 tokens, but capped at 100 total
        later = now + 1.0
        tokens = bucket.tokens_available(later)
        assert tokens == 100.0


class TestInMemoryBackend:
    """Test in-memory token bucket backend."""

    @pytest.mark.asyncio
    async def test_allow_request(self):
        """Test that allowed request returns True."""
        backend = InMemoryBackend(rps=10.0, burst=100.0)
        allowed = await backend.check_and_consume("test_identity")
        assert allowed is True

    @pytest.mark.asyncio
    async def test_burst_allowed(self):
        """Test burst capacity allows multiple rapid requests."""
        backend = InMemoryBackend(rps=1.0, burst=5.0)
        # Should allow 5 rapid requests (burst)
        for i in range(5):
            allowed = await backend.check_and_consume("test_id")
            assert allowed is True, f"Request {i+1} should be allowed"
        # 6th request should be denied
        allowed = await backend.check_and_consume("test_id")
        assert allowed is False

    @pytest.mark.asyncio
    async def test_refill_over_time(self):
        """Test requests are allowed again after refill time."""
        backend = InMemoryBackend(rps=10.0, burst=100.0)
        now = time.time()

        # Consume one token
        await backend.check_and_consume("test_id", now)

        # Immediately, next should fail if we simulate being at 0
        # Create new bucket with 0 tokens
        backend.buckets["test_id2"] = backend.buckets.__class__(
            capacity=100.0, tokens=0.0, refill_rate=10.0, last_refill=now
        )
        from app.services.rate_limiter import TokenBucket
        backend.buckets["test_id2"] = TokenBucket(
            capacity=100.0, tokens=0.0, refill_rate=10.0, last_refill=now
        )

        # After 0.2 seconds, 2 tokens should be available
        allowed_after_refill = await backend.check_and_consume("test_id2", now + 0.2)
        assert allowed_after_refill is True

    @pytest.mark.asyncio
    async def test_key_isolation(self):
        """Test different identities have separate limits."""
        backend = InMemoryBackend(rps=1.0, burst=1.0)

        # Consume burst for identity A
        allowed_a = await backend.check_and_consume("identity_a")
        assert allowed_a is True

        # Identity B should not be affected
        allowed_b = await backend.check_and_consume("identity_b")
        assert allowed_b is True

        # Next request for A should fail (out of burst)
        allowed_a2 = await backend.check_and_consume("identity_a")
        assert allowed_a2 is False

        # But B should still have tokens (not affected)
        allowed_b2 = await backend.check_and_consume("identity_b")
        assert allowed_b2 is False

    @pytest.mark.asyncio
    async def test_lru_eviction(self):
        """Test LRU eviction when max_keys exceeded."""
        backend = InMemoryBackend(rps=10.0, burst=100.0, max_keys=3)

        # Add 3 identities
        await backend.check_and_consume("id_1")
        await backend.check_and_consume("id_2")
        await backend.check_and_consume("id_3")
        assert len(backend.buckets) == 3

        # Add 4th identity, should evict id_1 (oldest)
        await backend.check_and_consume("id_4")
        assert len(backend.buckets) == 3
        assert "id_1" not in backend.buckets
        assert "id_4" in backend.buckets

    @pytest.mark.asyncio
    async def test_get_retry_after(self):
        """Test retry_after returns correct wait time."""
        backend = InMemoryBackend(rps=10.0, burst=1.0)
        now = time.time()

        # Consume the single token
        await backend.check_and_consume("test_id", now)

        # Try to get another and fail
        await backend.check_and_consume("test_id", now)

        # Get retry_after
        retry_after = await backend.get_retry_after("test_id")
        assert 0.09 < retry_after < 0.11  # ~0.1 seconds at 10 RPS


class TestValKeyBackend:
    """Test Valkey/Redis backend."""

    @pytest.mark.asyncio
    async def test_allow_request_with_redis_mock(self):
        """Test that allowed request returns True."""
        mock_redis = Mock()
        mock_redis.incr.return_value = 1
        mock_redis.expire.return_value = True

        backend = ValKeyBackend(mock_redis, rps=10.0, burst=100.0)
        allowed = await backend.check_and_consume("test_identity")

        assert allowed is True
        mock_redis.incr.assert_called_once()

    @pytest.mark.asyncio
    async def test_rate_limit_exceeded(self):
        """Test rate limit exceeded when counter exceeds max."""
        mock_redis = Mock()
        # First call returns count=11, which exceeds max_requests=10 (1 RPS * 1 second)
        mock_redis.incr.return_value = 11
        mock_redis.expire.return_value = True

        backend = ValKeyBackend(mock_redis, rps=10.0, burst=100.0, window_size=1)
        allowed = await backend.check_and_consume("test_identity")

        assert allowed is False

    @pytest.mark.asyncio
    async def test_redis_error_fails_open(self):
        """Test that Redis errors don't break the service (fail open)."""
        mock_redis = Mock()
        mock_redis.incr.side_effect = Exception("Connection error")

        backend = ValKeyBackend(mock_redis, rps=10.0, burst=100.0)
        allowed = await backend.check_and_consume("test_identity")

        # Should fail open (allow the request)
        assert allowed is True

    @pytest.mark.asyncio
    async def test_get_retry_after_with_redis_mock(self):
        """Test retry_after calculation."""
        mock_redis = Mock()
        mock_redis.get.return_value = str(11)  # Over limit

        backend = ValKeyBackend(mock_redis, rps=10.0, burst=100.0, window_size=1)
        retry_after = await backend.get_retry_after("test_identity")

        assert retry_after > 0.0


class TestRateLimiter:
    """Test the main RateLimiter orchestrator."""

    def test_disabled_by_default(self):
        """Test that rate limiting is disabled by default."""
        limiter = RateLimiter(enabled=False)
        assert limiter.enabled is False

    @pytest.mark.asyncio
    async def test_disabled_allows_all(self):
        """Test that disabled limiter allows all requests."""
        limiter = RateLimiter(enabled=False)
        allowed, retry_after = await limiter.check_limit(
            token_identity="user1", client_ip="127.0.0.1"
        )
        assert allowed is True
        assert retry_after == 0.0

    @pytest.mark.asyncio
    async def test_enabled_enforces_limit(self):
        """Test that enabled limiter enforces the limit."""
        limiter = RateLimiter(enabled=True, rps=1.0, burst=1.0)

        # First request allowed
        allowed1, _ = await limiter.check_limit(token_identity="user1")
        assert allowed1 is True

        # Second immediate request denied
        allowed2, retry_after = await limiter.check_limit(token_identity="user1")
        assert allowed2 is False
        assert retry_after > 0.0

    @pytest.mark.asyncio
    async def test_identity_priority_token_over_ip(self):
        """Test that token identity takes priority over IP."""
        limiter = RateLimiter(enabled=True, rps=1.0, burst=1.0)

        # Use both token and IP identity
        allowed1, _ = await limiter.check_limit(
            token_identity="user1", client_ip="192.168.1.1"
        )
        assert allowed1 is True

        # With same token identity, should fail (same bucket)
        allowed2, _ = await limiter.check_limit(
            token_identity="user1", client_ip="192.168.1.2"
        )
        assert allowed2 is False

    @pytest.mark.asyncio
    async def test_identity_fallback_to_ip(self):
        """Test fallback to client IP when no token identity."""
        limiter = RateLimiter(enabled=True, rps=1.0, burst=1.0)

        # First request with IP
        allowed1, _ = await limiter.check_limit(client_ip="10.0.0.1")
        assert allowed1 is True

        # Second request with same IP should fail
        allowed2, _ = await limiter.check_limit(client_ip="10.0.0.1")
        assert allowed2 is False

    @pytest.mark.asyncio
    async def test_identity_fallback_to_unknown(self):
        """Test fallback to 'unknown' when no identity provided."""
        limiter = RateLimiter(enabled=True, rps=1.0, burst=1.0)

        # Requests with no identity should share the "unknown" bucket
        allowed1, _ = await limiter.check_limit()
        assert allowed1 is True

        allowed2, _ = await limiter.check_limit()
        assert allowed2 is False

    def test_get_stats(self):
        """Test stats reporting."""
        limiter = RateLimiter(enabled=True, rps=50.0, burst=100.0)
        stats = limiter.get_stats()

        assert stats["enabled"] is True
        assert stats["rps"] == 50.0
        assert stats["burst"] == 100.0
        assert stats["total_requests"] == 0
        assert stats["limited_requests"] == 0
        assert stats["limit_rate"] == 0.0

    @pytest.mark.asyncio
    async def test_stats_tracking(self):
        """Test that stats are tracked correctly."""
        limiter = RateLimiter(enabled=True, rps=1.0, burst=1.0)

        # Make 3 requests (1 allowed, 1 limited)
        await limiter.check_limit(token_identity="user1")
        await limiter.check_limit(token_identity="user1")
        await limiter.check_limit(token_identity="user2")

        stats = limiter.get_stats()
        assert stats["total_requests"] == 3
        assert stats["limited_requests"] == 1
        assert 0.33 < stats["limit_rate"] < 0.34

    @pytest.mark.asyncio
    async def test_valkey_backend_selection(self):
        """Test Valkey backend is selected when redis_client provided."""
        mock_redis = Mock()
        mock_redis.incr.return_value = 1
        mock_redis.expire.return_value = True

        limiter = RateLimiter(
            enabled=True,
            redis_client=mock_redis,
            use_valkey=True
        )

        assert isinstance(limiter.backend, ValKeyBackend)

    def test_in_memory_backend_default(self):
        """Test in-memory backend is default."""
        limiter = RateLimiter(enabled=True)
        assert isinstance(limiter.backend, InMemoryBackend)

    def test_minimum_rps_enforced(self):
        """Test that minimum RPS of 1 is enforced."""
        limiter = RateLimiter(enabled=True, rps=0.1, burst=100.0)
        assert limiter.rps == 1.0

    def test_minimum_burst_enforced(self):
        """Test that minimum burst of 1 is enforced."""
        limiter = RateLimiter(enabled=True, rps=10.0, burst=0.1)
        assert limiter.burst == 1.0
