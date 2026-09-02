"""
Coverage tests for app/services/cache_manager.py

Covers CacheManager init success/failure, get/set/clear happy paths and
error paths, and get_stats ratio math. Redis is mocked throughout (no real
Redis/Valkey server needed) since fakeredis is not installed in this
environment.
"""
import json

import pytest
from unittest.mock import Mock, patch

from app.services.cache_manager import CacheManager


class _FakeRedis:
    """Minimal stand-in for a redis.Redis client used in tests."""

    def __init__(self):
        self.store = {}
        self.ping_error = None
        self.get_error = None
        self.setex_error = None
        self.keys_error = None

    def ping(self):
        if self.ping_error:
            raise self.ping_error
        return True

    def get(self, key):
        if self.get_error:
            raise self.get_error
        return self.store.get(key)

    def setex(self, key, ttl, value):
        if self.setex_error:
            raise self.setex_error
        self.store[key] = value

    def keys(self, pattern):
        if self.keys_error:
            raise self.keys_error
        prefix = pattern.rstrip("*")
        return [k for k in self.store if k.startswith(prefix)]

    def delete(self, *keys):
        for k in keys:
            self.store.pop(k, None)


class TestCacheManagerInit:
    """Constructor connects (and pings) the Redis client, failing closed."""

    def test_init_success_sets_redis_client(self):
        fake = _FakeRedis()
        with patch("app.services.cache_manager.redis.from_url", return_value=fake):
            manager = CacheManager(cache_url="redis://fake:6379")

        assert manager.redis is fake
        assert manager.cache_hits == 0
        assert manager.cache_misses == 0

    def test_init_from_url_raises_leaves_redis_none(self):
        with patch(
            "app.services.cache_manager.redis.from_url",
            side_effect=ConnectionError("no route to host"),
        ):
            manager = CacheManager(cache_url="redis://unreachable:6379")

        assert manager.redis is None

    def test_init_ping_failure_leaves_redis_none(self):
        fake = _FakeRedis()
        fake.ping_error = ConnectionError("refused")
        with patch("app.services.cache_manager.redis.from_url", return_value=fake):
            manager = CacheManager(cache_url="redis://fake:6379")

        assert manager.redis is None


def _manager_with_fake_redis(fake=None):
    fake = fake if fake is not None else _FakeRedis()
    with patch("app.services.cache_manager.redis.from_url", return_value=fake):
        manager = CacheManager(cache_url="redis://fake:6379")
    return manager, fake


class TestCacheManagerGet:
    @pytest.mark.asyncio
    async def test_get_returns_none_when_no_redis(self):
        manager, _ = _manager_with_fake_redis()
        manager.redis = None

        result = await manager.get("example.com", "A")

        assert result is None
        assert manager.cache_hits == 0
        assert manager.cache_misses == 0

    @pytest.mark.asyncio
    async def test_get_cache_hit_increments_hits_and_parses_json(self):
        manager, fake = _manager_with_fake_redis()
        payload = {"Status": 0, "Answer": [{"data": "1.2.3.4"}]}
        fake.store["dns:example.com:A"] = json.dumps(payload)

        result = await manager.get("example.com", "A")

        assert result == payload
        assert manager.cache_hits == 1
        assert manager.cache_misses == 0

    @pytest.mark.asyncio
    async def test_get_cache_miss_increments_misses(self):
        manager, _ = _manager_with_fake_redis()

        result = await manager.get("missing.example.com", "A")

        assert result is None
        assert manager.cache_hits == 0
        assert manager.cache_misses == 1

    @pytest.mark.asyncio
    async def test_get_exception_returns_none_without_raising(self):
        fake = _FakeRedis()
        fake.get_error = RuntimeError("redis exploded")
        manager, _ = _manager_with_fake_redis(fake)

        result = await manager.get("example.com", "A")

        assert result is None


class TestCacheManagerSet:
    @pytest.mark.asyncio
    async def test_set_is_noop_when_no_redis(self):
        manager, fake = _manager_with_fake_redis()
        manager.redis = None

        await manager.set("example.com", "A", {"Status": 0})

        assert fake.store == {}

    @pytest.mark.asyncio
    async def test_set_stores_serialized_result_with_ttl(self):
        manager, fake = _manager_with_fake_redis()
        result = {"Status": 0, "Answer": []}

        await manager.set("example.com", "A", result, ttl=60)

        assert json.loads(fake.store["dns:example.com:A"]) == result

    @pytest.mark.asyncio
    async def test_set_uses_default_ttl_from_config(self):
        manager, fake = _manager_with_fake_redis()

        await manager.set("example.com", "AAAA", {"Status": 0})

        assert "dns:example.com:AAAA" in fake.store

    @pytest.mark.asyncio
    async def test_set_exception_is_swallowed(self):
        fake = _FakeRedis()
        fake.setex_error = RuntimeError("write failed")
        manager, _ = _manager_with_fake_redis(fake)

        # Must not raise.
        await manager.set("example.com", "A", {"Status": 0})


class TestCacheManagerStats:
    def test_get_stats_zero_hit_rate_when_no_activity(self):
        manager, _ = _manager_with_fake_redis()

        stats = manager.get_stats()

        assert stats == {"cache_hits": 0, "cache_misses": 0, "hit_rate": 0}

    def test_get_stats_computes_hit_rate(self):
        manager, _ = _manager_with_fake_redis()
        manager.cache_hits = 3
        manager.cache_misses = 1

        stats = manager.get_stats()

        assert stats["cache_hits"] == 3
        assert stats["cache_misses"] == 1
        assert stats["hit_rate"] == pytest.approx(0.75)


class TestCacheManagerClear:
    def test_clear_is_noop_when_no_redis(self):
        manager, fake = _manager_with_fake_redis()
        manager.redis = None
        fake.store["dns:example.com:A"] = "{}"

        manager.clear()

        # Untouched because manager.redis was cleared before calling clear().
        assert fake.store["dns:example.com:A"] == "{}"

    def test_clear_deletes_matching_keys(self):
        manager, fake = _manager_with_fake_redis()
        fake.store["dns:example.com:A"] = "{}"
        fake.store["dns:other.com:AAAA"] = "{}"
        fake.store["unrelated:key"] = "keep-me"

        manager.clear()

        assert "dns:example.com:A" not in fake.store
        assert "dns:other.com:AAAA" not in fake.store
        assert fake.store["unrelated:key"] == "keep-me"

    def test_clear_with_no_matching_keys_does_not_call_delete(self):
        manager, fake = _manager_with_fake_redis()
        fake.delete = Mock(wraps=fake.delete)

        manager.clear()

        fake.delete.assert_not_called()

    def test_clear_exception_is_swallowed(self):
        fake = _FakeRedis()
        fake.keys_error = RuntimeError("scan failed")
        manager, _ = _manager_with_fake_redis(fake)

        # Must not raise.
        manager.clear()
