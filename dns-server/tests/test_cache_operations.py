"""
Test suite for DNS Server Cache Operations
Tests cache manager with in-memory cache backend (no external dependencies)
"""

import pytest
import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'bins'))

from cache_manager import CacheManager


@pytest.fixture
async def memory_cache():
    """Create CacheManager with in-memory backend"""
    # Force memory backend by removing Redis/Valkey URLs
    original_valkey = os.environ.get('VALKEY_URL')
    original_redis = os.environ.get('REDIS_URL')

    os.environ['CACHE_ENABLED'] = 'true'
    os.environ.pop('VALKEY_URL', None)
    os.environ.pop('REDIS_URL', None)

    cache = CacheManager()
    await cache.initialize()

    yield cache

    # Restore original environment
    if original_valkey:
        os.environ['VALKEY_URL'] = original_valkey
    if original_redis:
        os.environ['REDIS_URL'] = original_redis


class TestCacheManager:
    """Test cache manager operations"""

    @pytest.mark.asyncio
    async def test_cache_initialization(self, memory_cache):
        """Test cache manager initialization"""
        cache = memory_cache
        assert cache.backend is not None
        assert cache.enabled is True

    @pytest.mark.asyncio
    async def test_cache_get_miss(self, memory_cache):
        """Test cache miss"""
        cache = memory_cache
        result = await cache.get('nonexistent-key')
        assert result is None

    @pytest.mark.asyncio
    async def test_cache_get_hit(self, memory_cache):
        """Test cache hit"""
        cache = memory_cache
        test_data = {'domain': 'example.com', 'ip': '1.2.3.4'}

        # Set the cache
        await cache.set('test-key', test_data, ttl=300)

        # Get it back
        result = await cache.get('test-key')
        assert result == test_data

    @pytest.mark.asyncio
    async def test_cache_set(self, memory_cache):
        """Test cache set operation"""
        cache = memory_cache
        test_data = {'query': 'google.com', 'type': 'A'}

        success = await cache.set('dns:query:1', test_data, ttl=600)
        assert success is True

        # Verify it was stored
        result = await cache.get('dns:query:1')
        assert result == test_data

    @pytest.mark.asyncio
    async def test_cache_delete(self, memory_cache):
        """Test cache delete operation"""
        cache = memory_cache

        # Set a value
        await cache.set('delete-test', {'data': 'value'}, ttl=300)
        assert await cache.get('delete-test') is not None

        # Delete it
        await cache.delete('delete-test')

        # Verify it's gone
        result = await cache.get('delete-test')
        assert result is None

    @pytest.mark.asyncio
    async def test_cache_ttl(self, memory_cache):
        """Test cache TTL expiration"""
        import asyncio
        cache = memory_cache

        # Set with 1 second TTL
        await cache.set('ttl-test', {'data': 'expires'}, ttl=1)

        # Should exist immediately
        result = await cache.get('ttl-test')
        assert result == {'data': 'expires'}

        # Wait for expiration
        await asyncio.sleep(2)

        # Should be gone
        result = await cache.get('ttl-test')
        assert result is None


class TestCacheIntegration:
    """Test cache integration scenarios"""

    @pytest.mark.asyncio
    async def test_dns_query_caching(self, memory_cache):
        """Test DNS query result caching"""
        cache = memory_cache

        # Simulate DNS query response
        dns_response = {
            'domain': 'example.com',
            'type': 'A',
            'answers': ['93.184.216.34'],
            'ttl': 3600,
            'timestamp': '2025-12-10T12:00:00Z'
        }

        # Cache the query
        cache_key = 'dns:query:example.com:A'
        await cache.set(cache_key, dns_response, ttl=3600)

        # Retrieve from cache
        cached = await cache.get(cache_key)
        assert cached == dns_response
        assert cached['answers'] == ['93.184.216.34']

    @pytest.mark.asyncio
    async def test_cache_invalidation(self, memory_cache):
        """Test cache invalidation"""
        cache = memory_cache

        # Set multiple related cache entries
        await cache.set('query:1', {'result': 'data1'}, ttl=300)
        await cache.set('query:2', {'result': 'data2'}, ttl=300)

        # Invalidate one
        await cache.delete('query:1')

        # Verify selective invalidation
        assert await cache.get('query:1') is None
        assert await cache.get('query:2') is not None
        assert await cache.get('query:2') == {'result': 'data2'}
