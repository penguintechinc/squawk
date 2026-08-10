#!/usr/bin/env python3
"""
Unit tests for cache functionality
"""

import pytest
import asyncio
import sys
import os
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'dns-server', 'bins'))

from cache_manager import CacheManager, MemoryCache, RedisCache, ValkeyCache

class TestMemoryCache:
    """Test the in-memory cache backend"""

    @pytest.fixture
    def cache(self):
        """Create a MemoryCache instance for testing"""
        return MemoryCache(default_ttl=300)

    @pytest.mark.asyncio
    async def test_set_and_get(self, cache):
        """Test setting and getting values"""
        await cache.set('test_key', 'test_value', 60)
        result = await cache.get('test_key')
        assert result == 'test_value'

    @pytest.mark.asyncio
    async def test_get_nonexistent(self, cache):
        """Test getting a non-existent key"""
        result = await cache.get('nonexistent')
        assert result is None

    @pytest.mark.asyncio
    async def test_delete(self, cache):
        """Test deleting a key"""
        await cache.set('test_key', 'test_value', 60)
        deleted = await cache.delete('test_key')
        assert deleted is True

        result = await cache.get('test_key')
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_nonexistent(self, cache):
        """Test deleting a non-existent key"""
        deleted = await cache.delete('nonexistent')
        assert deleted is False

    @pytest.mark.asyncio
    async def test_expiration(self, cache):
        """Test that cached values expire"""
        # Set a value with immediate expiration
        cache.cache['test_key'] = ('test_value', datetime.now() - timedelta(seconds=1))

        result = await cache.get('test_key')
        assert result is None
        assert 'test_key' not in cache.cache

    @pytest.mark.asyncio
    async def test_clear_pattern(self, cache):
        """Test clearing keys by pattern"""
        await cache.set('dns:example.com:A', 'value1', 60)
        await cache.set('dns:example.com:AAAA', 'value2', 60)
        await cache.set('dns:other.com:A', 'value3', 60)
        await cache.set('other:key', 'value4', 60)

        # Clear all dns:example.com keys
        cleared = await cache.clear_pattern('dns:example.com:*')
        assert cleared == 2

        # Check what remains
        assert await cache.get('dns:example.com:A') is None
        assert await cache.get('dns:example.com:AAAA') is None
        assert await cache.get('dns:other.com:A') == 'value3'
        assert await cache.get('other:key') == 'value4'

    @pytest.mark.asyncio
    async def test_stats(self, cache):
        """Test cache statistics"""
        # Generate some hits and misses
        await cache.set('key1', 'value1', 60)
        await cache.get('key1')  # Hit
        await cache.get('key1')  # Hit
        await cache.get('nonexistent')  # Miss

        stats = await cache.get_stats()
        assert stats['hits'] == 2
        assert stats['misses'] == 1
        assert stats['keys'] == 1
        assert 'hit_rate' in stats


class TestRedisCache:
    """Test the Redis cache backend"""

    @pytest.fixture
    def mock_redis_client(self):
        """Create a mock Redis client"""
        client = AsyncMock()
        client.get = AsyncMock(return_value=None)
        client.setex = AsyncMock(return_value=True)
        client.delete = AsyncMock(return_value=1)
        client.scan_iter = AsyncMock(return_value=[])
        client.info = AsyncMock(return_value={
            'keyspace_hits': 100,
            'keyspace_misses': 20,
            'used_memory_human': '1.5M'
        })
        client.dbsize = AsyncMock(return_value=50)
        return client

    @pytest.fixture
    def cache(self, mock_redis_client):
        """Create a RedisCache instance for testing"""
        return RedisCache(mock_redis_client, default_ttl=300, prefix='test:')

    @pytest.mark.asyncio
    async def test_get_json(self, cache, mock_redis_client):
        """Test getting JSON values"""
        mock_redis_client.get.return_value = '{"key": "value"}'

        result = await cache.get('test_key')
        assert result == {"key": "value"}
        mock_redis_client.get.assert_called_with('test:test_key')

    @pytest.mark.asyncio
    async def test_set_json(self, cache, mock_redis_client):
        """Test setting JSON values"""
        await cache.set('test_key', {"key": "value"}, 60)

        mock_redis_client.setex.assert_called_with(
            'test:test_key',
            60,
            '{"key": "value"}'
        )

    @pytest.mark.asyncio
    async def test_delete(self, cache, mock_redis_client):
        """Test deleting a key"""
        mock_redis_client.delete.return_value = 1

        result = await cache.delete('test_key')
        assert result is True
        mock_redis_client.delete.assert_called_with('test:test_key')

    @pytest.mark.asyncio
    async def test_clear_pattern(self, cache, mock_redis_client):
        """Test clearing keys by pattern"""
        async def mock_scan():
            for key in ['test:dns:1', 'test:dns:2']:
                yield key

        mock_redis_client.scan_iter.return_value = mock_scan()
        mock_redis_client.delete.return_value = 2

        result = await cache.clear_pattern('dns:*')
        assert result == 2

    @pytest.mark.asyncio
    async def test_stats(self, cache, mock_redis_client):
        """Test getting cache statistics"""
        stats = await cache.get_stats()

        assert stats['hits'] == 100
        assert stats['misses'] == 20
        assert stats['memory_used'] == '1.5M'
        assert stats['keys'] == 50


class TestCacheManager:
    """Test the CacheManager class"""

    @pytest.fixture
    def cache_manager(self):
        """Create a CacheManager instance for testing"""
        with patch.dict(os.environ, {
            'CACHE_ENABLED': 'true',
            'CACHE_TTL': '300',
            'VALKEY_URL': ''
        }):
            manager = CacheManager()
            # Use memory backend for testing
            manager._setup_memory_cache()
            return manager

    @pytest.mark.asyncio
    async def test_cache_disabled(self):
        """Test that cache operations return appropriate values when disabled"""
        with patch.dict(os.environ, {'CACHE_ENABLED': 'false'}):
            manager = CacheManager()

            result = await manager.get('test_key')
            assert result is None

            result = await manager.set('test_key', 'value', 60)
            assert result is False

            result = await manager.delete('test_key')
            assert result is False

    @pytest.mark.asyncio
    async def test_get_set_delete(self, cache_manager):
        """Test basic cache operations through the manager"""
        # Set a value
        success = await cache_manager.set('test_key', 'test_value')
        assert success is True

        # Get the value
        result = await cache_manager.get('test_key')
        assert result == 'test_value'

        # Delete the value
        success = await cache_manager.delete('test_key')
        assert success is True

        # Verify it's gone
        result = await cache_manager.get('test_key')
        assert result is None

    @pytest.mark.asyncio
    async def test_error_handling(self, cache_manager):
        """Test that errors are handled gracefully"""
        # Mock the backend to raise an exception
        cache_manager.backend.get = AsyncMock(side_effect=Exception("Test error"))

        # Should return None instead of raising
        result = await cache_manager.get('test_key')
        assert result is None

    @pytest.mark.asyncio
    async def test_stats(self, cache_manager):
        """Test getting cache statistics"""
        stats = await cache_manager.get_stats()

        assert stats['enabled'] is True
        assert 'backend' in stats
        assert stats['backend'] == 'MemoryCache'
