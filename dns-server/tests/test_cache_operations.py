"""
Test suite for DNS Server Cache Operations
Tests cache manager with mocked Redis/Valkey operations
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import sys
import os
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'bins'))

from cache_manager import CacheManager


@pytest.fixture
def mock_redis():
    """Create mock Redis client"""
    mock_client = Mock()
    mock_client.get.return_value = None
    mock_client.set.return_value = True
    mock_client.delete.return_value = 1
    mock_client.exists.return_value = False
    return mock_client


class TestCacheManager:
    """Test cache manager operations"""
    
    @pytest.mark.asyncio
    async def test_cache_initialization(self, mock_redis):
        """Test cache manager initialization"""
        with patch('cache_manager.redis.Redis', return_value=mock_redis):
            cache = CacheManager(redis_url='redis://localhost:6379')
            await cache.initialize()
            assert cache.redis_client is not None
    
    @pytest.mark.asyncio
    async def test_cache_get_miss(self, mock_redis):
        """Test cache miss"""
        mock_redis.get.return_value = None
        
        with patch('cache_manager.redis.Redis', return_value=mock_redis):
            cache = CacheManager(redis_url='redis://localhost:6379')
            await cache.initialize()
            
            result = await cache.get('test-key')
            assert result is None
    
    @pytest.mark.asyncio
    async def test_cache_get_hit(self, mock_redis):
        """Test cache hit"""
        import json
        cached_data = {'domain': 'example.com', 'ip': '93.184.216.34'}
        mock_redis.get.return_value = json.dumps(cached_data).encode()
        
        with patch('cache_manager.redis.Redis', return_value=mock_redis):
            cache = CacheManager(redis_url='redis://localhost:6379')
            await cache.initialize()
            
            result = await cache.get('test-key')
            assert result == cached_data
    
    @pytest.mark.asyncio
    async def test_cache_set(self, mock_redis):
        """Test setting cache value"""
        with patch('cache_manager.redis.Redis', return_value=mock_redis):
            cache = CacheManager(redis_url='redis://localhost:6379')
            await cache.initialize()
            
            data = {'domain': 'example.com', 'ip': '93.184.216.34'}
            await cache.set('test-key', data, ttl=300)
            
            mock_redis.set.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_cache_delete(self, mock_redis):
        """Test deleting cache value"""
        with patch('cache_manager.redis.Redis', return_value=mock_redis):
            cache = CacheManager(redis_url='redis://localhost:6379')
            await cache.initialize()
            
            await cache.delete('test-key')
            mock_redis.delete.assert_called_once_with('test-key')
    
    @pytest.mark.asyncio
    async def test_cache_ttl(self, mock_redis):
        """Test cache with TTL"""
        with patch('cache_manager.redis.Redis', return_value=mock_redis):
            cache = CacheManager(redis_url='redis://localhost:6379')
            await cache.initialize()
            
            data = {'test': 'data'}
            await cache.set('test-key', data, ttl=60)
            
            # Verify TTL was set
            call_args = mock_redis.set.call_args
            assert 'ex' in call_args[1] or len(call_args[0]) > 2


class TestCacheIntegration:
    """Integration tests for cache operations"""
    
    @pytest.mark.asyncio
    async def test_dns_query_caching(self, mock_redis):
        """Test DNS query result caching"""
        import json
        
        query_result = {
            'Status': 0,
            'Answer': [{'name': 'example.com', 'type': 1, 'data': '93.184.216.34'}]
        }
        
        mock_redis.get.return_value = None  # First call: cache miss
        
        with patch('cache_manager.redis.Redis', return_value=mock_redis):
            cache = CacheManager(redis_url='redis://localhost:6379')
            await cache.initialize()
            
            # Simulate caching a DNS query result
            cache_key = 'dns:example.com:A'
            await cache.set(cache_key, query_result, ttl=300)
            
            # Verify set was called
            assert mock_redis.set.called
    
    @pytest.mark.asyncio
    async def test_cache_invalidation(self, mock_redis):
        """Test cache invalidation"""
        with patch('cache_manager.redis.Redis', return_value=mock_redis):
            cache = CacheManager(redis_url='redis://localhost:6379')
            await cache.initialize()
            
            # Invalidate cache for a domain
            await cache.delete('dns:example.com:A')
            assert mock_redis.delete.called
