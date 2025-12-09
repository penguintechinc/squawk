#!/usr/bin/env python3
"""
Cache Manager for Squawk DNS Server
Supports both Valkey and Redis with fallback to in-memory cache
"""

import os
import json
import hashlib
import asyncio
import logging
from typing import Optional, Any
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class CacheManager:
    def __init__(self):
        self.backend = None
        self.cache_ttl = int(os.getenv("CACHE_TTL", "300"))  # Default 5 minutes
        self.cache_enabled = os.getenv("CACHE_ENABLED", "true").lower() == "true"
        self.valkey_url = os.getenv("VALKEY_URL", os.getenv("REDIS_URL", ""))
        self.cache_prefix = os.getenv("CACHE_PREFIX", "squawk:dns:")

        # Security settings
        self.redis_username = os.getenv("REDIS_USERNAME", "")
        self.redis_password = os.getenv("REDIS_PASSWORD", "")
        self.redis_use_tls = os.getenv("REDIS_USE_TLS", "false").lower() == "true"
        self.redis_tls_cert_file = os.getenv("REDIS_TLS_CERT_FILE", "")
        self.redis_tls_key_file = os.getenv("REDIS_TLS_KEY_FILE", "")
        self.redis_tls_ca_file = os.getenv("REDIS_TLS_CA_FILE", "")
        self.redis_tls_verify_mode = os.getenv("REDIS_TLS_VERIFY_MODE", "required")

        # Initialization is deferred to explicit initialize() call
        # to avoid "no running event loop" errors during import

        # Security warnings for production
        self._check_security_warnings()

    def _check_security_warnings(self):
        """Check for insecure configurations and log warnings"""
        warnings = []

        if self.cache_enabled and self.valkey_url:
            # Check for insecure connections
            if not self.redis_use_tls and not self.valkey_url.startswith(
                ("rediss://", "valkeys://")
            ):
                warnings.append("Redis/Valkey TLS is disabled - traffic is unencrypted")

            # Check for missing authentication
            if not self.redis_username and not self.redis_password:
                if not (
                    "username" in self.valkey_url and "password" in self.valkey_url
                ):
                    warnings.append(
                        "Redis/Valkey authentication is not configured - cache is unsecured"
                    )

            # Check for insecure TLS verification
            if self.redis_tls_verify_mode == "none":
                warnings.append(
                    "Redis/Valkey TLS verification is disabled - vulnerable to MITM attacks"
                )
            elif self.redis_tls_verify_mode == "optional":
                warnings.append(
                    "Redis/Valkey TLS verification is optional - reduced security"
                )

        # Log security warnings
        for warning in warnings:
            logger.warning(f"SECURITY WARNING: {warning}")

        if warnings:
            logger.warning("=" * 80)
            logger.warning(
                "PRODUCTION SECURITY WARNING: Insecure cache configuration detected!"
            )
            logger.warning("For production deployments, ensure:")
            logger.warning("- REDIS_USE_TLS=true")
            logger.warning("- REDIS_USERNAME and REDIS_PASSWORD are set")
            logger.warning("- REDIS_TLS_VERIFY_MODE=required")
            logger.warning("- Use rediss:// or valkeys:// connection strings")
            logger.warning("=" * 80)

    async def initialize(self):
        """Initialize cache backend"""
        if self.cache_enabled:
            await self._initialize_backend()

    async def _initialize_backend(self):
        """Initialize cache backend (Valkey/Redis or in-memory)"""
        if self.valkey_url:
            try:
                # Try Valkey first
                try:
                    import valkey

                    self.backend = await self._setup_valkey()
                    logger.info("Using Valkey cache backend")
                except ImportError:
                    # Fall back to Redis
                    import redis.asyncio as redis

                    self.backend = await self._setup_redis()
                    logger.info("Using Redis cache backend")
            except Exception as e:
                logger.warning(f"Failed to connect to cache server: {e}")
                self._setup_memory_cache()
        else:
            self._setup_memory_cache()

    async def _setup_valkey(self):
        """Setup Valkey connection with TLS and authentication"""
        import valkey
        import ssl

        connection_kwargs = {
            "decode_responses": True,
            "socket_connect_timeout": 5,
            "socket_timeout": 5,
            "health_check_interval": 30,
        }

        # Add authentication if provided
        if self.redis_username:
            connection_kwargs["username"] = self.redis_username
        if self.redis_password:
            connection_kwargs["password"] = self.redis_password

        # Configure TLS if enabled
        if (
            self.redis_use_tls
            or self.valkey_url.startswith("rediss://")
            or self.valkey_url.startswith("valkeys://")
        ):
            ssl_context = ssl.create_default_context()

            # Set verification mode
            if self.redis_tls_verify_mode == "none":
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            elif self.redis_tls_verify_mode == "optional":
                ssl_context.verify_mode = ssl.CERT_OPTIONAL
            else:  # required (default)
                ssl_context.verify_mode = ssl.CERT_REQUIRED

            # Load certificates
            if self.redis_tls_ca_file:
                ssl_context.load_verify_locations(self.redis_tls_ca_file)

            if self.redis_tls_cert_file and self.redis_tls_key_file:
                ssl_context.load_cert_chain(
                    self.redis_tls_cert_file, self.redis_tls_key_file
                )

            connection_kwargs["ssl"] = ssl_context
            connection_kwargs["ssl_check_hostname"] = ssl_context.check_hostname

        # Create client from URL or manual configuration
        if self.valkey_url.startswith(
            ("valkey://", "valkeys://", "redis://", "rediss://")
        ):
            client = valkey.Valkey.from_url(self.valkey_url, **connection_kwargs)
        else:
            # Parse host:port format
            parts = self.valkey_url.split(":")
            host = parts[0]
            port = int(parts[1]) if len(parts) > 1 else 6379

            connection_kwargs.update(
                {
                    "host": host,
                    "port": port,
                }
            )

            client = valkey.Valkey(**connection_kwargs)

        # Test connection with authentication
        await client.ping()
        logger.info(
            f"Connected to Valkey at {self.valkey_url} (TLS: {self.redis_use_tls})"
        )
        return ValkeyCache(client, self.cache_ttl, self.cache_prefix)

    async def _setup_redis(self):
        """Setup Redis connection with TLS and authentication"""
        import redis.asyncio as redis
        import ssl

        connection_kwargs = {
            "encoding": "utf-8",
            "decode_responses": True,
            "socket_connect_timeout": 5,
            "socket_timeout": 5,
            "health_check_interval": 30,
        }

        # Add authentication if provided
        if self.redis_username:
            connection_kwargs["username"] = self.redis_username
        if self.redis_password:
            connection_kwargs["password"] = self.redis_password

        # Configure TLS if enabled
        if self.redis_use_tls or self.valkey_url.startswith("rediss://"):
            ssl_context = ssl.create_default_context()

            # Set verification mode
            if self.redis_tls_verify_mode == "none":
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            elif self.redis_tls_verify_mode == "optional":
                ssl_context.verify_mode = ssl.CERT_OPTIONAL
            else:  # required (default)
                ssl_context.verify_mode = ssl.CERT_REQUIRED

            # Load certificates
            if self.redis_tls_ca_file:
                ssl_context.load_verify_locations(self.redis_tls_ca_file)

            if self.redis_tls_cert_file and self.redis_tls_key_file:
                ssl_context.load_cert_chain(
                    self.redis_tls_cert_file, self.redis_tls_key_file
                )

            connection_kwargs["ssl"] = ssl_context
            connection_kwargs["ssl_check_hostname"] = ssl_context.check_hostname

        # Create client from URL or manual configuration
        if self.valkey_url.startswith(("redis://", "rediss://")):
            client = await redis.from_url(self.valkey_url, **connection_kwargs)
        else:
            # Parse host:port format
            parts = self.valkey_url.split(":")
            host = parts[0]
            port = int(parts[1]) if len(parts) > 1 else 6379

            connection_kwargs.update(
                {
                    "host": host,
                    "port": port,
                }
            )

            client = redis.Redis(**connection_kwargs)

        # Test connection with authentication
        await client.ping()
        logger.info(
            f"Connected to Redis at {self.valkey_url} (TLS: {self.redis_use_tls})"
        )
        return RedisCache(client, self.cache_ttl, self.cache_prefix)

    def _setup_memory_cache(self):
        """Setup in-memory cache as fallback"""
        logger.info("Using in-memory cache backend")
        self.backend = MemoryCache(self.cache_ttl)

    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        if not self.cache_enabled or not self.backend:
            return None

        try:
            return await self.backend.get(key)
        except Exception as e:
            logger.error(f"Cache get error: {e}")
            return None

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache"""
        if not self.cache_enabled or not self.backend:
            return False

        try:
            ttl = ttl or self.cache_ttl
            return await self.backend.set(key, value, ttl)
        except Exception as e:
            logger.error(f"Cache set error: {e}")
            return False

    async def delete(self, key: str) -> bool:
        """Delete value from cache"""
        if not self.cache_enabled or not self.backend:
            return False

        try:
            return await self.backend.delete(key)
        except Exception as e:
            logger.error(f"Cache delete error: {e}")
            return False

    async def clear_pattern(self, pattern: str) -> int:
        """Clear all keys matching pattern"""
        if not self.cache_enabled or not self.backend:
            return 0

        try:
            return await self.backend.clear_pattern(pattern)
        except Exception as e:
            logger.error(f"Cache clear pattern error: {e}")
            return 0

    async def get_stats(self) -> dict:
        """Get cache statistics"""
        if not self.backend:
            return {"enabled": False}

        try:
            stats = await self.backend.get_stats()
            stats["enabled"] = self.cache_enabled
            stats["backend"] = self.backend.__class__.__name__
            return stats
        except Exception as e:
            logger.error(f"Cache stats error: {e}")
            return {"enabled": self.cache_enabled, "error": str(e)}


class ValkeyCache:
    """Valkey cache backend"""

    def __init__(self, client, default_ttl: int, prefix: str):
        self.client = client
        self.default_ttl = default_ttl
        self.prefix = prefix

    def _make_key(self, key: str) -> str:
        return f"{self.prefix}{key}"

    async def get(self, key: str) -> Optional[Any]:
        value = await self.client.get(self._make_key(key))
        if value:
            try:
                return json.loads(value)
            except:
                return value
        return None

    async def set(self, key: str, value: Any, ttl: int) -> bool:
        try:
            value_str = json.dumps(value) if not isinstance(value, str) else value
            return await self.client.setex(self._make_key(key), ttl, value_str)
        except:
            return False

    async def delete(self, key: str) -> bool:
        return await self.client.delete(self._make_key(key)) > 0

    async def clear_pattern(self, pattern: str) -> int:
        keys = await self.client.keys(f"{self.prefix}{pattern}")
        if keys:
            return await self.client.delete(*keys)
        return 0

    async def get_stats(self) -> dict:
        info = await self.client.info()
        return {
            "hits": info.get("keyspace_hits", 0),
            "misses": info.get("keyspace_misses", 0),
            "memory_used": info.get("used_memory_human", "0"),
            "keys": await self.client.dbsize(),
        }


class RedisCache:
    """Redis cache backend"""

    def __init__(self, client, default_ttl: int, prefix: str):
        self.client = client
        self.default_ttl = default_ttl
        self.prefix = prefix

    def _make_key(self, key: str) -> str:
        return f"{self.prefix}{key}"

    async def get(self, key: str) -> Optional[Any]:
        value = await self.client.get(self._make_key(key))
        if value:
            try:
                return json.loads(value)
            except:
                return value
        return None

    async def set(self, key: str, value: Any, ttl: int) -> bool:
        try:
            value_str = json.dumps(value) if not isinstance(value, str) else value
            return await self.client.setex(self._make_key(key), ttl, value_str)
        except:
            return False

    async def delete(self, key: str) -> bool:
        return await self.client.delete(self._make_key(key)) > 0

    async def clear_pattern(self, pattern: str) -> int:
        keys = []
        async for key in self.client.scan_iter(f"{self.prefix}{pattern}"):
            keys.append(key)

        if keys:
            return await self.client.delete(*keys)
        return 0

    async def get_stats(self) -> dict:
        info = await self.client.info()
        return {
            "hits": info.get("keyspace_hits", 0),
            "misses": info.get("keyspace_misses", 0),
            "memory_used": info.get("used_memory_human", "0"),
            "keys": await self.client.dbsize(),
        }


class MemoryCache:
    """In-memory cache backend"""

    def __init__(self, default_ttl: int):
        self.cache = {}
        self.default_ttl = default_ttl
        self.hits = 0
        self.misses = 0

    async def get(self, key: str) -> Optional[Any]:
        if key in self.cache:
            value, expiry = self.cache[key]
            if datetime.now() < expiry:
                self.hits += 1
                return value
            else:
                del self.cache[key]

        self.misses += 1
        return None

    async def set(self, key: str, value: Any, ttl: int) -> bool:
        expiry = datetime.now() + timedelta(seconds=ttl)
        self.cache[key] = (value, expiry)

        # Clean up expired entries periodically
        if len(self.cache) % 100 == 0:
            await self._cleanup()

        return True

    async def delete(self, key: str) -> bool:
        if key in self.cache:
            del self.cache[key]
            return True
        return False

    async def clear_pattern(self, pattern: str) -> int:
        import fnmatch

        keys_to_delete = [k for k in self.cache.keys() if fnmatch.fnmatch(k, pattern)]
        for key in keys_to_delete:
            del self.cache[key]
        return len(keys_to_delete)

    async def _cleanup(self):
        """Remove expired entries"""
        now = datetime.now()
        expired = [k for k, (v, exp) in self.cache.items() if exp < now]
        for key in expired:
            del self.cache[key]

    async def get_stats(self) -> dict:
        await self._cleanup()
        total = self.hits + self.misses
        hit_rate = (self.hits / total * 100) if total > 0 else 0

        return {
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": f"{hit_rate:.2f}%",
            "keys": len(self.cache),
            "memory_used": f"{len(str(self.cache)) / 1024:.2f} KB",
        }


# Global cache manager instance
cache_manager = None


def get_cache_manager() -> CacheManager:
    """Get or create the global cache manager instance"""
    global cache_manager
    if cache_manager is None:
        cache_manager = CacheManager()
    return cache_manager
