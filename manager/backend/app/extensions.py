"""Shared Flask extensions instantiated once at import time.

Blueprint modules decorate routes with ``@limiter.limit(...)`` when the
module is *imported* (before any Flask app or request context exists), so
the limiter instance must be a module-level singleton configured directly
from the environment -- mirroring ``Config``'s own env-var pattern -- rather
than pulled from ``current_app``.
"""

from __future__ import annotations

import os

from penguin_limiter import FlaskRateLimiter, MemoryStorage, RateLimitConfig


def proxy_resolved_key(request: object) -> str:
    """Rate-limit key: the ProxyFix-resolved ``remote_addr`` only.

    Deliberately ignores ``X-Forwarded-For``/``X-Real-IP`` here -- those
    headers are client-supplied and are only trustworthy after Werkzeug's
    ``ProxyFix`` (wired in ``app/__init__.py``) has already rewritten
    ``request.remote_addr`` using a configured, trusted proxy-hop count.
    Keying on the raw headers directly (penguin_limiter's default key
    function) lets a caller bypass or split rate limits with a spoofed
    ``X-Forwarded-For`` value.
    """
    return getattr(request, "remote_addr", None) or "unknown"


_redis_url = os.getenv("REDIS_URL") or os.getenv("VALKEY_URL") or ""
_default_limit = os.getenv("RATE_LIMIT_DEFAULT", "100/hour")

if _redis_url:
    import redis
    from penguin_limiter.storage.redis_store import RedisStorage

    _storage = RedisStorage(client=redis.Redis.from_url(_redis_url))
else:
    _storage = MemoryStorage()

# skip_private_ips=False: private-range bypass is only safe when the *only*
# way to reach this service is through a trusted internal network. Since the
# key is now the ProxyFix-resolved remote_addr (never a raw client header),
# there is no header-spoofing path left to exploit, but we still don't want
# to silently exempt callers whose resolved address happens to be private.
limiter = FlaskRateLimiter(
    config=RateLimitConfig.from_string(_default_limit, skip_private_ips=False),
    storage=_storage,
    key_func=proxy_resolved_key,
)
