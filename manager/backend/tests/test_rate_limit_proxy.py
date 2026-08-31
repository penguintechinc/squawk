"""Regression tests for the rate-limiter IP-spoofing fix.

Prior implementation: penguin_limiter's default key function (and the
`skip_private_ips=True` default) reads X-Forwarded-For/X-Real-IP directly
from the request with no boundary on which hop is trustworthy. A caller
sending `X-Forwarded-For: 127.0.0.1` could make `should_rate_limit()`
treat the request as internal/private and skip rate limiting entirely; a
rotating, syntactically-valid public decoy IP would instead bucket every
request under a different key, defeating per-client limiting either way.

Fix: `app/extensions.py`'s `proxy_resolved_key` ignores X-Forwarded-For/
X-Real-IP entirely and keys only on `request.remote_addr`, which
Werkzeug's `ProxyFix` (wired in `app/__init__.py`) rewrites using a
configured, trusted hop count -- never raw, attacker-controlled header
content beyond that boundary. The limiter is also configured with
`skip_private_ips=False` so a resolved-private address is never silently
exempted.
"""

from werkzeug.middleware.proxy_fix import ProxyFix

from app.extensions import proxy_resolved_key, limiter


def test_proxy_resolved_key_ignores_private_range_decoy(app):
    """The classic bypass: X-Forwarded-For: 127.0.0.1 must not change the
    rate-limit key -- only the resolved remote_addr matters."""
    with app.test_request_context(
        '/api/v1/auth/login',
        headers={'X-Forwarded-For': '127.0.0.1'},
        environ_overrides={'REMOTE_ADDR': '203.0.113.7'},
    ):
        from flask import request
        key = proxy_resolved_key(request)
        assert key == '203.0.113.7'
        assert key != '127.0.0.1'


def test_proxy_resolved_key_ignores_rotating_spoofed_public_ip(app):
    """A rotating, syntactically-valid public X-Forwarded-For also must not
    change the key -- otherwise an attacker bucket-splits around any
    per-IP limit just by varying the header per request."""
    for decoy in ('198.51.100.1', '198.51.100.2', '198.51.100.3'):
        with app.test_request_context(
            '/api/v1/auth/login',
            headers={'X-Forwarded-For': decoy},
            environ_overrides={'REMOTE_ADDR': '203.0.113.7'},
        ):
            from flask import request
            assert proxy_resolved_key(request) == '203.0.113.7'


def test_proxy_resolved_key_ignores_x_real_ip_too(app):
    with app.test_request_context(
        '/api/v1/auth/login',
        headers={'X-Real-IP': '127.0.0.1'},
        environ_overrides={'REMOTE_ADDR': '203.0.113.7'},
    ):
        from flask import request
        assert proxy_resolved_key(request) == '203.0.113.7'


def test_proxy_resolved_key_falls_back_to_unknown_without_remote_addr():
    """Never returns None/empty -- a missing remote_addr still produces a
    deterministic, non-bypassing key rather than skipping the check."""
    class _NoAddr:
        remote_addr = None

    assert proxy_resolved_key(_NoAddr()) == 'unknown'


def test_proxyfix_wraps_wsgi_app(app):
    """app.wsgi_app must be wrapped with Werkzeug's ProxyFix so
    remote_addr reflects the trusted-hop-resolved client rather than just
    the immediate TCP peer (which, behind any reverse proxy, is the proxy
    itself, not the end client)."""
    assert isinstance(app.wsgi_app, ProxyFix)


def test_limiter_does_not_skip_private_ips():
    """skip_private_ips=False: a resolved-private remote_addr is never
    silently exempted from rate limiting."""
    assert limiter._config.skip_private_ips is False


def test_limiter_key_func_is_proxy_resolved_key():
    """The limiter must use the header-blind key function, not
    penguin_limiter's own default (which reads X-Forwarded-For/X-Real-IP
    directly)."""
    assert limiter._key_func is proxy_resolved_key
