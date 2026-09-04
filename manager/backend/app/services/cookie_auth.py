"""
Cookie-based JWT auth helpers for browser clients.

Squawk's browser client (dns-webui) previously stored access/refresh JWTs in
localStorage, which is readable by any JavaScript running on the page --
including a compromised dependency -- letting it exfiltrate long-lived
credentials (CWE-522: Insufficiently Protected Credentials). This module
issues the same tokens as HttpOnly, Secure, SameSite cookies instead, so the
token value is never exposed to page JavaScript.

Moving auth to cookies reintroduces CSRF exposure (the browser auto-attaches
cookies to same-site requests), so this module also implements a
double-submit CSRF check: the CSRF token is delivered in a JS-readable
cookie and must be echoed back in a header on state-changing requests.
SameSite=Strict is the primary defense; the CSRF header is defense in depth.

This is purely additive: bearer-token clients (manager/frontend, the Go
client, machine clients) are unaffected. Cookies are set *alongside* the
existing JSON token response; `token_required` (app/middleware/auth.py)
falls back to the cookie only when no Authorization header is present.
"""

from __future__ import annotations

import secrets
from typing import Optional, Tuple

from flask import Response, current_app, request

ACCESS_COOKIE_NAME = "access_token"
REFRESH_COOKIE_NAME = "refresh_token"
CSRF_COOKIE_NAME = "csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"

# The refresh token is only ever needed by the refresh/logout endpoints;
# scoping the cookie's Path to this prefix keeps it out of every other
# request the browser makes, narrowing its exposure.
REFRESH_COOKIE_PATH = "/api/v1/auth"

# State-changing methods require the double-submit CSRF check when auth
# comes from a cookie. GET/HEAD/OPTIONS are side-effect-free by contract.
_CSRF_PROTECTED_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _cookie_secure() -> bool:
    """Whether cookies carry the Secure flag.

    Defaults to True (HTTPS-only) and must be explicitly opted out for local
    HTTP development -- never inferred from DEBUG/TESTING, so a
    misconfigured production deploy fails closed rather than silently
    downgrading to non-Secure cookies.
    """
    return bool(current_app.config.get("COOKIE_SECURE", True))


def _cookie_domain() -> Optional[str]:
    return current_app.config.get("COOKIE_DOMAIN") or None


def generate_csrf_token() -> str:
    """Generate a fresh random token for the double-submit CSRF cookie."""
    return secrets.token_urlsafe(32)


def set_auth_cookies(
    response: Response,
    access_token: str,
    refresh_token: Optional[str] = None,
    csrf_token: Optional[str] = None,
) -> None:
    """Attach HttpOnly JWT cookies (and a JS-readable CSRF cookie).

    Additive: callers still return tokens in the JSON body for existing
    bearer-token clients. Cookie-based clients ignore the JSON tokens and
    rely on these cookies, which JavaScript cannot read.
    """
    secure = _cookie_secure()
    domain = _cookie_domain()
    access_max_age = int(current_app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds())

    response.set_cookie(
        ACCESS_COOKIE_NAME,
        access_token,
        max_age=access_max_age,
        httponly=True,
        secure=secure,
        samesite="Strict",
        domain=domain,
        path="/",
    )

    if refresh_token is not None:
        refresh_max_age = int(current_app.config["JWT_REFRESH_TOKEN_EXPIRES"].total_seconds())
        response.set_cookie(
            REFRESH_COOKIE_NAME,
            refresh_token,
            max_age=refresh_max_age,
            httponly=True,
            secure=secure,
            samesite="Strict",
            domain=domain,
            path=REFRESH_COOKIE_PATH,
        )

    if csrf_token is not None:
        # Lifetime matches the refresh token (the outer bound of the
        # session), not the short-lived access token -- otherwise the CSRF
        # cookie would expire at the same moment the access token does,
        # right when the browser needs it to call /auth/refresh.
        csrf_max_age = int(
            current_app.config["JWT_REFRESH_TOKEN_EXPIRES"].total_seconds()
        )
        # Deliberately NOT httponly -- the SPA must be able to read this
        # value to echo it back in the X-CSRF-Token header.
        response.set_cookie(
            CSRF_COOKIE_NAME,
            csrf_token,
            max_age=csrf_max_age,
            httponly=False,
            secure=secure,
            samesite="Strict",
            domain=domain,
            path="/",
        )


def clear_auth_cookies(response: Response) -> None:
    """Expire all cookie-auth cookies (logout).

    Delete attributes (path/domain/samesite) must match how each cookie was
    set, or the browser treats it as a different cookie and leaves the
    original in place.
    """
    domain = _cookie_domain()
    response.delete_cookie(ACCESS_COOKIE_NAME, path="/", domain=domain, samesite="Strict")
    response.delete_cookie(
        REFRESH_COOKIE_NAME, path=REFRESH_COOKIE_PATH, domain=domain, samesite="Strict"
    )
    response.delete_cookie(CSRF_COOKIE_NAME, path="/", domain=domain, samesite="Strict")


def extract_bearer_or_cookie_token() -> Tuple[Optional[str], bool]:
    """Return ``(token, from_cookie)``, preferring the Authorization header.

    The header always wins when present so existing header-based clients
    are unaffected by a stray cookie. ``from_cookie`` is True only when the
    token came exclusively from the cookie, telling the caller to enforce
    the CSRF check (header-based bearer auth is not CSRF-exposed: browsers
    do not auto-attach custom Authorization headers cross-site).
    """
    auth_header = request.headers.get("Authorization")
    if auth_header:
        parts = auth_header.split(" ")
        if len(parts) == 2:
            return parts[1], False
        return None, False  # Malformed header -- do not silently fall back

    cookie_token = request.cookies.get(ACCESS_COOKIE_NAME)
    if cookie_token:
        return cookie_token, True

    return None, False


def csrf_check_passes() -> bool:
    """Double-submit CSRF check for cookie-authenticated requests.

    The CSRF cookie value must match the ``X-CSRF-Token`` header exactly.
    An attacker's cross-site page can trigger the cookie to be sent
    automatically but cannot read it (different origin) to also set the
    matching header.
    """
    if request.method not in _CSRF_PROTECTED_METHODS:
        return True

    cookie_value = request.cookies.get(CSRF_COOKIE_NAME)
    header_value = request.headers.get(CSRF_HEADER_NAME)
    if not cookie_value or not header_value:
        return False
    return secrets.compare_digest(cookie_value, header_value)
