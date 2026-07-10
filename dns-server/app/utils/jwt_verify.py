"""Shared Squawk JWT verification (single implementation for dns-server).

Centralizes the ES256/RS256 verification contract used by every dns-server
authorization path (selective_router, resilience):

- asymmetric algorithms only (ES256/RS256) — HS256/none rejected, blocking
  the public-key-as-HMAC algorithm-confusion attack
- issuer + audience validated; exp/iat/tenant required
- fail closed: no public key configured, or missing/empty tenant → reject

Callers pass their configured public key and act on the returned payload;
authorization (zone visibility/team rules) stays with the caller.
"""

from __future__ import annotations

import logging
from typing import Optional

import jwt as pyjwt
from jwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    InvalidTokenError,
    MissingRequiredClaimError,
)

from app.config import JWT_AUDIENCE, JWT_ISSUER

logger = logging.getLogger(__name__)


def verify_squawk_jwt(token: str, public_key: Optional[str]) -> Optional[dict]:
    """Verify a Squawk user JWT; return its payload or None (fail closed).

    Args:
        token: The presented bearer token.
        public_key: PEM public key to verify with (caller's configured key).

    Returns:
        The verified payload dict, or None on any failure — unconfigured key,
        bad signature/alg, expired, wrong iss/aud, missing/empty tenant.
    """
    if not public_key:
        logger.error("JWT_PUBLIC_KEY not configured; denying access")
        return None

    if not token:
        return None

    try:
        payload = pyjwt.decode(
            token,
            public_key,
            algorithms=['ES256', 'RS256'],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            options={'require': ['exp', 'iat', 'tenant']},
        )
    except (InvalidSignatureError, ExpiredSignatureError, DecodeError) as e:
        logger.warning(f"Invalid JWT token: {e}")
        return None
    except (InvalidAudienceError, InvalidIssuerError, MissingRequiredClaimError) as e:
        logger.warning(f"JWT claim validation failed: {e}")
        return None
    except InvalidTokenError as e:
        logger.warning(f"Invalid token: {e}")
        return None
    except Exception as e:
        logger.error(f"Token validation error: {e}")
        return None

    # Fail closed: tenant claim must be present and non-empty
    if not payload.get('tenant'):
        logger.debug("Access denied: token missing or empty tenant claim")
        return None

    return payload
