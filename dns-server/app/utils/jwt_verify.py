"""Shared Squawk JWT verification (single implementation for dns-server).

Centralizes the ES256/RS256 verification contract used by every dns-server
authorization path (selective_router, resilience):

- asymmetric algorithms only (ES256/RS256) — HS256/none rejected, blocking
  the public-key-as-HMAC algorithm-confusion attack
- issuer + audience validated; exp/iat/tenant required
- supports kid-based key selection for rotation overlap (try all keys if no kid)
- fail closed: no public key configured, or missing/empty tenant → reject

Callers pass their configured public key(s) and act on the returned payload;
authorization (zone visibility/team rules) stays with the caller.
"""

from __future__ import annotations

import logging
from typing import Dict, Optional

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


def verify_squawk_jwt(
    token: str,
    public_key: Optional[str] = None,
    public_keys: Optional[Dict[str, str]] = None,
) -> Optional[dict]:
    """Verify a Squawk user JWT; return its payload or None (fail closed).

    Supports kid-based key selection for rotation overlap:
    - If token has kid header and matching key exists, use it
    - If token has no kid, try all provided keys (backward compat)
    - If kid present but not found in key set, reject

    Args:
        token: The presented bearer token.
        public_key: PEM public key to verify with (single key, for backward compat).
        public_keys: Dict mapping kid -> PEM public key (for key rotation).

    Returns:
        The verified payload dict, or None on any failure — unconfigured key,
        bad signature/alg, expired, wrong iss/aud, missing/empty tenant.
    """
    if not token:
        return None

    # Decode header to extract kid (without verifying signature yet)
    try:
        header = pyjwt.get_unverified_header(token)
    except Exception:
        logger.warning("Failed to extract JWT header")
        return None

    kid = header.get('kid')

    # Determine which key(s) to try
    keys_to_try: Dict[Optional[str], str] = {}

    if kid:
        # Token has kid: must match in public_keys (if provided)
        if public_keys and kid in public_keys:
            keys_to_try[kid] = public_keys[kid]
        else:
            # Kid present but not found: reject (unknown key)
            logger.warning(f"Unknown kid '{kid}' in token; denying access")
            return None
    else:
        # Token has no kid: try all keys (backward compat during rotation)
        if public_keys:
            keys_to_try = public_keys.copy()
        elif public_key:
            keys_to_try[None] = public_key
        else:
            logger.error("No JWT_PUBLIC_KEY or JWT_PUBLIC_KEYS configured; denying access")
            return None

    # Try each key until one succeeds
    last_error: Optional[Exception] = None
    for kid_val, key in keys_to_try.items():
        if not key:
            continue
        try:
            payload = pyjwt.decode(
                token,
                key,
                algorithms=['ES256', 'RS256'],
                audience=JWT_AUDIENCE,
                issuer=JWT_ISSUER,
                options={'require': ['exp', 'iat', 'tenant']},
            )
            # Fail closed: tenant claim must be present and non-empty
            if not payload.get('tenant'):
                logger.debug("Access denied: token missing or empty tenant claim")
                return None
            return payload
        except (InvalidSignatureError, DecodeError):
            last_error = None  # Signature mismatch is expected when trying multiple keys
            continue
        except (InvalidAudienceError, InvalidIssuerError, MissingRequiredClaimError) as e:
            logger.warning(f"JWT claim validation failed: {e}")
            return None
        except InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            return None
        except Exception as e:
            logger.error(f"Token validation error: {e}")
            last_error = e
            return None

    # No keys succeeded
    if kid:
        logger.warning(f"Token signature verification failed for kid '{kid}'")
    else:
        logger.warning("Token signature verification failed with all available keys")
    return None
