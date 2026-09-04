"""
Authentication and Authorization Module
JWT ES256/RS256 verification with scope-based access control and kid-based key rotation.
"""

import logging
from typing import Dict, Optional, Tuple
import jwt
from jwt.exceptions import (
    InvalidSignatureError, ExpiredSignatureError, InvalidTokenError,
    InvalidAudienceError, InvalidIssuerError, MissingRequiredClaimError
)

from app.config import (
    JWT_ISSUER, JWT_AUDIENCE, JWT_PUBLIC_KEY, JWT_PUBLIC_KEYS
)

logger = logging.getLogger(__name__)


def extract_token(auth_header: str) -> Optional[str]:
    """
    Extract JWT token from Authorization header.

    Args:
        auth_header: 'Bearer <token>' or empty string

    Returns:
        Token string or None
    """
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    return auth_header[7:]  # Remove 'Bearer ' prefix


def verify_token(token: str) -> Tuple[bool, Optional[dict]]:
    """
    Verify JWT token signature and expiration (ES256/RS256).
    Supports kid-based key selection for rotation overlap.
    Fail closed: returns (False, None) if no public key configured.

    Args:
        token: JWT token string

    Returns:
        (is_valid, payload) where payload is None if invalid
    """
    if not token:
        logger.warning("Missing token")
        return False, None

    # Decode header to extract kid (without verifying signature yet)
    try:
        header = jwt.get_unverified_header(token)
    except Exception:
        logger.warning("Failed to extract JWT header")
        return False, None

    kid = header.get('kid')

    # Determine which key(s) to try
    keys_to_try: Dict[Optional[str], str] = {}

    if kid:
        # Token has kid: must match in JWT_PUBLIC_KEYS (if provided)
        if JWT_PUBLIC_KEYS and kid in JWT_PUBLIC_KEYS:
            keys_to_try[kid] = JWT_PUBLIC_KEYS[kid]
        else:
            # Kid present but not found: reject (unknown key)
            logger.warning(f"Unknown kid '{kid}' in token; denying access")
            return False, None
    else:
        # Token has no kid: try all keys (backward compat during rotation)
        if JWT_PUBLIC_KEYS:
            keys_to_try = JWT_PUBLIC_KEYS.copy()
        elif JWT_PUBLIC_KEY:
            keys_to_try[None] = JWT_PUBLIC_KEY
        else:
            logger.error("No JWT_PUBLIC_KEY or JWT_PUBLIC_KEYS configured; denying all auth")
            return False, None

    # Try each key until one succeeds
    for _kid_val, key in keys_to_try.items():
        if not key:
            continue
        try:
            payload = jwt.decode(
                token,
                key,
                algorithms=["ES256", "RS256"],
                audience=JWT_AUDIENCE,
                issuer=JWT_ISSUER,
                options={"require": ["exp", "iat", "tenant"]}
            )

            # Fail closed: tenant claim must be present and non-empty
            if not payload.get('tenant'):
                logger.warning("Token missing or empty tenant claim")
                return False, None

            return True, payload
        except (InvalidSignatureError, ExpiredSignatureError):
            if kid:
                # Signature mismatch for known kid
                logger.warning(f"Token signature verification failed for kid '{kid}'")
                return False, None
            # For no-kid tokens, signature mismatch is expected when trying multiple keys
            continue
        except (InvalidAudienceError, InvalidIssuerError, MissingRequiredClaimError) as e:
            logger.warning(f"JWT claim validation failed: {e}")
            return False, None
        except InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            return False, None
        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return False, None

    # No keys succeeded
    if kid:
        logger.warning(f"Token signature verification failed for kid '{kid}'")
    else:
        logger.warning("Token signature verification failed with all available keys")
    return False, None


def check_scope(payload: dict, required_scope: str) -> bool:
    """
    Check if token payload contains required scope.

    Args:
        payload: JWT payload dict
        required_scope: Required scope (e.g., 'dhcp:read', 'dhcp:admin')

    Returns:
        True if required scope present, False otherwise
    """
    scopes = payload.get("scope", "").split()
    return required_scope in scopes


def check_auth(auth_header: str, required_scope: str) -> Tuple[int, Optional[dict]]:
    """
    Full auth check: extract token, verify signature, check scope.

    Args:
        auth_header: Authorization header value
        required_scope: Required scope

    Returns:
        (status_code, payload)
        - 200: Success, payload contains token claims
        - 403: Missing/no header
        - 401: Invalid/expired token
        - 403: Valid token but missing scope
    """
    token = extract_token(auth_header)
    if not token:
        logger.warning(f"Missing auth header for scope {required_scope}")
        return 403, None

    is_valid, payload = verify_token(token)
    if not is_valid or payload is None:
        logger.warning(f"Invalid token for scope {required_scope}")
        return 401, None

    if not check_scope(payload, required_scope):
        logger.warning(f"Token missing scope {required_scope}")
        return 403, None

    return 200, payload
