"""
Authentication and Authorization Module
JWT ES256/RS256 verification with scope-based access control.
"""

import logging
from typing import Optional, Tuple
import jwt
from jwt.exceptions import (
    InvalidSignatureError, ExpiredSignatureError, InvalidTokenError,
    InvalidAudienceError, InvalidIssuerError, MissingRequiredClaimError
)

from app.config import (
    JWT_ISSUER, JWT_AUDIENCE, _load_key_from_env_or_file
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
    Fail closed: returns (False, None) if JWT_PUBLIC_KEY not configured.

    Args:
        token: JWT token string

    Returns:
        (is_valid, payload) where payload is None if invalid
    """
    # Read the public key at call time (supports key rotation without restart
    # and keeps verification testable via env override).
    public_key = _load_key_from_env_or_file("JWT_PUBLIC_KEY", "JWT_PUBLIC_KEY_FILE")
    if not public_key:
        logger.error("JWT_PUBLIC_KEY not configured; denying all auth")
        return False, None

    if not token:
        logger.warning("Missing token")
        return False, None

    try:
        payload = jwt.decode(
            token,
            public_key,
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
    except ExpiredSignatureError:
        logger.warning("Token expired")
        return False, None
    except InvalidSignatureError:
        logger.warning("Invalid token signature")
        return False, None
    except (InvalidAudienceError, InvalidIssuerError, MissingRequiredClaimError) as e:
        logger.warning(f"JWT claim validation failed: {e}")
        return False, None
    except InvalidTokenError as e:
        logger.warning(f"Invalid token: {e}")
        return False, None
    except Exception as e:
        logger.error(f"Token validation error: {e}")
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
