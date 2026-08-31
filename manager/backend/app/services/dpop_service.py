"""
DPoP (RFC 9449) sender-constrained token support.

Validates Demonstrating Proof-of-Possession (DPoP) proofs for machine identities.
A DPoP proof binds an access token to a public key the client must prove possession of,
preventing token exfiltration attacks (stolen tokens are useless without the private key).

Reference: https://tools.ietf.org/html/rfc9449
"""

import json
import jwt
import hashlib
import base64
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from flask import current_app
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class DPoPProof:
    """Validated DPoP proof."""

    htm: str  # HTTP method (GET, POST, etc.)
    htu: str  # HTTP URI (scheme + host + path, query/fragment ignored)
    iat: int  # Issued at timestamp (UNIX seconds)
    jti: str  # Unique token ID
    jkt: str  # JWK thumbprint (RFC 7638)
    jwk: Dict[str, Any]  # Public key object


class DPoPService:
    """DPoP proof validation and replay defense."""

    # Allowed signature algorithms (reject symmetric and none)
    ALLOWED_ALGS = {"ES256", "RS256"}
    # Accept ±60 seconds clock skew per RFC 9449
    CLOCK_SKEW_SECONDS = 60

    @staticmethod
    def validate_proof(
        dpop_header: str,
        http_method: str,
        http_uri: str,
    ) -> Optional[DPoPProof]:
        """
        Validate a DPoP proof header.

        Args:
            dpop_header: DPoP proof JWT string
            http_method: HTTP method (GET, POST, etc.) — must match proof
            http_uri: Full request URI (https://host/path?query#fragment)
                      — only scheme+host+path used; query and fragment ignored

        Returns:
            DPoPProof if valid, None otherwise.

        Raises:
            No exceptions; all validation errors return None.
        """
        if not dpop_header:
            return None

        try:
            # Decode without verification to inspect header
            unverified = jwt.decode(
                dpop_header, options={"verify_signature": False}
            )
            header = jwt.get_unverified_header(dpop_header)

            # Check type (must be dpop+jwt, not JWT)
            if header.get("typ") != "dpop+jwt":
                return None

            # Check algorithm is asymmetric (reject HS256, none)
            alg = header.get("alg")
            if alg not in DPoPService.ALLOWED_ALGS:
                return None

            # Extract embedded public key
            jwk_dict = header.get("jwk")
            if not jwk_dict:
                return None

            # Reject if jwk contains private key material
            if _contains_private_key_material(jwk_dict):
                return None

            # Verify signature using embedded JWK
            if not _verify_with_jwk(dpop_header, jwk_dict, alg):
                return None

            # Extract and validate claims
            htm = unverified.get("htm", "").upper()
            if htm != http_method.upper():
                return None

            htu_claim = unverified.get("htu")
            if not htu_claim:
                return None
            if not _htu_matches(htu_claim, http_uri):
                return None

            iat = unverified.get("iat")
            if iat is None:
                return None
            if not _iat_within_skew(iat):
                return None

            jti = unverified.get("jti")
            if not jti:
                return None

            # Insert-first replay defense: a unique-constraint violation on
            # jti means a concurrent/prior request already claimed it. This
            # closes the check-then-insert race where two requests bearing
            # the identical proof could both see "not yet seen" and pass.
            if not DPoPService._check_and_record_jti(jti):
                return None

            # Compute JWK thumbprint (RFC 7638)
            jkt = _compute_jwk_thumbprint(jwk_dict)

            return DPoPProof(
                htm=htm,
                htu=htu_claim,
                iat=iat,
                jti=jti,
                jkt=jkt,
                jwk=jwk_dict,
            )

        except Exception:
            return None

    @staticmethod
    def _check_and_record_jti(jti: str) -> bool:
        """
        Atomically claim a jti, returning True the first time it is seen.

        Insert-first (not check-then-insert): the jti unique constraint is
        the source of truth. Two concurrent requests bearing the identical
        proof both attempt the insert; exactly one wins, the other hits the
        unique-constraint violation and is correctly rejected as a replay.
        """
        db = current_app.db
        now = datetime.utcnow()

        # Opportunistic cleanup of expired entries.
        db(db.dpop_replay.expires_at < now).delete()
        db.commit()

        ttl = timedelta(minutes=15)
        expires_at = now + ttl
        try:
            db.dpop_replay.insert(jti=jti, expires_at=expires_at)
            db.commit()
            return True
        except Exception:
            # Unique constraint violation (or any insert failure) — fail
            # closed and treat as a replay. penguin-dal's sync DB has no
            # rollback() (each TableProxy call is its own auto-committed
            # session; db.commit() itself is a documented no-op for the
            # sync DB), so there is no cross-call transaction to unwind here.
            return False


def _contains_private_key_material(jwk: Dict[str, Any]) -> bool:
    """Check if JWK dict contains private key parameters."""
    # Private key indicators: d (private exponent), p, q, dp, dq, qi (RSA),
    # k (symmetric), oth (other primes)
    private_params = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
    return bool(set(jwk.keys()) & private_params)


def _verify_with_jwk(dpop_header: str, jwk_dict: Dict[str, Any], alg: str) -> bool:
    """Verify JWT signature using embedded JWK (public key only)."""
    try:
        kty = jwk_dict.get("kty")

        if kty == "RSA":
            # RSA public key
            n = jwk_dict.get("n")
            e = jwk_dict.get("e")
            if not n or not e:
                return False

            # Base64url decode with proper padding
            n_bytes = base64.urlsafe_b64decode(n + "=" * (4 - len(n) % 4))
            e_bytes = base64.urlsafe_b64decode(e + "=" * (4 - len(e) % 4))
            n_int = int.from_bytes(n_bytes, byteorder="big")
            e_int = int.from_bytes(e_bytes, byteorder="big")

            public_numbers = rsa.RSAPublicNumbers(e_int, n_int)
            public_key = public_numbers.public_key(default_backend())

            jwt.decode(
                dpop_header,
                public_key,
                algorithms=[alg],
                options={"verify_signature": True, "verify_iat": False},
            )
            return True

        elif kty == "EC":
            # EC public key
            crv = jwk_dict.get("crv")
            x = jwk_dict.get("x")
            y = jwk_dict.get("y")
            if not crv or not x or not y:
                return False

            # Map curve name to cryptography curve
            if crv == "P-256":
                curve = ec.SECP256R1()
            elif crv == "P-384":
                curve = ec.SECP384R1()
            elif crv == "P-521":
                curve = ec.SECP521R1()
            else:
                return False

            # Base64url decode with proper padding
            x_bytes = base64.urlsafe_b64decode(x + "=" * (4 - len(x) % 4))
            y_bytes = base64.urlsafe_b64decode(y + "=" * (4 - len(y) % 4))
            x_int = int.from_bytes(x_bytes, byteorder="big")
            y_int = int.from_bytes(y_bytes, byteorder="big")

            public_numbers = ec.EllipticCurvePublicNumbers(x_int, y_int, curve)
            public_key = public_numbers.public_key(default_backend())

            jwt.decode(
                dpop_header,
                public_key,
                algorithms=[alg],
                options={"verify_signature": True, "verify_iat": False},
            )
            return True

        else:
            return False

    except Exception:
        logger.exception("DPoP JWK signature verification failed")
        return False


def _htu_matches(htu_claim: str, http_uri: str) -> bool:
    """
    Check if htu claim matches the request URI.

    Per RFC 9449, comparison is case-insensitive for scheme and host,
    case-sensitive for path. Query and fragment in request are ignored.
    """
    try:
        from urllib.parse import urlparse

        claim_parsed = urlparse(htu_claim)
        request_parsed = urlparse(http_uri)

        # Scheme and host (case-insensitive)
        if (claim_parsed.scheme.lower() != request_parsed.scheme.lower() or
            claim_parsed.netloc.lower() != request_parsed.netloc.lower()):
            return False

        # Path (case-sensitive)
        if claim_parsed.path != request_parsed.path:
            return False

        return True

    except Exception:
        return False


def _iat_within_skew(iat: int) -> bool:
    """Check if iat (UNIX seconds) is within acceptable clock skew."""
    import time
    now = int(time.time())
    skew = DPoPService.CLOCK_SKEW_SECONDS
    return (now - skew) <= iat <= (now + skew)


def _compute_jwk_thumbprint(jwk: Dict[str, Any]) -> str:
    """
    Compute JWK thumbprint per RFC 7638 (SHA-256).

    Constructs a JSON object with required fields in lexicographic order,
    computes SHA-256 hash, and returns base64url-encoded result.
    """
    try:
        kty = jwk.get("kty")

        if kty == "RSA":
            # Required fields: e, kty, n (in order)
            required = {
                "e": jwk.get("e"),
                "kty": jwk.get("kty"),
                "n": jwk.get("n"),
            }
        elif kty == "EC":
            # Required fields: crv, kty, x, y (in order)
            required = {
                "crv": jwk.get("crv"),
                "kty": jwk.get("kty"),
                "x": jwk.get("x"),
                "y": jwk.get("y"),
            }
        else:
            return ""

        # Serialize in lexicographic order (no spaces)
        json_str = json.dumps(required, separators=(",", ":"), sort_keys=True)
        hash_bytes = hashlib.sha256(json_str.encode("utf-8")).digest()
        jkt = base64.urlsafe_b64encode(hash_bytes).decode("utf-8").rstrip("=")
        return jkt

    except Exception:
        return ""
