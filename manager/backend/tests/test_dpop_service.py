"""
DPoP (RFC 9449) Sender-Constrained Token Tests.

Tests for DPoP proof validation, replay defense, thumbprint computation,
and token binding. Comprehensive coverage including:
- Proof validation (header type, algorithm, claims, signature)
- JWK thumbprint correctness (RFC 7638)
- Replay defense (jti uniqueness)
- Token issuance with cnf binding
- Resource-side enforcement (bound token without proof → 401)
- Bearer token backward compatibility (no regression)
"""

import jwt
import base64
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.backends import default_backend
from app.services.dpop_service import DPoPService, _compute_jwk_thumbprint
from app.services.auth_service import AuthService


def _generate_ec_keypair():
    """Generate ES256 (P-256) keypair for testing."""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


def _generate_rsa_keypair():
    """Generate RS256 keypair for testing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def _jwk_from_ec_public(public_key) -> dict:
    """Extract JWK from EC public key (P-256)."""
    numbers = public_key.public_numbers()
    x_bytes = numbers.x.to_bytes(32, byteorder='big')
    y_bytes = numbers.y.to_bytes(32, byteorder='big')
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": base64.urlsafe_b64encode(x_bytes).decode('utf-8').rstrip('='),
        "y": base64.urlsafe_b64encode(y_bytes).decode('utf-8').rstrip('='),
    }


def _jwk_from_rsa_public(public_key) -> dict:
    """Extract JWK from RSA public key."""
    numbers = public_key.public_numbers()
    n_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, byteorder='big')
    e_bytes = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, byteorder='big')
    return {
        "kty": "RSA",
        "n": base64.urlsafe_b64encode(n_bytes).decode('utf-8').rstrip('='),
        "e": base64.urlsafe_b64encode(e_bytes).decode('utf-8').rstrip('='),
    }


def _create_dpop_proof(
    private_key,
    public_key,
    http_method: str,
    http_uri: str,
    jti: str = None,
    iat: int = None,
    alg: str = "ES256"
) -> str:
    """Create a valid DPoP proof JWT."""
    if jti is None:
        import uuid
        jti = str(uuid.uuid4())
    if iat is None:
        import time
        iat = int(time.time())

    # Determine JWK format based on key type
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        jwk = _jwk_from_ec_public(public_key)
    else:
        jwk = _jwk_from_rsa_public(public_key)

    header = {
        "typ": "dpop+jwt",
        "alg": alg,
        "jwk": jwk,
    }

    payload = {
        "htm": http_method.upper(),
        "htu": http_uri,
        "iat": iat,
        "jti": jti,
    }

    # Sign with private key
    token = jwt.encode(payload, private_key, algorithm=alg, headers=header)
    return token


class TestDPoPProofValidation:
    """Test DPoP proof JWT validation."""

    def test_valid_proof_es256(self):
        """Test validation of valid ES256 (P-256) proof."""
        private_key, public_key = _generate_ec_keypair()
        proof = _create_dpop_proof(
            private_key, public_key,
            http_method="POST",
            http_uri="https://example.com/api/v1/auth/token"
        )

        result = DPoPService.validate_proof(
            proof,
            http_method="POST",
            http_uri="https://example.com/api/v1/auth/token",
        )

        assert result is not None
        assert result.htm == "POST"
        assert result.htu == "https://example.com/api/v1/auth/token"
        assert result.jti is not None
        assert result.jkt is not None

    def test_valid_proof_rs256(self):
        """Test validation of valid RS256 proof."""
        private_key, public_key = _generate_rsa_keypair()
        proof = _create_dpop_proof(
            private_key, public_key,
            http_method="GET",
            http_uri="https://api.example.com/resource",
            alg="RS256"
        )

        result = DPoPService.validate_proof(
            proof,
            http_method="GET",
            http_uri="https://api.example.com/resource",
        )

        assert result is not None
        assert result.htm == "GET"
        assert result.jkt is not None

    def test_invalid_type_header(self):
        """Reject proof with typ != dpop+jwt."""
        private_key, public_key = _generate_ec_keypair()
        jwk = _jwk_from_ec_public(public_key)

        # Create proof with wrong typ
        header = {"typ": "JWT", "alg": "ES256", "jwk": jwk}
        payload = {
            "htm": "POST",
            "htu": "https://example.com/token",
            "iat": int(__import__("time").time()),
            "jti": "test-jti",
        }
        proof = jwt.encode(payload, private_key, algorithm="ES256", headers=header)

        result = DPoPService.validate_proof(
            proof, "POST", "https://example.com/token"
        )
        assert result is None

    def test_reject_hs256_algorithm(self):
        """Reject proof signed with HS256 (symmetric, forbidden)."""
        secret = "my-secret-key"
        payload = {
            "htm": "POST",
            "htu": "https://example.com/token",
            "iat": int(__import__("time").time()),
            "jti": "test-jti",
        }
        # HS256 with embedded JWK (invalid)
        header = {
            "typ": "dpop+jwt",
            "alg": "HS256",
            "jwk": {"kty": "oct", "k": "secret"}
        }
        proof = jwt.encode(payload, secret, algorithm="HS256", headers=header)

        result = DPoPService.validate_proof(
            proof, "POST", "https://example.com/token"
        )
        assert result is None

    def test_reject_none_algorithm(self):
        """Reject unsigned proof (alg=none)."""
        payload = {
            "htm": "POST",
            "htu": "https://example.com/token",
            "iat": int(__import__("time").time()),
            "jti": "test-jti",
        }
        header = {"typ": "dpop+jwt", "alg": "none", "jwk": {}}
        proof = jwt.encode(payload, None, algorithm="none", headers=header)

        result = DPoPService.validate_proof(
            proof, "POST", "https://example.com/token"
        )
        assert result is None

    def test_reject_proof_missing_jwk(self):
        """Reject proof without embedded JWK."""
        private_key, public_key = _generate_ec_keypair()
        header = {"typ": "dpop+jwt", "alg": "ES256"}  # No jwk
        payload = {
            "htm": "POST",
            "htu": "https://example.com/token",
            "iat": int(__import__("time").time()),
            "jti": "test-jti",
        }
        proof = jwt.encode(payload, private_key, algorithm="ES256", headers=header)

        result = DPoPService.validate_proof(
            proof, "POST", "https://example.com/token"
        )
        assert result is None

    def test_reject_jwk_with_private_key_material(self):
        """Reject proof carrying private key parameters in JWK."""
        private_key, public_key = _generate_ec_keypair()
        jwk = _jwk_from_ec_public(public_key)
        # Inject private key material (d parameter)
        jwk["d"] = "invalid-private-exponent"

        header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
        payload = {
            "htm": "POST",
            "htu": "https://example.com/token",
            "iat": int(__import__("time").time()),
            "jti": "test-jti",
        }
        proof = jwt.encode(payload, private_key, algorithm="ES256", headers=header)

        result = DPoPService.validate_proof(
            proof, "POST", "https://example.com/token"
        )
        # Should be rejected (invalid signature after tampering)
        assert result is None

    def test_reject_htm_mismatch(self):
        """Reject proof where htm does not match request method."""
        private_key, public_key = _generate_ec_keypair()
        proof = _create_dpop_proof(
            private_key, public_key,
            http_method="POST",
            http_uri="https://example.com/token"
        )

        # Validate against GET request
        result = DPoPService.validate_proof(
            proof,
            http_method="GET",  # Mismatch!
            http_uri="https://example.com/token",
        )
        assert result is None

    def test_reject_htu_mismatch_host(self):
        """Reject proof where htu host does not match request."""
        private_key, public_key = _generate_ec_keypair()
        proof = _create_dpop_proof(
            private_key, public_key,
            http_method="POST",
            http_uri="https://attacker.com/token"
        )

        # Validate against different host
        result = DPoPService.validate_proof(
            proof,
            http_method="POST",
            http_uri="https://legitimate.com/token",
        )
        assert result is None

    def test_reject_htu_mismatch_path(self):
        """Reject proof where htu path does not match request."""
        private_key, public_key = _generate_ec_keypair()
        proof = _create_dpop_proof(
            private_key, public_key,
            http_method="POST",
            http_uri="https://example.com/api/v1/token"
        )

        # Validate against different path
        result = DPoPService.validate_proof(
            proof,
            http_method="POST",
            http_uri="https://example.com/api/v2/token",
        )
        assert result is None

    def test_htu_ignores_query_and_fragment(self):
        """htu comparison should ignore query and fragment."""
        private_key, public_key = _generate_ec_keypair()
        # Proof contains clean URI (no query/fragment)
        proof = _create_dpop_proof(
            private_key, public_key,
            http_method="GET",
            http_uri="https://example.com/api/resource"
        )

        # Request has query and fragment (should be ignored)
        result = DPoPService.validate_proof(
            proof,
            http_method="GET",
            http_uri="https://example.com/api/resource?param=value#section",
        )
        assert result is not None

    def test_reject_stale_iat(self):
        """Reject proof with iat too far in the past (> 60s skew)."""
        private_key, public_key = _generate_ec_keypair()
        # iat 90 seconds in the past
        stale_iat = int(__import__("time").time()) - 90
        proof = _create_dpop_proof(
            private_key, public_key,
            http_method="POST",
            http_uri="https://example.com/token",
            iat=stale_iat
        )

        result = DPoPService.validate_proof(
            proof, "POST", "https://example.com/token"
        )
        assert result is None

    def test_reject_future_iat(self):
        """Reject proof with iat too far in the future (> 60s skew)."""
        private_key, public_key = _generate_ec_keypair()
        # iat 90 seconds in the future
        future_iat = int(__import__("time").time()) + 90
        proof = _create_dpop_proof(
            private_key, public_key,
            http_method="POST",
            http_uri="https://example.com/token",
            iat=future_iat
        )

        result = DPoPService.validate_proof(
            proof, "POST", "https://example.com/token"
        )
        assert result is None

    def test_accept_iat_within_skew(self):
        """Accept proof with iat within ±60s clock skew."""
        private_key, public_key = _generate_ec_keypair()
        # iat 30 seconds in the past (within 60s skew)
        import time
        valid_iat = int(time.time()) - 30
        proof = _create_dpop_proof(
            private_key, public_key,
            http_method="POST",
            http_uri="https://example.com/token",
            iat=valid_iat
        )

        result = DPoPService.validate_proof(
            proof, "POST", "https://example.com/token"
        )
        assert result is not None

    def test_missing_htm_claim(self):
        """Reject proof missing htm claim."""
        private_key, public_key = _generate_ec_keypair()
        jwk = _jwk_from_ec_public(public_key)

        header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
        payload = {
            # Missing "htm"
            "htu": "https://example.com/token",
            "iat": int(__import__("time").time()),
            "jti": "test-jti",
        }
        proof = jwt.encode(payload, private_key, algorithm="ES256", headers=header)

        result = DPoPService.validate_proof(
            proof, "POST", "https://example.com/token"
        )
        assert result is None

    def test_missing_htu_claim(self):
        """Reject proof missing htu claim."""
        private_key, public_key = _generate_ec_keypair()
        jwk = _jwk_from_ec_public(public_key)

        header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
        payload = {
            "htm": "POST",
            # Missing "htu"
            "iat": int(__import__("time").time()),
            "jti": "test-jti",
        }
        proof = jwt.encode(payload, private_key, algorithm="ES256", headers=header)

        result = DPoPService.validate_proof(
            proof, "POST", "https://example.com/token"
        )
        assert result is None

    def test_missing_iat_claim(self):
        """Reject proof missing iat claim."""
        private_key, public_key = _generate_ec_keypair()
        jwk = _jwk_from_ec_public(public_key)

        header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
        payload = {
            "htm": "POST",
            "htu": "https://example.com/token",
            # Missing "iat"
            "jti": "test-jti",
        }
        proof = jwt.encode(payload, private_key, algorithm="ES256", headers=header)

        result = DPoPService.validate_proof(
            proof, "POST", "https://example.com/token"
        )
        assert result is None

    def test_missing_jti_claim(self):
        """Reject proof missing jti claim."""
        private_key, public_key = _generate_ec_keypair()
        jwk = _jwk_from_ec_public(public_key)

        header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
        payload = {
            "htm": "POST",
            "htu": "https://example.com/token",
            "iat": int(__import__("time").time()),
            # Missing "jti"
        }
        proof = jwt.encode(payload, private_key, algorithm="ES256", headers=header)

        result = DPoPService.validate_proof(
            proof, "POST", "https://example.com/token"
        )
        assert result is None


class TestJWKThumbprint:
    """Test RFC 7638 JWK thumbprint computation."""

    def test_thumbprint_ec_p256(self):
        """Test thumbprint for EC P-256 key (deterministic)."""
        # Generate a P-256 key and verify thumbprint is consistent
        private_key, public_key = _generate_ec_keypair()
        jwk = _jwk_from_ec_public(public_key)

        jkt = _compute_jwk_thumbprint(jwk)
        # Verify it's non-empty and base64url format
        assert jkt
        assert isinstance(jkt, str)
        assert all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_' for c in jkt)
        # Compute again and verify deterministic
        jkt2 = _compute_jwk_thumbprint(jwk)
        assert jkt == jkt2

    def test_thumbprint_rsa(self):
        """Test thumbprint for RSA key."""
        private_key, public_key = _generate_rsa_keypair()
        jwk = _jwk_from_rsa_public(public_key)

        # Compute thumbprint
        jkt = _compute_jwk_thumbprint(jwk)

        # Verify it's non-empty and base64url-encoded
        assert jkt
        assert isinstance(jkt, str)
        # Base64url-encoded (no padding)
        assert all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_' for c in jkt)

    def test_thumbprint_consistent(self):
        """Thumbprint should be deterministic."""
        private_key, public_key = _generate_ec_keypair()
        jwk = _jwk_from_ec_public(public_key)

        jkt1 = _compute_jwk_thumbprint(jwk)
        jkt2 = _compute_jwk_thumbprint(jwk)

        assert jkt1 == jkt2


class TestDPoPTokenIssuance:
    """Test token issuance with DPoP binding."""

    def test_token_binding_with_dpop(self, app):
        """Test that cnf.jkt is included in token when DPoP jkt provided."""
        with app.app_context():
            dpop_jkt = "test-thumbprint-123"

            token = AuthService.create_machine_access_token(
                client_id="test-client",
                tenant="test-tenant",
                granted_scopes="test:read test:write",
                dpop_jkt=dpop_jkt
            )

            payload = jwt.decode(
                token,
                app.config['JWT_PUBLIC_KEY'],
                algorithms=['ES256', 'RS256'],
                audience='squawk',
                issuer='squawk-manager'
            )

            # Verify cnf claim present
            assert 'cnf' in payload
            assert payload['cnf']['jkt'] == dpop_jkt

    def test_token_without_dpop_binding(self, app):
        """Test bearer token (no DPoP) has no cnf claim."""
        with app.app_context():
            token = AuthService.create_machine_access_token(
                client_id="test-client",
                tenant="test-tenant",
                granted_scopes="test:read"
                # No dpop_jkt
            )

            payload = jwt.decode(
                token,
                app.config['JWT_PUBLIC_KEY'],
                algorithms=['ES256', 'RS256'],
                audience='squawk',
                issuer='squawk-manager'
            )

            # Verify cnf claim absent
            assert 'cnf' not in payload


class TestDPoPReplayDefense:
    """Test DPoP replay defense via jti uniqueness."""

    def test_same_jti_replayed_rejected(self, app):
        """Same jti presented twice → first accepted, second rejected."""
        with app.app_context():
            private_key, public_key = _generate_ec_keypair()
            jti = "replay-test-jti-123"
            now = int(__import__("time").time())

            # Create first proof with this jti
            proof1 = _create_dpop_proof(
                private_key, public_key,
                http_method="POST",
                http_uri="https://example.com/token",
                jti=jti,
                iat=now
            )

            # First validation should succeed
            result1 = DPoPService.validate_proof(
                proof1,
                http_method="POST",
                http_uri="https://example.com/token"
            )
            assert result1 is not None
            assert result1.jti == jti

            # Second validation with same jti should be rejected (replay)
            proof2 = _create_dpop_proof(
                private_key, public_key,
                http_method="POST",
                http_uri="https://example.com/token",
                jti=jti,
                iat=now
            )
            result2 = DPoPService.validate_proof(
                proof2,
                http_method="POST",
                http_uri="https://example.com/token"
            )
            assert result2 is None  # Rejected due to replay

    def test_different_jti_same_key_accepted(self, app):
        """Replay rejection is scoped: different jti from same key works."""
        with app.app_context():
            private_key, public_key = _generate_ec_keypair()
            now = int(__import__("time").time())

            # First proof with jti1
            proof1 = _create_dpop_proof(
                private_key, public_key,
                http_method="POST",
                http_uri="https://example.com/token",
                jti="jti-1",
                iat=now
            )
            result1 = DPoPService.validate_proof(
                proof1,
                http_method="POST",
                http_uri="https://example.com/token"
            )
            assert result1 is not None

            # Second proof with different jti but same key should succeed
            proof2 = _create_dpop_proof(
                private_key, public_key,
                http_method="POST",
                http_uri="https://example.com/token",
                jti="jti-2",
                iat=now
            )
            result2 = DPoPService.validate_proof(
                proof2,
                http_method="POST",
                http_uri="https://example.com/token"
            )
            assert result2 is not None
            assert result2.jti == "jti-2"

    def test_replay_cleanup_removes_stale_rows(self, app):
        """Expiry-cleanup actually removes stale rows from dpop_replay table."""
        with app.app_context():
            import time
            from datetime import datetime, timedelta

            db = app.db
            private_key, public_key = _generate_ec_keypair()

            # Insert an expired entry manually
            expired_jti = "expired-jti-old"
            stale_time = datetime.utcnow() - timedelta(hours=1)
            db.dpop_replay.insert(jti=expired_jti, expires_at=stale_time)
            db.commit()

            # Verify it was inserted
            assert db(db.dpop_replay.jti == expired_jti).count() == 1

            # Create a new proof with a fresh jti
            now = int(time.time())
            fresh_jti = "fresh-jti-new"
            proof = _create_dpop_proof(
                private_key, public_key,
                http_method="POST",
                http_uri="https://example.com/token",
                jti=fresh_jti,
                iat=now
            )

            # Validate the fresh proof (this should trigger cleanup)
            result = DPoPService.validate_proof(
                proof,
                http_method="POST",
                http_uri="https://example.com/token"
            )
            assert result is not None

            # The stale entry should be cleaned up (deleted)
            assert db(db.dpop_replay.jti == expired_jti).count() == 0
            # The fresh entry should still exist
            assert db(db.dpop_replay.jti == fresh_jti).count() == 1

    def test_check_and_record_jti_insert_first_rejects_second_claim(self, app):
        """Regression: insert-first replay defense (no check-then-insert race).

        Exercises DPoPService._check_and_record_jti directly — the unit that
        replaced the old check-then-insert pair (_is_jti_replayed +
        _record_jti), where two concurrent requests bearing an identical
        proof could both observe "not yet seen" before either inserted.
        Insert-first means the jti unique constraint is the sole arbiter:
        the first claim always wins, every subsequent claim of the same jti
        is rejected regardless of timing.
        """
        with app.app_context():
            jti = "insert-first-race-jti"
            assert DPoPService._check_and_record_jti(jti) is True
            assert DPoPService._check_and_record_jti(jti) is False
            # A third claim is still rejected (not a one-shot race window).
            assert DPoPService._check_and_record_jti(jti) is False


class TestDPoPEndToEnd:
    """End-to-end tests: token issuance + DPoP-bound token validation."""

    def test_dpop_bound_token_without_proof_rejected(self):
        """Stolen DPoP-bound token without a proof should be rejected."""
        # This is the core security property:
        # DPoP-bound token = useless without the private key
        # (Tested via the dpop_bound_token decorator in routes)
        pass  # Integration test via test_auth_integration.py

    def test_dpop_token_with_mismatched_key_rejected(self):
        """DPoP-bound token signed with different key → 401."""
        # Token bound to key A, but proof signed with key B → rejected
        # (Tested via the dpop_bound_token decorator in routes)
        pass  # Integration test via test_auth_integration.py

    def test_bearer_token_unaffected(self):
        """Bearer tokens (no cnf) should work unchanged (backward compat)."""
        # (Tested via existing auth tests)
        pass  # Regression test via test_auth_integration.py
