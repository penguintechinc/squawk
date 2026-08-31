"""
Regression tests: SSO/SAML browser-binding hash comparison must use
constant-time comparison (hmac.compare_digest), not a plain `!=`/`==`
which can leak timing information about the expected digest value.

Both services compare a freshly-computed SHA-256 hash of the browser
binding cookie against the value stored on the login attempt -- this is a
secret-derived comparison and belongs on the constant-time path alongside
password/token hash checks elsewhere in the codebase.
"""

import hashlib
import hmac
import secrets
from unittest.mock import patch

from app.services.sso_service import SSOService
from app.services.saml_service import SAMLService


def test_sso_binding_check_uses_constant_time_compare(app, db):
    """exchange_code_for_token must call hmac.compare_digest for binding check."""
    with app.app_context():
        binding_a = secrets.token_urlsafe(32)
        state = SSOService.create_login_attempt(
            'okta', 'verifier', 'nonce',
            hashlib.sha256(binding_a.encode()).hexdigest(), db
        )

        with patch('hmac.compare_digest', wraps=hmac.compare_digest) as spy:
            # config is never touched before the (failing) binding check --
            # None keeps this test independent of OIDCConfig's field list.
            result = SSOService.exchange_code_for_token(
                config=None,
                code='fake-code',
                state=state,
                binding_cookie_value='wrong-binding-cookie',
                db=db,
            )

        assert result is None
        assert spy.called, (
            "browser binding check must use hmac.compare_digest, not == / !="
        )


def test_saml_binding_check_uses_constant_time_compare(app, db):
    """parse_and_validate_response must call hmac.compare_digest for binding check."""
    with app.app_context():
        binding_a = secrets.token_urlsafe(32)
        relay_state = SAMLService.create_login_attempt(
            'test-saml', f"id_{secrets.token_hex(8)}",
            hashlib.sha256(binding_a.encode()).hexdigest(), db
        )

        with patch('hmac.compare_digest', wraps=hmac.compare_digest) as spy:
            result = SAMLService.parse_and_validate_response(
                config=None,
                saml_response_b64='irrelevant',
                relay_state=relay_state,
                binding_cookie_value='wrong-binding-cookie',
                db=db,
            )

        assert result is None
        assert spy.called, (
            "browser binding check must use hmac.compare_digest, not == / !="
        )
