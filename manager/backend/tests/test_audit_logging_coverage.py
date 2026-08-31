"""Regression tests: audit coverage for previously-unaudited security events.

Prior to this change, several authentication-adjacent flows -- token
refresh, MFA verification, SSO/SAML login, SCIM provisioning, and
deployment-domain JWT rollover -- executed without writing a durable
`audit_event` row, and the login route wrote actor_id=NULL for every
attempt (get_current_user() has nothing to return pre-auth), making a
brute-force campaign against a specific account untraceable in the audit
trail. Each test here asserts the corresponding action is now recorded,
with correct actor/resource attribution where the account is known.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from unittest.mock import patch

import pyotp
from flask import g

from app.services.auth_service import AuthService
from app.services.mfa_service import MFAService
from app.services.sso_service import ValidatedIDToken, SSOService
from app.services.scim_service import SCIMTokenService


def _last_audit_event(db, action: str):
    """Fetch the most recent audit_event row for an action."""
    rows = db(db.audit_event.action == action).select(
        orderby=~db.audit_event.id
    )
    return rows.first() if rows else None


class TestTokenRefreshAudited:
    """/auth/refresh writes a token_refresh audit event attributed to the
    refresh token's subject (get_current_user() is unavailable on this
    route)."""

    def test_refresh_writes_audit_event(self, app, client, db):
        with app.app_context():
            user_id = db.auth_user.insert(
                username='refresh-audit-user',
                email='refresh-audit@example.com',
                password_hash='x',
                global_role='Viewer',
                active=True,
            )
            db.commit()
            original = AuthService.create_refresh_token(user_id)

        resp = client.post('/api/v1/auth/refresh', json={'refreshToken': original})
        assert resp.status_code == 200

        with app.app_context():
            event = _last_audit_event(db, 'token_refresh')
            assert event is not None
            assert event.outcome == 'success'
            assert event.actor_id == user_id


class TestLoginAuditAttribution:
    """A login attempt (success or failure) records the TARGET account and
    source IP, so brute-force attempts are traceable even though
    get_current_user() is None pre-auth."""

    def _make_user(self, db, username='login-audit-user', password='CorrectHorse123!'):
        user_id = db.auth_user.insert(
            username=username,
            email=f'{username}@example.com',
            password_hash=AuthService.hash_password(password),
            global_role='Viewer',
            active=True,
        )
        db.commit()
        return user_id

    def test_failed_login_attributes_target_account(self, app, client, db):
        with app.app_context():
            user_id = self._make_user(db, username='bob-login-audit')

        resp = client.post(
            '/api/v1/auth/login',
            json={'username': 'bob-login-audit', 'password': 'wrong-password'},
        )
        assert resp.status_code == 401

        with app.app_context():
            event = _last_audit_event(db, 'user_login')
            assert event is not None
            assert event.outcome == 'failure'
            # actor_id is NOT null: the targeted account is known even
            # though authentication failed -- this is what makes a
            # brute-force campaign traceable to the account under attack.
            assert event.actor_id == user_id
            assert event.resource_type == 'user'
            assert event.resource_id == user_id
            assert event.source_ip is not None

    def test_successful_login_attributes_account(self, app, client, db):
        with app.app_context():
            user_id = self._make_user(db, username='alice-login-audit')

        resp = client.post(
            '/api/v1/auth/login',
            json={'username': 'alice-login-audit', 'password': 'CorrectHorse123!'},
        )
        assert resp.status_code == 200

        with app.app_context():
            event = _last_audit_event(db, 'user_login')
            assert event is not None
            assert event.outcome == 'success'
            assert event.actor_id == user_id

    def test_unknown_username_login_leaves_actor_null(self, app, client, db):
        """No such account exists -- there's no internal id to attribute
        to, so actor_id stays NULL, but the failure and source_ip are still
        recorded.

        The `app` fixture is session-scoped and keeps a single application
        context open for the whole test run, so flask.g (which is bound to
        the app context, not the request) can carry a `current_user` set by
        an unrelated, earlier authenticated test in the suite. A real
        deployment never shares a context across requests; explicitly
        clearing it here reproduces that per-request isolation for this
        assertion.
        """
        g.current_user = None
        resp = client.post(
            '/api/v1/auth/login',
            json={'username': 'no-such-user-audit', 'password': 'whatever'},
        )
        assert resp.status_code == 401

        with app.app_context():
            event = _last_audit_event(db, 'user_login')
            assert event is not None
            assert event.outcome == 'failure'
            assert event.actor_id is None
            assert event.source_ip is not None


class TestMFAVerifyAudited:
    """MFA verify failures/successes are recorded, attributed to the
    account under verification (pre-auth token only, no JWT yet)."""

    def test_mfa_verify_failure_audited(self, client, app, db):
        with app.app_context():
            secret = pyotp.random_base32()
            encrypted = MFAService.encrypt_secret(secret)

            user_id = db.auth_user.insert(
                username='mfa-audit-user',
                email='mfa-audit@example.com',
                password_hash=AuthService.hash_password('CorrectHorse123!'),
                global_role='Viewer',
                active=True,
                mfa_enabled=True,
                mfa_secret=encrypted,
            )
            db.commit()

            resp_login = client.post(
                '/api/v1/auth/login',
                json={'username': 'mfa-audit-user', 'password': 'CorrectHorse123!'},
            )
            pre_auth_token = resp_login.get_json()['pre_auth_token']

        resp = client.post(
            '/api/v1/auth/mfa-verify',
            json={'pre_auth_token': pre_auth_token, 'totp_code': '000000'},
        )
        assert resp.status_code == 401

        with app.app_context():
            event = _last_audit_event(db, 'mfa_verify')
            assert event is not None
            assert event.outcome == 'failure'
            assert event.actor_id == user_id


class TestSSOLoginAudited:
    """OIDC SSO callback writes an sso_login audit event on success,
    attributed to both the provider used and the resulting account."""

    def test_sso_callback_success_audited(self, app, client, db):
        with app.app_context():
            provider_id = db.sso_providers.insert(
                name='okta-audit', display_name='Okta',
                issuer='https://okta.example.com/audit',
                client_id='client123',
                client_secret=SSOService.encrypt_secret('secret'),
                authorization_endpoint='https://okta.example.com/auth',
                token_endpoint='https://okta.example.com/token',
                jwks_url='https://okta.example.com/keys',
                enabled=True,
            )
            user_id = db.auth_user.insert(
                username='sso-audit-user',
                email='sso-audit@example.com',
                password_hash=None,
                global_role='Viewer',
                active=True,
                sso_provider='okta-audit',
                sso_subject='okta-user-audit-1',
            )
            db.commit()

        client.set_cookie('__Host-sso_binding', 'binding-token-value')

        fake_token_result = type('T', (), {'id_token': 'fake-id-token'})()
        validated = ValidatedIDToken(
            sub='okta-user-audit-1',
            email='sso-audit@example.com',
            email_verified=True,
            name='SSO User',
            iss='https://okta.example.com/audit',
            aud='client123',
        )

        with patch('app.blueprints.sso.SSOService.exchange_code_for_token',
                   return_value=fake_token_result), \
             patch('app.blueprints.sso.SSOService.get_login_attempt',
                   return_value={'nonce': 'nonce123'}), \
             patch('app.blueprints.sso.SSOService.validate_id_token',
                   return_value=validated), \
             patch('app.blueprints.sso.SSOService.jit_provision_or_match_user',
                   return_value=user_id):
            resp = client.post(
                '/api/v1/auth/sso/okta-audit/callback',
                json={'code': 'auth-code', 'state': 'opaque-state'},
            )

        assert resp.status_code == 200

        with app.app_context():
            event = _last_audit_event(db, 'sso_login')
            assert event is not None
            assert event.outcome == 'success'
            assert event.actor_id == user_id
            assert event.resource_type == 'sso_provider'
            assert event.resource_id == provider_id


class TestSCIMUserCreateAudited:
    """SCIM user provisioning (POST /scim/v2/Users) writes a
    scim_user_created audit event."""

    def test_scim_create_user_audited(self, app, client, db):
        with app.app_context():
            plaintext, _ = SCIMTokenService.create_token('audit-test-token', 'default')
            SCIMTokenService.store_token(plaintext, 'audit-test-token', 'default')

        resp = client.post(
            '/scim/v2/Users',
            headers={
                'Authorization': f'Bearer {plaintext}',
                'Content-Type': 'application/scim+json',
            },
            json={
                'userName': 'scim-audit-user',
                'externalId': 'ext-audit-1',
                'active': True,
            },
        )
        assert resp.status_code == 201
        created_id = resp.get_json()['id']

        with app.app_context():
            event = _last_audit_event(db, 'scim_user_created')
            assert event is not None
            assert event.outcome == 'success'
            assert event.resource_type == 'user'
            assert str(event.resource_id) == str(created_id)
            assert event.tenant == 'default'


class TestDomainJwtRolloverAudited:
    """POST .../jwt-rollover writes a domain_jwt_rollover audit event
    attributed to both the admin actor (JWT) and the deployment domain."""

    def test_rollover_writes_audit_event(self, app, client, db):
        with app.app_context():
            domain_id = db.deployment_domain.insert(
                name='audit-rollover-domain',
                jwt_token_hash=hashlib.sha256(b'placeholder-jwt').hexdigest(),
                jwt_expires=datetime.now(),
                active=True,
            )
            admin_id = db.auth_user.insert(
                username='cc-audit-admin', email='cc-audit-admin@example.com',
                password_hash='hashed', global_role='SystemAdmin',
            )
            db.commit()
            sysadmin_token = AuthService.create_access_token(
                user_id=admin_id, username='cc-audit-admin',
                global_role='SystemAdmin', team_roles={},
            )

        with patch.object(app.posthog, 'feature_enabled', lambda *a, **kw: True):
            resp = client.post(
                f'/api/v1/client-config/domains/{domain_id}/jwt-rollover',
                headers={'Authorization': f'Bearer {sysadmin_token}'},
            )
        assert resp.status_code == 200

        with app.app_context():
            event = _last_audit_event(db, 'domain_jwt_rollover')
            assert event is not None
            assert event.outcome == 'success'
            assert event.actor_id == admin_id
            assert event.resource_type == 'deployment_domain'
            assert event.resource_id == domain_id
