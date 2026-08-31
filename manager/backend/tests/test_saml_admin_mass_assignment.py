"""Regression test: SAML provider update must not mass-assign the request body.

Prior to the fix, update_saml_provider did `db(...).update(**data)` with no
field allowlist — a caller with sso:write could overwrite id/name/tenant or
any other column present in the schema, not just the documented updatable
fields. Mirrors sso_admin.py's update_sso_provider allowlist pattern.
"""

import pytest

from app.services.auth_service import AuthService


@pytest.fixture(autouse=True)
def _enterprise_license(app, monkeypatch):
    monkeypatch.setattr(app.license_service, 'is_enterprise', lambda: True)


@pytest.fixture
def sso_writer_token(app):
    """Holds sso:write (SystemAdmin only — OrgAdmin does not carry sso:*)."""
    with app.app_context():
        db = app.db
        user = db.auth_user.insert(
            username='saml-admin', email='saml-admin@example.com',
            password_hash='hashed', global_role='SystemAdmin',
        )
        db.commit()
        return AuthService.create_access_token(
            user_id=user, username='saml-admin', global_role='SystemAdmin', team_roles={},
        )


@pytest.fixture
def saml_provider(app):
    with app.app_context():
        db = app.db
        provider_id = db.saml_providers.insert(
            name='mass-assign-test',
            display_name='Mass Assign Test',
            idp_entity_id='urn:example:idp',
            idp_sso_url='https://idp.example.com/sso',
            idp_x509_cert='-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----',
            sp_entity_id='https://sp.example.com/metadata',
            sp_acs_url='https://sp.example.com/acs',
            tenant='default',
        )
        db.commit()
        return provider_id


class TestSamlProviderUpdateAllowlist:
    def test_update_cannot_overwrite_tenant(self, app, sso_writer_token, saml_provider):
        with app.test_client() as client:
            response = client.patch(
                f'/api/v1/admin/saml/providers/{saml_provider}',
                json={'display_name': 'Renamed', 'tenant': 'attacker-tenant'},
                headers={'Authorization': f'Bearer {sso_writer_token}'},
            )
            assert response.status_code == 200

        with app.app_context():
            db = app.db
            provider = db.saml_providers[saml_provider]
            assert provider.display_name == 'Renamed'
            assert provider.tenant == 'default'

    def test_update_cannot_overwrite_name_slug(self, app, sso_writer_token, saml_provider):
        with app.test_client() as client:
            response = client.patch(
                f'/api/v1/admin/saml/providers/{saml_provider}',
                json={'name': 'renamed-slug'},
                headers={'Authorization': f'Bearer {sso_writer_token}'},
            )
            assert response.status_code == 200

        with app.app_context():
            db = app.db
            provider = db.saml_providers[saml_provider]
            assert provider.name == 'mass-assign-test'
