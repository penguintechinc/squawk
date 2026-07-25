"""
Tests for OAuth2 client_credentials (machine identities) and OIDC token exchange.

Covers:
- Part 1: Machine client CRUD and client_credentials grant
- Part 2: OIDC trust anchor CRUD and token-exchange grant
"""

import pytest
import jwt
import base64
import json
from datetime import datetime, timedelta
from app.services.auth_service import AuthService
from app.services.scopes import ROLE_SCOPES, scope_string


class TestMachineClientCRUD:
    """Test machine client create/read/update/delete operations."""

    def test_create_machine_client(self, app, client, jwt_token_factory):
        """Create a machine client returns client_id and secret (once)."""
        auth_token = jwt_token_factory(global_role='SystemAdmin')

        response = client.post(
            '/api/v1/machine-clients',
            json={
                'scopes': 'users:read servers:write',
                'description': 'CI/CD pipeline',
                'tenant': 'default'
            },
            headers={'Authorization': f'Bearer {auth_token}'}
        )

        assert response.status_code == 201
        data = response.get_json()
        assert 'client_id' in data
        assert 'client_secret' in data
        assert data['client_id'].startswith('sqk_mc_')
        assert data['scopes'] == 'users:read servers:write'
        assert data['active'] is True

    def test_create_machine_client_invalid_scopes(self, app, client, jwt_token_factory):
        """Create fails with invalid scopes."""
        auth_token = jwt_token_factory(global_role='SystemAdmin')

        response = client.post(
            '/api/v1/machine-clients',
            json={
                'scopes': 'nonexistent:scope',
                'description': 'Test'
            },
            headers={'Authorization': f'Bearer {auth_token}'}
        )

        assert response.status_code == 400
        data = response.get_json()
        assert 'Invalid scopes' in data['error']

    def test_create_machine_client_requires_admin(self, app, client, jwt_token_factory):
        """Create requires admin scope."""
        auth_token = jwt_token_factory(global_role='Viewer')

        response = client.post(
            '/api/v1/machine-clients',
            json={
                'scopes': 'users:read',
                'description': 'Test'
            },
            headers={'Authorization': f'Bearer {auth_token}'}
        )

        assert response.status_code == 403

    def test_list_machine_clients(self, app, client, jwt_token_factory):
        """List machine clients with filters."""
        auth_token = jwt_token_factory(global_role='SystemAdmin')

        # Create two clients
        with app.app_context():
            client_id1, secret1, _ = AuthService.create_machine_client(
                'default', 'Client 1', 'users:read'
            )
            client_id2, secret2, _ = AuthService.create_machine_client(
                'default', 'Client 2', 'servers:write'
            )

        response = client.get(
            '/api/v1/machine-clients',
            headers={'Authorization': f'Bearer {auth_token}'}
        )

        assert response.status_code == 200
        data = response.get_json()
        assert len(data) >= 2
        ids = [c['client_id'] for c in data]
        assert client_id1 in ids
        assert client_id2 in ids

    def test_list_machine_clients_filter_active(self, app, client, jwt_token_factory):
        """List machine clients filters by active status."""
        auth_token = jwt_token_factory(global_role='SystemAdmin')

        with app.app_context():
            db = app.db
            c1_id, _, _ = AuthService.create_machine_client(
                'default', 'Active', 'users:read'
            )
            c2_id, _, _ = AuthService.create_machine_client(
                'default', 'Inactive', 'users:read'
            )
            # Deactivate second client
            db(db.machine_client.client_id == c2_id).update(active=False)
            db.commit()

        response = client.get(
            '/api/v1/machine-clients?active=true',
            headers={'Authorization': f'Bearer {auth_token}'}
        )

        assert response.status_code == 200
        data = response.get_json()
        active_ids = [c['client_id'] for c in data]
        assert c1_id in active_ids
        assert c2_id not in active_ids

    def test_get_machine_client(self, app, client, jwt_token_factory):
        """Get a specific machine client."""
        auth_token = jwt_token_factory(global_role='SystemAdmin')

        with app.app_context():
            db = app.db
            client_id, _, _ = AuthService.create_machine_client(
                'default', 'Test client', 'users:read'
            )
            record = db(db.machine_client.client_id == client_id).select().first()
            record_id = record.id

        response = client.get(
            f'/api/v1/machine-clients/{record_id}',
            headers={'Authorization': f'Bearer {auth_token}'}
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data['client_id'] == client_id

    def test_update_machine_client_scopes(self, app, client, jwt_token_factory):
        """Update machine client scopes."""
        auth_token = jwt_token_factory(global_role='SystemAdmin')

        with app.app_context():
            db = app.db
            client_id, _, _ = AuthService.create_machine_client(
                'default', 'Test', 'users:read'
            )
            record = db(db.machine_client.client_id == client_id).select().first()
            record_id = record.id

        response = client.patch(
            f'/api/v1/machine-clients/{record_id}',
            json={'scopes': 'users:read servers:write'},
            headers={'Authorization': f'Bearer {auth_token}'}
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data['scopes'] == 'users:read servers:write'

    def test_update_machine_client_active(self, app, client, jwt_token_factory):
        """Update machine client active status."""
        auth_token = jwt_token_factory(global_role='SystemAdmin')

        with app.app_context():
            db = app.db
            client_id, _, _ = AuthService.create_machine_client(
                'default', 'Test', 'users:read'
            )
            record = db(db.machine_client.client_id == client_id).select().first()
            record_id = record.id

        response = client.patch(
            f'/api/v1/machine-clients/{record_id}',
            json={'active': False},
            headers={'Authorization': f'Bearer {auth_token}'}
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data['active'] is False

    def test_delete_machine_client(self, app, client, jwt_token_factory):
        """Delete a machine client."""
        auth_token = jwt_token_factory(global_role='SystemAdmin')

        with app.app_context():
            db = app.db
            client_id, _, _ = AuthService.create_machine_client(
                'default', 'Test', 'users:read'
            )
            record = db(db.machine_client.client_id == client_id).select().first()
            record_id = record.id

        response = client.delete(
            f'/api/v1/machine-clients/{record_id}',
            headers={'Authorization': f'Bearer {auth_token}'}
        )

        assert response.status_code == 200

        # Verify it's gone
        with app.app_context():
            db = app.db
            still_exists = db(db.machine_client.client_id == client_id).count()
            assert still_exists == 0

    def test_rotate_machine_client_secret(self, app, client, jwt_token_factory):
        """Rotate machine client secret invalidates old secret."""
        auth_token = jwt_token_factory(global_role='SystemAdmin')

        with app.app_context():
            db = app.db
            client_id, old_secret, _ = AuthService.create_machine_client(
                'default', 'Test', 'users:read'
            )
            record = db(db.machine_client.client_id == client_id).select().first()
            record_id = record.id

        response = client.post(
            f'/api/v1/machine-clients/{record_id}/rotate-secret',
            headers={'Authorization': f'Bearer {auth_token}'}
        )

        assert response.status_code == 200
        data = response.get_json()
        new_secret = data['client_secret']
        assert new_secret != old_secret

        # Verify old secret no longer works
        with app.app_context():
            result = AuthService.verify_machine_client(client_id, old_secret)
            assert result is None

        # Verify new secret works
        with app.app_context():
            result = AuthService.verify_machine_client(client_id, new_secret)
            assert result is not None


class TestMachineClientTokenGrant:
    """Test OAuth2 client_credentials grant (/api/v1/auth/token)."""

    def test_token_client_credentials_http_basic(self, app, client):
        """Token endpoint accepts client_credentials with HTTP Basic Auth."""
        with app.app_context():
            client_id, secret, _ = AuthService.create_machine_client(
                'default', 'Test', 'users:read servers:write'
            )

        # HTTP Basic Auth: base64(client_id:secret)
        auth_header = base64.b64encode(f'{client_id}:{secret}'.encode()).decode()

        response = client.post(
            '/api/v1/auth/token',
            data={
                'grant_type': 'client_credentials'
            },
            headers={'Authorization': f'Basic {auth_header}'}
        )

        assert response.status_code == 200
        data = response.get_json()
        assert 'access_token' in data
        assert data['token_type'] == 'Bearer'
        assert data['expires_in'] == 900  # 15 min default
        assert 'users:read' in data['scope']
        assert 'servers:write' in data['scope']

    def test_token_client_credentials_form_body(self, app, client):
        """Token endpoint accepts client_credentials from form body."""
        with app.app_context():
            client_id, secret, _ = AuthService.create_machine_client(
                'default', 'Test', 'users:read'
            )

        response = client.post(
            '/api/v1/auth/token',
            data={
                'grant_type': 'client_credentials',
                'client_id': client_id,
                'client_secret': secret
            }
        )

        assert response.status_code == 200
        data = response.get_json()
        assert 'access_token' in data

    def test_token_client_credentials_wrong_secret(self, app, client):
        """Token endpoint rejects wrong client_secret (timing-safe check)."""
        with app.app_context():
            client_id, secret, _ = AuthService.create_machine_client(
                'default', 'Test', 'users:read'
            )

        # Use wrong secret
        auth_header = base64.b64encode(
            f'{client_id}:wrong_secret'.encode()
        ).decode()

        response = client.post(
            '/api/v1/auth/token',
            data={'grant_type': 'client_credentials'},
            headers={'Authorization': f'Basic {auth_header}'}
        )

        assert response.status_code == 401
        data = response.get_json()
        assert data['error'] == 'invalid_client'

    def test_token_client_credentials_inactive_client(self, app, client):
        """Token endpoint rejects inactive clients."""
        with app.app_context():
            db = app.db
            client_id, secret, _ = AuthService.create_machine_client(
                'default', 'Test', 'users:read'
            )
            # Deactivate
            db(db.machine_client.client_id == client_id).update(active=False)
            db.commit()

        auth_header = base64.b64encode(f'{client_id}:{secret}'.encode()).decode()

        response = client.post(
            '/api/v1/auth/token',
            data={'grant_type': 'client_credentials'},
            headers={'Authorization': f'Basic {auth_header}'}
        )

        assert response.status_code == 401

    def test_token_client_credentials_scope_subset(self, app, client):
        """Token endpoint enforces scope subset (requested ⊆ registered)."""
        with app.app_context():
            client_id, secret, _ = AuthService.create_machine_client(
                'default', 'Test', 'users:read servers:read'
            )

        auth_header = base64.b64encode(f'{client_id}:{secret}'.encode()).decode()

        # Request subset of registered scopes
        response = client.post(
            '/api/v1/auth/token',
            data={
                'grant_type': 'client_credentials',
                'scope': 'users:read'
            },
            headers={'Authorization': f'Basic {auth_header}'}
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data['scope'] == 'users:read'

    def test_token_client_credentials_scope_exceeds_registered(self, app, client):
        """Token endpoint rejects requested scopes exceeding registered."""
        with app.app_context():
            client_id, secret, _ = AuthService.create_machine_client(
                'default', 'Test', 'users:read'
            )

        auth_header = base64.b64encode(f'{client_id}:{secret}'.encode()).decode()

        # Request scope not in registered scopes
        response = client.post(
            '/api/v1/auth/token',
            data={
                'grant_type': 'client_credentials',
                'scope': 'users:read servers:write'
            },
            headers={'Authorization': f'Basic {auth_header}'}
        )

        assert response.status_code == 400
        data = response.get_json()
        assert data['error'] == 'invalid_scope'

    def test_token_access_token_has_machine_marker(self, app, client, jwt_keypair):
        """Issued access token has machine=True and correct claims."""
        with app.app_context():
            client_id, secret, _ = AuthService.create_machine_client(
                'default', 'Test', 'users:read'
            )

        auth_header = base64.b64encode(f'{client_id}:{secret}'.encode()).decode()

        response = client.post(
            '/api/v1/auth/token',
            data={'grant_type': 'client_credentials'},
            headers={'Authorization': f'Basic {auth_header}'}
        )

        assert response.status_code == 200
        data = response.get_json()
        access_token = data['access_token']

        # Decode token (verify with test keypair)
        payload = jwt.decode(
            access_token,
            jwt_keypair['public'],
            algorithms=['ES256'],
            audience='squawk'
        )

        assert payload['sub'] == f'client:{client_id}'
        assert payload['machine'] is True
        assert payload['type'] == 'access'
        assert payload['scope'] == 'users:read'
        assert payload['tenant'] == 'default'

    def test_token_updates_last_used_at(self, app, client):
        """Token endpoint updates last_used_at timestamp."""
        with app.app_context():
            db = app.db
            client_id, secret, _ = AuthService.create_machine_client(
                'default', 'Test', 'users:read'
            )
            record = db(db.machine_client.client_id == client_id).select().first()
            assert record.last_used_at is None

        auth_header = base64.b64encode(f'{client_id}:{secret}'.encode()).decode()

        response = client.post(
            '/api/v1/auth/token',
            data={'grant_type': 'client_credentials'},
            headers={'Authorization': f'Basic {auth_header}'}
        )

        assert response.status_code == 200

        # Verify last_used_at was updated
        with app.app_context():
            db = app.db
            record = db(db.machine_client.client_id == client_id).select().first()
            assert record.last_used_at is not None


class TestOIDCTrustAnchorCRUD:
    """Test OIDC trust anchor create/read/update/delete operations."""

    def test_create_oidc_trust_anchor_with_static_jwks(self, app, client, jwt_token_factory):
        """Create OIDC trust anchor with static PEM JWKS."""
        auth_token = jwt_token_factory(global_role='SystemAdmin')

        static_pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"

        response = client.post(
            '/api/v1/oidc-trust-anchors',
            json={
                'issuer': 'https://k8s.example.com',
                'audience': 'squawk-api',
                'static_jwks_pem': static_pem,
                'allowed_scopes': 'users:read servers:read',
                'subject_pattern': 'system:serviceaccount:*:*'
            },
            headers={'Authorization': f'Bearer {auth_token}'}
        )

        assert response.status_code == 201
        data = response.get_json()
        assert data['issuer'] == 'https://k8s.example.com'
        assert data['audience'] == 'squawk-api'
        assert data['active'] is True

    def test_create_oidc_trust_anchor_with_jwks_url(self, app, client, jwt_token_factory):
        """Create OIDC trust anchor with JWKS URL."""
        auth_token = jwt_token_factory(global_role='SystemAdmin')

        response = client.post(
            '/api/v1/oidc-trust-anchors',
            json={
                'issuer': 'https://github.com',
                'audience': 'squawk',
                'jwks_url': 'https://github.com/.well-known/openid-configuration',
                'allowed_scopes': 'users:read'
            },
            headers={'Authorization': f'Bearer {auth_token}'}
        )

        assert response.status_code == 201

    def test_create_oidc_trust_anchor_requires_admin(self, app, client, jwt_token_factory):
        """Create requires admin scope."""
        auth_token = jwt_token_factory(global_role='Viewer')

        response = client.post(
            '/api/v1/oidc-trust-anchors',
            json={
                'issuer': 'https://example.com',
                'audience': 'api',
                'static_jwks_pem': 'key'
            },
            headers={'Authorization': f'Bearer {auth_token}'}
        )

        assert response.status_code == 403

    def test_list_oidc_trust_anchors(self, app, client, jwt_token_factory):
        """List OIDC trust anchors."""
        auth_token = jwt_token_factory(global_role='SystemAdmin')

        with app.app_context():
            db = app.db
            db.oidc_trust_anchor.insert(
                issuer='https://k8s.example.com',
                audience='squawk',
                static_jwks_pem='test',
                tenant='default',
                allowed_scopes='users:read'
            )
            db.commit()

        response = client.get(
            '/api/v1/oidc-trust-anchors',
            headers={'Authorization': f'Bearer {auth_token}'}
        )

        assert response.status_code == 200
        data = response.get_json()
        issuers = [a['issuer'] for a in data]
        assert 'https://k8s.example.com' in issuers

    def test_update_oidc_trust_anchor_scopes(self, app, client, jwt_token_factory):
        """Update OIDC trust anchor allowed_scopes."""
        auth_token = jwt_token_factory(global_role='SystemAdmin')

        with app.app_context():
            db = app.db
            db.oidc_trust_anchor.insert(
                issuer='https://k8s.example.com',
                audience='squawk',
                static_jwks_pem='test',
                tenant='default',
                allowed_scopes='users:read',
                active=True
            )
            db.commit()
            anchor = db(db.oidc_trust_anchor.issuer == 'https://k8s.example.com').select().first()
            anchor_id = anchor.id

        response = client.patch(
            f'/api/v1/oidc-trust-anchors/{anchor_id}',
            json={'allowed_scopes': 'users:read servers:read'},
            headers={'Authorization': f'Bearer {auth_token}'}
        )

        assert response.status_code == 200

    def test_delete_oidc_trust_anchor(self, app, client, jwt_token_factory):
        """Delete an OIDC trust anchor."""
        auth_token = jwt_token_factory(global_role='SystemAdmin')

        with app.app_context():
            db = app.db
            db.oidc_trust_anchor.insert(
                issuer='https://k8s.example.com',
                audience='squawk',
                static_jwks_pem='test',
                tenant='default',
                allowed_scopes='users:read',
                active=True
            )
            db.commit()
            anchor = db(db.oidc_trust_anchor.issuer == 'https://k8s.example.com').select().first()
            anchor_id = anchor.id

        response = client.delete(
            f'/api/v1/oidc-trust-anchors/{anchor_id}',
            headers={'Authorization': f'Bearer {auth_token}'}
        )

        assert response.status_code == 200


class TestOIDCTokenExchange:
    """Test OIDC token-exchange grant (Part 2)."""

    def test_token_exchange_with_valid_token(self, app, client, jwt_keypair):
        """Token endpoint accepts valid external OIDC token."""
        # Create trust anchor
        with app.app_context():
            db = app.db
            db.oidc_trust_anchor.insert(
                issuer='https://external-oidc.example.com',
                audience='squawk-api',
                static_jwks_pem=jwt_keypair['public'],  # Use test keypair
                tenant='default',
                allowed_scopes='users:read servers:read',
                subject_pattern='system:serviceaccount:*:*',
                active=True
            )
            db.commit()

        # Create external token with test keypair
        external_payload = {
            'iss': 'https://external-oidc.example.com',
            'aud': 'squawk-api',
            'sub': 'system:serviceaccount:default:my-app',
            'exp': datetime.utcnow() + timedelta(hours=1),
            'iat': datetime.utcnow()
        }
        external_token = jwt.encode(
            external_payload,
            jwt_keypair['private'],
            algorithm='ES256'
        )

        response = client.post(
            '/api/v1/auth/token',
            data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token': external_token,
                'subject_token_type': 'urn:ietf:params:oauth:token-type:jwt'
            }
        )

        assert response.status_code == 200
        data = response.get_json()
        assert 'access_token' in data
        assert data['token_type'] == 'Bearer'

    def test_token_exchange_invalid_issuer(self, app, client, jwt_keypair):
        """Token exchange fails if issuer not in trust anchors."""
        # Create external token with unregistered issuer
        external_payload = {
            'iss': 'https://unknown-issuer.example.com',
            'aud': 'squawk-api',
            'sub': 'system:serviceaccount:default:my-app',
            'exp': datetime.utcnow() + timedelta(hours=1),
            'iat': datetime.utcnow()
        }
        external_token = jwt.encode(
            external_payload,
            jwt_keypair['private'],
            algorithm='ES256'
        )

        response = client.post(
            '/api/v1/auth/token',
            data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token': external_token,
                'subject_token_type': 'urn:ietf:params:oauth:token-type:jwt'
            }
        )

        assert response.status_code == 401
        data = response.get_json()
        assert data['error'] == 'invalid_grant'

    def test_token_exchange_scope_subset(self, app, client, jwt_keypair):
        """Token exchange enforces requested scopes ⊆ allowed_scopes."""
        with app.app_context():
            db = app.db
            db.oidc_trust_anchor.insert(
                issuer='https://external-oidc.example.com',
                audience='squawk-api',
                static_jwks_pem=jwt_keypair['public'],
                tenant='default',
                allowed_scopes='users:read servers:read',
                subject_pattern='*',
                active=True
            )
            db.commit()

        external_payload = {
            'iss': 'https://external-oidc.example.com',
            'aud': 'squawk-api',
            'sub': 'test-subject',
            'exp': datetime.utcnow() + timedelta(hours=1),
            'iat': datetime.utcnow()
        }
        external_token = jwt.encode(
            external_payload,
            jwt_keypair['private'],
            algorithm='ES256'
        )

        # Request subset
        response = client.post(
            '/api/v1/auth/token',
            data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token': external_token,
                'subject_token_type': 'urn:ietf:params:oauth:token-type:jwt',
                'scope': 'users:read'
            }
        )

        assert response.status_code == 200

        # Request exceeds allowed
        response = client.post(
            '/api/v1/auth/token',
            data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token': external_token,
                'subject_token_type': 'urn:ietf:params:oauth:token-type:jwt',
                'scope': 'users:admin'
            }
        )

        assert response.status_code == 400

    def test_token_exchange_subject_pattern_mismatch(self, app, client, jwt_keypair):
        """Token exchange fails if subject doesn't match pattern."""
        with app.app_context():
            db = app.db
            db.oidc_trust_anchor.insert(
                issuer='https://external-oidc.example.com',
                audience='squawk-api',
                static_jwks_pem=jwt_keypair['public'],
                tenant='default',
                allowed_scopes='users:read',
                subject_pattern='system:serviceaccount:*:*',  # Strict pattern
                active=True
            )
            db.commit()

        # Create token with non-matching subject
        external_payload = {
            'iss': 'https://external-oidc.example.com',
            'aud': 'squawk-api',
            'sub': 'invalid-subject',  # Doesn't match pattern
            'exp': datetime.utcnow() + timedelta(hours=1),
            'iat': datetime.utcnow()
        }
        external_token = jwt.encode(
            external_payload,
            jwt_keypair['private'],
            algorithm='ES256'
        )

        response = client.post(
            '/api/v1/auth/token',
            data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token': external_token,
                'subject_token_type': 'urn:ietf:params:oauth:token-type:jwt'
            }
        )

        assert response.status_code == 401
        data = response.get_json()
        assert data['error'] == 'invalid_grant'
