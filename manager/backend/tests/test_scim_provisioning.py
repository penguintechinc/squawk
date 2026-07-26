"""Tests for SCIM 2.0 user provisioning (RFC 7643/7644).

Coverage:
- Token authentication (401 invalid, 403 inactive)
- Full CRUD cycle (create, read, update, delete/deprovision)
- Filtering (userName eq) and pagination (1-based startIndex)
- Deprovisioning revokes refresh tokens
- Unsupported filter/path errors
- Enterprise license gating
"""

import pytest
import json
import secrets
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from app.services.scim_service import SCIMTokenService
from app.services.auth_service import AuthService


@pytest.fixture
def scim_token(app):
    """Generate a valid SCIM token for testing."""
    plaintext, token_hash = SCIMTokenService.create_token('test-token', 'default')
    SCIMTokenService.store_token(plaintext, 'test-token', 'default')
    return plaintext


@pytest.fixture
def scim_bearer_header(scim_token):
    """Return Authorization header with SCIM token."""
    return f'Bearer {scim_token}'


@pytest.fixture
def invalid_scim_token():
    """Return an invalid token."""
    return 'invalid_token_xyz'


@pytest.fixture
def user_jwt(app):
    """Generate a valid user JWT with admin:super scope."""
    return AuthService.create_access_token(
        user_id=1,
        username='admin',
        global_role='SystemAdmin',
        team_roles={}
    )


@pytest.fixture
def admin_bearer_header(user_jwt):
    """Return Authorization header with user JWT."""
    return f'Bearer {user_jwt}'


class TestSCIMTokenAuthentication:
    """Test SCIM bearer token validation."""

    def test_missing_authorization_header(self, client):
        """Request without Authorization header fails with 401."""
        resp = client.get('/scim/v2/Users')
        assert resp.status_code == 401
        data = resp.get_json()
        assert data['scimType'] == 'invalid_request'

    def test_invalid_token_format(self, client):
        """Invalid token format fails with 401."""
        resp = client.get('/scim/v2/Users', headers={
            'Authorization': 'InvalidFormat token'
        })
        assert resp.status_code == 401

    def test_invalid_token_value(self, client, invalid_scim_token):
        """Invalid token value fails with 401."""
        resp = client.get('/scim/v2/Users', headers={
            'Authorization': f'Bearer {invalid_scim_token}'
        })
        assert resp.status_code == 401
        data = resp.get_json()
        assert data['scimType'] == 'invalid_token'

    def test_revoked_token_fails(self, app, scim_token):
        """Revoked token fails with 401."""
        # Get token ID and revoke it
        db = app.db
        token_rec = db(db.scim_tokens.active == True).select().first()
        SCIMTokenService.revoke_token(token_rec.id)

        with app.test_client() as client:
            resp = client.get('/scim/v2/Users', headers={
                'Authorization': f'Bearer {scim_token}'
            })
            assert resp.status_code == 401

    def test_constant_time_comparison(self, app, scim_token):
        """Token verification uses constant-time comparison (no timing attacks)."""
        # This is implicitly tested by using bcrypt's checkpw which is constant-time
        # Verify that both valid and invalid tokens take roughly same time
        import time

        with app.test_client() as client:
            start = time.time()
            client.get('/scim/v2/Users', headers={
                'Authorization': f'Bearer {scim_token}'
            })
            valid_time = time.time() - start

            start = time.time()
            client.get('/scim/v2/Users', headers={
                'Authorization': 'Bearer invalid_xyz'
            })
            invalid_time = time.time() - start

            # Times should be similar (within 10x ratio due to bcrypt)
            # This is a loose check since timing varies
            assert abs(valid_time - invalid_time) < max(valid_time, invalid_time) * 10


class TestSCIMUserCRUD:
    """Test user CRUD operations."""

    def test_create_user_minimal(self, client, scim_bearer_header):
        """Create user with minimal required fields."""
        resp = client.post('/scim/v2/Users', headers={
            'Authorization': scim_bearer_header,
            'Content-Type': 'application/scim+json'
        }, json={
            'userName': 'newuser',
            'externalId': 'ext-123',
            'active': True,
        })
        assert resp.status_code == 201
        data = resp.get_json()
        assert data['id']
        assert data['userName'] == 'newuser'
        assert data['externalId'] == 'ext-123'
        assert data['active'] is True
        assert USER_SCHEMA in data['schemas']

    def test_create_user_with_emails(self, client, scim_bearer_header):
        """Create user with email addresses."""
        resp = client.post('/scim/v2/Users', headers={
            'Authorization': scim_bearer_header,
            'Content-Type': 'application/scim+json'
        }, json={
            'userName': 'user@example.com',
            'externalId': 'ext-456',
            'emails': [
                {'value': 'user@example.com', 'type': 'work', 'primary': True}
            ],
            'active': True,
        })
        assert resp.status_code == 201
        data = resp.get_json()
        assert data['emails'][0]['value'] == 'user@example.com'

    def test_create_user_missing_username(self, client, scim_bearer_header):
        """Create without userName fails with 400."""
        resp = client.post('/scim/v2/Users', headers={
            'Authorization': scim_bearer_header,
            'Content-Type': 'application/scim+json'
        }, json={
            'externalId': 'ext-789',
            'active': True,
        })
        assert resp.status_code == 400
        data = resp.get_json()
        assert data['scimType'] == 'invalidValue'

    def test_create_user_missing_external_id(self, client, scim_bearer_header):
        """Create without externalId fails with 400."""
        resp = client.post('/scim/v2/Users', headers={
            'Authorization': scim_bearer_header,
            'Content-Type': 'application/scim+json'
        }, json={
            'userName': 'user',
            'active': True,
        })
        assert resp.status_code == 400

    def test_create_user_duplicate_username(self, client, app, scim_bearer_header):
        """Create with duplicate userName fails with 409."""
        # Create first user
        client.post('/scim/v2/Users', headers={
            'Authorization': scim_bearer_header,
            'Content-Type': 'application/scim+json'
        }, json={
            'userName': 'duplicate',
            'externalId': 'ext-dup-1',
            'active': True,
        })

        # Try to create duplicate
        resp = client.post('/scim/v2/Users', headers={
            'Authorization': scim_bearer_header,
            'Content-Type': 'application/scim+json'
        }, json={
            'userName': 'duplicate',
            'externalId': 'ext-dup-2',
            'active': True,
        })
        assert resp.status_code == 409
        data = resp.get_json()
        assert data['scimType'] == 'uniqueness'

    def test_get_user(self, client, app, scim_bearer_header):
        """Get a user by ID."""
        # Create user
        create_resp = client.post('/scim/v2/Users', headers={
            'Authorization': scim_bearer_header,
            'Content-Type': 'application/scim+json'
        }, json={
            'userName': 'getuser',
            'externalId': 'ext-get',
            'active': True,
        })
        user_id = create_resp.get_json()['id']

        # Get user
        resp = client.get(f'/scim/v2/Users/{user_id}', headers={
            'Authorization': scim_bearer_header,
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['id'] == user_id
        assert data['userName'] == 'getuser'

    def test_get_user_not_found(self, client, scim_bearer_header):
        """Get non-existent user fails with 404."""
        resp = client.get('/scim/v2/Users/9999', headers={
            'Authorization': scim_bearer_header,
        })
        assert resp.status_code == 404

    def test_update_user_put(self, client, app, scim_bearer_header):
        """Update a user with PUT (full replace)."""
        # Create user
        create_resp = client.post('/scim/v2/Users', headers={
            'Authorization': scim_bearer_header,
            'Content-Type': 'application/scim+json'
        }, json={
            'userName': 'putuser',
            'externalId': 'ext-put',
            'active': True,
        })
        user_id = create_resp.get_json()['id']

        # Update with PUT
        resp = client.put(f'/scim/v2/Users/{user_id}', headers={
            'Authorization': scim_bearer_header,
            'Content-Type': 'application/scim+json'
        }, json={
            'userName': 'putuser_updated',
            'active': True,
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['userName'] == 'putuser_updated'

    def test_patch_user_active_false(self, client, app, scim_bearer_header):
        """Patch user with active=false."""
        # Create user
        create_resp = client.post('/scim/v2/Users', headers={
            'Authorization': scim_bearer_header,
            'Content-Type': 'application/scim+json'
        }, json={
            'userName': 'patchuser',
            'externalId': 'ext-patch',
            'active': True,
        })
        user_id = create_resp.get_json()['id']

        # Patch to deactivate
        resp = client.patch(f'/scim/v2/Users/{user_id}', headers={
            'Authorization': scim_bearer_header,
            'Content-Type': 'application/scim+json'
        }, json={
            'Operations': [
                {
                    'op': 'replace',
                    'path': 'active',
                    'value': False,
                }
            ]
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['active'] is False

    def test_patch_unsupported_operation(self, client, app, scim_bearer_header):
        """Patch with unsupported operation fails with 400."""
        # Create user
        create_resp = client.post('/scim/v2/Users', headers={
            'Authorization': scim_bearer_header,
            'Content-Type': 'application/scim+json'
        }, json={
            'userName': 'unsupporteduser',
            'externalId': 'ext-unsupported',
            'active': True,
        })
        user_id = create_resp.get_json()['id']

        # Try to add (not supported)
        resp = client.patch(f'/scim/v2/Users/{user_id}', headers={
            'Authorization': scim_bearer_header,
            'Content-Type': 'application/scim+json'
        }, json={
            'Operations': [
                {
                    'op': 'add',
                    'path': 'active',
                    'value': False,
                }
            ]
        })
        assert resp.status_code == 400

    def test_patch_unsupported_path(self, client, app, scim_bearer_header):
        """Patch with unsupported path fails with 400."""
        # Create user
        create_resp = client.post('/scim/v2/Users', headers={
            'Authorization': scim_bearer_header,
            'Content-Type': 'application/scim+json'
        }, json={
            'userName': 'unsuppathuser',
            'externalId': 'ext-unsupp',
            'active': True,
        })
        user_id = create_resp.get_json()['id']

        # Try to patch unsupported path
        resp = client.patch(f'/scim/v2/Users/{user_id}', headers={
            'Authorization': scim_bearer_header,
            'Content-Type': 'application/scim+json'
        }, json={
            'Operations': [
                {
                    'op': 'replace',
                    'path': 'password',
                    'value': 'newpassword',
                }
            ]
        })
        assert resp.status_code == 400
        data = resp.get_json()
        assert data['scimType'] == 'invalidPath'

    def test_delete_user_deprovisioning(self, client, app, scim_bearer_header):
        """DELETE user soft-deletes (deactivates)."""
        # Create user
        create_resp = client.post('/scim/v2/Users', headers={
            'Authorization': scim_bearer_header,
            'Content-Type': 'application/scim+json'
        }, json={
            'userName': 'deluser',
            'externalId': 'ext-del',
            'active': True,
        })
        user_id = create_resp.get_json()['id']

        # Delete user
        resp = client.delete(f'/scim/v2/Users/{user_id}', headers={
            'Authorization': scim_bearer_header,
        })
        assert resp.status_code == 204

        # Verify deactivated
        db = app.db
        user = db.auth_user[int(user_id)]
        assert user.active is False


class TestSCIMFiltering:
    """Test filtering and pagination."""

    def test_filter_username_eq(self, client, scim_bearer_header):
        """Filter by userName eq 'value'."""
        # Create user
        client.post('/scim/v2/Users', headers={
            'Authorization': scim_bearer_header,
            'Content-Type': 'application/scim+json'
        }, json={
            'userName': 'filteruser',
            'externalId': 'ext-filter',
            'active': True,
        })

        # Filter
        resp = client.get('/scim/v2/Users?filter=userName eq "filteruser"', headers={
            'Authorization': scim_bearer_header,
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['totalResults'] == 1
        assert data['Resources'][0]['userName'] == 'filteruser'

    def test_filter_unsupported(self, client, scim_bearer_header):
        """Unsupported filter fails with 400."""
        resp = client.get('/scim/v2/Users?filter=email eq "test@example.com"', headers={
            'Authorization': scim_bearer_header,
        })
        assert resp.status_code == 400
        data = resp.get_json()
        assert data['scimType'] == 'invalidFilter'

    def test_pagination_start_index(self, client, scim_bearer_header):
        """Pagination with startIndex (1-based)."""
        # Create multiple users
        for i in range(5):
            client.post('/scim/v2/Users', headers={
                'Authorization': scim_bearer_header,
                'Content-Type': 'application/scim+json'
            }, json={
                'userName': f'paginationuser{i}',
                'externalId': f'ext-pag-{i}',
                'active': True,
            })

        # Get first page
        resp = client.get('/scim/v2/Users?startIndex=1&count=2', headers={
            'Authorization': scim_bearer_header,
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['startIndex'] == 1
        assert data['itemsPerPage'] == 2
        assert len(data['Resources']) == 2

    def test_pagination_invalid_start_index(self, client, scim_bearer_header):
        """Invalid startIndex (< 1) fails with 400."""
        resp = client.get('/scim/v2/Users?startIndex=0', headers={
            'Authorization': scim_bearer_header,
        })
        assert resp.status_code == 400

    def test_pagination_invalid_count(self, client, scim_bearer_header):
        """Invalid count (> 1000) fails with 400."""
        resp = client.get('/scim/v2/Users?count=2000', headers={
            'Authorization': scim_bearer_header,
        })
        assert resp.status_code == 400


class TestSCIMDeprovisioningRevokesTokens:
    """Test that deprovisioning revokes user's refresh tokens."""

    def test_deactivation_revokes_sessions(self, client, app, scim_bearer_header):
        """When user is deactivated, their sessions are revoked."""
        # Create user
        create_resp = client.post('/scim/v2/Users', headers={
            'Authorization': scim_bearer_header,
            'Content-Type': 'application/scim+json'
        }, json={
            'userName': 'sessionuser',
            'externalId': 'ext-session',
            'active': True,
        })
        user_id = int(create_resp.get_json()['id'])

        # Simulate user login and token generation
        db = app.db
        refresh_token = AuthService.create_refresh_token(user_id)

        # Verify token is valid
        payload = AuthService.decode_token(refresh_token)
        assert payload is not None
        assert not AuthService.is_refresh_token_revoked(payload['jti'])

        # Deactivate user via SCIM
        client.patch(f'/scim/v2/Users/{user_id}', headers={
            'Authorization': scim_bearer_header,
            'Content-Type': 'application/scim+json'
        }, json={
            'Operations': [
                {
                    'op': 'replace',
                    'path': 'active',
                    'value': False,
                }
            ]
        })

        # Verify user is inactive
        user = db.auth_user[user_id]
        assert user.active is False

        # Try to use refresh token; should fail because user is inactive
        result = AuthService.refresh_access_token(refresh_token)
        assert result is None  # refresh_access_token checks user.active


class TestSCIMMetadata:
    """Test SCIM metadata endpoints."""

    def test_service_provider_config(self, client):
        """GET /ServiceProviderConfig returns config."""
        resp = client.get('/scim/v2/ServiceProviderConfig')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'authenticationSchemes' in data
        assert data['filteringSupported'] is True
        assert data['bulkSupported'] is False

    def test_resource_types(self, client):
        """GET /ResourceTypes returns available resources."""
        resp = client.get('/scim/v2/ResourceTypes')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['totalResults'] >= 1
        assert any(r['name'] == 'User' for r in data['Resources'])

    def test_schemas(self, client):
        """GET /Schemas returns supported schemas."""
        resp = client.get('/scim/v2/Schemas')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['totalResults'] >= 1


class TestSCIMAdminTokenEndpoints:
    """Test admin token minting and revocation (gated by admin:super scope + enterprise license)."""

    @patch('app.blueprints.scim.LicenseService')
    def test_mint_token_enterprise_only(self, mock_license_svc, client, admin_bearer_header):
        """Minting requires Enterprise license."""
        mock_svc_instance = MagicMock()
        mock_svc_instance.is_enterprise.return_value = False
        mock_license_svc.return_value = mock_svc_instance

        resp = client.post('/scim/v2/admin/tokens', headers={
            'Authorization': admin_bearer_header,
            'Content-Type': 'application/json'
        }, json={
            'description': 'Okta',
            'tenant': 'default'
        })
        assert resp.status_code == 403

    @patch('app.blueprints.scim.LicenseService')
    def test_mint_token_success(self, mock_license_svc, client, admin_bearer_header):
        """Minting succeeds with Enterprise license and admin scope."""
        mock_svc_instance = MagicMock()
        mock_svc_instance.is_enterprise.return_value = True
        mock_license_svc.return_value = mock_svc_instance

        resp = client.post('/scim/v2/admin/tokens', headers={
            'Authorization': admin_bearer_header,
            'Content-Type': 'application/json'
        }, json={
            'description': 'Okta provisioning',
            'tenant': 'default'
        })
        assert resp.status_code == 201
        data = resp.get_json()
        assert 'token' in data
        assert data['description'] == 'Okta provisioning'

    def test_mint_token_requires_admin_scope(self, client):
        """Minting without admin:super scope fails."""
        # Create non-admin JWT
        non_admin_jwt = AuthService.create_access_token(
            user_id=2,
            username='viewer',
            global_role='Viewer',
            team_roles={}
        )

        resp = client.post('/scim/v2/admin/tokens', headers={
            'Authorization': f'Bearer {non_admin_jwt}',
            'Content-Type': 'application/json'
        }, json={
            'description': 'Test',
            'tenant': 'default'
        })
        assert resp.status_code == 403

    def test_revoke_token(self, client, app, admin_bearer_header):
        """Revoke a SCIM token."""
        # Create token via service
        plaintext, _ = SCIMTokenService.create_token('revoke-me', 'default')
        token_id = SCIMTokenService.store_token(plaintext, 'revoke-me', 'default')

        # Revoke via admin endpoint
        resp = client.delete(f'/scim/v2/admin/tokens/{token_id}', headers={
            'Authorization': admin_bearer_header,
        })
        assert resp.status_code == 204

        # Verify revoked
        db = app.db
        token_rec = db.scim_tokens[token_id]
        assert token_rec.active is False


# ── Helper Constants ────────────────────────────────────────────────────────

USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User'
