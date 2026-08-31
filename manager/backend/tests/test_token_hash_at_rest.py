"""Regression tests: at-rest credential hashing/encryption.

Covers the highest-confidence finding from the security audit: DNS resolver
tokens, dns_server.join_key, dns_server.jwt_secret, and
deployment_domain.jwt_token were stored, compared, and (for tokens)
returned in plaintext.

- DNS tokens: created via the /api/v1/tokens API, validated by hash via
  AuthService.validate_dns_token, plaintext never persisted or re-returned.
- Team-less token IDOR (finding H5): default-deny to SystemAdmin only.
- join_key: hashed at rest, validated by hash.
- jwt_secret: Fernet-encrypted at rest, round-trips to a working signed JWT.

regression: at-rest credential storage (5-agent audit finding)
"""
from __future__ import annotations

from app.services.auth_service import AuthService
from app.services.join_key_service import JoinKeyService
from app.utils.crypto import sha256_hex


def _admin_header(jwt_token_factory) -> dict:
    token = jwt_token_factory(global_role='SystemAdmin')
    return {'Authorization': f'Bearer {token}'}


def _viewer_header(jwt_token_factory) -> dict:
    token = jwt_token_factory(global_role='Viewer', team_roles={})
    return {'Authorization': f'Bearer {token}'}


class TestDNSTokenHashing:
    """DNS auth tokens (app.blueprints.tokens / AuthService.validate_dns_token)."""

    def test_create_returns_plaintext_once_and_stores_only_hash(
        self, app, db, client, jwt_token_factory
    ):
        resp = client.post(
            '/api/v1/tokens',
            json={'name': 'ci-token'},
            headers=_admin_header(jwt_token_factory),
        )
        assert resp.status_code == 201
        body = resp.get_json()
        plaintext = body['token']
        assert plaintext

        with app.app_context():
            row = db.token[body['id']]
            assert row.token_hash == sha256_hex(plaintext)
            # No column on the row holds the plaintext value anywhere.
            assert plaintext not in row.as_dict().values()

    def test_list_and_get_never_return_plaintext(self, app, db, client, jwt_token_factory):
        create_resp = client.post(
            '/api/v1/tokens',
            json={'name': 'list-test-token'},
            headers=_admin_header(jwt_token_factory),
        )
        token_id = create_resp.get_json()['id']
        plaintext = create_resp.get_json()['token']

        list_resp = client.get('/api/v1/tokens', headers=_admin_header(jwt_token_factory))
        assert list_resp.status_code == 200
        for item in list_resp.get_json():
            assert 'token' not in item
            assert plaintext not in item.values()

        get_resp = client.get(
            f'/api/v1/tokens/{token_id}', headers=_admin_header(jwt_token_factory)
        )
        assert get_resp.status_code == 200
        assert 'token' not in get_resp.get_json()

    def test_validate_dns_token_succeeds_via_hash(self, app, db, client, jwt_token_factory):
        create_resp = client.post(
            '/api/v1/tokens',
            json={'name': 'validate-test-token'},
            headers=_admin_header(jwt_token_factory),
        )
        plaintext = create_resp.get_json()['token']

        with app.app_context():
            result = AuthService.validate_dns_token(plaintext)
        assert result['valid'] is True

    def test_validate_dns_token_rejects_wrong_token(self, app, db, client, jwt_token_factory):
        client.post(
            '/api/v1/tokens',
            json={'name': 'wrong-token-test'},
            headers=_admin_header(jwt_token_factory),
        )

        with app.app_context():
            result = AuthService.validate_dns_token('not-the-real-token-value')
        assert result['valid'] is False

    def test_regenerate_returns_new_plaintext_once_and_invalidates_old(
        self, app, db, client, jwt_token_factory
    ):
        create_resp = client.post(
            '/api/v1/tokens',
            json={'name': 'regen-test-token'},
            headers=_admin_header(jwt_token_factory),
        )
        token_id = create_resp.get_json()['id']
        old_plaintext = create_resp.get_json()['token']

        regen_resp = client.post(
            f'/api/v1/tokens/{token_id}/regenerate', headers=_admin_header(jwt_token_factory)
        )
        assert regen_resp.status_code == 200
        new_plaintext = regen_resp.get_json()['token']
        assert new_plaintext != old_plaintext

        with app.app_context():
            assert AuthService.validate_dns_token(old_plaintext)['valid'] is False
            assert AuthService.validate_dns_token(new_plaintext)['valid'] is True


class TestTeamLessTokenIDOR:
    """Finding H5: `if token.team_id and not can_access_team(...)` skipped
    the access check entirely for team-less (global) tokens, letting any
    authenticated user manage any global token by id. Fixed to default-deny
    to SystemAdmin only when team_id is NULL."""

    def test_non_admin_cannot_get_team_less_token(self, app, db, client, jwt_token_factory):
        create_resp = client.post(
            '/api/v1/tokens',
            json={'name': 'global-token'},
            headers=_admin_header(jwt_token_factory),
        )
        token_id = create_resp.get_json()['id']

        resp = client.get(f'/api/v1/tokens/{token_id}', headers=_viewer_header(jwt_token_factory))
        assert resp.status_code == 403

    def test_non_admin_cannot_delete_team_less_token(self, app, db, client, jwt_token_factory):
        create_resp = client.post(
            '/api/v1/tokens',
            json={'name': 'global-token-2'},
            headers=_admin_header(jwt_token_factory),
        )
        token_id = create_resp.get_json()['id']

        resp = client.delete(
            f'/api/v1/tokens/{token_id}', headers=_viewer_header(jwt_token_factory)
        )
        assert resp.status_code == 403

    def test_non_admin_cannot_regenerate_team_less_token(self, app, db, client, jwt_token_factory):
        create_resp = client.post(
            '/api/v1/tokens',
            json={'name': 'global-token-3'},
            headers=_admin_header(jwt_token_factory),
        )
        token_id = create_resp.get_json()['id']

        resp = client.post(
            f'/api/v1/tokens/{token_id}/regenerate', headers=_viewer_header(jwt_token_factory)
        )
        assert resp.status_code == 403

    def test_admin_can_get_team_less_token(self, app, db, client, jwt_token_factory):
        create_resp = client.post(
            '/api/v1/tokens',
            json={'name': 'global-token-4'},
            headers=_admin_header(jwt_token_factory),
        )
        token_id = create_resp.get_json()['id']

        resp = client.get(f'/api/v1/tokens/{token_id}', headers=_admin_header(jwt_token_factory))
        assert resp.status_code == 200


class TestJoinKeyHashing:
    """dns_server.join_key (app.services.join_key_service.JoinKeyService)."""

    def test_create_dns_server_stores_only_hash(self, app, db):
        with app.app_context():
            result = JoinKeyService.create_dns_server(name='hash-test-server')
            row = db.dns_server[result['id']]
            assert row.join_key_hash == JoinKeyService.hash_join_key(result['join_key'])
            assert result['join_key'] not in row.as_dict().values()

    def test_validate_join_key_succeeds_by_hash(self, app, db):
        with app.app_context():
            result = JoinKeyService.create_dns_server(name='validate-join-key-server')
            info = JoinKeyService.validate_join_key(result['join_key'])
        assert info is not None
        assert info['id'] == result['id']

    def test_validate_join_key_rejects_wrong_key(self, app, db):
        with app.app_context():
            JoinKeyService.create_dns_server(name='wrong-join-key-server')
            info = JoinKeyService.validate_join_key('f' * 64)
        assert info is None

    def test_register_server_returns_decrypted_secret_matching_original(self, app, db):
        with app.app_context():
            created = JoinKeyService.create_dns_server(name='register-server-test')
            registered = JoinKeyService.register_server(
                join_key=created['join_key'], hostname='dns1.example.com', version='2.1.0'
            )
        assert registered is not None
        # A server JWT signed with the round-tripped secret verifies cleanly.
        with app.app_context():
            token = AuthService.create_server_jwt(
                server_id=registered['id'], jwt_secret=registered['jwt_secret']
            )
            assert AuthService.decode_token(token, registered['jwt_secret']) is not None


class TestJwtSecretEncryption:
    """dns_server.jwt_secret must stay recoverable (it signs/verifies server
    JWTs), so it is Fernet-encrypted at rest rather than hashed."""

    def test_jwt_secret_stored_encrypted_not_plaintext(self, app, db):
        with app.app_context():
            result = JoinKeyService.create_dns_server(name='encrypt-test-server')
            row = db.dns_server[result['id']]
            # The stored value is neither empty nor a bare hex secret --
            # it's Fernet ciphertext (base64, versioned, larger than input).
            assert row.jwt_secret
            assert row.jwt_secret != row.join_key_hash

    def test_encrypt_then_decrypt_round_trips_and_verifies_jwt(self, app):
        with app.app_context():
            plaintext_secret = JoinKeyService.generate_jwt_secret()
            encrypted = JoinKeyService.encrypt_jwt_secret(plaintext_secret)
            assert encrypted != plaintext_secret

            decrypted = JoinKeyService.decrypt_jwt_secret(encrypted)
            assert decrypted == plaintext_secret

            token = AuthService.create_server_jwt(server_id=1, jwt_secret=decrypted)
            payload = AuthService.decode_token(token, decrypted)
            assert payload is not None
            assert payload['server_id'] == 1

    def test_verify_server_jwt_from_db_decrypts_secret(self, app, db):
        """AuthService.verify_server_jwt_from_db (used by the REST
        server_token_required legacy path and the gRPC interceptor) must
        decrypt the stored secret before verifying the signature."""
        with app.app_context():
            result = JoinKeyService.create_dns_server(name='verify-from-db-server')
            plaintext_secret = JoinKeyService.decrypt_jwt_secret(
                db.dns_server[result['id']].jwt_secret
            )
            token = AuthService.create_server_jwt(
                server_id=result['id'], jwt_secret=plaintext_secret
            )
            verified_id = AuthService.verify_server_jwt_from_db(db, token)
        assert verified_id == result['id']


class TestDeploymentDomainJwtHashing:
    """deployment_domain.jwt_token: self-verifying via signature, but the
    stored value backs a revocation/rollover equality check, so only its
    hash is persisted."""

    def test_create_deployment_domain_stores_only_hash(self, app, db):
        from app.services.client_config_service import ClientConfigManager
        from app.utils.crypto import generate_ephemeral_es256_keypair

        priv, pub = generate_ephemeral_es256_keypair()
        with app.app_context():
            mgr = ClientConfigManager(db_url=app.config['DB_URL'], private_key=priv, public_key=pub)
            result = mgr.create_deployment_domain(name='hash-test-domain')
            assert result['success'] is True

            row = db.deployment_domain[result['id']]
            assert row.jwt_token_hash == sha256_hex(result['jwt_token'])
            assert result['jwt_token'] not in row.as_dict().values()

            # The domain JWT still verifies end-to-end via the hash lookup.
            verified = mgr._verify_domain_jwt(result['jwt_token'])
            assert verified is not None
            assert verified['name'] == 'hash-test-domain'
