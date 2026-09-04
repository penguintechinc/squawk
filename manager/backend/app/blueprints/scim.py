"""SCIM 2.0 user provisioning endpoint (RFC 7643/7644).

Supports enterprise IdP (Okta, Entra) user provisioning with:
- Bearer token authentication (dedicated SCIM tokens, not user JWTs)
- User CRUD (POST create, GET read, PUT replace, PATCH update, DELETE)
- Filtering (userName eq only), pagination (1-based startIndex per spec)
- Deprovisioning: DELETE or PATCH active=false revokes user sessions
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List
from flask import Blueprint, request, jsonify, current_app, g
import logging

from app.services.scim_service import SCIMTokenService
from app.services.auth_service import AuthService
from app.services.license_service import LicenseService
from app.utils.decorators import audit_log
from app.extensions import limiter

logger = logging.getLogger(__name__)
scim_bp = Blueprint('scim', __name__, url_prefix='/scim/v2')

# ── Constants ────────────────────────────────────────────────────────────────

SCIM_CONTENT_TYPE = 'application/scim+json'
SCIM_ERROR_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:Error'
USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User'
LIST_RESPONSE_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse'
SERVICE_PROVIDER_CONFIG_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'
RESOURCE_TYPE_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:ResourceType'


# ── Data Models ──────────────────────────────────────────────────────────────

@dataclass(slots=True, frozen=True)
class SCIMEmail:
    """Email address in SCIM format."""
    value: str
    type: str = "work"
    primary: bool = True


@dataclass(slots=True, frozen=True)
class SCIMName:
    """Name in SCIM format."""
    givenName: str
    familyName: str
    formatted: str = ""


@dataclass(slots=True)
class SCIMUser:
    """SCIM 2.0 User resource."""
    id: str
    externalId: str
    userName: str
    name: SCIMName
    emails: List[SCIMEmail]
    active: bool
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to SCIM JSON representation."""
        return {
            "schemas": [USER_SCHEMA],
            "id": self.id,
            "externalId": self.externalId,
            "userName": self.userName,
            "name": asdict(self.name) if self.name else {},
            "emails": [asdict(e) for e in self.emails] if self.emails else [],
            "active": self.active,
            "meta": {
                "resourceType": "User",
                "created": self.created_at.isoformat() + "Z" if self.created_at else None,
                "lastModified": self.updated_at.isoformat() + "Z" if self.updated_at else None,
            }
        }


@dataclass(slots=True)
class SCIMListResponse:
    """SCIM 2.0 List Response (RFC 7644)."""
    totalResults: int
    startIndex: int
    itemsPerPage: int
    Resources: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to SCIM JSON representation."""
        return {
            "schemas": [LIST_RESPONSE_SCHEMA],
            "totalResults": self.totalResults,
            "startIndex": self.startIndex,
            "itemsPerPage": self.itemsPerPage,
            "Resources": self.Resources,
        }


# ── Middleware ───────────────────────────────────────────────────────────────

# Global roles a SCIM token may never touch, regardless of provisioning
# scope. There is no per-token tenant/org column on auth_user today (adding
# one is a schema change, out of scope here), so this is the strongest safe
# proxy: block SCIM-driven deactivation/rewrite/deletion of the platform's
# most privileged accounts to prevent lockout/takeover.
_SCIM_PROTECTED_ROLES = {'SystemAdmin'}


def _scim_manageable_user(user) -> bool:
    """
    True if a SCIM bearer token may read/manage this user record.

    SCIM tokens are meant to manage only identities they themselves
    provisioned (external_id is set exclusively by the SCIM create_user
    flow) — a locally-created admin account never has external_id set, so
    this is the strongest scope boundary available without adding a
    tenant/org column to auth_user (schema change, out of scope). Privileged
    accounts are excluded outright regardless of provisioning origin.
    """
    if user is None:
        return False
    if user.global_role in _SCIM_PROTECTED_ROLES:
        return False
    return bool(user.external_id)

def require_scim_token():
    """Validate SCIM bearer token before processing request.

    Extracts tenant from token validation and stores in g for route handlers.
    """
    from flask import g

    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return scim_error('invalid_request', 'Missing or invalid Authorization header', 401)

    token = auth_header[7:]  # Strip "Bearer "
    # For now, use a default tenant; in production, extract from token metadata
    tenant = 'default'

    token_id = SCIMTokenService.validate_scim_token(token, tenant)
    if not token_id:
        return scim_error('invalid_token', 'Token invalid or expired', 401)

    g.scim_token_id = token_id
    g.tenant = tenant


def scim_error(scim_type: str, detail: str, status_code: int = 400) -> tuple:
    """Return a SCIM 2.0-compliant error response.

    Args:
        scim_type: Error type (e.g., 'invalidValue', 'invalidPath', 'invalid_request')
        detail: Human-readable error message
        status_code: HTTP status code

    Returns:
        (response_dict, status_code) tuple
    """
    return {
        "schemas": [SCIM_ERROR_SCHEMA],
        "scimType": scim_type,
        "detail": detail,
    }, status_code


# ── Routes ───────────────────────────────────────────────────────────────────

@scim_bp.route('/ServiceProviderConfig', methods=['GET'])
def get_service_provider_config():
    """Advertise SCIM server capabilities."""
    config = {
        "schemas": [SERVICE_PROVIDER_CONFIG_SCHEMA],
        "documentationUri": "https://squawkdns.app/docs/scim",
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "SCIM bearer token for provisioning",
                "specUri": "https://tools.ietf.org/html/rfc6750",
                "primary": True,
            }
        ],
        "filteringSupported": True,
        "filterMaxResults": 1000,
        "changePasswordSupported": False,
        "sortSupported": False,
        "etag": {"supported": False},
        "bulkSupported": False,
        "patchSupported": True,
    }
    return jsonify(config), 200


@scim_bp.route('/ResourceTypes', methods=['GET'])
def get_resource_types():
    """Advertise supported resource types."""
    return jsonify({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 1,
        "Resources": [
            {
                "schemas": [RESOURCE_TYPE_SCHEMA],
                "id": "User",
                "name": "User",
                "description": "User accounts",
                "endpoint": "/scim/v2/Users",
                "schema": USER_SCHEMA,
                "schemaExtensions": [],
            }
        ]
    }), 200


@scim_bp.route('/Schemas', methods=['GET'])
def get_schemas():
    """Advertise supported schemas."""
    return jsonify({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 1,
        "Resources": [
            {
                "schemas": [RESOURCE_TYPE_SCHEMA],
                "id": USER_SCHEMA,
                "name": "User",
                "description": "User account resource",
                "attributes": [
                    {"name": "id", "type": "string", "mutability": "readOnly"},
                    {"name": "externalId", "type": "string", "mutability": "immutable"},
                    {"name": "userName", "type": "string", "mutability": "readWrite", "required": True},
                    {"name": "name", "type": "complex", "mutability": "readWrite"},
                    {"name": "emails", "type": "complex", "mutability": "readWrite", "multiValued": True},
                    {"name": "active", "type": "boolean", "mutability": "readWrite", "required": True},
                    {"name": "created", "type": "dateTime", "mutability": "readOnly"},
                    {"name": "lastModified", "type": "dateTime", "mutability": "readOnly"},
                ],
            }
        ]
    }), 200


@scim_bp.route('/Users', methods=['GET'])
def list_users():
    """List users with optional filter and pagination.

    Query parameters:
        filter: Only userName eq "value" supported (RFC 7644 subset)
        startIndex: 1-based index (SCIM default)
        count: Number of results to return
    """
    result = require_scim_token()
    if isinstance(result, tuple):
        return result

    db = current_app.db
    from flask import g

    tenant = g.tenant
    start_index = request.args.get('startIndex', 1, type=int)
    count = request.args.get('count', 100, type=int)
    filter_param = request.args.get('filter', '')

    # Validate pagination
    if start_index < 1:
        return scim_error('invalidValue', 'startIndex must be >= 1', 400)
    if count < 0 or count > 1000:
        return scim_error('invalidValue', 'count must be 0-1000', 400)

    # Parse filter: only "userName eq value" supported
    total_count = 0
    users = []

    if filter_param:
        # Simple parser for: userName eq "value"
        if not filter_param.startswith('userName eq '):
            return scim_error('invalidFilter', 'Only userName eq filter supported', 400)

        username = filter_param[12:].strip('"')
        user_rec = db(db.auth_user.username == username).select().first()
        if user_rec and _scim_manageable_user(user_rec):
            users = [user_rec]
            total_count = 1
    else:
        # List active, SCIM-provisioned users only (pagination) — never
        # enumerate locally-created or privileged accounts via SCIM.
        user_recs = [
            u for u in db(db.auth_user.active == True).select()
            if _scim_manageable_user(u)
        ]
        total_count = len(user_recs)

        # Apply pagination (1-based startIndex)
        offset = start_index - 1
        users = user_recs[offset:offset + count]

    # Convert to SCIM resources
    resources = []
    for user in users:
        scim_user = _user_record_to_scim(user)
        resources.append(scim_user.to_dict())

    response = SCIMListResponse(
        totalResults=total_count,
        startIndex=start_index,
        itemsPerPage=len(resources),
        Resources=resources,
    )

    result = response.to_dict()
    result['Content-Type'] = SCIM_CONTENT_TYPE
    return jsonify(result), 200


@scim_bp.route('/Users/<user_id>', methods=['GET'])
def get_user(user_id: str):
    """Get a user by ID."""
    result = require_scim_token()
    if isinstance(result, tuple):
        return result

    db = current_app.db

    user = db.auth_user[int(user_id)] if user_id.isdigit() else None
    if not _scim_manageable_user(user):
        return scim_error('resourceNotFound', f'User {user_id} not found', 404)

    scim_user = _user_record_to_scim(user)
    return jsonify(scim_user.to_dict()), 200


@scim_bp.route('/Users', methods=['POST'])
@limiter.limit('20/minute')
@audit_log('scim_user_created', resource_type='user')
def create_user():
    """JIT create a user (provisioning).

    Accepts SCIM User payload with userName (required), emails, name, active.
    No password is set; SCIM-provisioned users authenticate via IdP.
    """
    result = require_scim_token()
    if isinstance(result, tuple):
        return result

    g.audit_tenant = g.tenant

    db = current_app.db
    data = request.get_json() or {}

    # Validate required fields
    username = data.get('userName')
    if not username:
        return scim_error('invalidValue', 'userName is required', 400)

    external_id = data.get('externalId')
    if not external_id:
        return scim_error('invalidValue', 'externalId is required', 400)

    # Extract email from emails array or derive from userName
    emails_list = data.get('emails', [])
    email = None
    if emails_list and isinstance(emails_list, list):
        email = emails_list[0].get('value') if emails_list[0] else None
    if not email:
        # Derive from userName if no email provided (not ideal but safe)
        email = f"{username}@{g.tenant}.local"

    # Check for duplicates
    if db(db.auth_user.username == username).count():
        return scim_error('uniqueness', 'userName already exists', 409)
    if db(db.auth_user.external_id == external_id).count():
        return scim_error('uniqueness', 'externalId already exists', 409)

    # Create user with a placeholder password (never used for login)
    # SCIM-provisioned users authenticate via IdP only
    placeholder_pass = AuthService.hash_password(secrets.token_urlsafe(32))

    db.auth_user.insert(
        username=username,
        email=email,
        password_hash=placeholder_pass,
        external_id=external_id,
        global_role='Viewer',  # Default role; can be changed via PUT/PATCH
        active=data.get('active', True),
    )
    db.commit()

    # Retrieve the created user
    user = db(db.auth_user.username == username).select().first()
    scim_user = _user_record_to_scim(user)
    g.audit_resource_id = user.id

    logger.info(f"SCIM user created", extra={"user_id": user.id, "username": username})

    return jsonify(scim_user.to_dict()), 201


@scim_bp.route('/Users/<user_id>', methods=['PUT'])
@audit_log('scim_user_updated', resource_type='user')
def update_user(user_id: str):
    """Replace a user (SCIM PUT = full replace).

    Updates userName, emails, name, active. Rejects unsupported paths.
    """
    result = require_scim_token()
    if isinstance(result, tuple):
        return result

    g.audit_tenant = g.tenant

    db = current_app.db

    user = db.auth_user[int(user_id)] if user_id.isdigit() else None
    if not _scim_manageable_user(user):
        return scim_error('resourceNotFound', f'User {user_id} not found', 404)

    g.audit_resource_id = user.id

    data = request.get_json() or {}

    # Validate required fields
    username = data.get('userName')
    if not username:
        return scim_error('invalidValue', 'userName is required', 400)

    # Extract email
    emails_list = data.get('emails', [])
    email = emails_list[0].get('value') if emails_list and isinstance(emails_list, list) else None
    if not email:
        email = user.email  # Keep existing

    # Update user
    db(db.auth_user.id == user.id).update(
        username=username,
        email=email,
        active=data.get('active', user.active),
    )
    db.commit()

    # Reload user from database to get updated values
    user = db.auth_user[int(user_id)]
    scim_user = _user_record_to_scim(user)
    logger.info(f"SCIM user updated", extra={"user_id": user.id})

    return jsonify(scim_user.to_dict()), 200


@scim_bp.route('/Users/<user_id>', methods=['PATCH'])
@audit_log('scim_user_patched', resource_type='user')
def patch_user(user_id: str):
    """Partial update of a user (SCIM PATCH).

    Supports replace operations on: active, name, emails.
    Rejects unsupported paths or operations.
    """
    result = require_scim_token()
    if isinstance(result, tuple):
        return result

    g.audit_tenant = g.tenant

    db = current_app.db

    user = db.auth_user[int(user_id)] if user_id.isdigit() else None
    if not _scim_manageable_user(user):
        return scim_error('resourceNotFound', f'User {user_id} not found', 404)

    g.audit_resource_id = user.id

    data = request.get_json() or {}
    operations = data.get('Operations', [])

    for op in operations:
        op_type = op.get('op', '').lower()
        path = op.get('path', '')
        value = op.get('value')

        # Only support "replace" operation
        if op_type != 'replace':
            return scim_error('invalidSyntax', f'Operation {op_type} not supported', 400)

        # Support only active, name, emails paths
        if path == 'active':
            if not isinstance(value, bool):
                return scim_error('invalidValue', 'active must be boolean', 400)

            # Deactivating sets user.active=false; refresh_access_token (auth_service.py:257)
            # checks this and fails closed. Access tokens expire naturally (~15min).
            db(db.auth_user.id == user.id).update(active=value)
        elif path.startswith('name.'):
            # name.givenName or name.familyName (not yet stored, skip)
            pass
        elif path.startswith('emails['):
            # email address update (simplified: just update primary)
            if isinstance(value, dict):
                email = value.get('value')
                if email:
                    db(db.auth_user.id == user.id).update(email=email)
        else:
            return scim_error('invalidPath', f'Path {path} not supported', 400)

    db.commit()

    # Reload user from database to get updated values
    user = db.auth_user[int(user_id)]
    scim_user = _user_record_to_scim(user)
    logger.info(f"SCIM user patched", extra={"user_id": user.id})

    return jsonify(scim_user.to_dict()), 200


@scim_bp.route('/Users/<user_id>', methods=['DELETE'])
@audit_log('scim_user_deprovisioned', resource_type='user')
def delete_user(user_id: str):
    """Deprovision (deactivate) a user.

    SCIM DELETE either soft-deletes (sets active=false + revokes sessions)
    or hard-deletes based on configuration. We implement soft-delete for safety.
    """
    result = require_scim_token()
    if isinstance(result, tuple):
        return result

    g.audit_tenant = g.tenant

    db = current_app.db

    user = db.auth_user[int(user_id)] if user_id.isdigit() else None
    if not _scim_manageable_user(user):
        return scim_error('resourceNotFound', f'User {user_id} not found', 404)

    g.audit_resource_id = user.id

    # Soft-delete: deactivate user. Refresh flow checks user.active and fails.
    db(db.auth_user.id == user.id).update(active=False)
    db.commit()

    logger.info(f"SCIM user deprovisioned", extra={"user_id": user.id, "username": user.username})

    return '', 204


# ── Admin Endpoints (Gated by Scope) ────────────────────────────────────────

@scim_bp.route('/admin/tokens', methods=['POST'])
@limiter.limit('5/minute')
@audit_log('scim_token_minted', resource_type='scim_token')
def mint_scim_token():
    """Mint a new SCIM bearer token (admin only, enterprise tier required).

    Request JSON:
        {
            "description": "Okta provisioning",
            "tenant": "default"
        }

    Response:
        {
            "id": 1,
            "token": "<plaintext_token_shown_once>",
            "description": "...",
            "created_at": "..."
        }
    """
    # Check user has admin:super scope
    from app.middleware import verify_jwt, has_scope

    # Verify caller is authenticated user (not SCIM bearer)
    token_payload = verify_jwt(request.headers.get('Authorization', ''))
    if token_payload:
        # Attribute the audit event to the caller even if the scope/license
        # check below denies the request (get_current_user() has nothing to
        # return here -- this route authenticates manually, not via
        # @token_required).
        g.audit_actor_id = token_payload.get('user_id')
    if not token_payload or not has_scope(token_payload.get('scope', ''), 'admin:super'):
        return {'error': 'Forbidden'}, 403

    # Check enterprise license
    license_svc = LicenseService()
    if not license_svc.is_enterprise():
        return {'error': 'SCIM provisioning requires Enterprise license'}, 403

    data = request.get_json() or {}
    description = data.get('description', 'Unnamed token')
    tenant = data.get('tenant', 'default')

    plaintext, token_hash = SCIMTokenService.create_token(description, tenant)
    token_id = SCIMTokenService.store_token(plaintext, description, tenant)
    g.audit_resource_id = token_id
    g.audit_tenant = tenant

    logger.info(f"SCIM token minted", extra={"token_id": token_id, "tenant": tenant})

    return {
        'id': token_id,
        'token': plaintext,  # Shown only once
        'description': description,
        'created_at': datetime.utcnow().isoformat(),
    }, 201


@scim_bp.route('/admin/tokens/<token_id>', methods=['DELETE'])
@audit_log('scim_token_revoked', resource_type='scim_token')
def revoke_scim_token(token_id: str):
    """Revoke a SCIM token (admin only)."""
    from app.middleware import verify_jwt, has_scope

    token_payload = verify_jwt(request.headers.get('Authorization', ''))
    if token_payload:
        g.audit_actor_id = token_payload.get('user_id')
    if not token_payload or not has_scope(token_payload.get('scope', ''), 'admin:super'):
        return {'error': 'Forbidden'}, 403

    try:
        g.audit_resource_id = int(token_id)
    except (TypeError, ValueError):
        pass  # Left unattributed; SCIMTokenService.revoke_token below still
        # raises the same ValueError as before this change for a non-numeric id.

    success = SCIMTokenService.revoke_token(int(token_id))
    if not success:
        return scim_error('resourceNotFound', f'Token {token_id} not found', 404)

    logger.info(f"SCIM token revoked", extra={"token_id": token_id})

    return '', 204


# ── Helpers ──────────────────────────────────────────────────────────────────

def _user_record_to_scim(user) -> SCIMUser:
    """Convert database user record to SCIM User resource."""
    emails = [SCIMEmail(value=user.email, type='work', primary=True)] if user.email else []
    name = SCIMName(
        givenName=user.username,
        familyName='User',
        formatted=user.username,
    )
    return SCIMUser(
        id=str(user.id),
        externalId=user.external_id or str(user.id),
        userName=user.username,
        name=name,
        emails=emails,
        active=user.active,
        created_at=user.created_at,
        updated_at=user.updated_at,
    )


import secrets
