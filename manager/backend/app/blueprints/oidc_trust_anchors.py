"""
OIDC trust anchor management API blueprint.
Handles CRUD for OIDC token exchange (federated workload identity).
"""

from flask import Blueprint, request, jsonify, current_app
from app.middleware.auth import token_required, get_current_user
from app.middleware.rbac import requires_system_admin
from app.utils.decorators import validate_json, audit_log
from app.utils.domain_validation import validate_allowed_domains
from datetime import datetime
import logging
import json

oidc_trust_anchors_bp = Blueprint('oidc_trust_anchors', __name__)
log = logging.getLogger(__name__)


@oidc_trust_anchors_bp.route('/api/v1/oidc-trust-anchors', methods=['GET'])
@token_required
@requires_system_admin
def list_oidc_trust_anchors():
    """
    List all OIDC trust anchors (admin only).

    Query params:
        - active: Filter by active status (true/false)
        - tenant: Filter by tenant (default: 'default')

    Response:
        [
            {
                "id": 1,
                "issuer": "https://k8s.example.com",
                "audience": "squawk-api",
                "tenant": "default",
                "allowed_scopes": "users:read servers:read",
                "subject_pattern": "system:serviceaccount:*:*",
                "active": true,
                "created_at": "2024-01-01T00:00:00"
            }
        ]
    """
    db = current_app.db

    # Start with tenant filter (always filter by tenant)
    tenant = request.args.get('tenant', 'default')
    query = db.oidc_trust_anchor.tenant == tenant

    # Filter by active status
    active_filter = request.args.get('active')
    if active_filter is not None:
        active_bool = active_filter.lower() == 'true'
        query = query & (db.oidc_trust_anchor.active == active_bool)

    # Pagination
    limit = min(int(request.args.get('limit', 100)), 1000)
    offset = int(request.args.get('offset', 0))

    anchors = db(query).select(
        orderby=db.oidc_trust_anchor.created_at,
        limitby=(offset, offset + limit)
    )

    result = []
    for a in anchors:
        allowed_domains = None
        if a.allowed_domains:
            try:
                allowed_domains = json.loads(a.allowed_domains)
            except (json.JSONDecodeError, TypeError):
                allowed_domains = None
        result.append({
            'id': a.id,
            'issuer': a.issuer,
            'audience': a.audience,
            'tenant': a.tenant,
            'allowed_scopes': a.allowed_scopes,
            'allowed_domains': allowed_domains,
            'subject_pattern': a.subject_pattern,
            'active': a.active,
            'created_at': a.created_at.isoformat(),
            'updated_at': a.updated_at.isoformat() if a.updated_at else None,
        })
    return jsonify(result), 200


@oidc_trust_anchors_bp.route('/api/v1/oidc-trust-anchors', methods=['POST'])
@token_required
@requires_system_admin
@validate_json('issuer', 'audience', 'allowed_scopes')
@audit_log('oidc_trust_anchor_created')
def create_oidc_trust_anchor():
    """
    Create a new OIDC trust anchor (admin only).

    Request:
        {
            "issuer": "https://k8s.example.com",
            "audience": "squawk-api",
            "jwks_url": "https://k8s.example.com/.well-known/openid-configuration",
            (or)
            "static_jwks_pem": "-----BEGIN PUBLIC KEY-----\n...",
            "allowed_scopes": "users:read servers:read",
            "subject_pattern": "system:serviceaccount:*:*",
            "tenant": "default"  (optional)
        }

    Response:
        {
            "id": 1,
            "issuer": "https://k8s.example.com",
            "audience": "squawk-api",
            "tenant": "default",
            "allowed_scopes": "users:read servers:read",
            "subject_pattern": "system:serviceaccount:*:*",
            "active": true,
            "created_at": "2024-01-01T00:00:00"
        }
    """
    data = request.get_json()
    issuer = data.get('issuer', '').strip()
    audience = data.get('audience', '').strip()
    jwks_url = data.get('jwks_url', '').strip() or None
    static_jwks_pem = data.get('static_jwks_pem', '').strip() or None
    allowed_scopes = data.get('allowed_scopes', '').strip()
    subject_pattern = data.get('subject_pattern', '').strip() or None
    allowed_domains = data.get('allowed_domains')  # None or list
    tenant = data.get('tenant', 'default').strip()

    if not issuer or not audience or not allowed_scopes:
        return jsonify({'error': 'issuer, audience, and allowed_scopes required'}), 400

    if not jwks_url and not static_jwks_pem:
        return jsonify({'error': 'Either jwks_url or static_jwks_pem required'}), 400

    # Validate allowed_domains if provided
    is_valid, error_msg = validate_allowed_domains(allowed_domains)
    if not is_valid:
        return jsonify({'error': error_msg}), 400

    # Validate scopes exist in the system
    from app.services.scopes import ROLE_SCOPES
    all_valid_scopes = set()
    for scope_bundle in ROLE_SCOPES.values():
        all_valid_scopes.update(scope_bundle)

    requested = set(allowed_scopes.split())
    if not requested.issubset(all_valid_scopes):
        invalid = requested - all_valid_scopes
        return jsonify({
            'error': 'Invalid scopes',
            'invalid_scopes': list(invalid)
        }), 400

    db = current_app.db

    # Check for duplicate issuer
    if db((db.oidc_trust_anchor.issuer == issuer) &
          (db.oidc_trust_anchor.active == True)).count():
        return jsonify({'error': 'Issuer already exists and is active'}), 409

    db.oidc_trust_anchor.insert(
        issuer=issuer,
        audience=audience,
        jwks_url=jwks_url,
        static_jwks_pem=static_jwks_pem,
        tenant=tenant,
        allowed_scopes=allowed_scopes,
        allowed_domains=json.dumps(allowed_domains) if allowed_domains is not None else None,
        subject_pattern=subject_pattern,
        active=True,
        created_at=datetime.utcnow()
    )
    db.commit()

    log.info(f"OIDC trust anchor created: issuer={issuer}",
             extra={'audit': True})

    return jsonify({
        'issuer': issuer,
        'audience': audience,
        'tenant': tenant,
        'allowed_scopes': allowed_scopes,
        'allowed_domains': allowed_domains,
        'subject_pattern': subject_pattern,
        'active': True,
        'created_at': datetime.utcnow().isoformat()
    }), 201


@oidc_trust_anchors_bp.route('/api/v1/oidc-trust-anchors/<int:anchor_id>', methods=['GET'])
@token_required
@requires_system_admin
def get_oidc_trust_anchor(anchor_id: int):
    """Get a specific OIDC trust anchor (admin only)."""
    db = current_app.db
    anchor = db.oidc_trust_anchor[anchor_id]

    if not anchor:
        return jsonify({'error': 'OIDC trust anchor not found'}), 404

    allowed_domains = None
    if anchor.allowed_domains:
        try:
            allowed_domains = json.loads(anchor.allowed_domains)
        except (json.JSONDecodeError, TypeError):
            allowed_domains = None

    return jsonify({
        'id': anchor.id,
        'issuer': anchor.issuer,
        'audience': anchor.audience,
        'tenant': anchor.tenant,
        'allowed_scopes': anchor.allowed_scopes,
        'allowed_domains': allowed_domains,
        'subject_pattern': anchor.subject_pattern,
        'active': anchor.active,
        'created_at': anchor.created_at.isoformat(),
        'updated_at': anchor.updated_at.isoformat() if anchor.updated_at else None,
    }), 200


@oidc_trust_anchors_bp.route('/api/v1/oidc-trust-anchors/<int:anchor_id>', methods=['PATCH'])
@token_required
@requires_system_admin
@audit_log('oidc_trust_anchor_updated')
def update_oidc_trust_anchor(anchor_id: int):
    """Update an OIDC trust anchor (admin only)."""
    db = current_app.db
    anchor = db.oidc_trust_anchor[anchor_id]

    if not anchor:
        return jsonify({'error': 'OIDC trust anchor not found'}), 404

    data = request.get_json(silent=True) or {}

    update_fields = {}
    if 'allowed_scopes' in data:
        scopes = data['allowed_scopes'].strip()
        from app.services.scopes import ROLE_SCOPES
        all_valid_scopes = set()
        for scope_bundle in ROLE_SCOPES.values():
            all_valid_scopes.update(scope_bundle)

        requested = set(scopes.split())
        if not requested.issubset(all_valid_scopes):
            invalid = requested - all_valid_scopes
            return jsonify({
                'error': 'Invalid scopes',
                'invalid_scopes': list(invalid)
            }), 400
        update_fields['allowed_scopes'] = scopes

    if 'subject_pattern' in data:
        update_fields['subject_pattern'] = data['subject_pattern']

    if 'active' in data:
        update_fields['active'] = bool(data['active'])

    if 'allowed_domains' in data:
        allowed_domains = data['allowed_domains']
        is_valid, error_msg = validate_allowed_domains(allowed_domains)
        if not is_valid:
            return jsonify({'error': error_msg}), 400
        update_fields['allowed_domains'] = json.dumps(allowed_domains) if allowed_domains is not None else None

    update_fields['updated_at'] = datetime.utcnow()

    if update_fields:
        db(db.oidc_trust_anchor.id == anchor_id).update(**update_fields)
        db.commit()
        # Refetch after update
        anchor = db.oidc_trust_anchor[anchor_id]
    else:
        db.commit()

    log.info(f"OIDC trust anchor updated: issuer={anchor.issuer}",
             extra={'audit': True})

    allowed_domains = None
    if anchor.allowed_domains:
        try:
            allowed_domains = json.loads(anchor.allowed_domains)
        except (json.JSONDecodeError, TypeError):
            allowed_domains = None

    return jsonify({
        'id': anchor.id,
        'issuer': anchor.issuer,
        'audience': anchor.audience,
        'tenant': anchor.tenant,
        'allowed_scopes': anchor.allowed_scopes,
        'allowed_domains': allowed_domains,
        'subject_pattern': anchor.subject_pattern,
        'active': anchor.active,
        'created_at': anchor.created_at.isoformat(),
        'updated_at': anchor.updated_at.isoformat() if anchor.updated_at else None,
    }), 200


@oidc_trust_anchors_bp.route('/api/v1/oidc-trust-anchors/<int:anchor_id>', methods=['DELETE'])
@token_required
@requires_system_admin
@audit_log('oidc_trust_anchor_deleted')
def delete_oidc_trust_anchor(anchor_id: int):
    """Delete an OIDC trust anchor (admin only)."""
    db = current_app.db
    anchor = db.oidc_trust_anchor[anchor_id]

    if not anchor:
        return jsonify({'error': 'OIDC trust anchor not found'}), 404

    issuer = anchor.issuer
    db(db.oidc_trust_anchor.id == anchor_id).delete()
    db.commit()

    log.info(f"OIDC trust anchor deleted: issuer={issuer}",
             extra={'audit': True})

    return jsonify({'message': 'OIDC trust anchor deleted'}), 200
