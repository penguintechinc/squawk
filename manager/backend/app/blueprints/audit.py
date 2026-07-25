"""Audit event API — query durable audit trail.

Gated on scope audit:read (default granted to SystemAdmin).
Supports filtering by action, actor_id, resource_type, outcome, date range.
"""

from datetime import datetime
from flask import Blueprint, request, jsonify, current_app
from app.middleware.auth import token_required
from app.middleware.rbac import requires_scope

audit_bp = Blueprint('audit', __name__)


@audit_bp.route('/api/v1/audit-events', methods=['GET'])
@token_required
@requires_scope('audit:read')
def list_audit_events():
    """List audit events with optional filtering.

    Query params:
        - action: Filter by action name (e.g., 'user_created')
        - actor_id: Filter by actor user ID
        - resource_type: Filter by resource type (e.g., 'token', 'dns_server')
        - resource_id: Filter by specific resource ID
        - outcome: Filter by outcome ('success' or 'failure')
        - since: ISO 8601 datetime (inclusive); events after this time
        - until: ISO 8601 datetime (inclusive); events before this time
        - limit: Max results (default 50, max 500)
        - offset: Pagination offset (default 0)

    Response:
        {
            "events": [
                {
                    "id": 1,
                    "created_at": "2026-07-25T12:00:00",
                    "actor_id": 123,
                    "action": "user_created",
                    "resource_type": "user",
                    "resource_id": 456,
                    "outcome": "success",
                    "status_code": 201,
                    "request_id": "abc-123",
                    "source_ip": "192.168.1.1"
                }
            ],
            "total": 150,
            "limit": 50,
            "offset": 0
        }
    """
    db = current_app.db

    # Build query filters
    query = None

    # Filter by action
    action = request.args.get('action')
    if action:
        query = db.audit_event.action == action if query is None else query & (db.audit_event.action == action)

    # Filter by actor_id
    actor_id = request.args.get('actor_id', type=int)
    if actor_id is not None:
        cond = db.audit_event.actor_id == actor_id
        query = cond if query is None else query & cond

    # Filter by resource_type
    resource_type = request.args.get('resource_type')
    if resource_type:
        cond = db.audit_event.resource_type == resource_type
        query = cond if query is None else query & cond

    # Filter by resource_id
    resource_id = request.args.get('resource_id', type=int)
    if resource_id is not None:
        cond = db.audit_event.resource_id == resource_id
        query = cond if query is None else query & cond

    # Filter by outcome
    outcome = request.args.get('outcome')
    if outcome:
        if outcome not in ('success', 'failure'):
            return jsonify({'error': 'Invalid outcome; must be "success" or "failure"'}), 400
        cond = db.audit_event.outcome == outcome
        query = cond if query is None else query & cond

    # Filter by date range
    since = request.args.get('since')
    if since:
        try:
            since_dt = datetime.fromisoformat(since)
            cond = db.audit_event.created_at >= since_dt
            query = cond if query is None else query & cond
        except ValueError:
            return jsonify({'error': 'Invalid "since" datetime; use ISO 8601 format'}), 400

    until = request.args.get('until')
    if until:
        try:
            until_dt = datetime.fromisoformat(until)
            cond = db.audit_event.created_at <= until_dt
            query = cond if query is None else query & cond
        except ValueError:
            return jsonify({'error': 'Invalid "until" datetime; use ISO 8601 format'}), 400

    # Pagination
    limit = request.args.get('limit', default=50, type=int)
    offset = request.args.get('offset', default=0, type=int)

    if limit < 1 or limit > 500:
        return jsonify({'error': 'limit must be between 1 and 500'}), 400
    if offset < 0:
        return jsonify({'error': 'offset must be >= 0'}), 400

    # Count total matching and fetch records
    if query is None:
        # No filters — use a tautology to select all rows
        query = db.audit_event.id != None  # Every row's id is not null

    total = db(query).count()
    events = db(query).select(
        orderby=~db.audit_event.created_at,
        limitby=(offset, offset + limit)
    )

    return jsonify({
        'events': [
            {
                'id': e.id,
                'created_at': e.created_at.isoformat(),
                'actor_id': e.actor_id,
                'action': e.action,
                'resource_type': e.resource_type,
                'resource_id': e.resource_id,
                'outcome': e.outcome,
                'status_code': e.status_code,
                'request_id': e.request_id,
                'source_ip': e.source_ip,
            }
            for e in events
        ],
        'total': total,
        'limit': limit,
        'offset': offset,
    }), 200
