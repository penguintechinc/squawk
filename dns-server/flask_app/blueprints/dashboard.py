"""
Dashboard Blueprint - JSON REST API
All endpoints return JSON responses with JWT or Flask-Login authentication
"""

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, current_user as jwt_current_user
from flask_login import current_user as login_current_user
from werkzeug.security import generate_password_hash
import os
import sys
from datetime import datetime, timedelta

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import shared database instance
from database import db

dashboard_bp = Blueprint('dashboard', __name__)


def get_current_user():
    """Get current user from JWT or Flask-Login session."""
    if jwt_current_user:
        return jwt_current_user
    if login_current_user and login_current_user.is_authenticated:
        return login_current_user
    return None


def _is_json_safe(value):
    """Check if a value is JSON-serializable (basic types only).
    Uses exact type checks for containers to exclude PyDAL internal
    types (RecordUpdater, RecordDeleter, LazySet) that inherit from dict.
    """
    if value is None:
        return True
    if isinstance(value, (str, int, float, bool)):
        return True
    # Exact type check for containers - excludes PyDAL dict subclasses
    if type(value) in (list, dict, tuple):
        return True
    # datetime objects are handled by Flask's jsonify
    import datetime as dt
    if isinstance(value, (dt.datetime, dt.date, dt.time)):
        return True
    return False


def serialize_row(row):
    """Convert PyDAL Row to dictionary, filtering non-serializable types."""
    if row is None:
        return None
    result = {}
    for k, v in row.items():
        if _is_json_safe(v):
            result[k] = v
    return result


def serialize_rows(rows):
    """Convert PyDAL Rows to list of dictionaries."""
    return [serialize_row(row) for row in rows]


# ============================================================================
# GET Endpoints (List/Read)
# ============================================================================

@dashboard_bp.route('/dashboard/stats', methods=['GET'])
@jwt_required(optional=True)
def get_dashboard_stats():
    """Get dashboard statistics."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    try:
        # Get recent query stats
        last_24h = datetime.utcnow() - timedelta(hours=24)
        recent_queries = db(db.dns_query_log.timestamp > last_24h).count()
        cache_hits = db((db.dns_query_log.timestamp > last_24h) &
                        (db.dns_query_log.cache_hit == True)).count()

        # Get recent queries for display
        recent_query_list = db(db.dns_query_log).select(
            orderby=~db.dns_query_log.timestamp,
            limitby=(0, 10)
        )

        stats = {
            'total_queries_24h': recent_queries,
            'cache_hit_rate': (cache_hits / recent_queries * 100) if recent_queries > 0 else 0,
            'active_ioc_feeds': db(db.ioc_feed.is_active == True).count(),
            'total_ioc_entries': db(db.ioc_entry).count(),
            'internal_domains': db(db.internal_domain.is_active == True).count(),
            'ioc_blocks_24h': 0,  # Will be tracked when IOC blocking is integrated
            'recent_queries': serialize_rows(recent_query_list)
        }

        return jsonify(stats), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@dashboard_bp.route('/domains', methods=['GET'])
@jwt_required(optional=True)
def get_domains():
    """List all domains with optional filtering."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    try:
        filter_type = request.args.get('filter', 'all')

        # Build query based on filter
        if filter_type == 'active':
            query = db.internal_domain.is_active == True
        elif filter_type == 'inactive':
            query = db.internal_domain.is_active == False
        elif filter_type == 'groups':
            query = db.internal_domain.access_type == 'groups'
        else:
            query = db.internal_domain

        domains_list = db(query).select(orderby=~db.internal_domain.modified_on)

        # Enrich domains with access group information
        domains_data = []
        for domain in domains_list:
            domain_dict = serialize_row(domain)
            # Get access groups for this domain
            groups = db(db.internal_domain_group.domain_id == domain.id).select()
            domain_dict['access_groups'] = [g.group_name for g in groups]
            domains_data.append(domain_dict)

        return jsonify({'domains': domains_data}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@dashboard_bp.route('/users', methods=['GET'])
@jwt_required(optional=True)
def get_users():
    """List all users."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    try:
        users = db(db.auth_user).select(orderby=db.auth_user.email)
        users_data = serialize_rows(users)

        # Remove password hashes from response
        for u in users_data:
            if 'password' in u:
                del u['password']

        return jsonify({'users': users_data}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@dashboard_bp.route('/groups', methods=['GET'])
@jwt_required(optional=True)
def get_groups():
    """List all groups."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    try:
        groups_list = []
        if 'dns_group' in db.tables:
            groups = db(db.dns_group).select(orderby=db.dns_group.name)
            groups_list = serialize_rows(groups)

        return jsonify({'groups': groups_list}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@dashboard_bp.route('/zones', methods=['GET'])
@jwt_required(optional=True)
def get_zones():
    """List all DNS zones."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    try:
        zones_list = []
        if 'dns_zone' in db.tables:
            zones = db(db.dns_zone).select(orderby=db.dns_zone.name)
            zones_list = serialize_rows(zones)

        return jsonify({'zones': zones_list}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@dashboard_bp.route('/records', methods=['GET'])
@jwt_required(optional=True)
def get_records():
    """List all DNS records with zones list."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    try:
        records_list = []
        zones_list = []

        if 'dns_record' in db.tables:
            records = db(db.dns_record).select(orderby=db.dns_record.zone)
            records_list = serialize_rows(records)

        if 'dns_zone' in db.tables:
            zones = db(db.dns_zone).select(orderby=db.dns_zone.name)
            zones_list = serialize_rows(zones)

        return jsonify({
            'records': records_list,
            'zones': zones_list
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@dashboard_bp.route('/permissions', methods=['GET'])
@jwt_required(optional=True)
def get_permissions():
    """List all permissions with groups list."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    try:
        permissions_list = []
        groups_list = []

        if 'dns_permission' in db.tables:
            permissions = db(db.dns_permission).select(orderby=db.dns_permission.group_name)
            permissions_list = serialize_rows(permissions)

        if 'dns_group' in db.tables:
            groups = db(db.dns_group).select(orderby=db.dns_group.name)
            groups_list = serialize_rows(groups)

        return jsonify({
            'permissions': permissions_list,
            'groups': groups_list
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@dashboard_bp.route('/blocked', methods=['GET'])
@jwt_required(optional=True)
def get_blocked():
    """List blocked queries (limit 100)."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    try:
        blocked_list = []
        if 'blocked_query' in db.tables:
            blocked = db(db.blocked_query).select(
                orderby=~db.blocked_query.blocked_at,
                limitby=(0, 100)
            )
            blocked_list = serialize_rows(blocked)

        return jsonify({'blocked_queries': blocked_list}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@dashboard_bp.route('/threats', methods=['GET'])
@jwt_required(optional=True)
def get_threats():
    """List threat intelligence feeds and recent IOC entries."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    try:
        feeds = db(db.ioc_feed).select(orderby=db.ioc_feed.name)
        recent_entries = db(db.ioc_entry).select(
            orderby=~db.ioc_entry.last_seen,
            limitby=(0, 50)
        )

        return jsonify({
            'feeds': serialize_rows(feeds),
            'recent_entries': serialize_rows(recent_entries)
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@dashboard_bp.route('/logs', methods=['GET'])
@jwt_required(optional=True)
def get_logs():
    """Get paginated system logs."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 100))

        logs_list = db(db.dns_query_log).select(
            orderby=~db.dns_query_log.timestamp,
            limitby=((page-1)*per_page, page*per_page)
        )

        total = db(db.dns_query_log).count()

        return jsonify({
            'logs': serialize_rows(logs_list),
            'page': page,
            'per_page': per_page,
            'total': total,
            'total_pages': (total + per_page - 1) // per_page
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@dashboard_bp.route('/config', methods=['GET'])
@jwt_required(optional=True)
def get_config():
    """Get system configuration (placeholder)."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    try:
        # Placeholder for system configuration
        config = {
            'message': 'System configuration endpoint',
            'status': 'active'
        }
        return jsonify(config), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@dashboard_bp.route('/cache', methods=['GET'])
@jwt_required(optional=True)
def get_cache():
    """Get cache information (placeholder)."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    try:
        # Placeholder for cache information
        cache_info = {
            'message': 'Cache management endpoint',
            'status': 'active'
        }
        return jsonify(cache_info), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# POST Endpoints (Create)
# ============================================================================

@dashboard_bp.route('/domains', methods=['POST'])
@jwt_required(optional=True)
def create_domain():
    """Create a new internal domain."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400

        domain_name = data.get('domain_name')
        ip_address = data.get('ip_address')
        description = data.get('description', '')
        access_type = data.get('access_type', 'all')
        is_active = data.get('is_active', True)
        access_groups = data.get('access_groups', '')
        access_users = data.get('access_users', '')

        # Validate required fields
        if not domain_name or not ip_address:
            return jsonify({'error': 'domain_name and ip_address are required'}), 400

        # Check if domain already exists
        existing = db(db.internal_domain.name == domain_name).select().first()
        if existing:
            return jsonify({'error': 'Domain with this name already exists'}), 409

        # Create the domain
        domain_id = db.internal_domain.insert(
            name=domain_name,
            ip_address=ip_address,
            description=description,
            access_type=access_type,
            is_active=is_active,
            created_by=user.id,
            created_on=datetime.utcnow(),
            modified_on=datetime.utcnow()
        )

        # Add group access if specified
        if access_type == 'groups' and access_groups:
            group_names = [g.strip() for g in access_groups.split(',') if g.strip()]
            for group_name in group_names:
                db.internal_domain_group.insert(
                    domain_id=domain_id,
                    group_name=group_name,
                    created_on=datetime.utcnow()
                )

        # Add user access if specified
        if access_type == 'users' and access_users:
            user_emails = [u.strip() for u in access_users.split(',') if u.strip()]
            warnings = []
            for email in user_emails:
                # Find user by email
                target_user = db(db.auth_user.email == email).select().first()
                if target_user:
                    db.internal_domain_user.insert(
                        domain_id=domain_id,
                        user_id=target_user.id,
                        created_on=datetime.utcnow()
                    )
                else:
                    warnings.append(f'User {email} not found, skipped')

            db.commit()
            return jsonify({
                'message': 'Domain created successfully',
                'domain_id': domain_id,
                'warnings': warnings
            }), 201

        db.commit()
        return jsonify({
            'message': 'Domain created successfully',
            'domain_id': domain_id
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@dashboard_bp.route('/users', methods=['POST'])
@jwt_required(optional=True)
def create_user():
    """Create a new user."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400

        email = data.get('email')
        first_name = data.get('first_name', '')
        last_name = data.get('last_name', '')
        password = data.get('password')
        is_admin = data.get('is_admin', False)

        # Validate required fields
        if not email or not password:
            return jsonify({'error': 'email and password are required'}), 400

        # Check if user already exists
        existing = db(db.auth_user.email == email).select().first()
        if existing:
            return jsonify({'error': 'User with this email already exists'}), 409

        # Create user
        user_id = db.auth_user.insert(
            email=email,
            first_name=first_name,
            last_name=last_name,
            password=generate_password_hash(password),
            is_admin=is_admin,
            created_on=datetime.utcnow()
        )
        db.commit()

        return jsonify({
            'message': 'User created successfully',
            'user_id': user_id
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@dashboard_bp.route('/groups', methods=['POST'])
@jwt_required(optional=True)
def create_group():
    """Create a new group."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400

        group_name = data.get('name')
        group_type = data.get('group_type')
        description = data.get('description', '')

        # Validate required fields
        if not group_name or not group_type:
            return jsonify({'error': 'name and group_type are required'}), 400

        # Create group table if it doesn't exist
        if 'dns_group' not in db.tables:
            db.define_table('dns_group',
                db.Field('name', 'string', notnull=True, unique=True),
                db.Field('group_type', 'string'),
                db.Field('description', 'text'),
                db.Field('created_on', 'datetime', default=datetime.utcnow)
            )

        # Check if group already exists
        existing = db(db.dns_group.name == group_name).select().first()
        if existing:
            return jsonify({'error': 'Group with this name already exists'}), 409

        group_id = db.dns_group.insert(
            name=group_name,
            group_type=group_type,
            description=description,
            created_on=datetime.utcnow()
        )
        db.commit()

        return jsonify({
            'message': 'Group created successfully',
            'group_id': group_id
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@dashboard_bp.route('/zones', methods=['POST'])
@jwt_required(optional=True)
def create_zone():
    """Create a new DNS zone."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400

        zone_name = data.get('zone_name')
        visibility = data.get('visibility', 'PUBLIC')
        primary_ns = data.get('primary_ns', '')
        admin_email = data.get('admin_email', '')
        ttl = int(data.get('ttl', 3600))

        # Validate required fields
        if not zone_name:
            return jsonify({'error': 'zone_name is required'}), 400

        # Create zone table if it doesn't exist
        if 'dns_zone' not in db.tables:
            db.define_table('dns_zone',
                db.Field('name', 'string', notnull=True, unique=True),
                db.Field('visibility', 'string', default='PUBLIC'),
                db.Field('primary_ns', 'string'),
                db.Field('admin_email', 'string'),
                db.Field('ttl', 'integer', default=3600),
                db.Field('created_on', 'datetime', default=datetime.utcnow)
            )

        zone_id = db.dns_zone.insert(
            name=zone_name,
            visibility=visibility,
            primary_ns=primary_ns,
            admin_email=admin_email,
            ttl=ttl,
            created_on=datetime.utcnow()
        )
        db.commit()

        return jsonify({
            'message': 'Zone created successfully',
            'zone_id': zone_id
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@dashboard_bp.route('/records', methods=['POST'])
@jwt_required(optional=True)
def create_record():
    """Create a new DNS record."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400

        zone = data.get('zone')
        record_name = data.get('record_name')
        record_type = data.get('record_type')
        record_value = data.get('record_value')
        ttl = int(data.get('ttl', 3600))

        # Validate required fields
        if not zone or not record_name or not record_type or not record_value:
            return jsonify({'error': 'zone, record_name, record_type, and record_value are required'}), 400

        # Create record table if it doesn't exist
        if 'dns_record' not in db.tables:
            db.define_table('dns_record',
                db.Field('zone', 'string', notnull=True),
                db.Field('name', 'string', notnull=True),
                db.Field('record_type', 'string', notnull=True),
                db.Field('value', 'string', notnull=True),
                db.Field('ttl', 'integer', default=3600),
                db.Field('created_on', 'datetime', default=datetime.utcnow)
            )

        record_id = db.dns_record.insert(
            zone=zone,
            name=record_name,
            record_type=record_type,
            value=record_value,
            ttl=ttl,
            created_on=datetime.utcnow()
        )
        db.commit()

        return jsonify({
            'message': 'Record created successfully',
            'record_id': record_id
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@dashboard_bp.route('/permissions', methods=['POST'])
@jwt_required(optional=True)
def create_permission():
    """Create a new permission rule."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400

        group = data.get('group')
        zone_pattern = data.get('zone_pattern')
        access_level = data.get('access_level', 'READ')
        can_query = data.get('can_query', True)
        can_modify = data.get('can_modify', False)

        # Validate required fields
        if not group or not zone_pattern:
            return jsonify({'error': 'group and zone_pattern are required'}), 400

        # Create permission table if it doesn't exist
        if 'dns_permission' not in db.tables:
            db.define_table('dns_permission',
                db.Field('group_name', 'string', notnull=True),
                db.Field('zone_pattern', 'string', notnull=True),
                db.Field('access_level', 'string', default='READ'),
                db.Field('can_query', 'boolean', default=True),
                db.Field('can_modify', 'boolean', default=False),
                db.Field('created_on', 'datetime', default=datetime.utcnow)
            )

        permission_id = db.dns_permission.insert(
            group_name=group,
            zone_pattern=zone_pattern,
            access_level=access_level,
            can_query=can_query,
            can_modify=can_modify,
            created_on=datetime.utcnow()
        )
        db.commit()

        return jsonify({
            'message': 'Permission created successfully',
            'permission_id': permission_id
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# Action Endpoints
# ============================================================================

@dashboard_bp.route('/feeds/update', methods=['POST'])
@jwt_required(optional=True)
def update_feeds():
    """Update all threat intelligence feeds."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    try:
        # Get all active feeds
        feeds = db(db.ioc_feed.is_active == True).select()
        updated_count = 0

        for feed in feeds:
            # Update last_updated timestamp
            db(db.ioc_feed.id == feed.id).update(last_updated=datetime.utcnow())
            updated_count += 1

        db.commit()
        return jsonify({
            'message': f'Updated {updated_count} feeds',
            'updated_count': updated_count
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@dashboard_bp.route('/blocked/clear', methods=['POST'])
@jwt_required(optional=True)
def clear_blocked():
    """Clear blocked query history."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    try:
        # Create blocked_query table if it doesn't exist
        if 'blocked_query' not in db.tables:
            db.define_table('blocked_query',
                db.Field('domain', 'string'),
                db.Field('client_ip', 'string'),
                db.Field('reason', 'string'),
                db.Field('threat_level', 'string'),
                db.Field('feed_source', 'string'),
                db.Field('blocked_at', 'datetime', default=datetime.utcnow)
            )

        # Delete all blocked query records
        deleted_count = db(db.blocked_query).delete()
        db.commit()

        return jsonify({
            'success': True,
            'message': 'Blocked query history cleared',
            'deleted_count': deleted_count
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@dashboard_bp.route('/logs/clear', methods=['POST'])
@jwt_required(optional=True)
def clear_logs():
    """Clear system logs."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    try:
        # Clear DNS query logs
        deleted_count = db(db.dns_query_log).delete()
        db.commit()

        return jsonify({
            'success': True,
            'message': 'Logs cleared successfully',
            'deleted_count': deleted_count
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# Autocomplete Endpoints
# ============================================================================

@dashboard_bp.route('/search/groups', methods=['GET'])
@jwt_required(optional=True)
def search_groups():
    """Search for groups by name (autocomplete endpoint)."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    try:
        query = request.args.get('q', '').strip()

        # Get unique group names from various sources
        group_names = set()

        # From dns_group table if it exists
        if 'dns_group' in db.tables:
            groups = db(db.dns_group.name.contains(query)).select(db.dns_group.name, distinct=True)
            group_names.update([g.name for g in groups])

        # From internal_domain_group table
        domain_groups = db(db.internal_domain_group.group_name.contains(query)).select(
            db.internal_domain_group.group_name, distinct=True, limitby=(0, 20)
        )
        group_names.update([g.group_name for g in domain_groups])

        # Return sorted list
        return jsonify({'groups': sorted(list(group_names))}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@dashboard_bp.route('/search/users', methods=['GET'])
@jwt_required(optional=True)
def search_users():
    """Search for users by email (autocomplete endpoint)."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    try:
        query = request.args.get('q', '').strip()

        # Search users by email
        users = db(db.auth_user.email.contains(query)).select(
            db.auth_user.email,
            db.auth_user.first_name,
            db.auth_user.last_name,
            limitby=(0, 20),
            orderby=db.auth_user.email
        )

        # Format user data
        user_list = []
        for u in users:
            display_name = f"{u.email}"
            if u.first_name or u.last_name:
                full_name = f"{u.first_name or ''} {u.last_name or ''}".strip()
                display_name = f"{u.email} ({full_name})"
            user_list.append({
                'email': u.email,
                'display': display_name
            })

        return jsonify({'users': user_list}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
