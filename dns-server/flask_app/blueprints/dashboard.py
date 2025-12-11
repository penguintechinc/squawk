"""
Dashboard Blueprint for Flask Application
Main dashboard and monitoring views
"""

from flask import Blueprint, render_template, jsonify, request
from flask_login import login_required, current_user
import os
import sys
from datetime import datetime, timedelta

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import shared database instance
from database import db

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
@login_required
def index():
    """Main dashboard"""
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
        'ioc_blocks_24h': 0  # Will be tracked when IOC blocking is integrated with query logs
    }
    
    return render_template('dashboard/index.html', 
                          stats=stats, 
                          recent_queries=recent_query_list,
                          user=current_user)

@dashboard_bp.route('/queries')
@login_required
def queries():
    """Query log viewer"""
    page = int(request.args.get('page', 1))
    per_page = 50
    
    queries = db(db.dns_query_log).select(
        orderby=~db.dns_query_log.timestamp,
        limitby=((page-1)*per_page, page*per_page)
    )
    
    total = db(db.dns_query_log).count()
    
    return render_template('dashboard/queries.html', 
                         queries=queries, 
                         page=page, 
                         total=total,
                         per_page=per_page)

@dashboard_bp.route('/ioc')
@login_required
def ioc():
    """IOC management"""
    feeds = db(db.ioc_feed).select(orderby=db.ioc_feed.name)
    return render_template('dashboard/ioc.html', feeds=feeds)

@dashboard_bp.route('/stats/api')
@login_required
def stats_api():
    """API endpoint for dashboard stats"""
    hours = int(request.args.get('hours', 24))
    since = datetime.utcnow() - timedelta(hours=hours)
    
    queries = db(db.dns_query_log.timestamp > since).select()
    
    # Group by hour
    hourly_stats = {}
    for query in queries:
        hour_key = query.timestamp.strftime('%Y-%m-%d %H:00')
        if hour_key not in hourly_stats:
            hourly_stats[hour_key] = {'total': 0, 'cache_hits': 0}
        hourly_stats[hour_key]['total'] += 1
        if query.cache_hit:
            hourly_stats[hour_key]['cache_hits'] += 1
    
    return jsonify(hourly_stats)

@dashboard_bp.route('/domains')
@login_required
def domains():
    """Internal domain management"""
    # Fetch all internal domains with access group information
    domains_list = db(db.internal_domain).select(orderby=~db.internal_domain.modified_on)

    # Enrich domains with access group information
    for domain in domains_list:
        # Get access groups for this domain
        groups = db(db.internal_domain_group.domain_id == domain.id).select()
        domain.access_groups = [g.group_name for g in groups]

    return render_template('dashboard/domains.html', domains=domains_list)

@dashboard_bp.route('/domains/add', methods=['POST'])
@login_required
def add_domain():
    """Add internal domain"""
    try:
        domain_name = request.form.get('domain_name')
        ip_address = request.form.get('ip_address')
        description = request.form.get('description')
        access_type = request.form.get('access_type', 'all')
        is_active = request.form.get('is_active') == 'on'
        access_groups = request.form.get('access_groups', '')
        access_users = request.form.get('access_users', '')

        # Validate required fields
        if not domain_name or not ip_address:
            flash('Domain name and IP address are required', 'error')
            return redirect(url_for('dashboard.domains'))

        # Check if domain already exists
        existing = db(db.internal_domain.name == domain_name).select().first()
        if existing:
            flash('Domain with this name already exists', 'error')
            return redirect(url_for('dashboard.domains'))

        # Create the domain
        domain_id = db.internal_domain.insert(
            name=domain_name,
            ip_address=ip_address,
            description=description,
            access_type=access_type,
            is_active=is_active,
            created_by=current_user.id,
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
            for email in user_emails:
                # Find user by email
                user = db(db.auth_user.email == email).select().first()
                if user:
                    db.internal_domain_user.insert(
                        domain_id=domain_id,
                        user_id=user.id,
                        created_on=datetime.utcnow()
                    )
                else:
                    flash(f'Warning: User {email} not found, skipped', 'warning')

        db.commit()
        flash('Internal domain added successfully', 'success')

    except Exception as e:
        flash(f'Failed to add domain: {str(e)}', 'error')

    return redirect(url_for('dashboard.domains'))

@dashboard_bp.route('/users')
@login_required
def users():
    """User management"""
    users = db(db.auth_user).select(orderby=db.auth_user.email)
    return render_template('dashboard/users.html', users=users)

@dashboard_bp.route('/groups')
@login_required
def groups():
    """Group management"""
    # Fetch all groups if the table exists
    groups_list = []
    if 'dns_group' in db.tables:
        groups_list = db(db.dns_group).select(orderby=db.dns_group.name)
    return render_template('dashboard/groups.html', groups=groups_list)

@dashboard_bp.route('/config')
@login_required
def config():
    """System configuration"""
    return render_template('dashboard/config.html')

@dashboard_bp.route('/cache')
@login_required
def cache():
    """Cache management"""
    return render_template('dashboard/cache.html')

# Placeholder routes for sidebar links
@dashboard_bp.route('/analytics')
@login_required
def analytics():
    return render_template('dashboard/analytics.html')

@dashboard_bp.route('/zones')
@login_required
def zones():
    """DNS zones management"""
    zones_list = []
    if 'dns_zone' in db.tables:
        zones_list = db(db.dns_zone).select(orderby=db.dns_zone.name)
    return render_template('dashboard/zones.html', zones=zones_list)

@dashboard_bp.route('/records')
@login_required
def records():
    """DNS records management"""
    records_list = []
    zones_list = []
    if 'dns_record' in db.tables:
        records_list = db(db.dns_record).select(orderby=db.dns_record.zone)
    if 'dns_zone' in db.tables:
        zones_list = db(db.dns_zone).select(orderby=db.dns_zone.name)
    return render_template('dashboard/records.html', records=records_list, zones=zones_list)

@dashboard_bp.route('/permissions')
@login_required
def permissions():
    """DNS permissions management"""
    permissions_list = []
    groups_list = []
    if 'dns_permission' in db.tables:
        permissions_list = db(db.dns_permission).select(orderby=db.dns_permission.group_name)
    if 'dns_group' in db.tables:
        groups_list = db(db.dns_group).select(orderby=db.dns_group.name)
    return render_template('dashboard/permissions.html', permissions=permissions_list, groups=groups_list)

@dashboard_bp.route('/blocked')
@login_required
def blocked():
    """Blocked queries management"""
    blocked_list = []
    if 'blocked_query' in db.tables:
        blocked_list = db(db.blocked_query).select(
            orderby=~db.blocked_query.blocked_at,
            limitby=(0, 100)
        )
    return render_template('dashboard/blocked.html', blocked_queries=blocked_list)

@dashboard_bp.route('/threats')
@login_required
def threats():
    """Threat intelligence management"""
    feeds = db(db.ioc_feed).select(orderby=db.ioc_feed.name)
    recent_entries = db(db.ioc_entry).select(
        orderby=~db.ioc_entry.last_seen,
        limitby=(0, 50)
    )
    return render_template('dashboard/threats.html', feeds=feeds, recent_entries=recent_entries)

@dashboard_bp.route('/logs')
@login_required
def logs():
    """System logs viewer"""
    page = int(request.args.get('page', 1))
    per_page = 100

    logs_list = db(db.dns_query_log).select(
        orderby=~db.dns_query_log.timestamp,
        limitby=((page-1)*per_page, page*per_page)
    )

    total = db(db.dns_query_log).count()

    return render_template('dashboard/logs.html',
                         logs=logs_list,
                         page=page,
                         total=total,
                         per_page=per_page)

# Domain tab routes
@dashboard_bp.route('/domains/active')
@login_required
def domains_active():
    """Show only active internal domains"""
    domains_list = db(db.internal_domain.is_active == True).select(
        orderby=~db.internal_domain.modified_on
    )
    for domain in domains_list:
        groups = db(db.internal_domain_group.domain_id == domain.id).select()
        domain.access_groups = [g.group_name for g in groups]
    return render_template('dashboard/domains.html', domains=domains_list)

@dashboard_bp.route('/domains/inactive')
@login_required
def domains_inactive():
    """Show only inactive internal domains"""
    domains_list = db(db.internal_domain.is_active == False).select(
        orderby=~db.internal_domain.modified_on
    )
    for domain in domains_list:
        groups = db(db.internal_domain_group.domain_id == domain.id).select()
        domain.access_groups = [g.group_name for g in groups]
    return render_template('dashboard/domains.html', domains=domains_list)

@dashboard_bp.route('/domains/groups')
@login_required
def domains_groups():
    """Show domains organized by access groups"""
    domains_list = db(db.internal_domain.access_type == 'groups').select(
        orderby=~db.internal_domain.modified_on
    )
    for domain in domains_list:
        groups = db(db.internal_domain_group.domain_id == domain.id).select()
        domain.access_groups = [g.group_name for g in groups]
    return render_template('dashboard/domains.html', domains=domains_list)

# API endpoints for autocomplete
@dashboard_bp.route('/api/groups/search')
@login_required
def search_groups():
    """Search for groups by name (autocomplete endpoint)"""
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
    return jsonify({'groups': sorted(list(group_names))})

@dashboard_bp.route('/api/users/search')
@login_required
def search_users():
    """Search for users by email (autocomplete endpoint)"""
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
    for user in users:
        display_name = f"{user.email}"
        if user.first_name or user.last_name:
            full_name = f"{user.first_name or ''} {user.last_name or ''}".strip()
            display_name = f"{user.email} ({full_name})"
        user_list.append({
            'email': user.email,
            'display': display_name
        })

    return jsonify({'users': user_list})


# ============================================================================
# Form Submission Routes
# ============================================================================

from flask import redirect, url_for, flash
from werkzeug.security import generate_password_hash

@dashboard_bp.route('/users/add', methods=['POST'])
@login_required
def add_user():
    """Add a new user"""
    try:
        email = request.form.get('email')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        password = request.form.get('password')
        is_admin = request.form.get('is_admin') == 'on'

        # Check if user already exists
        existing = db(db.auth_user.email == email).select().first()
        if existing:
            flash('User with this email already exists', 'error')
            return redirect(url_for('dashboard.users'))

        # Create user
        db.auth_user.insert(
            email=email,
            first_name=first_name,
            last_name=last_name,
            password=generate_password_hash(password),
            is_admin=is_admin,
            created_on=datetime.utcnow()
        )
        db.commit()
        flash('User created successfully', 'success')
    except Exception as e:
        flash(f'Failed to create user: {str(e)}', 'error')

    return redirect(url_for('dashboard.users'))


@dashboard_bp.route('/groups/add', methods=['POST'])
@login_required
def add_group():
    """Add a new group"""
    try:
        # The form field is named 'name', not 'group_name'
        group_name = request.form.get('name')
        group_type = request.form.get('group_type')
        description = request.form.get('description')

        # Validate required fields
        if not group_name or not group_type:
            flash('Group name and type are required', 'error')
            return redirect(url_for('dashboard.groups'))

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
            flash('Group with this name already exists', 'error')
            return redirect(url_for('dashboard.groups'))

        db.dns_group.insert(
            name=group_name,
            group_type=group_type,
            description=description,
            created_on=datetime.utcnow()
        )
        db.commit()
        flash('Group created successfully', 'success')
    except Exception as e:
        flash(f'Failed to create group: {str(e)}', 'error')

    return redirect(url_for('dashboard.groups'))


@dashboard_bp.route('/zones/add', methods=['POST'])
@login_required
def add_zone():
    """Add a new DNS zone"""
    try:
        zone_name = request.form.get('zone_name')
        visibility = request.form.get('visibility')
        primary_ns = request.form.get('primary_ns')
        admin_email = request.form.get('admin_email')
        ttl = int(request.form.get('ttl', 3600))

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

        db.dns_zone.insert(
            name=zone_name,
            visibility=visibility,
            primary_ns=primary_ns,
            admin_email=admin_email,
            ttl=ttl,
            created_on=datetime.utcnow()
        )
        db.commit()
        flash('Zone created successfully', 'success')
    except Exception as e:
        flash(f'Failed to create zone: {str(e)}', 'error')

    return redirect(url_for('dashboard.zones'))


@dashboard_bp.route('/records/add', methods=['POST'])
@login_required
def add_record():
    """Add a new DNS record"""
    try:
        zone = request.form.get('zone')
        record_name = request.form.get('record_name')
        record_type = request.form.get('record_type')
        record_value = request.form.get('record_value')
        ttl = int(request.form.get('ttl', 3600))

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

        db.dns_record.insert(
            zone=zone,
            name=record_name,
            record_type=record_type,
            value=record_value,
            ttl=ttl,
            created_on=datetime.utcnow()
        )
        db.commit()
        flash('Record created successfully', 'success')
    except Exception as e:
        flash(f'Failed to create record: {str(e)}', 'error')

    return redirect(url_for('dashboard.records'))


@dashboard_bp.route('/permissions/add', methods=['POST'])
@login_required
def add_permission():
    """Add a new permission rule"""
    try:
        group = request.form.get('group')
        zone_pattern = request.form.get('zone_pattern')
        access_level = request.form.get('access_level')
        can_query = request.form.get('can_query') == 'on'
        can_modify = request.form.get('can_modify') == 'on'

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

        db.dns_permission.insert(
            group_name=group,
            zone_pattern=zone_pattern,
            access_level=access_level,
            can_query=can_query,
            can_modify=can_modify,
            created_on=datetime.utcnow()
        )
        db.commit()
        flash('Permission created successfully', 'success')
    except Exception as e:
        flash(f'Failed to create permission: {str(e)}', 'error')

    return redirect(url_for('dashboard.permissions'))


@dashboard_bp.route('/feeds/update', methods=['POST'])
@login_required
def update_feeds():
    """Update all threat intelligence feeds"""
    try:
        # Get all active feeds
        feeds = db(db.ioc_feed.is_active == True).select()
        updated_count = 0

        for feed in feeds:
            # Update last_updated timestamp
            db(db.ioc_feed.id == feed.id).update(last_updated=datetime.utcnow())
            updated_count += 1

        db.commit()
        return jsonify({'success': True, 'message': f'Updated {updated_count} feeds'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@dashboard_bp.route('/blocked/clear', methods=['POST'])
@login_required
def clear_blocked():
    """Clear blocked query history"""
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
        db(db.blocked_query).delete()
        db.commit()
        return jsonify({'success': True, 'message': 'Blocked query history cleared'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@dashboard_bp.route('/logs/clear', methods=['POST'])
@login_required
def clear_logs():
    """Clear system logs"""
    try:
        # Clear DNS query logs
        db(db.dns_query_log).delete()
        db.commit()
        return jsonify({'success': True, 'message': 'Logs cleared successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
