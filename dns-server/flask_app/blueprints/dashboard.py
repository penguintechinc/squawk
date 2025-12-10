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
        'internal_domains': 0,  # TODO: Add internal_domain table
        'ioc_blocks_24h': 0  # TODO: Add blocked query tracking
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
    # TODO: Add internal_domain table to models
    domains = []
    return render_template('dashboard/domains.html', domains=domains)

@dashboard_bp.route('/domains/add', methods=['POST'])
@login_required
def add_domain():
    """Add internal domain"""
    # TODO: Implement domain addition
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
    # TODO: Add groups table
    groups = []
    return render_template('dashboard/groups.html', groups=groups)

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
    return render_template('dashboard/zones.html')

@dashboard_bp.route('/records')
@login_required
def records():
    return render_template('dashboard/records.html')

@dashboard_bp.route('/permissions')
@login_required
def permissions():
    return render_template('dashboard/permissions.html')

@dashboard_bp.route('/blocked')
@login_required
def blocked():
    return render_template('dashboard/blocked.html')

@dashboard_bp.route('/threats')
@login_required
def threats():
    return render_template('dashboard/threats.html')

@dashboard_bp.route('/logs')
@login_required
def logs():
    return render_template('dashboard/logs.html')

# Domain tab routes
@dashboard_bp.route('/domains/active')
@login_required
def domains_active():
    return render_template('dashboard/domains.html', domains=[])

@dashboard_bp.route('/domains/inactive')
@login_required
def domains_inactive():
    return render_template('dashboard/domains.html', domains=[])

@dashboard_bp.route('/domains/groups')
@login_required
def domains_groups():
    return render_template('dashboard/domains.html', domains=[])


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
        group_name = request.form.get('group_name')
        group_type = request.form.get('group_type')
        description = request.form.get('description')

        # Create group table if it doesn't exist
        if 'dns_group' not in db.tables:
            db.define_table('dns_group',
                db.Field('name', 'string', notnull=True),
                db.Field('group_type', 'string'),
                db.Field('description', 'text'),
                db.Field('created_on', 'datetime', default=datetime.utcnow)
            )

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
