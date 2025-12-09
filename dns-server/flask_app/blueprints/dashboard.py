"""
Dashboard Blueprint for Flask Application
Main dashboard and monitoring views
"""

from flask import Blueprint, render_template, jsonify, request
from flask_login import login_required, current_user
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from models import define_tables
from pydal import DAL
from datetime import datetime, timedelta

dashboard_bp = Blueprint('dashboard', __name__)

# Get database instance
db = DAL(os.environ.get('DATABASE_URI', 'sqlite://storage.db'), 
         folder=os.path.join(os.path.dirname(__file__), '..', 'databases'))
define_tables(db)

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
        'total_ioc_entries': db.ioc_entry.count(),
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
