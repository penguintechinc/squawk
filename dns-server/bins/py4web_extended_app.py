#!/usr/bin/env python3
"""
Py4web Extended Application for Squawk DNS
Uses py4web's native REST API, authentication, and other built-in features.
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional

# py4web imports
from py4web import action, request, response, Field, DAL
from py4web.utils.auth import Auth
from py4web.utils.cors import CORS
from py4web.utils.form import Form, FormStyleBulma
from py4web.utils.publisher import Publisher
from py4web.utils.grid import Grid
from py4web.core import Template, HTTP, redirect, URL

# Feature managers
from whois_manager import WHOISManager
from ioc_manager import IOCManager
from client_config_api import ClientConfigManager
from prometheus_metrics import get_metrics_instance
from performance_api import PerformanceDataManager

logger = logging.getLogger(__name__)

# Database connection
DB_URL = os.environ.get("DB_URL", "sqlite://storage.db")
db = DAL(DB_URL)

# Authentication system
auth = Auth(session, db)

# CORS for API endpoints
cors = CORS()

# Define database tables using py4web conventions
db.define_table(
    "whois_cache",
    Field("query", "string", unique=True),
    Field("query_type", "string"),
    Field("whois_data", "json"),
    Field("parsed_data", "json"),
    Field("registrar", "string"),
    Field("creation_date", "datetime"),
    Field("expiration_date", "datetime"),
    Field("nameservers", "json"),
    Field("query_timestamp", "datetime", default=datetime.now),
    Field("last_updated", "datetime", default=datetime.now),
    auth.signature,  # Adds created_by, created_on, modified_by, modified_on
)

db.define_table(
    "ioc_feeds",
    Field("name", "string", unique=True),
    Field("url", "string"),
    Field("feed_type", "string"),
    Field("format", "string"),
    Field("enabled", "boolean", default=True),
    Field("update_frequency_hours", "integer", default=6),
    Field("last_update", "datetime"),
    Field("last_success", "datetime"),
    Field("entry_count", "integer", default=0),
    auth.signature,
)

db.define_table(
    "ioc_entries",
    Field("feed_id", "reference ioc_feeds"),
    Field("indicator", "string"),
    Field("indicator_type", "string"),
    Field("threat_type", "string"),
    Field("confidence", "integer", default=50),
    Field("description", "text"),
    Field("first_seen", "datetime"),
    Field("last_seen", "datetime"),
    auth.signature,
)

db.define_table(
    "deployment_domains",
    Field("name", "string", unique=True),
    Field("description", "text"),
    Field("jwt_token", "string", unique=True),
    Field("jwt_expires", "datetime"),
    Field("active", "boolean", default=True),
    auth.signature,
)

db.define_table(
    "client_configs",
    Field("name", "string"),
    Field("domain_id", "reference deployment_domains"),
    Field("config_data", "json"),
    Field("version", "integer", default=1),
    Field("description", "text"),
    Field("active", "boolean", default=True),
    auth.signature,
)

db.define_table(
    "client_instances",
    Field("client_id", "string", unique=True),
    Field("domain_id", "reference deployment_domains"),
    Field("config_id", "reference client_configs"),
    Field("hostname", "string"),
    Field("ip_address", "string"),
    Field("last_checkin", "datetime"),
    Field("last_config_pull", "datetime"),
    Field("client_version", "string"),
    Field("os_info", "string"),
    Field("status", "string", default="active"),
    auth.signature,
)

# Initialize feature managers
whois_manager = WHOISManager(DB_URL)
ioc_manager = IOCManager(DB_URL)
config_manager = ClientConfigManager(DB_URL)
performance_manager = PerformanceDataManager(DB_URL)


# Py4web authentication decorator
def auth_required(func):
    """Decorator to require authentication for API endpoints"""

    def wrapper(*args, **kwargs):
        if not auth.is_logged_in:
            # Check for API token authentication
            token = request.headers.get("X-Auth-Token") or request.headers.get(
                "Authorization"
            )
            if token:
                if token.startswith("Bearer "):
                    token = token[7:]
                # Validate token against database
                token_record = (
                    db(
                        (db.auth_user.api_token == token)
                        & (db.auth_user.active == True)
                    )
                    .select()
                    .first()
                )
                if not token_record:
                    raise HTTP(401, "Invalid API token")
            else:
                raise HTTP(401, "Authentication required")
        return func(*args, **kwargs)

    return wrapper


# ============================================================================
# REST API Endpoints using py4web's native REST capabilities
# ============================================================================

# Publisher for REST API
publisher = Publisher(
    db,
    policy=dict(
        whois_cache=["GET"],
        ioc_feeds=["GET", "POST", "PUT", "DELETE"],
        ioc_entries=["GET", "POST"],
        deployment_domains=["GET", "POST", "PUT"],
        client_configs=["GET", "POST", "PUT", "DELETE"],
        client_instances=["GET", "POST", "PUT"],
    ),
)


@action("api/rest/<tablename>")
@action("api/rest/<tablename>/<int:record_id>", method=["GET", "POST", "PUT", "DELETE"])
@cors.enable
@auth_required
def rest_api(tablename, record_id=None):
    """
    Native py4web REST API for database operations.
    Automatically handles CRUD operations with proper authentication.
    """
    return publisher(tablename, record_id)


# ============================================================================
# WHOIS API Endpoints
# ============================================================================


@action("api/whois/lookup")
@action.uses(cors)
@auth_required
def whois_lookup():
    """WHOIS lookup API using py4web structure"""
    if request.method == "GET":
        query = request.params.domain or request.params.ip
        query_type = "domain" if request.params.domain else "ip"
        force_refresh = request.params.force == "true"
    else:
        data = request.json
        query = data.get("query")
        query_type = data.get("type", "domain")
        force_refresh = data.get("force_refresh", False)

    if not query:
        raise HTTP(400, "Query parameter required")

    client_ip = request.environ.get(
        "HTTP_X_FORWARDED_FOR", request.environ.get("REMOTE_ADDR")
    )

    # Use async wrapper for compatibility
    import asyncio

    async def lookup():
        if query_type == "domain":
            return await whois_manager.lookup_domain(query, client_ip, force_refresh)
        else:
            return await whois_manager.lookup_ip(query, client_ip, force_refresh)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    result = loop.run_until_complete(lookup())
    loop.close()

    return result


@action("api/whois/search")
@action.uses(cors)
@auth_required
def whois_search():
    """WHOIS search API"""
    search_term = request.params.q
    search_field = request.params.field
    limit = int(request.params.limit or 50)

    if not search_term:
        raise HTTP(400, "Search term required (q parameter)")

    # Use py4web's built-in async support
    import asyncio

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    results = loop.run_until_complete(
        whois_manager.search_whois(search_term, search_field, limit)
    )
    loop.close()

    return dict(
        results=results,
        count=len(results),
        search_term=search_term,
        search_field=search_field,
    )


# ============================================================================
# IOC API Endpoints
# ============================================================================


@action("api/ioc/check")
@action.uses(cors)
@auth_required
def ioc_check():
    """IOC check API"""
    if request.method == "GET":
        query = request.params.domain or request.params.ip
        query_type = "domain" if request.params.domain else "ip"
    else:
        data = request.json
        query = data.get("query")
        query_type = data.get("type", "domain")

    if not query:
        raise HTTP(400, "Query parameter required")

    token_id = auth.user_id  # Get from py4web auth

    import asyncio

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    if query_type == "domain":
        should_block, reason = loop.run_until_complete(
            ioc_manager.check_domain(query, token_id)
        )
    else:
        should_block, reason = loop.run_until_complete(
            ioc_manager.check_ip(query, token_id)
        )

    loop.close()

    return dict(
        query=query,
        type=query_type,
        blocked=should_block,
        reason=reason,
        timestamp=datetime.now().isoformat(),
    )


@action("api/ioc/overrides")
@action("api/ioc/overrides", method=["POST", "DELETE"])
@action.uses(cors)
@auth_required
def ioc_overrides():
    """IOC override management API"""
    token_id = auth.user_id

    import asyncio

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    if request.method == "GET":
        # Get overrides for this user
        overrides = loop.run_until_complete(ioc_manager.get_overrides(token_id))
        loop.close()
        return dict(overrides=overrides)

    elif request.method == "POST":
        # Add new override
        data = request.json

        indicator = data.get("indicator")
        indicator_type = data.get("type")
        override_type = data.get("override")
        reason = data.get("reason", "")
        expires_at = data.get("expires_at")

        if not all([indicator, indicator_type, override_type]):
            raise HTTP(400, "indicator, type, and override are required")

        if expires_at:
            expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))

        success = loop.run_until_complete(
            ioc_manager.add_override(
                token_id,
                indicator,
                indicator_type,
                override_type,
                reason,
                str(auth.user.email),
                expires_at,
            )
        )
        loop.close()

        if success:
            return dict(success=True, message="Override added")
        else:
            raise HTTP(500, "Failed to add override")

    elif request.method == "DELETE":
        # Remove override
        data = request.json
        indicator = data.get("indicator")
        indicator_type = data.get("type")

        if not all([indicator, indicator_type]):
            raise HTTP(400, "indicator and type are required")

        success = loop.run_until_complete(
            ioc_manager.remove_override(token_id, indicator, indicator_type)
        )
        loop.close()

        if success:
            return dict(success=True, message="Override removed")
        else:
            raise HTTP(404, "Override not found")


# ============================================================================
# Performance Monitoring API (Enterprise Feature)
# ============================================================================


@action("api/performance/upload", method="POST")
@action.uses(cors)
@auth_required
def performance_upload():
    """Performance data upload endpoint for Go clients"""
    data = request.json

    if not data:
        raise HTTP(400, "No data provided")

    client_id = data.get("client_id")
    stats_data = data.get("statistics", [])

    if not client_id:
        raise HTTP(400, "client_id is required")

    if not stats_data:
        raise HTTP(400, "No statistics data provided")

    # Get client IP and user agent
    client_ip = request.environ.get(
        "HTTP_X_FORWARDED_FOR", request.environ.get("REMOTE_ADDR")
    )
    user_agent = request.environ.get("HTTP_USER_AGENT", "")

    # Upload performance data
    import asyncio

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    result = loop.run_until_complete(
        performance_manager.upload_performance_stats(
            client_id, stats_data, client_ip, user_agent
        )
    )
    loop.close()

    if result["success"]:
        return result
    else:
        raise HTTP(500, result.get("error", "Failed to upload performance data"))


@action("api/performance/dashboard/<client_id>")
@action.uses(cors)
@auth_required
def performance_dashboard(client_id):
    """Get performance dashboard data for a specific client"""
    days = int(request.params.days or 7)

    dashboard_data = performance_manager.get_client_performance_dashboard(
        client_id, days
    )

    if "error" in dashboard_data:
        raise HTTP(500, dashboard_data["error"])

    return dashboard_data


@action("api/performance/stats")
@action.uses(cors)
@auth_required
def performance_stats():
    """Get overall performance statistics for admin dashboard"""
    stats = performance_manager.get_performance_stats()

    if "error" in stats:
        raise HTTP(500, stats["error"])

    return stats


# ============================================================================
# Client Configuration API using py4web REST
# ============================================================================


@action("api/client/config/pull")
@action.uses(cors)
@auth_required
def client_config_pull():
    """Client configuration pull API"""
    client_id = request.params.client_id
    domain_jwt = request.params.domain_jwt or request.headers.get("X-Domain-JWT")

    if not all([client_id, domain_jwt]):
        raise HTTP(400, "client_id and domain_jwt are required")

    # Get user token and certificate info
    user_token = request.headers.get("X-Auth-Token") or request.headers.get(
        "Authorization"
    )
    if user_token and user_token.startswith("Bearer "):
        user_token = user_token[7:]

    client_cert_subject = request.headers.get("X-SSL-Client-S-DN")

    result = config_manager.pull_client_config(
        client_id, domain_jwt, user_token, client_cert_subject
    )

    if result["success"]:
        return result
    else:
        raise HTTP(400, result.get("error", "Configuration pull failed"))


@action("api/client/register", method="POST")
@action.uses(cors)
@auth_required
def client_register():
    """Client registration API"""
    data = request.json

    client_id = data.get("client_id")
    domain_jwt = data.get("domain_jwt")
    hostname = data.get("hostname")
    ip_address = data.get("ip_address")
    client_version = data.get("client_version", "")
    os_info = data.get("os_info", "")

    if not all([client_id, domain_jwt, hostname, ip_address]):
        raise HTTP(400, "client_id, domain_jwt, hostname, and ip_address are required")

    user_token = request.headers.get("X-Auth-Token") or request.headers.get(
        "Authorization"
    )
    if user_token and user_token.startswith("Bearer "):
        user_token = user_token[7:]

    client_cert_subject = request.headers.get("X-SSL-Client-S-DN")

    result = config_manager.register_client(
        client_id,
        domain_jwt,
        hostname,
        ip_address,
        client_version,
        os_info,
        user_token,
        client_cert_subject,
    )

    if result["success"]:
        return result
    else:
        raise HTTP(400, result.get("error", "Client registration failed"))


# ============================================================================
# Prometheus Metrics Endpoint
# ============================================================================


@action("metrics")
def prometheus_metrics():
    """Prometheus metrics endpoint"""
    # Optional authentication for metrics
    metrics_auth = request.headers.get("X-Metrics-Token")
    if metrics_auth and not auth.is_logged_in:
        # Validate metrics token
        token_valid = db(db.auth_user.api_token == metrics_auth).select().first()
        if not token_valid:
            raise HTTP(401, "Invalid metrics token")

    prometheus = get_metrics_instance()
    if not prometheus:
        response.headers["Content-Type"] = "text/plain"
        return "# Prometheus metrics not initialized\n"

    metrics_output, content_type = prometheus.get_metrics_endpoint()
    response.headers["Content-Type"] = content_type
    return metrics_output


# ============================================================================
# Web UI using py4web Forms and Grid
# ============================================================================


@action("whois")
@action.uses("whois.html", auth.user)
def whois_ui():
    """WHOIS lookup web interface using py4web forms"""
    form = Form(
        [
            Field("query", "string", label="Domain or IP", requires=lambda v: v),
            Field(
                "query_type",
                "string",
                default="domain",
                requires=lambda v: v in ["domain", "ip"],
                widget=lambda field, value: f'<select name="{field.name}"><option value="domain">Domain</option><option value="ip">IP Address</option></select>',
            ),
            Field("force_refresh", "boolean", label="Force Refresh"),
        ],
        formstyle=FormStyleBulma,
    )

    result = None
    if form.accepted:
        # Perform WHOIS lookup
        import asyncio

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        if form.vars.query_type == "domain":
            result = loop.run_until_complete(
                whois_manager.lookup_domain(
                    form.vars.query, None, form.vars.force_refresh
                )
            )
        else:
            result = loop.run_until_complete(
                whois_manager.lookup_ip(form.vars.query, None, form.vars.force_refresh)
            )
        loop.close()

    return dict(form=form, result=result)


@action("ioc/feeds")
@action.uses("ioc_feeds.html", auth.user)
def ioc_feeds_ui():
    """IOC feeds management interface using py4web Grid"""
    grid = Grid(
        path=["ioc", "feeds"],
        query=db.ioc_feeds.created_by == auth.user_id,
        orderby=[db.ioc_feeds.name],
        create=True,
        editable=True,
        deletable=True,
        details=True,
        formstyle=FormStyleBulma,
    )
    return dict(grid=grid)


@action("client/configs")
@action.uses("client_configs.html", auth.user)
def client_configs_ui():
    """Client configurations management interface"""
    grid = Grid(
        path=["client", "configs"],
        query=db.client_configs.created_by == auth.user_id,
        orderby=[db.client_configs.name],
        create=True,
        editable=True,
        deletable=True,
        details=True,
        formstyle=FormStyleBulma,
    )
    return dict(grid=grid)


@action("client/instances")
@action.uses("client_instances.html", auth.user)
def client_instances_ui():
    """Client instances monitoring interface"""
    # Join with deployment domains for better display
    query = db.client_instances.domain_id == db.deployment_domains.id

    grid = Grid(
        path=["client", "instances"],
        query=query,
        left=[
            db.deployment_domains.on(
                db.client_instances.domain_id == db.deployment_domains.id
            )
        ],
        orderby=[db.client_instances.last_checkin],
        create=False,  # Clients register themselves
        editable=True,
        deletable=True,
        details=True,
        formstyle=FormStyleBulma,
    )
    return dict(grid=grid)


@action("performance")
@action.uses("performance.html", auth.user)
def performance_ui():
    """Performance monitoring web interface"""
    # Get overall performance stats
    stats = performance_manager.get_performance_stats()

    # Get list of clients for dropdown (if any)
    from pydal import DAL

    db_temp = DAL(DB_URL)
    clients = db_temp().select(
        db_temp.performance_stats.client_id,
        distinct=True,
        orderby=db_temp.performance_stats.client_id,
    )
    db_temp.close()

    return dict(stats=stats, clients=clients)


@action("performance/client/<client_id>")
@action.uses("performance_client.html", auth.user)
def performance_client_ui(client_id):
    """Individual client performance dashboard"""
    days = int(request.params.days or 7)
    dashboard_data = performance_manager.get_client_performance_dashboard(
        client_id, days
    )

    return dict(client_id=client_id, dashboard=dashboard_data, days=days)


# ============================================================================
# Dashboard
# ============================================================================


@action("dashboard")
@action.uses("dashboard.html", auth.user)
def dashboard():
    """Main dashboard showing statistics from all services"""
    # Get statistics
    import asyncio

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    whois_stats = loop.run_until_complete(whois_manager.get_stats())
    ioc_stats = loop.run_until_complete(ioc_manager.get_stats())
    config_stats = config_manager.get_client_stats()

    loop.close()

    # Get Prometheus metrics
    prometheus = get_metrics_instance()
    dns_stats = prometheus.get_current_stats() if prometheus else {}

    return dict(
        whois_stats=whois_stats,
        ioc_stats=ioc_stats,
        config_stats=config_stats,
        dns_stats=dns_stats,
    )


# ============================================================================
# Background Tasks using py4web Scheduler
# ============================================================================

from py4web.utils.scheduler import Scheduler

scheduler = Scheduler(
    tasks={
        "update_ioc_feeds": dict(
            function=lambda: asyncio.run(ioc_manager.update_all_feeds()),
            period=3600,  # Every hour
            immediate=False,
        ),
        "cleanup_whois_cache": dict(
            function=lambda: asyncio.run(whois_manager.cleanup_old_data()),
            period=86400,  # Daily
            immediate=False,
        ),
        "cleanup_inactive_clients": dict(
            function=lambda: config_manager.cleanup_inactive_clients(),
            period=86400,  # Daily
            immediate=False,
        ),
    }
)

# Commit database changes
db.commit()

logger.info("Py4web extended application initialized")
