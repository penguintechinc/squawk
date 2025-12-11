#!/usr/bin/env python3
"""
Premium Features Module for Squawk DNS
Implements license-gated premium functionality including:
- Selective DNS routing based on user/group permissions
- Priority DNS resolution for licensed users
- Enhanced caching optimization
- Multi-tenant support
- Advanced analytics and monitoring
"""

import asyncio
import json
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from collections import deque, defaultdict
from dataclasses import dataclass
from enum import Enum
import heapq
from pydal import DAL, Field

logger = logging.getLogger(__name__)


class UserType(Enum):
    """User classification for selective DNS routing"""

    COMMUNITY = "community"
    PREMIUM = "premium"
    ENTERPRISE = "enterprise"
    INTERNAL = "internal"
    EXTERNAL = "external"


class DNSZone(Enum):
    """DNS zone classification"""

    PUBLIC = "public"
    PRIVATE = "private"
    RESTRICTED = "restricted"


@dataclass
class DNSRoute:
    """Represents a DNS routing rule"""

    pattern: str  # Domain pattern (e.g., "*.internal.company.com")
    zone: DNSZone
    allowed_users: List[UserType]
    priority: int = 0
    description: str = ""


@dataclass
class PriorityRequest:
    """Priority queue item for DNS requests"""

    priority: int
    timestamp: float
    request_id: str
    query: str
    query_type: str
    token: str

    def __lt__(self, other):
        # Higher priority value = processed first
        return self.priority > other.priority


class SelectiveDNSRouter:
    """
    Implements selective DNS routing based on user permissions.
    Premium feature that serves different DNS responses based on authentication.
    """

    def __init__(self, db_url: str = None):
        self.routes: List[DNSRoute] = []
        self.user_cache: Dict[str, UserType] = {}
        self.zone_entries: Dict[DNSZone, Dict[str, Any]] = {
            DNSZone.PUBLIC: {},
            DNSZone.PRIVATE: {},
            DNSZone.RESTRICTED: {},
        }
        self.db_url = db_url
        self._init_database()
        self._load_routes()

    def _init_database(self):
        """Initialize database tables for selective routing"""
        if not self.db_url:
            return

        db = DAL(self.db_url)

        # DNS zones table
        db.define_table(
            "dns_zones",
            Field("name", "string", unique=True),
            Field("zone_type", "string"),  # public, private, restricted
            Field("description", "text"),
            Field("created_at", "datetime", default=datetime.now),
            migrate=True,
        )

        # DNS entries per zone
        db.define_table(
            "dns_entries",
            Field("zone_id", "reference dns_zones"),
            Field("domain", "string"),
            Field("record_type", "string"),
            Field("record_data", "json"),
            Field("ttl", "integer", default=300),
            Field("created_at", "datetime", default=datetime.now),
            migrate=True,
        )

        # User group permissions
        db.define_table(
            "user_groups",
            Field("name", "string", unique=True),
            Field(
                "user_type", "string"
            ),  # community, premium, enterprise, internal, external
            Field("description", "text"),
            Field("created_at", "datetime", default=datetime.now),
            migrate=True,
        )

        # Token to user group mapping
        db.define_table(
            "token_groups",
            Field("token_id", "reference tokens"),
            Field("group_id", "reference user_groups"),
            Field("created_at", "datetime", default=datetime.now),
            migrate=True,
        )

        # Zone access permissions
        db.define_table(
            "zone_permissions",
            Field("zone_id", "reference dns_zones"),
            Field("group_id", "reference user_groups"),
            Field("can_read", "boolean", default=True),
            Field("can_write", "boolean", default=False),
            Field("created_at", "datetime", default=datetime.now),
            migrate=True,
        )

        db.commit()
        db.close()

    def _load_routes(self):
        """Load routing rules from database"""
        if not self.db_url:
            # Default routes for demo
            self.routes = [
                DNSRoute(
                    "*.internal.*",
                    DNSZone.PRIVATE,
                    [UserType.INTERNAL, UserType.ENTERPRISE],
                ),
                DNSRoute(
                    "*.corp.*",
                    DNSZone.PRIVATE,
                    [UserType.INTERNAL, UserType.ENTERPRISE],
                ),
                DNSRoute(
                    "*.dev.*",
                    DNSZone.PRIVATE,
                    [UserType.INTERNAL, UserType.PREMIUM, UserType.ENTERPRISE],
                ),
                DNSRoute("*.restricted.*", DNSZone.RESTRICTED, [UserType.ENTERPRISE]),
                DNSRoute(
                    "*",
                    DNSZone.PUBLIC,
                    [
                        UserType.COMMUNITY,
                        UserType.PREMIUM,
                        UserType.ENTERPRISE,
                        UserType.INTERNAL,
                        UserType.EXTERNAL,
                    ],
                ),
            ]
            return

        db = DAL(self.db_url)
        # Load routes from database
        # Implementation would fetch and parse routing rules
        db.close()

    def get_user_type(self, token: str) -> UserType:
        """Determine user type from token"""
        if token in self.user_cache:
            return self.user_cache[token]

        if not self.db_url:
            # Demo mode - classify based on token pattern
            if not token:
                return UserType.EXTERNAL
            elif "enterprise" in token.lower():
                return UserType.ENTERPRISE
            elif "premium" in token.lower():
                return UserType.PREMIUM
            elif "internal" in token.lower():
                return UserType.INTERNAL
            else:
                return UserType.COMMUNITY

        # Database lookup
        db = DAL(self.db_url)
        db.define_table(
            "tokens",
            Field("token", "string"),
            Field("license_type", "string"),
            migrate=False,
        )

        token_record = db(db.tokens.token == token).select().first()
        db.close()

        if token_record and token_record.license_type:
            user_type = UserType(token_record.license_type)
        else:
            user_type = UserType.COMMUNITY

        self.user_cache[token] = user_type
        return user_type

    def can_access_domain(self, domain: str, token: str) -> bool:
        """Check if user can access the requested domain"""
        user_type = self.get_user_type(token)

        for route in self.routes:
            if self._matches_pattern(domain, route.pattern):
                return user_type in route.allowed_users

        return True  # Default allow for unmatched domains

    def _matches_pattern(self, domain: str, pattern: str) -> bool:
        """Check if domain matches pattern (supports wildcards)"""
        import fnmatch

        return fnmatch.fnmatch(domain.lower(), pattern.lower())

    async def route_dns_query(
        self, domain: str, token: str, original_response: Dict
    ) -> Dict:
        """
        Route DNS query based on user permissions.
        Returns modified response based on access level.
        """
        user_type = self.get_user_type(token)

        # Check if user can access this domain
        if not self.can_access_domain(domain, token):
            # Return NXDOMAIN for unauthorized access
            return {
                "Status": 3,  # NXDOMAIN
                "Answer": [],
                "Question": [{"name": domain, "type": 1}],
                "Comment": "Domain not found",
            }

        # For private domains, check if user has permission
        for route in self.routes:
            if self._matches_pattern(domain, route.pattern):
                if (
                    route.zone == DNSZone.PRIVATE
                    and user_type not in route.allowed_users
                ):
                    # Hide private DNS entries from unauthorized users
                    return {
                        "Status": 3,  # NXDOMAIN
                        "Answer": [],
                        "Question": [{"name": domain, "type": 1}],
                        "Comment": "Domain not found",
                    }
                elif (
                    route.zone == DNSZone.RESTRICTED
                    and user_type != UserType.ENTERPRISE
                ):
                    # Restricted zones only for enterprise users
                    return {
                        "Status": 3,
                        "Answer": [],
                        "Question": [{"name": domain, "type": 1}],
                        "Comment": "Access denied",
                    }

        # User has permission, return original response
        return original_response


class PriorityDNSResolver:
    """
    Implements priority-based DNS resolution for premium users.
    Premium users get faster processing through priority queues.
    """

    def __init__(self, max_queue_size: int = 10000):
        self.priority_queue = []
        self.request_counter = 0
        self.max_queue_size = max_queue_size
        self.processing_stats = defaultdict(lambda: {"count": 0, "total_time": 0})

    def get_request_priority(self, token: str, is_licensed: bool) -> int:
        """Calculate request priority based on license status"""
        if not token:
            return 0  # Lowest priority for anonymous

        if is_licensed:
            # Check license type for priority
            if "enterprise" in token.lower():
                return 100  # Highest priority
            elif "premium" in token.lower():
                return 50  # Medium-high priority
            else:
                return 25  # Licensed but basic
        else:
            return 10  # Community users

    async def queue_request(
        self, query: str, query_type: str, token: str, is_licensed: bool
    ) -> str:
        """Add request to priority queue and return request ID"""
        priority = self.get_request_priority(token, is_licensed)
        request_id = f"req_{self.request_counter}_{time.time()}"
        self.request_counter += 1

        request = PriorityRequest(
            priority=priority,
            timestamp=time.time(),
            request_id=request_id,
            query=query,
            query_type=query_type,
            token=token,
        )

        heapq.heappush(self.priority_queue, request)

        # Maintain queue size limit
        if len(self.priority_queue) > self.max_queue_size:
            # Remove lowest priority items
            self.priority_queue = heapq.nlargest(
                self.max_queue_size, self.priority_queue
            )
            heapq.heapify(self.priority_queue)

        return request_id

    async def get_next_request(self) -> Optional[PriorityRequest]:
        """Get highest priority request from queue"""
        if self.priority_queue:
            return heapq.heappop(self.priority_queue)
        return None

    def record_processing_time(self, token: str, processing_time: float):
        """Record processing statistics for analytics"""
        stats = self.processing_stats[token]
        stats["count"] += 1
        stats["total_time"] += processing_time
        stats["avg_time"] = stats["total_time"] / stats["count"]


class EnhancedCacheManager:
    """
    Premium caching with optimization for licensed users.
    Includes predictive prefetching and longer TTLs for premium users.
    """

    def __init__(self, base_cache_manager):
        self.base_cache = base_cache_manager
        self.premium_cache = {}  # Additional cache layer for premium users
        self.prefetch_patterns = defaultdict(list)
        self.access_history = defaultdict(deque)
        self.max_history = 1000

    async def get(self, key: str, is_premium: bool = False) -> Optional[Any]:
        """Get from cache with premium optimization"""
        # Check premium cache first for premium users
        if is_premium and key in self.premium_cache:
            entry = self.premium_cache[key]
            if entry["expires"] > time.time():
                self._record_access(key, is_premium)
                return entry["data"]

        # Fall back to base cache
        result = await self.base_cache.get(key)

        if result and is_premium:
            # Store in premium cache with extended TTL
            self.premium_cache[key] = {
                "data": result,
                "expires": time.time() + 3600,  # 1 hour for premium
            }

        self._record_access(key, is_premium)
        return result

    async def set(self, key: str, value: Any, ttl: int = 300, is_premium: bool = False):
        """Set cache with premium optimization"""
        # Store in base cache
        await self.base_cache.set(key, value, ttl)

        # Store in premium cache with extended TTL
        if is_premium:
            self.premium_cache[key] = {
                "data": value,
                "expires": time.time()
                + max(ttl * 2, 3600),  # Double TTL or 1 hour minimum
            }

    def _record_access(self, key: str, is_premium: bool):
        """Record access pattern for predictive prefetching"""
        history = self.access_history[key]
        history.append(time.time())

        # Maintain history size
        if len(history) > self.max_history:
            history.popleft()

        # Analyze patterns for premium users
        if is_premium and len(history) > 10:
            self._analyze_prefetch_pattern(key, history)

    def _analyze_prefetch_pattern(self, key: str, history: deque):
        """Analyze access patterns to predict future requests"""
        # Simple pattern detection - can be enhanced with ML
        if len(history) < 2:
            return

        # Calculate average interval between accesses
        intervals = []
        for i in range(1, len(history)):
            intervals.append(history[i] - history[i - 1])

        avg_interval = sum(intervals) / len(intervals)

        # If consistent pattern, schedule prefetch
        if avg_interval < 300:  # Accessed frequently (< 5 min)
            self.prefetch_patterns[key] = {
                "interval": avg_interval,
                "next_prefetch": time.time() + avg_interval,
            }

    async def prefetch_premium(self):
        """Prefetch DNS entries for premium users based on patterns"""
        current_time = time.time()

        for key, pattern in list(self.prefetch_patterns.items()):
            if pattern["next_prefetch"] <= current_time:
                # Trigger prefetch (would need actual DNS resolution)
                # This is a placeholder for the prefetch logic
                pattern["next_prefetch"] = current_time + pattern["interval"]


class MultiTenantManager:
    """
    Manages multi-tenant architecture for enterprise customers.
    Provides isolated DNS namespaces and configurations per tenant.
    """

    def __init__(self, db_url: str = None):
        self.tenants = {}
        self.db_url = db_url
        self._init_database()

    def _init_database(self):
        """Initialize multi-tenant database schema"""
        if not self.db_url:
            return

        db = DAL(self.db_url)

        # Tenant table
        db.define_table(
            "tenants",
            Field("name", "string", unique=True),
            Field("organization", "string"),
            Field("license_key", "string"),
            Field("max_users", "integer", default=100),
            Field("max_queries_per_day", "integer", default=1000000),
            Field(
                "isolation_level", "string", default="shared"
            ),  # shared, dedicated, isolated
            Field("created_at", "datetime", default=datetime.now),
            Field("active", "boolean", default=True),
            migrate=True,
        )

        # Tenant-specific DNS zones
        db.define_table(
            "tenant_dns_zones",
            Field("tenant_id", "reference tenants"),
            Field("zone_name", "string"),
            Field("zone_type", "string"),  # authoritative, forward, stub
            Field("configuration", "json"),
            Field("created_at", "datetime", default=datetime.now),
            migrate=True,
        )

        # Tenant users
        db.define_table(
            "tenant_users",
            Field("tenant_id", "reference tenants"),
            Field("token_id", "reference tokens"),
            Field("role", "string"),  # admin, user, viewer
            Field("created_at", "datetime", default=datetime.now),
            migrate=True,
        )

        # Tenant usage tracking
        db.define_table(
            "tenant_usage",
            Field("tenant_id", "reference tenants"),
            Field("date", "date"),
            Field("query_count", "integer", default=0),
            Field("cache_hits", "integer", default=0),
            Field("blocked_queries", "integer", default=0),
            Field("unique_users", "integer", default=0),
            migrate=True,
        )

        db.commit()
        db.close()

    def get_tenant_by_token(self, token: str) -> Optional[Dict]:
        """Get tenant information from token"""
        if not self.db_url:
            return None

        db = DAL(self.db_url)

        # Define tables
        db.define_table("tokens", Field("token", "string"), migrate=False)

        db.define_table(
            "tenant_users",
            Field("tenant_id", "reference tenants"),
            Field("token_id", "reference tokens"),
            migrate=False,
        )

        db.define_table(
            "tenants",
            Field("name", "string"),
            Field("organization", "string"),
            Field("isolation_level", "string"),
            migrate=False,
        )

        # Lookup tenant
        token_record = db(db.tokens.token == token).select().first()
        if not token_record:
            db.close()
            return None

        tenant_user = db(db.tenant_users.token_id == token_record.id).select().first()
        if not tenant_user:
            db.close()
            return None

        tenant = db(db.tenants.id == tenant_user.tenant_id).select().first()
        db.close()

        if tenant:
            return {
                "id": tenant.id,
                "name": tenant.name,
                "organization": tenant.organization,
                "isolation_level": tenant.isolation_level,
            }

        return None

    def apply_tenant_isolation(self, query: str, tenant: Dict) -> str:
        """Apply tenant-specific DNS namespace isolation"""
        if not tenant:
            return query

        isolation_level = tenant.get("isolation_level", "shared")

        if isolation_level == "isolated":
            # Prefix queries with tenant namespace
            tenant_prefix = f"{tenant['name']}.tenant."
            if not query.startswith(tenant_prefix):
                # For isolated tenants, prepend their namespace
                return f"{tenant_prefix}{query}"

        elif isolation_level == "dedicated":
            # Use tenant-specific DNS servers (would be configured separately)
            pass

        return query


class AnalyticsEngine:
    """
    Advanced analytics and reporting for premium users.
    Tracks usage patterns, performance metrics, and generates reports.
    """

    def __init__(self, db_url: str = None):
        self.db_url = db_url
        self.metrics_buffer = []
        self.buffer_size = 1000
        self._init_database()

    def _init_database(self):
        """Initialize analytics database schema"""
        if not self.db_url:
            return

        db = DAL(self.db_url)

        # Query analytics
        db.define_table(
            "dns_analytics",
            Field("token_id", "reference tokens"),
            Field("query_domain", "string"),
            Field("query_type", "string"),
            Field("response_time_ms", "double"),
            Field("cache_hit", "boolean"),
            Field("blocked", "boolean"),
            Field("response_code", "integer"),
            Field("client_ip", "string"),
            Field("timestamp", "datetime", default=datetime.now),
            migrate=True,
        )

        # Aggregated metrics (hourly)
        db.define_table(
            "dns_metrics_hourly",
            Field("token_id", "reference tokens"),
            Field("hour", "datetime"),
            Field("total_queries", "integer"),
            Field("unique_domains", "integer"),
            Field("cache_hit_rate", "double"),
            Field("avg_response_time_ms", "double"),
            Field("error_rate", "double"),
            Field("blocked_count", "integer"),
            migrate=True,
        )

        # Performance metrics
        db.define_table(
            "performance_metrics",
            Field("metric_name", "string"),
            Field("metric_value", "double"),
            Field("tags", "json"),
            Field("timestamp", "datetime", default=datetime.now),
            migrate=True,
        )

        # Usage reports
        db.define_table(
            "usage_reports",
            Field("token_id", "reference tokens"),
            Field("report_type", "string"),  # daily, weekly, monthly
            Field("period_start", "datetime"),
            Field("period_end", "datetime"),
            Field("report_data", "json"),
            Field("generated_at", "datetime", default=datetime.now),
            migrate=True,
        )

        db.commit()
        db.close()

    async def track_query(
        self,
        token: str,
        domain: str,
        query_type: str,
        response_time: float,
        cache_hit: bool,
        blocked: bool,
        response_code: int,
        client_ip: str,
    ):
        """Track DNS query for analytics"""
        metric = {
            "token": token,
            "domain": domain,
            "query_type": query_type,
            "response_time_ms": response_time * 1000,
            "cache_hit": cache_hit,
            "blocked": blocked,
            "response_code": response_code,
            "client_ip": client_ip,
            "timestamp": datetime.now(),
        }

        self.metrics_buffer.append(metric)

        # Flush buffer if full
        if len(self.metrics_buffer) >= self.buffer_size:
            await self._flush_metrics()

    async def _flush_metrics(self):
        """Flush metrics buffer to database"""
        if not self.db_url or not self.metrics_buffer:
            return

        db = DAL(self.db_url)

        # Batch insert metrics
        for metric in self.metrics_buffer:
            # Would implement actual database insert here
            pass

        db.commit()
        db.close()

        self.metrics_buffer = []

    async def generate_report(self, token: str, report_type: str = "daily") -> Dict:
        """Generate usage report for premium users"""
        if not self.db_url:
            # Demo report
            return {
                "report_type": report_type,
                "period": datetime.now().isoformat(),
                "summary": {
                    "total_queries": 10000,
                    "unique_domains": 500,
                    "cache_hit_rate": 0.85,
                    "avg_response_time_ms": 25,
                    "blocked_queries": 150,
                },
                "top_domains": [
                    {"domain": "example.com", "count": 1000},
                    {"domain": "api.internal.com", "count": 800},
                ],
                "performance_trends": {
                    "response_time_trend": "improving",
                    "error_rate": 0.001,
                },
            }

        # Would implement actual report generation from database
        return {}


class EnterpriseMonitoring:
    """
    Advanced monitoring and alerting for enterprise customers.
    Includes SIEM integration, audit trails, and compliance reporting.
    """

    def __init__(self, db_url: str = None):
        self.db_url = db_url
        self.alert_thresholds = {
            "error_rate": 0.05,
            "response_time_ms": 100,
            "queries_per_second": 10000,
        }
        self._init_database()

    def _init_database(self):
        """Initialize monitoring database schema"""
        if not self.db_url:
            return

        db = DAL(self.db_url)

        # Security audit log
        db.define_table(
            "security_audit_log",
            Field(
                "event_type", "string"
            ),  # auth_failure, suspicious_query, blocked_access
            Field("severity", "string"),  # info, warning, critical
            Field("token_id", "reference tokens"),
            Field("details", "json"),
            Field("client_ip", "string"),
            Field("timestamp", "datetime", default=datetime.now),
            migrate=True,
        )

        # Alert configuration
        db.define_table(
            "alert_rules",
            Field("name", "string"),
            Field("condition", "json"),  # Condition configuration
            Field("action", "json"),  # Action to take (email, webhook, etc.)
            Field("enabled", "boolean", default=True),
            Field("created_at", "datetime", default=datetime.now),
            migrate=True,
        )

        # Compliance reports
        db.define_table(
            "compliance_reports",
            Field("report_type", "string"),  # gdpr, hipaa, sox, etc.
            Field("period_start", "datetime"),
            Field("period_end", "datetime"),
            Field("report_data", "json"),
            Field("generated_at", "datetime", default=datetime.now),
            migrate=True,
        )

        db.commit()
        db.close()

    async def log_security_event(
        self, event_type: str, severity: str, token: str, details: Dict, client_ip: str
    ):
        """Log security event for audit trail"""
        if not self.db_url:
            logger.info(f"Security event: {event_type} - {severity} - {details}")
            return

        # Would implement database logging here

    async def check_alerts(self, metrics: Dict):
        """Check if any alert thresholds are exceeded"""
        alerts = []

        if metrics.get("error_rate", 0) > self.alert_thresholds["error_rate"]:
            alerts.append(
                {
                    "type": "high_error_rate",
                    "severity": "critical",
                    "value": metrics["error_rate"],
                    "threshold": self.alert_thresholds["error_rate"],
                }
            )

        if (
            metrics.get("response_time_ms", 0)
            > self.alert_thresholds["response_time_ms"]
        ):
            alerts.append(
                {
                    "type": "slow_response",
                    "severity": "warning",
                    "value": metrics["response_time_ms"],
                    "threshold": self.alert_thresholds["response_time_ms"],
                }
            )

        for alert in alerts:
            await self._trigger_alert(alert)

    async def _trigger_alert(self, alert: Dict):
        """Trigger alert action (email, webhook, etc.)"""
        logger.warning(f"Alert triggered: {alert}")
        # Would implement actual alert actions here

    def export_siem_format(self, events: List[Dict], format_type: str = "cef") -> str:
        """Export events in SIEM-compatible format (CEF, LEEF, etc.)"""
        if format_type == "cef":
            # Common Event Format
            output = []
            for event in events:
                cef_event = (
                    f"CEF:0|SquawkDNS|DNS|1.0|{event.get('event_type', 'unknown')}|"
                    f"{event.get('description', '')}|{event.get('severity', 3)}|"
                    f"src={event.get('client_ip', '')} "
                    f"dst={event.get('server_ip', '')} "
                    f"msg={json.dumps(event.get('details', {}))}"
                )
                output.append(cef_event)
            return "\n".join(output)

        # Would implement other formats
        return json.dumps(events)


class PremiumFeatureManager:
    """
    Central manager for all premium features.
    Coordinates between different premium components.
    """

    def __init__(self, db_url: str = None, license_server_url: str = None):
        self.db_url = db_url
        self.license_server_url = license_server_url

        # Initialize premium components
        self.selective_router = SelectiveDNSRouter(db_url)
        self.priority_resolver = PriorityDNSResolver()
        self.enhanced_cache = None  # Will be set with base cache manager
        self.multi_tenant = MultiTenantManager(db_url)
        self.analytics = AnalyticsEngine(db_url)
        self.monitoring = EnterpriseMonitoring(db_url)

        self.license_cache = {}

    def set_cache_manager(self, base_cache_manager):
        """Set the base cache manager for enhanced caching"""
        self.enhanced_cache = EnhancedCacheManager(base_cache_manager)

    async def check_license(self, token: str) -> Dict:
        """Check license status for token"""
        if token in self.license_cache:
            cached = self.license_cache[token]
            if cached["expires"] > time.time():
                return cached["data"]

        # Would implement actual license server check
        is_licensed = "premium" in token.lower() or "enterprise" in token.lower()
        license_type = (
            "enterprise"
            if "enterprise" in token.lower()
            else ("premium" if "premium" in token.lower() else "community")
        )

        result = {
            "is_licensed": is_licensed,
            "license_type": license_type,
            "features": self._get_features_for_license(license_type),
        }

        self.license_cache[token] = {
            "data": result,
            "expires": time.time() + 3600,  # Cache for 1 hour
        }

        return result

    def _get_features_for_license(self, license_type: str) -> List[str]:
        """Get enabled features based on license type"""
        features = {
            "community": ["basic_dns", "standard_cache"],
            "premium": [
                "basic_dns",
                "standard_cache",
                "selective_routing",
                "priority_resolution",
                "enhanced_cache",
                "analytics",
            ],
            "enterprise": [
                "basic_dns",
                "standard_cache",
                "selective_routing",
                "priority_resolution",
                "enhanced_cache",
                "analytics",
                "multi_tenant",
                "enterprise_monitoring",
                "siem_integration",
                "compliance_reporting",
            ],
        }
        return features.get(license_type, features["community"])

    async def process_dns_request(
        self, query: str, query_type: str, token: str, client_ip: str, original_resolver
    ) -> Dict:
        """
        Process DNS request with premium features.
        This is the main entry point for premium processing.
        """
        start_time = time.time()

        # Check license
        license_info = await self.check_license(token)
        is_licensed = license_info["is_licensed"]
        features = license_info["features"]

        # Apply multi-tenant isolation if enabled
        if "multi_tenant" in features:
            tenant = self.multi_tenant.get_tenant_by_token(token)
            if tenant:
                query = self.multi_tenant.apply_tenant_isolation(query, tenant)

        # Check cache with enhancement for premium users
        cache_hit = False
        cached_result = None

        if self.enhanced_cache:
            cached_result = await self.enhanced_cache.get(
                f"dns:{query}:{query_type}", is_premium="enhanced_cache" in features
            )
            cache_hit = cached_result is not None

        if cached_result:
            response = cached_result
        else:
            # Queue request with priority
            if "priority_resolution" in features:
                request_id = await self.priority_resolver.queue_request(
                    query, query_type, token, is_licensed
                )
                # In production, would process from queue
                # For now, process directly

            # Resolve DNS
            response = await original_resolver(query, query_type)

            # Cache the result with enhancement
            if self.enhanced_cache and response.get("Status") == 0:
                ttl = response.get("TTL", 300)
                await self.enhanced_cache.set(
                    f"dns:{query}:{query_type}",
                    response,
                    ttl,
                    is_premium="enhanced_cache" in features,
                )

        # Apply selective routing
        if "selective_routing" in features:
            response = await self.selective_router.route_dns_query(
                query, token, response
            )

        # Track analytics
        if "analytics" in features:
            processing_time = time.time() - start_time
            await self.analytics.track_query(
                token,
                query,
                query_type,
                processing_time,
                cache_hit,
                False,
                response.get("Status", 0),
                client_ip,
            )

        # Enterprise monitoring
        if "enterprise_monitoring" in features:
            if response.get("Status", 0) != 0:
                await self.monitoring.log_security_event(
                    "dns_error",
                    "warning",
                    token,
                    {"query": query, "error": response.get("Status")},
                    client_ip,
                )

        return response


# Export the main manager
premium_manager = None


def init_premium_features(
    db_url: str = None, license_server_url: str = None, base_cache_manager=None
) -> PremiumFeatureManager:
    """Initialize premium features with configuration"""
    global premium_manager
    premium_manager = PremiumFeatureManager(db_url, license_server_url)
    if base_cache_manager:
        premium_manager.set_cache_manager(base_cache_manager)
    return premium_manager
