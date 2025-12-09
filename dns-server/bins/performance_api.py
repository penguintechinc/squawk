#!/usr/bin/env python3
"""
Performance Data API for Squawk DNS
Handles DNS over HTTP performance statistics upload and monitoring from Go clients.
"""

import json
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pydal import DAL, Field
from collections import defaultdict
import statistics

logger = logging.getLogger(__name__)


class PerformanceDataManager:
    """
    Manages DNS performance data collection and analysis from Go clients.
    Provides Enterprise-level performance monitoring and analytics.
    """

    def __init__(self, db_url: str):
        self.db_url = db_url
        self._init_database()

    def _init_database(self):
        """Initialize performance monitoring database schema"""
        db = DAL(self.db_url)

        # Performance statistics table
        db.define_table(
            "performance_stats",
            # Request Information
            Field("client_id", "string"),
            Field("server_url", "string"),
            Field("test_domain", "string"),
            Field("query_type", "string"),
            Field("timestamp", "datetime"),
            # Network Timing (milliseconds for easier analysis)
            Field("dns_lookup_ms", "double"),
            Field("tcp_connection_ms", "double"),
            Field("tls_handshake_ms", "double"),
            Field("server_processing_ms", "double"),
            Field("content_transfer_ms", "double"),
            Field("total_time_ms", "double"),
            Field("name_lookup_ms", "double"),
            Field("connect_ms", "double"),
            # HTTP Details
            Field("http_status", "integer"),
            Field("http_headers_size", "integer"),
            Field("response_size", "integer"),
            # DNS Response Details
            Field("dns_status", "string"),
            Field("dns_answer_count", "integer"),
            Field("dns_response_code", "integer"),
            Field("cache_hit", "boolean"),
            # Network Information
            Field("local_addr", "string"),
            Field("remote_addr", "string"),
            Field("protocol", "string"),
            Field("tls_version", "string"),
            Field("tls_cipher_suite", "string"),
            # Error Information
            Field("error_type", "string"),
            Field("error_message", "text"),
            Field("successful", "boolean"),
            # Performance Metrics
            Field("jitter_ms", "double"),
            Field("packet_loss", "double"),
            Field("retries", "integer"),
            # Metadata
            Field("created_at", "datetime", default=datetime.now),
            Field("client_ip", "string"),
            Field("user_agent", "string"),
            migrate=True,
        )

        # Client performance summary (aggregated data)
        db.define_table(
            "client_performance_summary",
            Field("client_id", "string"),
            Field("server_url", "string"),
            Field("test_domain", "string"),
            Field("date", "date"),
            # Aggregated metrics
            Field("total_tests", "integer"),
            Field("successful_tests", "integer"),
            Field("avg_response_time_ms", "double"),
            Field("min_response_time_ms", "double"),
            Field("max_response_time_ms", "double"),
            Field("median_response_time_ms", "double"),
            Field("p95_response_time_ms", "double"),
            Field("p99_response_time_ms", "double"),
            # Error rates
            Field("error_rate", "double"),
            Field("timeout_rate", "double"),
            Field("dns_error_rate", "double"),
            # Network metrics
            Field("avg_dns_lookup_ms", "double"),
            Field("avg_tls_handshake_ms", "double"),
            Field("cache_hit_rate", "double"),
            Field("created_at", "datetime", default=datetime.now),
            Field("updated_at", "datetime", default=datetime.now),
            migrate=True,
        )

        # Performance alerts table
        db.define_table(
            "performance_alerts",
            Field("client_id", "string"),
            Field("server_url", "string"),
            Field(
                "alert_type", "string"
            ),  # slow_response, high_error_rate, connection_issues
            Field("severity", "string"),  # low, medium, high, critical
            Field("description", "text"),
            Field("threshold_value", "double"),
            Field("current_value", "double"),
            Field("alert_time", "datetime", default=datetime.now),
            Field("resolved", "boolean", default=False),
            Field("resolved_time", "datetime"),
            migrate=True,
        )

        # Performance thresholds configuration
        db.define_table(
            "performance_thresholds",
            Field("metric_name", "string"),
            Field("warning_threshold", "double"),
            Field("critical_threshold", "double"),
            Field("enabled", "boolean", default=True),
            Field("description", "text"),
            Field("created_at", "datetime", default=datetime.now),
            migrate=True,
        )

        # Initialize default thresholds
        self._create_default_thresholds(db)

        db.commit()
        db.close()

    def _create_default_thresholds(self, db: DAL):
        """Create default performance thresholds"""
        default_thresholds = [
            {
                "metric_name": "response_time_ms",
                "warning_threshold": 500.0,  # 500ms
                "critical_threshold": 1000.0,  # 1 second
                "description": "Total DNS response time",
            },
            {
                "metric_name": "error_rate",
                "warning_threshold": 0.05,  # 5%
                "critical_threshold": 0.10,  # 10%
                "description": "DNS query error rate",
            },
            {
                "metric_name": "dns_lookup_ms",
                "warning_threshold": 100.0,  # 100ms
                "critical_threshold": 250.0,  # 250ms
                "description": "DNS lookup time",
            },
            {
                "metric_name": "tls_handshake_ms",
                "warning_threshold": 200.0,  # 200ms
                "critical_threshold": 500.0,  # 500ms
                "description": "TLS handshake time",
            },
        ]

        for threshold in default_thresholds:
            existing = (
                db(db.performance_thresholds.metric_name == threshold["metric_name"])
                .select()
                .first()
            )
            if not existing:
                db.performance_thresholds.insert(**threshold)

    async def upload_performance_stats(
        self,
        client_id: str,
        stats_data: List[Dict],
        client_ip: str = None,
        user_agent: str = None,
    ) -> Dict:
        """Upload performance statistics from Go clients"""
        db = DAL(self.db_url)

        try:
            uploaded_count = 0
            error_count = 0

            for stat in stats_data:
                try:
                    # Validate required fields
                    if not self._validate_performance_stat(stat):
                        error_count += 1
                        continue

                    # Convert timing data from nanoseconds to milliseconds
                    processed_stat = self._process_timing_data(stat)
                    processed_stat["client_id"] = client_id
                    processed_stat["client_ip"] = client_ip
                    processed_stat["user_agent"] = user_agent

                    # Insert into database
                    db.performance_stats.insert(**processed_stat)
                    uploaded_count += 1

                except Exception as e:
                    logger.error(f"Failed to process performance stat: {e}")
                    error_count += 1

            db.commit()

            # Trigger analysis for this client (async)
            if uploaded_count > 0:
                await self._analyze_client_performance(client_id)

            return {
                "success": True,
                "uploaded": uploaded_count,
                "errors": error_count,
                "total": len(stats_data),
                "message": f"Successfully uploaded {uploaded_count} performance statistics",
            }

        except Exception as e:
            logger.error(f"Failed to upload performance stats: {e}")
            return {
                "success": False,
                "error": str(e),
                "uploaded": 0,
                "errors": len(stats_data),
            }
        finally:
            db.close()

    def _validate_performance_stat(self, stat: Dict) -> bool:
        """Validate performance statistics data"""
        required_fields = [
            "timestamp",
            "server_url",
            "test_domain",
            "total_time",
            "successful",
        ]

        for field in required_fields:
            if field not in stat:
                return False

        # Validate timestamp
        try:
            if isinstance(stat["timestamp"], str):
                datetime.fromisoformat(stat["timestamp"].replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return False

        return True

    def _process_timing_data(self, stat: Dict) -> Dict:
        """Process timing data from Go client format to database format"""
        processed = {}

        # Basic fields
        processed["timestamp"] = self._parse_timestamp(stat.get("timestamp"))
        processed["server_url"] = stat.get("server_url", "")
        processed["test_domain"] = stat.get("test_domain", "")
        processed["query_type"] = stat.get("query_type", "A")

        # Convert timing data from nanoseconds to milliseconds
        timing_fields = [
            "dns_lookup",
            "tcp_connection",
            "tls_handshake",
            "server_processing",
            "content_transfer",
            "total_time",
            "name_lookup",
            "connect",
            "jitter",
        ]

        for field in timing_fields:
            if field in stat and stat[field]:
                # Handle nested duration object from Go JSON
                if isinstance(stat[field], dict) and "milliseconds" in stat[field]:
                    processed[f"{field}_ms"] = float(stat[field]["milliseconds"])
                elif isinstance(stat[field], dict) and "nanoseconds" in stat[field]:
                    processed[f"{field}_ms"] = float(stat[field]["nanoseconds"]) / 1e6
                elif isinstance(stat[field], (int, float)):
                    # Assume it's already in milliseconds or nanoseconds
                    processed[f"{field}_ms"] = (
                        float(stat[field]) / 1e6
                        if stat[field] > 1e6
                        else float(stat[field])
                    )

        # HTTP details
        processed["http_status"] = stat.get("http_status", 0)
        processed["http_headers_size"] = stat.get("http_headers_size", 0)
        processed["response_size"] = stat.get("response_size", 0)

        # DNS details
        processed["dns_status"] = stat.get("dns_status", "")
        processed["dns_answer_count"] = stat.get("dns_answer_count", 0)
        processed["dns_response_code"] = stat.get("dns_response_code", 0)
        processed["cache_hit"] = stat.get("cache_hit", False)

        # Network info
        processed["local_addr"] = stat.get("local_addr", "")
        processed["remote_addr"] = stat.get("remote_addr", "")
        processed["protocol"] = stat.get("protocol", "")
        processed["tls_version"] = stat.get("tls_version", "")
        processed["tls_cipher_suite"] = stat.get("tls_cipher_suite", "")

        # Error info
        processed["error_type"] = stat.get("error_type", "")
        processed["error_message"] = stat.get("error_message", "")
        processed["successful"] = stat.get("successful", False)

        # Performance metrics
        processed["packet_loss"] = stat.get("packet_loss", 0.0)
        processed["retries"] = stat.get("retries", 0)

        return processed

    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse timestamp string to datetime object"""
        if isinstance(timestamp_str, datetime):
            return timestamp_str

        try:
            # Handle different timestamp formats
            if timestamp_str.endswith("Z"):
                timestamp_str = timestamp_str[:-1] + "+00:00"

            return datetime.fromisoformat(timestamp_str)
        except (ValueError, AttributeError):
            return datetime.now()

    async def _analyze_client_performance(self, client_id: str):
        """Analyze client performance and generate alerts if needed"""
        try:
            # Generate daily summary
            await self._generate_daily_summary(client_id)

            # Check for performance issues
            await self._check_performance_thresholds(client_id)

        except Exception as e:
            logger.error(f"Failed to analyze client performance: {e}")

    async def _generate_daily_summary(self, client_id: str):
        """Generate daily performance summary for a client"""
        db = DAL(self.db_url)

        try:
            today = datetime.now().date()
            yesterday = today - timedelta(days=1)

            # Get stats for today
            stats = db(
                (db.performance_stats.client_id == client_id)
                & (db.performance_stats.timestamp >= today)
                & (db.performance_stats.timestamp < today + timedelta(days=1))
            ).select()

            if len(stats) == 0:
                return

            # Group by server_url and test_domain
            grouped_stats = defaultdict(list)
            for stat in stats:
                key = (stat.server_url, stat.test_domain)
                grouped_stats[key].append(stat)

            # Generate summary for each group
            for (server_url, test_domain), group_stats in grouped_stats.items():
                response_times = [
                    s.total_time_ms
                    for s in group_stats
                    if s.total_time_ms and s.successful
                ]

                if not response_times:
                    continue

                summary_data = {
                    "client_id": client_id,
                    "server_url": server_url,
                    "test_domain": test_domain,
                    "date": today,
                    "total_tests": len(group_stats),
                    "successful_tests": sum(1 for s in group_stats if s.successful),
                    "avg_response_time_ms": statistics.mean(response_times),
                    "min_response_time_ms": min(response_times),
                    "max_response_time_ms": max(response_times),
                    "median_response_time_ms": statistics.median(response_times),
                    "error_rate": 1.0
                    - (sum(1 for s in group_stats if s.successful) / len(group_stats)),
                    "cache_hit_rate": sum(1 for s in group_stats if s.cache_hit)
                    / len(group_stats),
                    "updated_at": datetime.now(),
                }

                # Calculate percentiles
                if len(response_times) >= 20:  # Need sufficient data for percentiles
                    summary_data["p95_response_time_ms"] = self._percentile(
                        response_times, 0.95
                    )
                    summary_data["p99_response_time_ms"] = self._percentile(
                        response_times, 0.99
                    )

                # Calculate network metrics
                dns_times = [s.dns_lookup_ms for s in group_stats if s.dns_lookup_ms]
                tls_times = [
                    s.tls_handshake_ms for s in group_stats if s.tls_handshake_ms
                ]

                if dns_times:
                    summary_data["avg_dns_lookup_ms"] = statistics.mean(dns_times)
                if tls_times:
                    summary_data["avg_tls_handshake_ms"] = statistics.mean(tls_times)

                # Calculate specific error rates
                timeout_errors = sum(
                    1 for s in group_stats if "timeout" in (s.error_type or "").lower()
                )
                dns_errors = sum(
                    1
                    for s in group_stats
                    if s.dns_response_code != 0 and not s.successful
                )

                summary_data["timeout_rate"] = timeout_errors / len(group_stats)
                summary_data["dns_error_rate"] = dns_errors / len(group_stats)

                # Update or insert summary
                existing = (
                    db(
                        (db.client_performance_summary.client_id == client_id)
                        & (db.client_performance_summary.server_url == server_url)
                        & (db.client_performance_summary.test_domain == test_domain)
                        & (db.client_performance_summary.date == today)
                    )
                    .select()
                    .first()
                )

                if existing:
                    existing.update_record(**summary_data)
                else:
                    db.client_performance_summary.insert(**summary_data)

            db.commit()

        except Exception as e:
            logger.error(f"Failed to generate daily summary: {e}")
        finally:
            db.close()

    def _percentile(self, data: List[float], percentile: float) -> float:
        """Calculate percentile value"""
        if not data:
            return 0.0

        sorted_data = sorted(data)
        index = int(percentile * len(sorted_data))
        if index >= len(sorted_data):
            index = len(sorted_data) - 1

        return sorted_data[index]

    async def _check_performance_thresholds(self, client_id: str):
        """Check performance against thresholds and create alerts"""
        db = DAL(self.db_url)

        try:
            # Get recent performance summary
            recent_summary = (
                db(
                    (db.client_performance_summary.client_id == client_id)
                    & (db.client_performance_summary.date >= datetime.now().date())
                )
                .select()
                .first()
            )

            if not recent_summary:
                return

            # Get active thresholds
            thresholds = db(db.performance_thresholds.enabled == True).select()

            for threshold in thresholds:
                current_value = self._get_metric_value(
                    recent_summary, threshold.metric_name
                )

                if current_value is None:
                    continue

                # Check if threshold is exceeded
                severity = None
                if current_value >= threshold.critical_threshold:
                    severity = "critical"
                elif current_value >= threshold.warning_threshold:
                    severity = "warning"

                if severity:
                    # Check if alert already exists
                    existing_alert = (
                        db(
                            (db.performance_alerts.client_id == client_id)
                            & (
                                db.performance_alerts.server_url
                                == recent_summary.server_url
                            )
                            & (
                                db.performance_alerts.alert_type
                                == threshold.metric_name
                            )
                            & (db.performance_alerts.resolved == False)
                        )
                        .select()
                        .first()
                    )

                    if not existing_alert:
                        # Create new alert
                        db.performance_alerts.insert(
                            client_id=client_id,
                            server_url=recent_summary.server_url,
                            alert_type=threshold.metric_name,
                            severity=severity,
                            description=f"{threshold.description} exceeded threshold: {current_value} >= {threshold.warning_threshold}",
                            threshold_value=(
                                threshold.warning_threshold
                                if severity == "warning"
                                else threshold.critical_threshold
                            ),
                            current_value=current_value,
                        )

                        logger.warning(
                            f"Performance alert created for client {client_id}: {threshold.metric_name} = {current_value}"
                        )

            db.commit()

        except Exception as e:
            logger.error(f"Failed to check performance thresholds: {e}")
        finally:
            db.close()

    def _get_metric_value(self, summary_record, metric_name: str) -> Optional[float]:
        """Get metric value from summary record"""
        if metric_name == "response_time_ms":
            return summary_record.avg_response_time_ms
        elif metric_name == "error_rate":
            return summary_record.error_rate
        elif metric_name == "dns_lookup_ms":
            return summary_record.avg_dns_lookup_ms
        elif metric_name == "tls_handshake_ms":
            return getattr(summary_record, "avg_tls_handshake_ms", None)

        return None

    def get_client_performance_dashboard(self, client_id: str, days: int = 7) -> Dict:
        """Get performance dashboard data for a client"""
        db = DAL(self.db_url)

        try:
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=days)

            # Get summary data
            summaries = db(
                (db.client_performance_summary.client_id == client_id)
                & (db.client_performance_summary.date >= start_date)
                & (db.client_performance_summary.date <= end_date)
            ).select(orderby=db.client_performance_summary.date)

            # Get recent alerts
            alerts = db(
                (db.performance_alerts.client_id == client_id)
                & (db.performance_alerts.alert_time >= start_date)
                & (db.performance_alerts.resolved == False)
            ).select(orderby=~db.performance_alerts.alert_time)

            # Calculate aggregate metrics
            if summaries:
                total_tests = sum(s.total_tests for s in summaries)
                successful_tests = sum(s.successful_tests for s in summaries)
                avg_response_time = statistics.mean(
                    [
                        s.avg_response_time_ms
                        for s in summaries
                        if s.avg_response_time_ms
                    ]
                )
                avg_error_rate = statistics.mean(
                    [s.error_rate for s in summaries if s.error_rate is not None]
                )
                avg_cache_hit_rate = statistics.mean(
                    [
                        s.cache_hit_rate
                        for s in summaries
                        if s.cache_hit_rate is not None
                    ]
                )
            else:
                total_tests = successful_tests = avg_response_time = avg_error_rate = (
                    avg_cache_hit_rate
                ) = 0

            # Prepare chart data
            chart_data = {
                "dates": [str(s.date) for s in summaries],
                "response_times": [s.avg_response_time_ms for s in summaries],
                "error_rates": [
                    s.error_rate * 100 for s in summaries
                ],  # Convert to percentage
                "test_counts": [s.total_tests for s in summaries],
            }

            return {
                "client_id": client_id,
                "period_days": days,
                "summary": {
                    "total_tests": total_tests,
                    "successful_tests": successful_tests,
                    "success_rate": (successful_tests / max(total_tests, 1)) * 100,
                    "avg_response_time_ms": avg_response_time,
                    "avg_error_rate": avg_error_rate * 100,  # Convert to percentage
                    "avg_cache_hit_rate": avg_cache_hit_rate * 100,
                },
                "chart_data": chart_data,
                "alerts": [
                    {
                        "type": alert.alert_type,
                        "severity": alert.severity,
                        "description": alert.description,
                        "time": alert.alert_time.isoformat(),
                        "current_value": alert.current_value,
                        "threshold": alert.threshold_value,
                    }
                    for alert in alerts
                ],
            }

        except Exception as e:
            logger.error(f"Failed to get performance dashboard: {e}")
            return {"error": str(e)}
        finally:
            db.close()

    def get_performance_stats(self) -> Dict:
        """Get overall performance statistics for admin dashboard"""
        db = DAL(self.db_url)

        try:
            # Get counts
            total_clients = db(db.performance_stats.client_id != "").count(
                distinct=db.performance_stats.client_id
            )
            total_stats = db(db.performance_stats).count()
            active_alerts = db(db.performance_alerts.resolved == False).count()

            # Recent activity (last 24 hours)
            yesterday = datetime.now() - timedelta(hours=24)
            recent_stats = db(db.performance_stats.timestamp >= yesterday).count()

            # Average response time (last 7 days)
            week_ago = datetime.now().date() - timedelta(days=7)
            recent_summaries = db(
                db.client_performance_summary.date >= week_ago
            ).select()

            if recent_summaries:
                avg_response_time = statistics.mean(
                    [
                        s.avg_response_time_ms
                        for s in recent_summaries
                        if s.avg_response_time_ms is not None
                    ]
                )
                avg_error_rate = statistics.mean(
                    [s.error_rate for s in recent_summaries if s.error_rate is not None]
                )
            else:
                avg_response_time = avg_error_rate = 0

            # Top domains being tested
            domain_stats = db().select(
                db.performance_stats.test_domain,
                db.performance_stats.client_id.count().with_alias("test_count"),
                groupby=db.performance_stats.test_domain,
                orderby=~db.performance_stats.client_id.count(),
                limitby=(0, 10),
            )

            return {
                "overview": {
                    "total_clients": total_clients,
                    "total_statistics": total_stats,
                    "active_alerts": active_alerts,
                    "recent_activity_24h": recent_stats,
                    "avg_response_time_ms": avg_response_time,
                    "avg_error_rate": avg_error_rate * 100,  # Convert to percentage
                },
                "top_domains": [
                    {"domain": d.performance_stats.test_domain, "tests": d.test_count}
                    for d in domain_stats
                ],
            }

        except Exception as e:
            logger.error(f"Failed to get performance stats: {e}")
            return {"error": str(e)}
        finally:
            db.close()
