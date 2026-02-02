#!/usr/bin/env python3
"""
IOC (Indicators of Compromise) Manager for Squawk DNS
Implements threat intelligence blocking with multiple feed sources including MISP integration.
Addresses Issues #15, #16, and #25: IOC blocking, API management, and MISP integration
"""

import asyncio
import aiofiles
import aiohttp
import json
import logging
import hashlib
import time
import csv
import defusedxml.ElementTree as ET
import yaml
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Tuple, Union
from pydal import DAL, Field
import re
import ipaddress
from urllib.parse import urlparse, parse_qs
import ssl
import uuid

logger = logging.getLogger(__name__)


class IOCManager:
    """
    Manages IOC (Indicators of Compromise) feeds and blocking decisions.
    Features:
    - Multiple threat intelligence sources
    - Per-token override capabilities
    - API for IOC management
    - Automatic feed updates
    - Performance-optimized lookups
    """

    def __init__(
        self, db_url: str, update_interval_hours: int = 6, license_manager=None
    ):
        self.db_url = db_url
        self.update_interval_hours = update_interval_hours
        self.blocked_domains = set()
        self.blocked_ips = set()
        self.allow_overrides = {}  # token -> set of allowed domains/IPs
        self.block_overrides = {}  # token -> set of additionally blocked domains/IPs
        self.license_manager = license_manager
        self._init_database()

    def _init_database(self):
        """Initialize IOC database schema"""
        db = DAL(self.db_url)

        # IOC feed sources
        db.define_table(
            "ioc_feeds",
            Field("name", "string", unique=True),
            Field("url", "string"),
            Field("feed_type", "string"),  # domain, ip, mixed, hash, yara, snort
            Field(
                "format", "string"
            ),  # txt, csv, json, xml, stix, taxii, openioc, yara, snort, misp
            Field("enabled", "boolean", default=True),
            Field("update_frequency_hours", "integer", default=6),
            Field("last_update", "datetime"),
            Field("last_success", "datetime"),
            Field("entry_count", "integer", default=0),
            Field("parser_config", "json"),  # Configuration for specific parsers
            Field("authentication", "json"),  # Auth config (API keys, tokens, etc.)
            Field("created_at", "datetime", default=datetime.now),
            migrate=True,
        )

        # IOC entries from feeds
        db.define_table(
            "ioc_entries",
            Field("feed_id", "reference ioc_feeds"),
            Field("indicator", "string"),  # Domain, IP, hash, etc.
            Field("indicator_type", "string"),  # domain, ip, hash, url, email
            Field("threat_type", "string"),  # malware, phishing, botnet, c2, etc.
            Field("confidence", "integer", default=50),  # 0-100
            Field("description", "text"),
            Field("first_seen", "datetime"),
            Field("last_seen", "datetime"),
            Field("added_at", "datetime", default=datetime.now),
            Field("misp_event_id", "string"),  # MISP Event ID if available
            Field("misp_attribute_id", "string"),  # MISP Attribute ID if available
            Field("tags", "json"),  # Associated tags/labels
            Field("context", "json"),  # Additional contextual data
            Field("source_format", "string"),  # Original format (stix, misp, csv, etc.)
            migrate=True,
        )

        # User/token-specific overrides
        db.define_table(
            "ioc_overrides",
            Field(
                "token_id", "integer"
            ),  # Changed from reference to integer for standalone use
            Field("indicator", "string"),
            Field("indicator_type", "string"),  # domain, ip
            Field("override_type", "string"),  # allow, block
            Field("reason", "text"),
            Field("created_by", "string"),
            Field("created_at", "datetime", default=datetime.now),
            Field("expires_at", "datetime"),
            migrate=True,
        )

        # IOC lookup statistics
        db.define_table(
            "ioc_stats",
            Field("date", "date"),
            Field("feed_id", "reference ioc_feeds"),
            Field("lookups", "integer", default=0),
            Field("blocks", "integer", default=0),
            Field("overrides_applied", "integer", default=0),
            migrate=True,
        )

        # Initialize default feeds
        self._create_default_feeds(db)

        db.commit()
        db.close()

    def _create_default_feeds(self, db: DAL):
        """Create default threat intelligence feeds including MISP-compatible sources"""
        default_feeds = [
            # Traditional text/domain feeds
            {
                "name": "abuse.ch URLhaus",
                "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
                "feed_type": "domain",
                "format": "txt",
                "update_frequency_hours": 1,
                "parser_config": {"comment_chars": ["#"], "skip_localhost": True},
            },
            {
                "name": "abuse.ch Malware Domains",
                "url": "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt",
                "feed_type": "domain",
                "format": "txt",
                "update_frequency_hours": 6,
                "parser_config": {"comment_chars": ["#"], "skip_localhost": True},
            },
            {
                "name": "Emerging Threats Compromised IPs",
                "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                "feed_type": "ip",
                "format": "txt",
                "update_frequency_hours": 1,
                "parser_config": {"comment_chars": ["#"]},
            },
            {
                "name": "Feodo Tracker",
                "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
                "feed_type": "ip",
                "format": "txt",
                "update_frequency_hours": 1,
                "parser_config": {"comment_chars": ["#"]},
            },
            # MISP-compatible JSON feeds
            {
                "name": "abuse.ch URLhaus JSON",
                "url": "https://urlhaus.abuse.ch/downloads/json/",
                "feed_type": "mixed",
                "format": "json",
                "update_frequency_hours": 1,
                "parser_config": {
                    "json_path": "url_list",
                    "domain_field": "host",
                    "url_field": "url",
                    "threat_type_field": "threat",
                    "confidence_field": "confidence",
                    "date_field": "date_added",
                },
            },
            {
                "name": "CIRCL CVE Search",
                "url": "https://cve.circl.lu/api/query",
                "feed_type": "mixed",
                "format": "json",
                "update_frequency_hours": 24,
                "parser_config": {"api_endpoint": True, "requires_query": True},
            },
            # CSV format feeds
            {
                "name": "Cyber Threat Coalition COVID-19 Threats",
                "url": "https://blacklist.cyberthreatcoalition.org/vetted_domain.csv",
                "feed_type": "domain",
                "format": "csv",
                "update_frequency_hours": 6,
                "parser_config": {
                    "delimiter": ",",
                    "domain_column": "domain",
                    "confidence_column": "confidence",
                    "threat_type_column": "category",
                },
            },
            # STIX/TAXII compatible feeds (example configurations)
            {
                "name": "STIX Domain Indicators",
                "url": "",  # To be configured by user
                "feed_type": "mixed",
                "format": "stix",
                "enabled": False,  # Disabled by default, user must configure
                "update_frequency_hours": 6,
                "parser_config": {
                    "stix_version": "2.1",
                    "extract_types": ["domain-name", "ipv4-addr", "ipv6-addr", "url"],
                    "confidence_mapping": {"high": 90, "medium": 70, "low": 30},
                    "include_relationships": True,
                    "min_confidence": 30,
                },
                "authentication": {
                    "auth_type": "basic",
                    "username": "",
                    "password": "",
                },
            },
            # TAXII 2.x Server Integration
            {
                "name": "TAXII 2.x Collection",
                "url": "",  # To be configured: https://taxii-server.com/taxii2/collections/{collection-id}/objects/
                "feed_type": "mixed",
                "format": "taxii",
                "enabled": False,  # Disabled by default
                "update_frequency_hours": 4,
                "parser_config": {
                    "taxii_version": "2.1",
                    "collection_id": "",
                    "api_root": "",  # https://taxii-server.com/taxii2/
                    "discovery_endpoint": "",  # https://taxii-server.com/taxii2/
                    "extract_types": [
                        "domain-name",
                        "ipv4-addr",
                        "ipv6-addr",
                        "url",
                        "file",
                    ],
                    "confidence_threshold": 50,
                    "added_after": None,  # ISO timestamp for incremental updates
                    "max_objects": 10000,
                    "verify_ssl": True,
                },
                "authentication": {"auth_type": "bearer", "token": ""},
            },
            # MISP feed configuration template
            {
                "name": "MISP Instance Feed",
                "url": "",  # To be configured by user (e.g., https://misp.local/events/restSearch)
                "feed_type": "mixed",
                "format": "misp",
                "enabled": False,  # Disabled by default, user must configure
                "update_frequency_hours": 2,
                "parser_config": {
                    "misp_format": "json",
                    "event_types": ["domain", "hostname", "ip-src", "ip-dst", "url"],
                    "confidence_threshold": 50,
                    "include_context": True,
                    "max_events": 1000,
                },
                "authentication": {"auth_type": "apikey", "api_key": ""},
            },
            # OpenIOC format support
            {
                "name": "OpenIOC Threat Feed",
                "url": "",  # To be configured by user
                "feed_type": "mixed",
                "format": "openioc",
                "enabled": False,  # Disabled by default
                "update_frequency_hours": 6,
                "parser_config": {
                    "extract_network_indicators": True,
                    "extract_file_indicators": False,  # DNS doesn't need file hashes
                    "confidence_default": 75,
                },
            },
        ]

        for feed in default_feeds:
            existing = db(db.ioc_feeds.name == feed["name"]).select().first()
            if not existing:
                db.ioc_feeds.insert(**feed)

    async def update_all_feeds(self):
        """Update all enabled IOC feeds"""
        db = DAL(self.db_url)

        try:
            feeds = db(db.ioc_feeds.enabled == True).select()

            for feed in feeds:
                try:
                    # Check if update is needed
                    if feed.last_update:
                        next_update = feed.last_update + timedelta(
                            hours=feed.update_frequency_hours
                        )
                        if datetime.now() < next_update:
                            continue

                    logger.info(f"Updating IOC feed: {feed.name}")
                    await self._update_feed(db, feed)

                except Exception as e:
                    logger.error(f"Failed to update feed {feed.name}: {e}")

            # Rebuild in-memory caches
            await self._rebuild_caches(db)

        except Exception as e:
            logger.error(f"IOC feed update failed: {e}")
        finally:
            db.close()

    async def _update_feed(self, db: DAL, feed):
        """Update a single IOC feed"""
        try:
            if feed.format == "taxii":
                # Handle TAXII 2.x feeds differently
                indicators = await self._fetch_taxii_feed(feed)
            else:
                # Standard HTTP fetch for other formats
                indicators = await self._fetch_http_feed(feed)

            if indicators is not None:
                # Clear old entries for this feed
                db(db.ioc_entries.feed_id == feed.id).delete()

                # Insert new entries
                entry_count = 0
                for indicator in indicators:
                    db.ioc_entries.insert(
                        feed_id=feed.id,
                        indicator=indicator["value"],
                        indicator_type=indicator["type"],
                        threat_type=indicator.get("threat_type", "unknown"),
                        confidence=indicator.get("confidence", 50),
                        description=indicator.get("description", ""),
                        first_seen=indicator.get("first_seen", datetime.now()),
                        last_seen=indicator.get("last_seen", datetime.now()),
                        misp_event_id=indicator.get("misp_event_id"),
                        misp_attribute_id=indicator.get("misp_attribute_id"),
                        tags=indicator.get("tags", []),
                        context=indicator.get("context", {}),
                        source_format=feed.format,
                    )
                    entry_count += 1

                # Update feed metadata
                feed.update_record(
                    last_update=datetime.now(),
                    last_success=datetime.now(),
                    entry_count=entry_count,
                )

                logger.info(f"Updated feed {feed.name}: {entry_count} indicators")
            else:
                logger.error(f"Failed to fetch indicators from feed {feed.name}")

        except Exception as e:
            logger.error(f"Failed to update feed {feed.name}: {e}")
            # Update last_update to prevent constant retries
            feed.update_record(last_update=datetime.now())

    async def _fetch_http_feed(self, feed):
        """Fetch feed data via HTTP"""
        try:
            headers = {}
            auth = None

            # Setup authentication
            auth_config = feed.authentication or {}
            if auth_config.get("auth_type") == "basic":
                auth = aiohttp.BasicAuth(
                    auth_config.get("username", ""), auth_config.get("password", "")
                )
            elif auth_config.get("auth_type") == "bearer":
                headers["Authorization"] = f"Bearer {auth_config.get('token', '')}"
            elif auth_config.get("auth_type") == "apikey":
                headers["Authorization"] = auth_config.get("api_key", "")

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    feed.url, headers=headers, auth=auth, timeout=60
                ) as response:
                    if response.status == 200:
                        content = await response.text()

                        # Parse feed content using enhanced parser
                        indicators = await self._parse_feed_content(
                            content, feed.format, feed.feed_type, feed.parser_config
                        )
                        return indicators
                    else:
                        logger.error(
                            f"Feed {feed.name} returned HTTP {response.status}"
                        )
                        return None

        except Exception as e:
            logger.error(f"Failed to fetch HTTP feed {feed.name}: {e}")
            return None

    async def _fetch_taxii_feed(self, feed):
        """Fetch data from TAXII 2.x server"""
        try:
            config = feed.parser_config or {}
            auth_config = feed.authentication or {}

            # TAXII 2.x client implementation
            taxii_client = TAXII2Client(
                api_root=config.get("api_root", ""),
                collection_id=config.get("collection_id", ""),
                auth_type=auth_config.get("auth_type", "none"),
                token=auth_config.get("token", ""),
                username=auth_config.get("username", ""),
                password=auth_config.get("password", ""),
                verify_ssl=config.get("verify_ssl", True),
            )

            # Fetch STIX objects from collection
            stix_objects = await taxii_client.get_objects(
                added_after=config.get("added_after"),
                limit=config.get("max_objects", 10000),
            )

            # Parse STIX objects into indicators
            if stix_objects:
                indicators = await self._parse_stix_objects(stix_objects, config)
                return indicators
            else:
                return []

        except Exception as e:
            logger.error(f"Failed to fetch TAXII feed {feed.name}: {e}")
            return None

    async def _parse_feed_content(
        self, content: str, format_type: str, feed_type: str, parser_config: dict = None
    ) -> List[Dict]:
        """Parse feed content based on format with MISP and multiple format support"""
        indicators = []
        config = parser_config or {}

        try:
            if format_type == "txt":
                indicators = await self._parse_text_feed(content, feed_type, config)
            elif format_type == "json":
                indicators = await self._parse_json_feed(content, feed_type, config)
            elif format_type == "csv":
                indicators = await self._parse_csv_feed(content, feed_type, config)
            elif format_type == "xml":
                indicators = await self._parse_xml_feed(content, feed_type, config)
            elif format_type == "stix":
                indicators = await self._parse_stix_feed(content, feed_type, config)
            elif format_type == "taxii":
                # TAXII feeds are handled differently in _fetch_taxii_feed
                logger.warning(
                    "TAXII feeds should not use _parse_feed_content - use _fetch_taxii_feed instead"
                )
                indicators = []
            elif format_type == "misp":
                indicators = await self._parse_misp_feed(content, feed_type, config)
            elif format_type == "openioc":
                indicators = await self._parse_openioc_feed(content, feed_type, config)
            elif format_type == "yara":
                indicators = await self._parse_yara_feed(content, feed_type, config)
            elif format_type == "snort":
                indicators = await self._parse_snort_feed(content, feed_type, config)
            else:
                logger.warning(f"Unsupported format type: {format_type}")

        except Exception as e:
            logger.error(f"Failed to parse feed content ({format_type}): {e}")

        return indicators

    async def _parse_text_feed(
        self, content: str, feed_type: str, config: dict
    ) -> List[Dict]:
        """Parse text-based feeds (original functionality enhanced)"""
        indicators = []
        comment_chars = config.get("comment_chars", ["#", ";"])
        skip_localhost = config.get("skip_localhost", True)

        lines = content.split("\n")
        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Skip comments
            if any(line.startswith(char) for char in comment_chars):
                continue

            # Handle different text formats
            if feed_type == "domain":
                domain = self._extract_domain_from_line(line, skip_localhost)
                if domain:
                    indicators.append(
                        {
                            "value": domain,
                            "type": "domain",
                            "threat_type": "malware",
                            "confidence": config.get("default_confidence", 75),
                        }
                    )

            elif feed_type == "ip":
                ip = self._extract_ip_from_line(line)
                if ip:
                    indicators.append(
                        {
                            "value": ip,
                            "type": "ip",
                            "threat_type": "malware",
                            "confidence": config.get("default_confidence", 75),
                        }
                    )

        return indicators

    async def _parse_json_feed(
        self, content: str, feed_type: str, config: dict
    ) -> List[Dict]:
        """Parse JSON-based feeds including URLhaus and MISP-compatible formats"""
        indicators = []

        try:
            data = json.loads(content)

            # Handle different JSON structures
            if config.get("json_path"):
                # Navigate to the data array
                json_path = config["json_path"]
                if isinstance(data, dict) and json_path in data:
                    data = data[json_path]

            if isinstance(data, list):
                for item in data:
                    indicator = self._extract_indicator_from_json(item, config)
                    if indicator:
                        indicators.append(indicator)
            elif isinstance(data, dict):
                # Single indicator
                indicator = self._extract_indicator_from_json(data, config)
                if indicator:
                    indicators.append(indicator)

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in feed: {e}")

        return indicators

    async def _parse_csv_feed(
        self, content: str, feed_type: str, config: dict
    ) -> List[Dict]:
        """Parse CSV-based threat feeds"""
        indicators = []
        delimiter = config.get("delimiter", ",")
        domain_column = config.get("domain_column", "domain")
        ip_column = config.get("ip_column", "ip")

        try:
            reader = csv.DictReader(content.splitlines(), delimiter=delimiter)
            for row in reader:
                if domain_column in row and row[domain_column]:
                    domain = row[domain_column].strip().lower()
                    if self._is_valid_domain(domain):
                        indicators.append(
                            {
                                "value": domain,
                                "type": "domain",
                                "threat_type": row.get(
                                    config.get("threat_type_column", "category"),
                                    "unknown",
                                ),
                                "confidence": int(
                                    row.get(
                                        config.get("confidence_column", "confidence"),
                                        50,
                                    )
                                ),
                                "description": row.get("description", ""),
                                "context": dict(row),  # Store full row as context
                            }
                        )

                elif ip_column in row and row[ip_column]:
                    ip = row[ip_column].strip()
                    if self._is_valid_ip(ip):
                        indicators.append(
                            {
                                "value": ip,
                                "type": "ip",
                                "threat_type": row.get(
                                    config.get("threat_type_column", "category"),
                                    "unknown",
                                ),
                                "confidence": int(
                                    row.get(
                                        config.get("confidence_column", "confidence"),
                                        50,
                                    )
                                ),
                                "description": row.get("description", ""),
                                "context": dict(row),
                            }
                        )

        except Exception as e:
            logger.error(f"Error parsing CSV feed: {e}")

        return indicators

    async def _parse_misp_feed(
        self, content: str, feed_type: str, config: dict
    ) -> List[Dict]:
        """Parse MISP JSON export format"""
        indicators = []

        try:
            data = json.loads(content)
            event_types = config.get(
                "event_types", ["domain", "hostname", "ip-src", "ip-dst", "url"]
            )
            confidence_threshold = config.get("confidence_threshold", 50)
            include_context = config.get("include_context", True)

            # Handle MISP event structure
            if isinstance(data, dict) and "Event" in data:
                events = (
                    [data["Event"]]
                    if isinstance(data["Event"], dict)
                    else data["Event"]
                )
            elif isinstance(data, dict) and "response" in data:
                events = data["response"]
            elif isinstance(data, list):
                events = data
            else:
                events = [data]

            for event in events:
                event_id = event.get("id", "")
                event_info = event.get("info", "")

                # Process attributes
                attributes = event.get("Attribute", [])
                for attr in attributes:
                    attr_type = attr.get("type", "")
                    attr_value = attr.get("value", "")
                    attr_confidence = int(attr.get("confidence", 50))

                    if (
                        attr_type in event_types
                        and attr_confidence >= confidence_threshold
                    ):
                        indicator_type = self._misp_type_to_indicator_type(attr_type)
                        if indicator_type and self._is_valid_indicator(
                            attr_value, indicator_type
                        ):
                            indicator = {
                                "value": (
                                    attr_value.lower()
                                    if indicator_type == "domain"
                                    else attr_value
                                ),
                                "type": indicator_type,
                                "threat_type": attr.get("category", "unknown"),
                                "confidence": attr_confidence,
                                "description": f"MISP Event: {event_info}",
                                "misp_event_id": str(event_id),
                                "misp_attribute_id": str(attr.get("id", "")),
                                "tags": [
                                    tag.get("name", "") for tag in attr.get("Tag", [])
                                ],
                                "first_seen": self._parse_misp_date(
                                    attr.get("first_seen")
                                ),
                                "last_seen": self._parse_misp_date(
                                    attr.get("last_seen")
                                ),
                            }

                            if include_context:
                                indicator["context"] = {
                                    "misp_event": event_info,
                                    "misp_category": attr.get("category", ""),
                                    "misp_comment": attr.get("comment", ""),
                                }

                            indicators.append(indicator)

        except Exception as e:
            logger.error(f"Error parsing MISP feed: {e}")

        return indicators

    async def _parse_stix_feed(
        self, content: str, feed_type: str, config: dict
    ) -> List[Dict]:
        """Parse STIX 2.x format"""
        indicators = []

        try:
            data = json.loads(content)
            stix_version = config.get("stix_version", "2.1")
            extract_types = config.get(
                "extract_types", ["domain-name", "ipv4-addr", "ipv6-addr"]
            )
            confidence_mapping = config.get(
                "confidence_mapping", {"high": 90, "medium": 70, "low": 30}
            )

            # Handle STIX bundle format
            if isinstance(data, dict) and "objects" in data:
                objects = data["objects"]
            elif isinstance(data, list):
                objects = data
            else:
                objects = [data]

            for obj in objects:
                if obj.get("type") == "indicator":
                    pattern = obj.get("pattern", "")
                    labels = obj.get("labels", [])
                    confidence = confidence_mapping.get(
                        obj.get("confidence", "medium"), 50
                    )

                    # Extract indicators from STIX pattern
                    extracted = self._extract_from_stix_pattern(pattern, extract_types)
                    for indicator_value, indicator_type in extracted:
                        if self._is_valid_indicator(indicator_value, indicator_type):
                            indicators.append(
                                {
                                    "value": (
                                        indicator_value.lower()
                                        if indicator_type == "domain"
                                        else indicator_value
                                    ),
                                    "type": indicator_type,
                                    "threat_type": (
                                        ", ".join(labels) if labels else "unknown"
                                    ),
                                    "confidence": confidence,
                                    "description": obj.get("name", ""),
                                    "tags": labels,
                                    "context": {
                                        "stix_id": obj.get("id", ""),
                                        "stix_pattern": pattern,
                                        "stix_valid_from": obj.get("valid_from", ""),
                                        "stix_valid_until": obj.get("valid_until", ""),
                                    },
                                }
                            )

        except Exception as e:
            logger.error(f"Error parsing STIX feed: {e}")

        return indicators

    async def _parse_openioc_feed(
        self, content: str, feed_type: str, config: dict
    ) -> List[Dict]:
        """Parse OpenIOC XML format with enhanced IOC extraction"""
        indicators = []

        try:
            root = ET.fromstring(content)
            extract_network = config.get("extract_network_indicators", True)
            extract_file = config.get("extract_file_indicators", False)
            confidence_default = config.get("confidence_default", 75)

            # Extract metadata from IOC definition
            ioc_id = root.get("id", "")
            ioc_name = ""
            ioc_description = ""

            # Get IOC metadata
            short_desc = root.find(".//short_description")
            if short_desc is not None:
                ioc_name = short_desc.text or ""

            desc = root.find(".//description")
            if desc is not None:
                ioc_description = desc.text or ""

            # OpenIOC uses IndicatorItem elements within Definition/Criteria
            for indicator_item in root.findall(".//IndicatorItem"):
                try:
                    context_elem = indicator_item.find("Context")
                    content_elem = indicator_item.find("Content")

                    if context_elem is not None and content_elem is not None:
                        context_type = context_elem.get("type", "")
                        context_document = context_elem.get("document", "")
                        context_search = context_elem.get("search", "")
                        indicator_value = content_elem.text

                        if not indicator_value:
                            continue

                        indicator_value = indicator_value.strip()

                        # Enhanced mapping of OpenIOC context types
                        if extract_network and any(
                            net_type in context_type
                            for net_type in [
                                "Network/DNS",
                                "DnsEntryItem",
                                "DNS",
                                "HostnameItem",
                            ]
                        ):
                            # DNS/Domain indicators
                            if self._is_valid_domain(indicator_value):
                                indicators.append(
                                    {
                                        "value": indicator_value.lower(),
                                        "type": "domain",
                                        "threat_type": "openioc",
                                        "confidence": confidence_default,
                                        "description": f"OpenIOC {ioc_name}: {context_type}",
                                        "tags": ["openioc"],
                                        "context": {
                                            "openioc_context": context_type,
                                            "openioc_document": context_document,
                                            "openioc_search": context_search,
                                            "openioc_id": ioc_id,
                                            "openioc_name": ioc_name,
                                            "openioc_description": ioc_description,
                                        },
                                    }
                                )

                        elif extract_network and any(
                            ip_type in context_type
                            for ip_type in [
                                "Network/IP",
                                "NetworkItem",
                                "PortItem/remoteIP",
                                "RouteEntryItem",
                            ]
                        ):
                            # IP indicators
                            # Handle CIDR notation and IP ranges
                            ip_values = self._extract_ips_from_openioc_value(
                                indicator_value
                            )
                            for ip in ip_values:
                                if self._is_valid_ip(ip):
                                    indicators.append(
                                        {
                                            "value": ip,
                                            "type": "ip",
                                            "threat_type": "openioc",
                                            "confidence": confidence_default,
                                            "description": f"OpenIOC {ioc_name}: {context_type}",
                                            "tags": ["openioc"],
                                            "context": {
                                                "openioc_context": context_type,
                                                "openioc_document": context_document,
                                                "openioc_search": context_search,
                                                "openioc_id": ioc_id,
                                                "openioc_name": ioc_name,
                                                "openioc_description": ioc_description,
                                                "original_value": indicator_value,
                                            },
                                        }
                                    )

                        elif extract_network and any(
                            url_type in context_type
                            for url_type in [
                                "Network/URI",
                                "UrlHistoryItem",
                                "Network/UserAgent",
                            ]
                        ):
                            # URL indicators - extract domains
                            try:
                                parsed_url = urlparse(indicator_value)
                                if parsed_url.netloc and self._is_valid_domain(
                                    parsed_url.netloc
                                ):
                                    indicators.append(
                                        {
                                            "value": parsed_url.netloc.lower(),
                                            "type": "domain",
                                            "threat_type": "openioc_url",
                                            "confidence": confidence_default,
                                            "description": f"OpenIOC {ioc_name}: Extracted from URL",
                                            "tags": ["openioc", "extracted_url"],
                                            "context": {
                                                "openioc_context": context_type,
                                                "openioc_id": ioc_id,
                                                "openioc_name": ioc_name,
                                                "original_url": indicator_value,
                                            },
                                        }
                                    )
                            except Exception:
                                pass

                        elif extract_file and any(
                            file_type in context_type
                            for file_type in [
                                "FileItem/Md5sum",
                                "FileItem/Sha1sum",
                                "FileItem/Sha256sum",
                            ]
                        ):
                            # File hash indicators (less relevant for DNS but included for completeness)
                            hash_type = (
                                "md5"
                                if "Md5" in context_type
                                else "sha1" if "Sha1" in context_type else "sha256"
                            )
                            if self._is_valid_hash(indicator_value, hash_type):
                                indicators.append(
                                    {
                                        "value": indicator_value.lower(),
                                        "type": "hash",
                                        "threat_type": f"openioc_{hash_type}",
                                        "confidence": confidence_default,
                                        "description": f"OpenIOC {ioc_name}: {hash_type.upper()} hash",
                                        "tags": ["openioc", "file_hash"],
                                        "context": {
                                            "openioc_context": context_type,
                                            "openioc_id": ioc_id,
                                            "openioc_name": ioc_name,
                                            "hash_type": hash_type,
                                        },
                                    }
                                )

                except Exception as e:
                    logger.warning(f"Failed to parse OpenIOC indicator item: {e}")
                    continue

        except ET.ParseError as e:
            logger.error(f"Error parsing OpenIOC XML: {e}")
        except Exception as e:
            logger.error(f"Unexpected error parsing OpenIOC feed: {e}")

        return indicators

    def _extract_ips_from_openioc_value(self, value: str) -> List[str]:
        """Extract IP addresses from OpenIOC value (handles CIDR, ranges, etc.)"""
        ips = []

        try:
            # Handle CIDR notation
            if "/" in value:
                try:
                    network = ipaddress.ip_network(value, strict=False)
                    # For small networks, extract individual IPs
                    if network.num_addresses <= 256:
                        ips.extend([str(ip) for ip in network.hosts()])
                    else:
                        # For large networks, just add the network address
                        ips.append(str(network.network_address))
                except ValueError:
                    pass

            # Handle IP ranges (e.g., 192.168.1.1-192.168.1.10)
            elif "-" in value and "." in value:
                try:
                    start_ip, end_ip = value.split("-", 1)
                    start_addr = ipaddress.IPv4Address(start_ip.strip())
                    end_addr = ipaddress.IPv4Address(end_ip.strip())

                    # Only extract ranges with reasonable size
                    if int(end_addr) - int(start_addr) <= 256:
                        current = start_addr
                        while current <= end_addr:
                            ips.append(str(current))
                            current += 1
                    else:
                        ips.extend([str(start_addr), str(end_addr)])
                except ValueError:
                    pass

            # Handle single IP
            else:
                if self._is_valid_ip(value):
                    ips.append(value)

        except Exception as e:
            logger.warning(f"Failed to extract IPs from OpenIOC value '{value}': {e}")

        return ips

    def _is_valid_hash(self, hash_value: str, hash_type: str) -> bool:
        """Validate hash format"""
        if not hash_value or not isinstance(hash_value, str):
            return False

        hash_value = hash_value.lower().strip()

        # Check hex characters only
        if not re.match(r"^[a-f0-9]+$", hash_value):
            return False

        # Check length based on hash type
        expected_lengths = {"md5": 32, "sha1": 40, "sha256": 64}

        expected_length = expected_lengths.get(hash_type.lower())
        if expected_length and len(hash_value) == expected_length:
            return True

        return False

    async def _parse_yara_feed(
        self, content: str, feed_type: str, config: dict
    ) -> List[Dict]:
        """Parse YARA rules for network indicators"""
        indicators = []

        try:
            # Extract domains and IPs from YARA rule strings and conditions
            domain_pattern = (
                r"\"([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\""
            )
            ip_pattern = r"\"(?:[0-9]{1,3}\.){3}[0-9]{1,3}\""

            domains = re.findall(domain_pattern, content)
            ips = re.findall(ip_pattern, content)

            # Extract rule metadata
            rule_name = ""
            rule_match = re.search(r"rule\s+(\w+)", content)
            if rule_match:
                rule_name = rule_match.group(1)

            for domain_match in domains:
                domain = (
                    domain_match[0] if isinstance(domain_match, tuple) else domain_match
                )
                domain = domain.strip('"').lower()
                if self._is_valid_domain(domain):
                    indicators.append(
                        {
                            "value": domain,
                            "type": "domain",
                            "threat_type": "yara_rule",
                            "confidence": config.get("default_confidence", 80),
                            "description": f"From YARA rule: {rule_name}",
                            "context": {"yara_rule": rule_name},
                        }
                    )

            for ip in ips:
                ip = ip.strip('"')
                if self._is_valid_ip(ip):
                    indicators.append(
                        {
                            "value": ip,
                            "type": "ip",
                            "threat_type": "yara_rule",
                            "confidence": config.get("default_confidence", 80),
                            "description": f"From YARA rule: {rule_name}",
                            "context": {"yara_rule": rule_name},
                        }
                    )

        except Exception as e:
            logger.error(f"Error parsing YARA feed: {e}")

        return indicators

    async def _parse_snort_feed(
        self, content: str, feed_type: str, config: dict
    ) -> List[Dict]:
        """Parse Snort rules for network indicators"""
        indicators = []

        try:
            lines = content.split("\n")
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Extract domains and IPs from Snort rule content
                if "content:" in line:
                    # Extract domains from content field
                    content_matches = re.findall(r'content:\s*"([^"]*)"', line)
                    for match in content_matches:
                        # Look for domain patterns
                        domain_pattern = (
                            r"([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"
                        )
                        domains = re.findall(domain_pattern, match)
                        for domain_match in domains:
                            domain = (
                                domain_match[0]
                                if isinstance(domain_match, tuple)
                                else domain_match
                            )
                            if self._is_valid_domain(domain):
                                indicators.append(
                                    {
                                        "value": domain.lower(),
                                        "type": "domain",
                                        "threat_type": "snort_rule",
                                        "confidence": config.get(
                                            "default_confidence", 75
                                        ),
                                        "description": f"From Snort rule content",
                                        "context": {"snort_rule": line[:100]},
                                    }
                                )

        except Exception as e:
            logger.error(f"Error parsing Snort feed: {e}")

        return indicators

    async def _parse_xml_feed(
        self, content: str, feed_type: str, config: dict
    ) -> List[Dict]:
        """Parse generic XML-based threat feeds"""
        indicators = []

        try:
            root = ET.fromstring(content)

            # Generic XML parsing - look for common elements
            for elem in root.iter():
                if elem.text:
                    text = elem.text.strip()

                    # Check if it looks like a domain
                    if self._is_valid_domain(text):
                        indicators.append(
                            {
                                "value": text.lower(),
                                "type": "domain",
                                "threat_type": elem.tag,
                                "confidence": config.get("default_confidence", 60),
                                "description": f"From XML element: {elem.tag}",
                                "context": {"xml_element": elem.tag},
                            }
                        )
                    # Check if it looks like an IP
                    elif self._is_valid_ip(text):
                        indicators.append(
                            {
                                "value": text,
                                "type": "ip",
                                "threat_type": elem.tag,
                                "confidence": config.get("default_confidence", 60),
                                "description": f"From XML element: {elem.tag}",
                                "context": {"xml_element": elem.tag},
                            }
                        )

        except ET.ParseError as e:
            logger.error(f"Error parsing XML feed: {e}")

        return indicators

    # Helper methods for parsers
    def _extract_indicator_from_json(self, item: dict, config: dict) -> Optional[Dict]:
        """Extract indicator from JSON item based on configuration"""
        try:
            # Handle URLhaus format
            if config.get("domain_field") and config["domain_field"] in item:
                domain = item[config["domain_field"]]
                if self._is_valid_domain(domain):
                    return {
                        "value": domain.lower(),
                        "type": "domain",
                        "threat_type": item.get(
                            config.get("threat_type_field", "threat"), "malware"
                        ),
                        "confidence": int(
                            item.get(config.get("confidence_field", "confidence"), 75)
                        ),
                        "description": item.get("description", ""),
                        "context": item,
                    }

            # Handle generic JSON with common field names
            if "domain" in item and self._is_valid_domain(item["domain"]):
                return {
                    "value": item["domain"].lower(),
                    "type": "domain",
                    "threat_type": item.get("category", "malware"),
                    "confidence": int(item.get("confidence", 75)),
                    "description": item.get("description", ""),
                    "context": item,
                }

            if "ip" in item and self._is_valid_ip(item["ip"]):
                return {
                    "value": item["ip"],
                    "type": "ip",
                    "threat_type": item.get("category", "malware"),
                    "confidence": int(item.get("confidence", 75)),
                    "description": item.get("description", ""),
                    "context": item,
                }
        except (ValueError, TypeError):
            pass

        return None

    def _misp_type_to_indicator_type(self, misp_type: str) -> Optional[str]:
        """Convert MISP attribute type to our indicator type"""
        mapping = {
            "domain": "domain",
            "hostname": "domain",
            "ip-src": "ip",
            "ip-dst": "ip",
            "url": "url",
            "email": "email",
        }
        return mapping.get(misp_type)

    def _parse_misp_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse MISP date format"""
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None

    def _extract_from_stix_pattern(
        self, pattern: str, extract_types: List[str]
    ) -> List[Tuple[str, str]]:
        """Extract indicators from STIX pattern"""
        indicators = []

        try:
            # Basic STIX pattern parsing
            for extract_type in extract_types:
                if extract_type in pattern:
                    # Look for values after the type
                    pattern_regex = rf"{extract_type}:value\s*=\s*'([^']+)'"
                    matches = re.findall(pattern_regex, pattern)

                    for match in matches:
                        indicator_type = "domain" if "domain" in extract_type else "ip"
                        indicators.append((match, indicator_type))

        except Exception as e:
            logger.error(f"Error parsing STIX pattern: {e}")

        return indicators

    def _is_valid_indicator(self, value: str, indicator_type: str) -> bool:
        """Validate indicator based on type"""
        if indicator_type == "domain":
            return self._is_valid_domain(value)
        elif indicator_type == "ip":
            return self._is_valid_ip(value)
        elif indicator_type in ["url", "email"]:
            return len(value) > 3  # Basic validation
        return False

    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain format"""
        if len(domain) > 255 or len(domain) < 4:
            return False

        # Check for valid characters
        if not re.match(r"^[a-zA-Z0-9.-]+$", domain):
            return False

        # Must have at least one dot
        if "." not in domain:
            return False

        # Check each part
        parts = domain.split(".")
        for part in parts:
            if len(part) == 0 or len(part) > 63:
                return False
            if part.startswith("-") or part.endswith("-"):
                return False

        return True

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address"""
        try:
            addr = ipaddress.ip_address(ip)
            # Skip private/local/multicast IPs for threat intelligence
            return not (
                addr.is_private
                or addr.is_loopback
                or addr.is_multicast
                or addr.is_reserved
            )
        except ValueError:
            return False

    async def check_domain(self, domain: str, token_id: int = None) -> Tuple[bool, str]:
        """
        Check if domain should be blocked based on IOC feeds and overrides.
        Returns (should_block, reason)
        """
        domain_lower = domain.lower()

        # Check token-specific allow overrides first
        if token_id and token_id in self.allow_overrides:
            if domain_lower in self.allow_overrides[token_id]:
                return False, "Allowed by token override"

        # Check token-specific block overrides
        if token_id and token_id in self.block_overrides:
            if domain_lower in self.block_overrides[token_id]:
                return True, "Blocked by token override"

        # Check global IOC feeds
        if domain_lower in self.blocked_domains:
            return True, "Blocked by threat intelligence"

        # Check subdomains
        domain_parts = domain_lower.split(".")
        for i in range(1, len(domain_parts)):
            parent_domain = ".".join(domain_parts[i:])
            if parent_domain in self.blocked_domains:
                return True, f"Blocked by parent domain: {parent_domain}"

        return False, "Not blocked"

    async def check_ip(self, ip_addr: str, token_id: int = None) -> Tuple[bool, str]:
        """
        Check if IP should be blocked based on IOC feeds and overrides.
        Returns (should_block, reason)
        """
        # Check token-specific allow overrides first
        if token_id and token_id in self.allow_overrides:
            if ip_addr in self.allow_overrides[token_id]:
                return False, "Allowed by token override"

        # Check token-specific block overrides
        if token_id and token_id in self.block_overrides:
            if ip_addr in self.block_overrides[token_id]:
                return True, "Blocked by token override"

        # Check global IOC feeds
        if ip_addr in self.blocked_ips:
            return True, "Blocked by threat intelligence"

        return False, "Not blocked"

    async def add_override(
        self,
        token_id: int,
        indicator: str,
        indicator_type: str,
        override_type: str,
        reason: str = "",
        created_by: str = "",
        expires_at: datetime = None,
    ) -> bool:
        """Add an IOC override for a specific token"""
        from pydal import DAL

        db = DAL(self.db_url)

        try:
            # Validate inputs
            if indicator_type not in ["domain", "ip"]:
                return False
            if override_type not in ["allow", "block"]:
                return False

            # Check if override already exists
            existing = (
                db(
                    (db.ioc_overrides.token_id == token_id)
                    & (db.ioc_overrides.indicator == indicator)
                    & (db.ioc_overrides.indicator_type == indicator_type)
                )
                .select()
                .first()
            )

            if existing:
                # Update existing override
                existing.update_record(
                    override_type=override_type,
                    reason=reason,
                    created_by=created_by,
                    created_at=datetime.now(),
                    expires_at=expires_at,
                )
            else:
                # Create new override
                db.ioc_overrides.insert(
                    token_id=token_id,
                    indicator=indicator,
                    indicator_type=indicator_type,
                    override_type=override_type,
                    reason=reason,
                    created_by=created_by,
                    expires_at=expires_at,
                )

            db.commit()

            # Reload overrides
            await self._load_overrides(db)

            return True

        except Exception as e:
            logger.error(f"Failed to add IOC override: {e}")
            return False
        finally:
            db.close()

    async def _load_overrides(self, db):
        """Load token-specific overrides"""
        try:
            self.allow_overrides.clear()
            self.block_overrides.clear()

            # Get current overrides (not expired)
            overrides = db(
                (db.ioc_overrides.expires_at == None)
                | (db.ioc_overrides.expires_at > datetime.now())
            ).select()

            for override in overrides:
                token_id = override.token_id
                indicator = (
                    override.indicator.lower()
                    if override.indicator_type == "domain"
                    else override.indicator
                )

                if override.override_type == "allow":
                    if token_id not in self.allow_overrides:
                        self.allow_overrides[token_id] = set()
                    self.allow_overrides[token_id].add(indicator)

                elif override.override_type == "block":
                    if token_id not in self.block_overrides:
                        self.block_overrides[token_id] = set()
                    self.block_overrides[token_id].add(indicator)

        except Exception as e:
            logger.error(f"Failed to load IOC overrides: {e}")

    async def _rebuild_caches(self, db):
        """Rebuild in-memory caches for fast lookups"""
        try:
            # Clear existing caches
            self.blocked_domains.clear()
            self.blocked_ips.clear()

            # Load domains
            domain_entries = db(
                (db.ioc_entries.indicator_type == "domain")
                & (db.ioc_feeds.id == db.ioc_entries.feed_id)
                & (db.ioc_feeds.enabled == True)
            ).select(db.ioc_entries.indicator)

            for entry in domain_entries:
                self.blocked_domains.add(entry.indicator.lower())

            # Load IPs
            ip_entries = db(
                (db.ioc_entries.indicator_type == "ip")
                & (db.ioc_feeds.id == db.ioc_entries.feed_id)
                & (db.ioc_feeds.enabled == True)
            ).select(db.ioc_entries.indicator)

            for entry in ip_entries:
                self.blocked_ips.add(entry.indicator)

            # Load overrides
            await self._load_overrides(db)

            logger.info(
                f"IOC cache rebuilt: {len(self.blocked_domains)} domains, {len(self.blocked_ips)} IPs"
            )

        except Exception as e:
            logger.error(f"Failed to rebuild IOC caches: {e}")

    async def can_add_feed(self, feed_name: str) -> Tuple[bool, str]:
        """Check if user can add a new threat intelligence feed based on licensing"""
        try:
            from pydal import DAL

            db = DAL(self.db_url)

            # Count current enabled feeds
            enabled_feeds = db(db.ioc_feeds.enabled == True).count()

            # Check licensing
            if self.license_manager:
                # Check license tier
                license_status = await self.license_manager.check_enterprise_features()

                # Check for Enterprise Self-Hosted or Cloud-Hosted
                if license_status.get(
                    "enterprise_self_hosted", False
                ) or license_status.get("enterprise_cloud_hosted", False):
                    # Both enterprise tiers: unlimited feeds
                    return (
                        True,
                        "Enterprise license allows unlimited threat intelligence feeds",
                    )

            # Community: 1 feed limit
            max_community_feeds = 1
            if enabled_feeds >= max_community_feeds:
                return (
                    False,
                    f"Community edition limited to {max_community_feeds} threat intelligence feed. Upgrade to Enterprise Self-Hosted ($5/user/month) or Cloud-Hosted ($7/user/month) for unlimited feeds.",
                )

            return (
                True,
                f"Community feed slot available ({enabled_feeds}/{max_community_feeds})",
            )

        except Exception as e:
            logger.error(f"Failed to check feed limits: {e}")
            return False, "Unable to verify licensing status"
        finally:
            db.close()

    async def add_threat_feed(
        self,
        name: str,
        url: str,
        feed_type: str,
        format_type: str,
        config: dict = None,
        auth_config: dict = None,
        update_frequency_hours: int = 6,
        enabled: bool = True,
    ) -> Tuple[bool, str]:
        """Add a new threat intelligence feed with licensing checks"""
        try:
            # Check if user can add more feeds
            can_add, reason = await self.can_add_feed(name)
            if not can_add:
                return False, reason

            from pydal import DAL

            db = DAL(self.db_url)

            # Check if feed already exists
            existing = db(db.ioc_feeds.name == name).select().first()
            if existing:
                return False, f"Threat intelligence feed '{name}' already exists"

            # Add the feed
            feed_id = db.ioc_feeds.insert(
                name=name,
                url=url,
                feed_type=feed_type,
                format=format_type,
                enabled=enabled,
                update_frequency_hours=update_frequency_hours,
                parser_config=config or {},
                authentication=auth_config or {},
            )

            db.commit()

            if enabled:
                logger.info(f"Added and enabled threat intelligence feed: {name}")
            else:
                logger.info(f"Added threat intelligence feed (disabled): {name}")

            return True, f"Successfully added threat intelligence feed '{name}'"

        except Exception as e:
            logger.error(f"Failed to add threat feed: {e}")
            return False, f"Database error: {str(e)}"
        finally:
            if "db" in locals():
                db.close()

    async def enable_threat_feed(self, feed_name: str) -> Tuple[bool, str]:
        """Enable a threat intelligence feed with licensing checks"""
        try:
            from pydal import DAL

            db = DAL(self.db_url)

            # Find the feed
            feed = db(db.ioc_feeds.name == feed_name).select().first()
            if not feed:
                return False, f"Threat intelligence feed '{feed_name}' not found"

            if feed.enabled:
                return (
                    True,
                    f"Threat intelligence feed '{feed_name}' is already enabled",
                )

            # Check if user can enable more feeds (excluding the current one since it's disabled)
            can_add, reason = await self.can_add_feed(feed_name)
            if not can_add:
                return False, reason

            # Enable the feed
            feed.update_record(enabled=True)
            db.commit()

            logger.info(f"Enabled threat intelligence feed: {feed_name}")
            return True, f"Successfully enabled threat intelligence feed '{feed_name}'"

        except Exception as e:
            logger.error(f"Failed to enable threat feed: {e}")
            return False, f"Database error: {str(e)}"
        finally:
            db.close()

    async def disable_threat_feed(self, feed_name: str) -> Tuple[bool, str]:
        """Disable a threat intelligence feed"""
        try:
            from pydal import DAL

            db = DAL(self.db_url)

            # Find the feed
            feed = db(db.ioc_feeds.name == feed_name).select().first()
            if not feed:
                return False, f"Threat intelligence feed '{feed_name}' not found"

            if not feed.enabled:
                return (
                    True,
                    f"Threat intelligence feed '{feed_name}' is already disabled",
                )

            # Disable the feed
            feed.update_record(enabled=False)
            db.commit()

            logger.info(f"Disabled threat intelligence feed: {feed_name}")
            return True, f"Successfully disabled threat intelligence feed '{feed_name}'"

        except Exception as e:
            logger.error(f"Failed to disable threat feed: {e}")
            return False, f"Database error: {str(e)}"
        finally:
            db.close()

    async def get_threat_feeds(self) -> List[Dict]:
        """Get all threat intelligence feeds with status information"""
        try:
            from pydal import DAL

            db = DAL(self.db_url)

            feeds = db(db.ioc_feeds).select()

            result = []
            for feed in feeds:
                result.append(
                    {
                        "id": feed.id,
                        "name": feed.name,
                        "url": feed.url,
                        "feed_type": feed.feed_type,
                        "format": feed.format,
                        "enabled": feed.enabled,
                        "update_frequency_hours": feed.update_frequency_hours,
                        "last_update": (
                            feed.last_update.isoformat() if feed.last_update else None
                        ),
                        "last_success": (
                            feed.last_success.isoformat() if feed.last_success else None
                        ),
                        "entry_count": feed.entry_count or 0,
                        "created_at": (
                            feed.created_at.isoformat() if feed.created_at else None
                        ),
                    }
                )

            return result

        except Exception as e:
            logger.error(f"Failed to get threat feeds: {e}")
            return []
        finally:
            db.close()

    async def get_licensing_info(self) -> Dict:
        """Get licensing information for threat intelligence features"""
        try:
            from pydal import DAL

            db = DAL(self.db_url)

            # Count feeds
            total_feeds = db(db.ioc_feeds).count()
            enabled_feeds = db(db.ioc_feeds.enabled == True).count()

            # Default to Community
            edition = "Community"
            tier = "free"
            max_feeds = 1
            pricing = "Free"
            is_enterprise = False
            is_self_hosted = False
            is_cloud_hosted = False

            if self.license_manager:
                license_status = await self.license_manager.check_enterprise_features()

                if license_status.get("enterprise_cloud_hosted", False):
                    edition = "Enterprise Cloud-Hosted"
                    tier = "cloud_hosted"
                    pricing = "$7/user/month"
                    max_feeds = -1  # Unlimited
                    is_enterprise = True
                    is_cloud_hosted = True
                elif license_status.get("enterprise_self_hosted", False):
                    edition = "Enterprise Self-Hosted"
                    tier = "self_hosted"
                    pricing = "$5/user/month"
                    max_feeds = -1  # Unlimited
                    is_enterprise = True
                    is_self_hosted = True

            return {
                "edition": edition,
                "tier": tier,
                "pricing": pricing,
                "is_enterprise": is_enterprise,
                "is_self_hosted": is_self_hosted,
                "is_cloud_hosted": is_cloud_hosted,
                "max_feeds": max_feeds,
                "current_enabled_feeds": enabled_feeds,
                "total_feeds": total_feeds,
                "feeds_remaining": max_feeds - enabled_feeds if max_feeds > 0 else -1,
                "features": {
                    # Community features
                    "basic_dns_resolution": True,
                    "basic_caching": True,
                    "mtls_auth": True,
                    "basic_web_console": True,
                    "single_threat_feed": True,
                    # Enterprise Self-Hosted features
                    "unlimited_feeds": is_enterprise,
                    "selective_dns_routing": is_enterprise,
                    "advanced_token_management": is_enterprise,
                    "multi_tenant": is_enterprise,
                    "saml_ldap_sso": is_enterprise,
                    "priority_processing": is_enterprise,
                    "enhanced_caching": is_enterprise,
                    "technical_support": is_enterprise,
                    "self_managed": is_self_hosted,
                    # Enterprise Cloud-Hosted exclusive features
                    "managed_infrastructure": is_cloud_hosted,
                    "sla_guarantee": is_cloud_hosted,
                    "automatic_updates": is_cloud_hosted,
                    "advanced_monitoring": is_cloud_hosted,
                    "compliance_reporting": is_cloud_hosted,
                    "dedicated_support": is_cloud_hosted,
                    "global_cdn": is_cloud_hosted,
                    "advanced_threat_curation": is_cloud_hosted,
                    "custom_development": is_cloud_hosted,
                },
            }

        except Exception as e:
            logger.error(f"Failed to get licensing info: {e}")
            return {
                "edition": "Community",
                "tier": "free",
                "pricing": "Free",
                "is_enterprise": False,
                "max_feeds": 1,
                "error": str(e),
            }
        finally:
            if "db" in locals():
                db.close()

    async def _parse_stix_objects(
        self, stix_objects: List[Dict], config: dict
    ) -> List[Dict]:
        """Parse STIX objects from TAXII feed into indicators"""
        indicators = []

        try:
            extract_types = config.get(
                "extract_types", ["domain-name", "ipv4-addr", "ipv6-addr", "url"]
            )
            confidence_threshold = config.get("confidence_threshold", 50)
            confidence_mapping = config.get(
                "confidence_mapping", {"high": 90, "medium": 70, "low": 30}
            )
            include_relationships = config.get("include_relationships", True)
            min_confidence = config.get("min_confidence", 30)

            for obj in stix_objects:
                try:
                    if obj.get("type") == "indicator":
                        # STIX Indicator object
                        pattern = obj.get("pattern", "")
                        labels = obj.get("labels", [])
                        confidence = obj.get("confidence", 50)

                        # Map confidence levels
                        if isinstance(confidence, str):
                            confidence = confidence_mapping.get(confidence.lower(), 50)

                        if confidence < min_confidence:
                            continue

                        # Extract indicators from pattern
                        extracted = self._extract_from_stix_pattern(
                            pattern, extract_types
                        )
                        for indicator_value, indicator_type in extracted:
                            if self._is_valid_indicator(
                                indicator_value, indicator_type
                            ):
                                indicators.append(
                                    {
                                        "value": (
                                            indicator_value.lower()
                                            if indicator_type == "domain"
                                            else indicator_value
                                        ),
                                        "type": indicator_type,
                                        "threat_type": (
                                            ", ".join(labels) if labels else "unknown"
                                        ),
                                        "confidence": confidence,
                                        "description": obj.get("name", ""),
                                        "tags": labels,
                                        "first_seen": self._parse_iso_date(
                                            obj.get("valid_from")
                                        ),
                                        "last_seen": self._parse_iso_date(
                                            obj.get("valid_until")
                                        ),
                                        "context": {
                                            "stix_id": obj.get("id", ""),
                                            "stix_pattern": pattern,
                                            "stix_created": obj.get("created", ""),
                                            "stix_modified": obj.get("modified", ""),
                                            "stix_revoked": obj.get("revoked", False),
                                        },
                                    }
                                )

                    elif obj.get("type") in [
                        "malware",
                        "attack-pattern",
                        "intrusion-set",
                    ]:
                        # Extract network indicators from SDO descriptions and kill chain phases
                        description = obj.get("description", "")
                        name = obj.get("name", "")

                        # Extract domains and IPs from description text
                        domain_matches = re.findall(
                            r"\b([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",
                            description,
                        )
                        ip_matches = re.findall(
                            r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", description
                        )

                        for domain_match in domain_matches:
                            domain = (
                                domain_match[0]
                                if isinstance(domain_match, tuple)
                                else domain_match
                            )
                            if self._is_valid_domain(domain.lower()):
                                indicators.append(
                                    {
                                        "value": domain.lower(),
                                        "type": "domain",
                                        "threat_type": obj.get("type", "unknown"),
                                        "confidence": 60,  # Lower confidence for extracted indicators
                                        "description": f"Extracted from {obj.get('type')}: {name}",
                                        "tags": [obj.get("type", "unknown")],
                                        "context": {
                                            "stix_id": obj.get("id", ""),
                                            "stix_type": obj.get("type", ""),
                                            "extracted_from_description": True,
                                        },
                                    }
                                )

                        for ip in ip_matches:
                            if self._is_valid_ip(ip):
                                indicators.append(
                                    {
                                        "value": ip,
                                        "type": "ip",
                                        "threat_type": obj.get("type", "unknown"),
                                        "confidence": 60,
                                        "description": f"Extracted from {obj.get('type')}: {name}",
                                        "tags": [obj.get("type", "unknown")],
                                        "context": {
                                            "stix_id": obj.get("id", ""),
                                            "stix_type": obj.get("type", ""),
                                            "extracted_from_description": True,
                                        },
                                    }
                                )

                    elif (
                        obj.get("type")
                        in ["ipv4-addr", "ipv6-addr", "domain-name", "url"]
                        and "domain-name" in extract_types
                    ):
                        # STIX Cyber Observable Objects (SCO)
                        value = obj.get("value", "")
                        if value:
                            indicator_type = (
                                "domain" if obj.get("type") == "domain-name" else "ip"
                            )
                            if self._is_valid_indicator(value, indicator_type):
                                indicators.append(
                                    {
                                        "value": (
                                            value.lower()
                                            if indicator_type == "domain"
                                            else value
                                        ),
                                        "type": indicator_type,
                                        "threat_type": "sco",
                                        "confidence": 70,
                                        "description": f"STIX Cyber Observable: {obj.get('type')}",
                                        "tags": ["sco"],
                                        "context": {
                                            "stix_id": obj.get("id", ""),
                                            "stix_type": obj.get("type", ""),
                                            "is_sco": True,
                                        },
                                    }
                                )

                except Exception as e:
                    logger.warning(f"Failed to parse STIX object: {e}")
                    continue

        except Exception as e:
            logger.error(f"Failed to parse STIX objects: {e}")

        return indicators

    def _parse_iso_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse ISO 8601 date format"""
        if not date_str:
            return None
        try:
            # Handle different ISO formats
            if date_str.endswith("Z"):
                date_str = date_str[:-1] + "+00:00"
            return datetime.fromisoformat(date_str)
        except (ValueError, AttributeError):
            return None


class TAXII2Client:
    """TAXII 2.x client for fetching STIX threat intelligence"""

    def __init__(
        self,
        api_root: str,
        collection_id: str,
        auth_type: str = "none",
        token: str = "",
        username: str = "",
        password: str = "",
        verify_ssl: bool = True,
    ):
        self.api_root = api_root.rstrip("/")
        self.collection_id = collection_id
        self.auth_type = auth_type
        self.token = token
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl

    async def get_objects(
        self, added_after: Optional[str] = None, limit: int = 10000
    ) -> Optional[List[Dict]]:
        """Fetch STIX objects from TAXII collection"""
        try:
            url = f"{self.api_root}/collections/{self.collection_id}/objects/"
            headers = {
                "Accept": "application/taxii+json;version=2.1",
                "Content-Type": "application/json",
            }
            params = {}

            if added_after:
                params["added_after"] = added_after
            if limit:
                params["limit"] = limit

            # Setup authentication
            auth = None
            if self.auth_type == "basic" and self.username and self.password:
                auth = aiohttp.BasicAuth(self.username, self.password)
            elif self.auth_type == "bearer" and self.token:
                headers["Authorization"] = f"Bearer {self.token}"

            ssl_context = None
            if not self.verify_ssl:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    headers=headers,
                    params=params,
                    auth=auth,
                    ssl=ssl_context,
                    timeout=120,
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        # TAXII 2.x envelope format
                        if "objects" in data:
                            return data["objects"]
                        else:
                            return [data]
                    else:
                        logger.error(
                            f"TAXII server returned HTTP {response.status}: {await response.text()}"
                        )
                        return None

        except Exception as e:
            logger.error(f"Failed to fetch TAXII objects: {e}")
            return None

    async def discover_api_roots(self, discovery_url: str) -> List[str]:
        """Discover available API roots from TAXII server"""
        try:
            headers = {"Accept": "application/taxii+json;version=2.1"}

            auth = None
            if self.auth_type == "basic" and self.username and self.password:
                auth = aiohttp.BasicAuth(self.username, self.password)
            elif self.auth_type == "bearer" and self.token:
                headers["Authorization"] = f"Bearer {self.token}"

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    discovery_url, headers=headers, auth=auth
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get("api_roots", [])
                    else:
                        logger.error(f"Discovery failed with HTTP {response.status}")
                        return []

        except Exception as e:
            logger.error(f"TAXII discovery failed: {e}")
            return []

    async def get_collections(self) -> List[Dict]:
        """Get available collections from API root"""
        try:
            url = f"{self.api_root}/collections/"
            headers = {"Accept": "application/taxii+json;version=2.1"}

            auth = None
            if self.auth_type == "basic" and self.username and self.password:
                auth = aiohttp.BasicAuth(self.username, self.password)
            elif self.auth_type == "bearer" and self.token:
                headers["Authorization"] = f"Bearer {self.token}"

            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, auth=auth) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get("collections", [])
                    else:
                        logger.error(
                            f"Collections request failed with HTTP {response.status}"
                        )
                        return []

        except Exception as e:
            logger.error(f"Failed to get TAXII collections: {e}")
            return []
