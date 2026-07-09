"""
IOC (Indicators of Compromise) Ingestion Service for Squawk Manager.

Manages threat intelligence feed ingestion, parsing, and indicator blocking.
Uses penguin-dal for runtime database operations.
Schema is managed by Alembic (ioc_feed, ioc_entry, ioc_override tables).
"""

from __future__ import annotations

import asyncio
import aiohttp
import json
import logging
import os
import re
import csv
import socket
import defusedxml.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from io import StringIO
from urllib.parse import urlparse
import ipaddress

from penguin_dal import DB

logger = logging.getLogger(__name__)


async def _assert_feed_url_safe(url: str) -> None:
    """Reject SSRF-prone feed URLs before any outbound fetch.

    Requires http/https, then resolves the host and refuses private,
    loopback, link-local (incl. cloud metadata 169.254.169.254), reserved,
    or multicast targets. Set IOC_ALLOW_PRIVATE_FEEDS=true to permit
    internal feeds in on-prem deployments. Residual DNS-rebinding risk
    remains (resolve-time check), which is acceptable for admin-configured
    feeds; pin-and-connect can be added if needed.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Feed URL scheme not allowed: {parsed.scheme!r}")
    host = parsed.hostname
    if not host:
        raise ValueError("Feed URL has no host")
    if os.getenv("IOC_ALLOW_PRIVATE_FEEDS", "false").lower() == "true":
        return
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = await asyncio.to_thread(socket.getaddrinfo, host, port)
    except socket.gaierror as e:
        raise ValueError(f"Feed URL host does not resolve: {host}") from e
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise ValueError(f"Feed URL resolves to a disallowed address ({ip}); refusing to fetch")


@dataclass(slots=True)
class IOCIndicator:
    """Represents a single indicator in an IOC feed."""
    value: str
    type: str  # domain, ip, hash, url, email
    threat_type: Optional[str] = None
    confidence: int = 50
    description: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    tags: Optional[List[str]] = field(default_factory=list)
    context: Optional[Dict[str, Any]] = field(default_factory=dict)
    source_format: Optional[str] = None
    misp_event_id: Optional[str] = None
    misp_attribute_id: Optional[str] = None


@dataclass(slots=True, frozen=True)
class OverrideRecord:
    """Represents an IOC override record."""
    token_id: int
    indicator: str
    indicator_type: str
    override_type: str  # allow, block
    reason: Optional[str] = None
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None


class IOCManager:
    """
    Manages IOC feeds, parsing, and blocking decisions.

    Features:
    - Multiple feed format support (txt, csv, json, xml, stix, misp, openioc, yara, snort)
    - Per-token override capabilities (allow/block)
    - Automatic feed updates with frequency control
    - Domain wildcard matching and CIDR IP matching
    - Expiring overrides
    """

    # Enterprise-only formats (require license)
    ENTERPRISE_FORMATS = {'taxii', 'misp', 'stix', 'openioc'}
    COMMUNITY_FORMATS = {'txt', 'csv', 'json', 'xml'}

    def __init__(
        self,
        db_url: str,
        update_interval_hours: int = 6,
        license_manager: Optional[Any] = None,
    ) -> None:
        """
        Initialize IOC Manager.

        Args:
            db_url: Database URL for penguin-dal
            update_interval_hours: Default feed update frequency
            license_manager: Optional license manager for feature gating
        """
        self.db_url = db_url
        self.update_interval_hours = update_interval_hours
        self.license_manager = license_manager

        # In-memory caches for fast lookups
        self.blocked_domains: Dict[str, List[str]] = {}  # domain -> [feed_names]
        self.blocked_ips: Dict[str, List[str]] = {}  # ip/cidr -> [feed_names]
        self.cidr_blocks: List[Tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, List[str]]] = []

        # Per-token overrides
        self.allow_overrides: Dict[int, set] = {}  # token_id -> set of (indicator, type)
        self.block_overrides: Dict[int, set] = {}  # token_id -> set of (indicator, type)
        self.override_expiry: Dict[Tuple[int, str, str], datetime] = {}  # (token_id, indicator, type) -> expires_at

        self._initialize_database()

    def _initialize_database(self) -> None:
        """Create database connection and ensure schema exists."""
        try:
            db = DB(self.db_url)
            # Tables are already defined in schema.py and migrated by Alembic
            # Just verify they exist by attempting a simple query
            _ = db(db.ioc_feed.id > 0).select()
            _ = db(db.ioc_entry.id > 0).select()
            _ = db(db.ioc_override.id > 0).select()
            db.close()
        except Exception as e:
            logger.warning(f"Database initialization check failed: {e}. Schema may not exist yet.")

    def _is_format_licensed(self, format_type: str) -> bool:
        """
        Check if a format is available (licensed).

        Community formats are always available.
        Enterprise formats require 'ioc_advanced_feeds' license.

        Args:
            format_type: Format name (txt, csv, json, xml, taxii, misp, stix, openioc)

        Returns:
            True if format is available, False if requires unavailable license.
        """
        fmt = format_type.lower() if format_type else ''

        # Community formats always available
        if fmt in self.COMMUNITY_FORMATS:
            return True

        # Enterprise formats require license
        if fmt in self.ENTERPRISE_FORMATS:
            if self.license_manager:
                return self.license_manager.is_feature_enabled('ioc_advanced_feeds')
            # No license manager set; deny enterprise formats
            return False

        # Unknown format; deny by default
        return False

    # ── Normalization ────────────────────────────────────────────────────────

    def _normalize_domain(self, domain: str) -> str:
        """
        Normalize domain name.
        - Lowercase
        - Strip whitespace
        - Remove trailing dot
        """
        if not domain:
            return ""
        return domain.strip().lower().rstrip(".")

    def _normalize_ip(self, ip: str) -> str:
        """
        Normalize IP address.
        - Strip whitespace
        - Lowercase (for IPv6)
        """
        if not ip:
            return ""
        normalized = ip.strip()
        # IPv6 addresses are case-insensitive but conventionally lowercase
        try:
            addr = ipaddress.ip_address(normalized)
            return str(addr)
        except ValueError:
            # Try as CIDR
            try:
                net = ipaddress.ip_network(normalized, strict=False)
                return str(net)
            except ValueError:
                return normalized

    # ── Validation ───────────────────────────────────────────────────────────

    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain format."""
        if not domain or len(domain) > 255 or len(domain) < 4:
            return False

        # Allow wildcard
        if domain.startswith("*."):
            domain = domain[2:]

        # Check for valid characters
        if not re.match(r"^[a-zA-Z0-9.-]+$", domain):
            return False

        # Must have at least one dot
        if "." not in domain:
            return False

        # Check each part
        parts = domain.split(".")
        for part in parts:
            if not part or len(part) > 63:
                return False
            if part.startswith("-") or part.endswith("-"):
                return False

        return True

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address or CIDR block."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            pass

        try:
            ipaddress.ip_network(ip, strict=False)
            return True
        except ValueError:
            return False

    # ── Feed Parsing ─────────────────────────────────────────────────────────

    async def _parse_text_feed(
        self,
        content: str,
        feed_type: str,
        config: Optional[Dict[str, Any]] = None,
    ) -> List[IOCIndicator]:
        """Parse text-based feeds (one indicator per line)."""
        indicators: List[IOCIndicator] = []
        config = config or {}
        comment_chars = config.get("comment_chars", ["#", ";"])
        skip_localhost = config.get("skip_localhost", False)

        for line in content.split("\n"):
            line = line.strip()
            if not line or any(line.startswith(c) for c in comment_chars):
                continue

            if feed_type == "domain":
                if self._is_valid_domain(line):
                    indicators.append(
                        IOCIndicator(
                            value=self._normalize_domain(line),
                            type="domain",
                            threat_type="malware",
                            confidence=75,
                        )
                    )

            elif feed_type == "ip":
                if self._is_valid_ip(line):
                    normalized = self._normalize_ip(line)
                    indicators.append(
                        IOCIndicator(
                            value=normalized,
                            type="ip",
                            threat_type="malware",
                            confidence=75,
                        )
                    )

        return indicators

    async def _parse_csv_feed(
        self,
        content: str,
        feed_type: str,
        config: Optional[Dict[str, Any]] = None,
    ) -> List[IOCIndicator]:
        """Parse CSV-based feeds."""
        indicators: List[IOCIndicator] = []
        config = config or {}
        delimiter = config.get("delimiter", ",")

        try:
            reader = csv.DictReader(StringIO(content), delimiter=delimiter)
            if reader.fieldnames is None:
                logger.warning("CSV has no headers")
                return indicators

            for row in reader:
                # Try different column name variants
                indicator_val = None
                ind_type = None

                # For mixed feeds, check if row has explicit type column
                if feed_type == "mixed" and "type" in row:
                    row_type = row["type"].strip().lower()
                    if row_type in ["domain", "ip"]:
                        ind_type = row_type

                # Get indicator value
                for col in ["indicator", "domain", "host", "ip", "ip_address"]:
                    if col in row and row[col]:
                        indicator_val = row[col].strip()
                        break

                if not indicator_val:
                    continue

                # Validate and classify if type not yet determined
                if not ind_type:
                    if self._is_valid_domain(indicator_val):
                        ind_type = "domain"
                        indicator_val = self._normalize_domain(indicator_val)
                    elif self._is_valid_ip(indicator_val):
                        ind_type = "ip"
                        indicator_val = self._normalize_ip(indicator_val)
                    else:
                        continue
                else:
                    # Type was explicitly set, validate accordingly
                    if ind_type == "domain":
                        if not self._is_valid_domain(indicator_val):
                            continue
                        indicator_val = self._normalize_domain(indicator_val)
                    elif ind_type == "ip":
                        if not self._is_valid_ip(indicator_val):
                            continue
                        indicator_val = self._normalize_ip(indicator_val)

                threat_type = row.get("threat_type") or row.get("category") or "unknown"
                try:
                    confidence = int(row.get("confidence", 50))
                except (ValueError, TypeError):
                    confidence = 50

                indicators.append(
                    IOCIndicator(
                        value=indicator_val,
                        type=ind_type,
                        threat_type=threat_type,
                        confidence=confidence,
                        description=row.get("description", ""),
                    )
                )

        except Exception as e:
            logger.warning(f"CSV parsing error: {e}")

        return indicators

    async def _parse_json_feed(
        self,
        content: str,
        feed_type: str,
        config: Optional[Dict[str, Any]] = None,
    ) -> List[IOCIndicator]:
        """Parse JSON-based feeds."""
        indicators: List[IOCIndicator] = []
        config = config or {}

        try:
            data = json.loads(content)

            # Navigate json_path if specified
            if config.get("json_path"):
                for key in config["json_path"].split("."):
                    if isinstance(data, dict):
                        data = data.get(key, {})
                    else:
                        break

            if isinstance(data, list):
                items = data
            elif isinstance(data, dict) and "indicators" in data:
                items = data["indicators"]
            else:
                items = []

            for item in items:
                if not isinstance(item, dict):
                    continue

                indicator_val = item.get("indicator")
                if not indicator_val:
                    continue

                indicator_val = str(indicator_val).strip()

                # For mixed feeds, check if item has explicit type
                ind_type = None
                if feed_type == "mixed" and "type" in item:
                    item_type = str(item["type"]).strip().lower()
                    if item_type in ["domain", "ip"]:
                        ind_type = item_type

                # Determine type if not yet known
                if not ind_type:
                    if self._is_valid_domain(indicator_val):
                        ind_type = "domain"
                    elif self._is_valid_ip(indicator_val):
                        ind_type = "ip"
                    else:
                        continue
                else:
                    # Type was explicit, validate it
                    if ind_type == "domain" and not self._is_valid_domain(indicator_val):
                        continue
                    elif ind_type == "ip" and not self._is_valid_ip(indicator_val):
                        continue

                # Normalize the value
                if ind_type == "domain":
                    indicator_val = self._normalize_domain(indicator_val)
                else:
                    indicator_val = self._normalize_ip(indicator_val)

                indicators.append(
                    IOCIndicator(
                        value=indicator_val,
                        type=ind_type,
                        threat_type=item.get("threat_type", "unknown"),
                        confidence=int(item.get("confidence", 50)),
                        description=item.get("description"),
                    )
                )

        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing error: {e}")
            raise  # Re-raise to mark as error
        except Exception as e:
            logger.warning(f"JSON feed parsing error: {e}")

        return indicators

    async def _parse_xml_feed(
        self,
        content: str,
        feed_type: str,
        config: Optional[Dict[str, Any]] = None,
    ) -> List[IOCIndicator]:
        """Parse XML-based feeds."""
        indicators: List[IOCIndicator] = []

        try:
            root = ET.fromstring(content)

            # Look for common XML patterns
            for elem in root.iter():
                value = elem.text
                if not value:
                    continue

                value = value.strip()
                if self._is_valid_domain(value):
                    indicators.append(
                        IOCIndicator(
                            value=self._normalize_domain(value),
                            type="domain",
                            threat_type=elem.get("threat_type", "unknown"),
                        )
                    )
                elif self._is_valid_ip(value):
                    indicators.append(
                        IOCIndicator(
                            value=self._normalize_ip(value),
                            type="ip",
                            threat_type=elem.get("threat_type", "unknown"),
                        )
                    )

        except ET.ParseError as e:
            logger.warning(f"XML parsing error: {e}")
        except Exception as e:
            logger.warning(f"XML feed parsing error: {e}")

        return indicators

    async def _parse_feed_content(
        self,
        content: str,
        feed_type: str,
        format_type: str,
        config: Optional[Dict[str, Any]] = None,
    ) -> List[IOCIndicator]:
        """Parse feed content based on format."""
        config = config or {}

        if format_type == "txt":
            return await self._parse_text_feed(content, feed_type, config)
        elif format_type == "csv":
            return await self._parse_csv_feed(content, feed_type, config)
        elif format_type == "json":
            return await self._parse_json_feed(content, feed_type, config)
        elif format_type == "xml":
            return await self._parse_xml_feed(content, feed_type, config)
        else:
            logger.warning(f"Unsupported format: {format_type}")
            return []

    # ── Feed Operations ──────────────────────────────────────────────────────

    async def update_feed_from_content(
        self,
        name: str,
        content: str,
        feed_type: str,
        format_type: str,
    ) -> Dict[str, Any]:
        """
        Update a feed with provided content.

        Returns dict with keys:
        - success (bool)
        - indicators_added (int)
        - warnings (optional list)
        - error (optional str)
        """
        # Check license for enterprise formats
        if not self._is_format_licensed(format_type):
            return {
                "success": False,
                "indicators_added": 0,
                "error": f"Format '{format_type}' requires Enterprise license (ioc_advanced_feeds)",
            }

        try:
            db = DB(self.db_url)

            try:
                # Parse content - catch JSON parse errors specially
                try:
                    indicators = await self._parse_feed_content(
                        content, feed_type, format_type
                    )
                except json.JSONDecodeError as e:
                    # Parse error is a failure, not just empty result
                    return {
                        "success": False,
                        "indicators_added": 0,
                        "error": f"Parse error: {str(e)}",
                    }

                if not indicators:
                    return {
                        "success": True,
                        "indicators_added": 0,
                        "warnings": ["No valid indicators found in content"],
                    }

                # Get or create feed
                feed = db(db.ioc_feed.name == name).select().first()
                if not feed:
                    feed_id = db.ioc_feed.insert(
                        name=name,
                        url="",
                        feed_type=feed_type,
                        format=format_type,
                        enabled=True,
                        update_interval=self.update_interval_hours,
                    )
                else:
                    feed_id = feed.id
                    # Clear old entries
                    db(db.ioc_entry.feed_id == feed_id).delete()

                # Insert indicators
                for ind in indicators:
                    db.ioc_entry.insert(
                        feed_id=feed_id,
                        indicator=ind.value,
                        indicator_type=ind.type,
                        threat_type=ind.threat_type,
                        confidence=ind.confidence,
                        source_format=format_type,
                    )

                db.commit()

                # Rebuild cache
                await self._rebuild_cache(db)

                return {
                    "success": True,
                    "indicators_added": len(indicators),
                }

            finally:
                db.close()

        except Exception as e:
            logger.error(f"Feed update failed: {e}")
            return {
                "success": False,
                "indicators_added": 0,
                "error": str(e),
            }

    async def register_feed(
        self,
        name: str,
        url: str,
        feed_type: str,
        format_type: str,
        update_frequency_hours: int = 6,
        enabled: bool = True,
    ) -> Dict[str, Any]:
        """
        Register a new IOC feed.

        Returns dict with:
        - success (bool)
        - feed_id (int, if success)
        """
        # Check license for enterprise formats
        if not self._is_format_licensed(format_type):
            return {
                "success": False,
                "error": f"Format '{format_type}' requires Enterprise license (ioc_advanced_feeds)",
            }

        try:
            db = DB(self.db_url)

            try:
                # Check if already exists
                existing = db(db.ioc_feed.name == name).select().first()
                if existing:
                    return {
                        "success": False,
                        "error": f"Feed '{name}' already exists",
                    }

                feed_id = db.ioc_feed.insert(
                    name=name,
                    url=url,
                    feed_type=feed_type,
                    format=format_type,
                    enabled=enabled,
                    update_interval=update_frequency_hours,
                )
                db.commit()

                return {
                    "success": True,
                    "feed_id": feed_id,
                }

            finally:
                db.close()

        except Exception as e:
            logger.error(f"Feed registration failed: {e}")
            return {
                "success": False,
                "error": str(e),
            }

    async def update_all_feeds(self) -> Dict[str, Any]:
        """
        Update all enabled feeds that are due for update.

        Returns dict with:
        - success (bool)
        - feeds_updated (int)
        - skipped (int, optional)
        - error (optional str if any feed failed)
        """
        try:
            db = DB(self.db_url)

            try:
                feeds = db(db.ioc_feed.enabled == True).select()
                updated = 0
                skipped = 0
                failed = 0
                errors = []

                for feed in feeds:
                    # Check if update is needed
                    if feed.last_updated:
                        next_update = feed.last_updated + timedelta(
                            hours=feed.update_interval
                        )
                        if datetime.now() < next_update:
                            skipped += 1
                            continue

                    # Fetch and update
                    try:
                        await self._update_single_feed(db, feed)
                        updated += 1
                    except Exception as e:
                        failed += 1
                        errors.append(f"{feed.name}: {str(e)}")
                        logger.error(f"Failed to update feed {feed.name}: {e}")

                # Rebuild cache after all updates
                await self._rebuild_cache(db)

                result: Dict[str, Any] = {
                    "success": failed == 0,
                    "feeds_updated": updated,
                }
                if skipped > 0:
                    result["skipped"] = skipped
                if errors:
                    result["error"] = "; ".join(errors)

                return result

            finally:
                db.close()

        except Exception as e:
            logger.error(f"Feed update all failed: {e}")
            return {
                "success": False,
                "feeds_updated": 0,
                "error": str(e),
            }

    async def _update_single_feed(self, db: DB, feed: Any) -> None:
        """Update a single feed by fetching from its URL. Raises on error."""
        await _assert_feed_url_safe(feed.url)
        async with aiohttp.ClientSession() as session:
            # Do not follow redirects: an allowed host could 302 to an internal target.
            async with session.get(feed.url, timeout=60, allow_redirects=False) as response:
                if response.status == 200:
                    content = await response.text()

                    # Parse indicators
                    indicators = await self._parse_feed_content(
                        content,
                        feed.feed_type,
                        feed.format,
                    )

                    # Clear old entries
                    db(db.ioc_entry.feed_id == feed.id).delete()

                    # Insert new entries
                    for ind in indicators:
                        db.ioc_entry.insert(
                            feed_id=feed.id,
                            indicator=ind.value,
                            indicator_type=ind.type,
                            threat_type=ind.threat_type,
                            confidence=ind.confidence,
                            source_format=feed.format,
                        )

                    # Update feed metadata
                    db(db.ioc_feed.id == feed.id).update(
                        last_updated=datetime.now(),
                        last_success=datetime.now(),
                        entry_count=len(indicators),
                    )
                    db.commit()

                    logger.info(f"Updated feed {feed.name}: {len(indicators)} indicators")
                else:
                    raise Exception(f"Feed {feed.name} returned HTTP {response.status}")

    async def set_feed_enabled(self, feed_id: int, enabled: bool) -> Dict[str, Any]:
        """Enable or disable a feed."""
        try:
            db = DB(self.db_url)

            try:
                db(db.ioc_feed.id == feed_id).update(enabled=enabled)
                db.commit()

                return {"success": True}

            finally:
                db.close()

        except Exception as e:
            logger.error(f"Set feed enabled failed: {e}")
            return {"success": False, "error": str(e)}

    async def initialize_default_feeds(self) -> None:
        """Initialize default threat intelligence feeds."""
        try:
            db = DB(self.db_url)

            try:
                default_feeds = [
                    {
                        "name": "abuse.ch URLhaus",
                        "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
                        "feed_type": "domain",
                        "format": "txt",
                        "update_interval": 1,
                    },
                    {
                        "name": "abuse.ch Malware Domains",
                        "url": "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt",
                        "feed_type": "domain",
                        "format": "txt",
                        "update_interval": 6,
                    },
                    {
                        "name": "Emerging Threats Compromised IPs",
                        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                        "feed_type": "ip",
                        "format": "txt",
                        "update_interval": 1,
                    },
                    {
                        "name": "Feodo Tracker",
                        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
                        "feed_type": "ip",
                        "format": "txt",
                        "update_interval": 1,
                    },
                    {
                        "name": "Generic Threat Feed",
                        "url": "",
                        "feed_type": "mixed",
                        "format": "json",
                        "update_interval": 6,
                    },
                ]

                for feed_data in default_feeds:
                    existing = db(db.ioc_feed.name == feed_data["name"]).select().first()
                    if not existing:
                        db.ioc_feed.insert(
                            name=feed_data["name"],
                            url=feed_data["url"],
                            feed_type=feed_data["feed_type"],
                            format=feed_data["format"],
                            update_interval=feed_data["update_interval"],
                            enabled=True,
                        )

                db.commit()

            finally:
                db.close()

        except Exception as e:
            logger.warning(f"Default feeds initialization failed: {e}")

    # ── Override Operations ──────────────────────────────────────────────────

    async def add_override(
        self,
        token_id: int,
        indicator: str,
        indicator_type: str,
        override_type: str,  # allow or block
        reason: str = "",
        created_by: str = "",
        expires_at: Optional[datetime] = None,
    ) -> bool:
        """Add a per-token override."""
        try:
            db = DB(self.db_url)

            try:
                # Normalize indicator
                if indicator_type == "domain":
                    indicator = self._normalize_domain(indicator)
                elif indicator_type == "ip":
                    indicator = self._normalize_ip(indicator)

                # Check existing
                existing = db(
                    (db.ioc_override.token_id == token_id) &
                    (db.ioc_override.indicator == indicator) &
                    (db.ioc_override.indicator_type == indicator_type)
                ).select().first()

                if existing:
                    db(
                        (db.ioc_override.token_id == token_id) &
                        (db.ioc_override.indicator == indicator) &
                        (db.ioc_override.indicator_type == indicator_type)
                    ).update(
                        override_type=override_type,
                        reason=reason,
                        created_by=created_by,
                        created_at=datetime.now(),
                        expires_at=expires_at,
                    )
                else:
                    db.ioc_override.insert(
                        token_id=token_id,
                        indicator=indicator,
                        indicator_type=indicator_type,
                        override_type=override_type,
                        reason=reason,
                        created_by=created_by,
                        expires_at=expires_at,
                    )

                db.commit()

                # Rebuild overrides cache
                await self._load_overrides(db)

                return True

            finally:
                db.close()

        except Exception as e:
            logger.error(f"Add override failed: {e}")
            return False

    async def remove_override(
        self,
        token_id: int,
        indicator: str,
        indicator_type: str,
    ) -> bool:
        """Remove a per-token override."""
        try:
            db = DB(self.db_url)

            try:
                # Normalize indicator
                if indicator_type == "domain":
                    indicator = self._normalize_domain(indicator)
                elif indicator_type == "ip":
                    indicator = self._normalize_ip(indicator)

                db(
                    (db.ioc_override.token_id == token_id) &
                    (db.ioc_override.indicator == indicator) &
                    (db.ioc_override.indicator_type == indicator_type)
                ).delete()
                db.commit()

                # Rebuild overrides cache
                await self._load_overrides(db)

                return True

            finally:
                db.close()

        except Exception as e:
            logger.error(f"Remove override failed: {e}")
            return False

    async def get_overrides(self, token_id: int) -> List[Dict[str, Any]]:
        """Get all active overrides for a token."""
        try:
            db = DB(self.db_url)

            try:
                overrides = db(db.ioc_override.token_id == token_id).select()
                result = []

                for override in overrides:
                    # Skip expired
                    if override.expires_at and override.expires_at < datetime.now():
                        continue

                    result.append({
                        "indicator": override.indicator,
                        "indicator_type": override.indicator_type,
                        "override_type": override.override_type,
                        "reason": override.reason,
                        "created_by": override.created_by,
                        "created_at": override.created_at,
                        "expires_at": override.expires_at,
                    })

                return result

            finally:
                db.close()

        except Exception as e:
            logger.error(f"Get overrides failed: {e}")
            return []

    async def _load_overrides(self, db: DB) -> None:
        """Load overrides into memory cache."""
        try:
            self.allow_overrides.clear()
            self.block_overrides.clear()
            self.override_expiry.clear()

            overrides = db(db.ioc_override.id > 0).select()

            for override in overrides:
                # Skip expired
                if override.expires_at and override.expires_at < datetime.now():
                    continue

                key = (override.token_id, override.indicator, override.indicator_type)
                self.override_expiry[key] = override.expires_at

                if override.override_type == "allow":
                    if override.token_id not in self.allow_overrides:
                        self.allow_overrides[override.token_id] = set()
                    self.allow_overrides[override.token_id].add(
                        (override.indicator, override.indicator_type)
                    )
                elif override.override_type == "block":
                    if override.token_id not in self.block_overrides:
                        self.block_overrides[override.token_id] = set()
                    self.block_overrides[override.token_id].add(
                        (override.indicator, override.indicator_type)
                    )

        except Exception as e:
            logger.error(f"Load overrides failed: {e}")

    # ── Checking / Blocking ──────────────────────────────────────────────────

    async def check_domain(
        self,
        domain: str,
        token_id: Optional[int] = None,
    ) -> Tuple[bool, str]:
        """
        Check if domain should be blocked.

        Returns (should_block, reason_string).
        Overrides take precedence: allow beats block.
        """
        domain_normalized = self._normalize_domain(domain)

        # Check token overrides first (allow beats block)
        if token_id:
            # Check allow overrides
            if token_id in self.allow_overrides:
                for indicator, ind_type in self.allow_overrides[token_id]:
                    if ind_type != "domain":
                        continue

                    # Check exact match and wildcard parent match
                    if indicator == domain_normalized:
                        return False, "Allowed by override"

                    # Wildcard match: *.example.com matches subdomain.example.com
                    if indicator.startswith("*."):
                        parent = indicator[2:]  # Remove *.
                        if domain_normalized.endswith("." + parent) or domain_normalized == parent:
                            return False, "Allowed by override"

            # Check block overrides
            if token_id in self.block_overrides:
                for indicator, ind_type in self.block_overrides[token_id]:
                    if ind_type != "domain":
                        continue

                    if indicator == domain_normalized:
                        return True, "Blocked by override"

                    if indicator.startswith("*."):
                        parent = indicator[2:]
                        if domain_normalized.endswith("." + parent) or domain_normalized == parent:
                            return True, "Blocked by override"

        # Check IOC feeds
        if domain_normalized in self.blocked_domains:
            return True, "Blocked by threat intelligence"

        # Check parent domains and wildcard matches
        parts = domain_normalized.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self.blocked_domains:
                return True, f"Blocked by threat intelligence ({parent})"

            # Check for wildcard in feed
            wildcard = "*." + parent
            if wildcard in self.blocked_domains:
                return True, f"Blocked by threat intelligence ({wildcard})"

        return False, "Not blocked"

    async def check_ip(
        self,
        ip_addr: str,
        token_id: Optional[int] = None,
    ) -> Tuple[bool, str]:
        """
        Check if IP should be blocked.

        Returns (should_block, reason_string).
        Honors CIDR blocks and exact matches.
        Overrides take precedence: allow beats block.
        """
        ip_normalized = self._normalize_ip(ip_addr)

        # Check token overrides first (allow beats block)
        if token_id:
            # Check allow overrides
            if token_id in self.allow_overrides:
                for indicator, ind_type in self.allow_overrides[token_id]:
                    if ind_type != "ip":
                        continue

                    # Exact match or in CIDR
                    try:
                        if self._ip_in_range(ip_normalized, indicator):
                            return False, "Allowed by override"
                    except (ValueError, ipaddress.AddressValueError):
                        pass

            # Check block overrides
            if token_id in self.block_overrides:
                for indicator, ind_type in self.block_overrides[token_id]:
                    if ind_type != "ip":
                        continue

                    try:
                        if self._ip_in_range(ip_normalized, indicator):
                            return True, "Blocked by override"
                    except (ValueError, ipaddress.AddressValueError):
                        pass

        # Check IOC feeds
        if ip_normalized in self.blocked_ips:
            return True, "Blocked by threat intelligence"

        # Check CIDR blocks
        for net, feeds in self.cidr_blocks:
            try:
                addr = ipaddress.ip_address(ip_normalized)
                if addr in net:
                    return True, f"Blocked by threat intelligence (CIDR: {net})"
            except (ValueError, ipaddress.AddressValueError):
                pass

        return False, "Not blocked"

    def _ip_in_range(self, ip: str, range_str: str) -> bool:
        """Check if IP is in range (exact match or CIDR block)."""
        try:
            addr = ipaddress.ip_address(ip)

            # Try exact match first
            try:
                range_addr = ipaddress.ip_address(range_str)
                return addr == range_addr
            except ValueError:
                pass

            # Try CIDR
            net = ipaddress.ip_network(range_str, strict=False)
            return addr in net

        except (ValueError, ipaddress.AddressValueError):
            return False

    # ── Cache Management ─────────────────────────────────────────────────────

    async def _rebuild_cache(self, db: DB) -> None:
        """Rebuild in-memory indicator caches from database."""
        try:
            self.blocked_domains.clear()
            self.blocked_ips.clear()
            self.cidr_blocks.clear()

            # Get all enabled feed entries
            entries = db(db.ioc_entry.id > 0).select()

            for entry in entries:
                if entry.indicator_type == "domain":
                    if entry.indicator not in self.blocked_domains:
                        self.blocked_domains[entry.indicator] = []
                    # Could track feed names here if needed
                elif entry.indicator_type == "ip":
                    # Check if CIDR
                    try:
                        net = ipaddress.ip_network(entry.indicator, strict=False)
                        self.cidr_blocks.append((net, []))
                    except (ValueError, ipaddress.AddressValueError):
                        if entry.indicator not in self.blocked_ips:
                            self.blocked_ips[entry.indicator] = []

            await self._load_overrides(db)
            logger.info(
                f"Cache rebuilt: {len(self.blocked_domains)} domains, "
                f"{len(self.blocked_ips)} IPs, {len(self.cidr_blocks)} CIDR blocks"
            )

        except Exception as e:
            logger.error(f"Cache rebuild failed: {e}")

    async def get_stats(self) -> Dict[str, Any]:
        """Get statistics on feeds and indicators."""
        try:
            db = DB(self.db_url)

            try:
                total_feeds = len(list(db(db.ioc_feed.id > 0).select()))
                enabled_feeds = len(list(db(db.ioc_feed.enabled == True).select()))
                total_indicators = len(list(db(db.ioc_entry.id > 0).select()))
                total_overrides = len(list(db(db.ioc_override.id > 0).select()))

                return {
                    "feeds": {
                        "total": total_feeds,
                        "enabled": enabled_feeds,
                    },
                    "indicators": {
                        "total": total_indicators,
                    },
                    "overrides": {
                        "total": total_overrides,
                    },
                    "recent_activity": {
                        "timestamp": datetime.now().isoformat(),
                    },
                }

            finally:
                db.close()

        except Exception as e:
            logger.error(f"Get stats failed: {e}")
            return {
                "feeds": {"total": 0, "enabled": 0},
                "indicators": {"total": 0},
                "overrides": {"total": 0},
            }

    async def cleanup_old_indicators(self, retention_days: int) -> int:
        """
        Delete indicators older than retention_days.

        Returns count of deleted indicators.
        """
        try:
            db = DB(self.db_url)

            try:
                # For retention_days=0, delete everything
                if retention_days == 0:
                    cutoff = datetime.now() + timedelta(days=1)  # Future time to catch all
                else:
                    cutoff = datetime.now() - timedelta(days=retention_days)

                # Count and delete old entries
                old_entries = db(db.ioc_entry.created_at <= cutoff).select()
                count = len(list(old_entries))

                db(db.ioc_entry.created_at <= cutoff).delete()
                db.commit()

                # Rebuild cache after deletion
                await self._rebuild_cache(db)

                return count

            finally:
                db.close()

        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
            return 0
