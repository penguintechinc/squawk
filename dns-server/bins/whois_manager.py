#!/usr/bin/env python3
"""
WHOIS Manager for Squawk DNS
Provides WHOIS lookup functionality with database caching and web interface.
Implements Issue #17: Secure Client - WHOIS section
"""

import re
import asyncio
import json
import logging
import time
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from pydal import DAL, Field
import whois
import ipwhois
from ipaddress import ip_address, AddressValueError

logger = logging.getLogger(__name__)


class WHOISManager:
    """
    Manages WHOIS lookups with PostgreSQL caching and web interface.
    Features:
    - Domain and IP WHOIS lookups
    - Database caching with configurable retention
    - JSON conversion and storage
    - Searchable web interface
    - Monthly cleanup job
    """

    def __init__(self, db_url: str, retention_days: int = 30):
        self.db_url = db_url
        self.retention_days = retention_days
        self._init_database()

    def _init_database(self):
        """Initialize WHOIS database schema"""
        db = DAL(self.db_url)

        # WHOIS cache table
        db.define_table(
            "whois_cache",
            Field("query", "string", unique=True),  # Domain or IP queried
            Field("query_type", "string"),  # 'domain' or 'ip'
            Field("whois_data", "json"),  # Raw WHOIS data as JSON
            Field("parsed_data", "json"),  # Parsed/structured data
            Field("registrar", "string"),  # Quick lookup field
            Field("creation_date", "datetime"),  # Domain creation date
            Field("expiration_date", "datetime"),  # Domain expiration date
            Field("nameservers", "json"),  # List of nameservers
            Field("query_timestamp", "datetime", default=datetime.now),
            Field("last_updated", "datetime", default=datetime.now),
            migrate=True,
        )

        # WHOIS search index for faster lookups
        db.define_table(
            "whois_search_index",
            Field("whois_id", "reference whois_cache"),
            Field("search_field", "string"),  # registrar, organization, etc.
            Field("search_value", "string"),  # Value to search for
            Field("indexed_at", "datetime", default=datetime.now),
            migrate=True,
        )

        # WHOIS query log for analytics
        db.define_table(
            "whois_query_log",
            Field("query", "string"),
            Field("query_type", "string"),
            Field("cache_hit", "boolean"),
            Field("response_time_ms", "double"),
            Field("client_ip", "string"),
            Field("timestamp", "datetime", default=datetime.now),
            migrate=True,
        )

        db.commit()
        db.close()

    async def lookup_domain(
        self, domain: str, client_ip: str = None, force_refresh: bool = False
    ) -> Dict:
        """
        Lookup WHOIS information for a domain.
        Returns cached data if available and fresh, otherwise performs new lookup.
        """
        start_time = time.time()
        cache_hit = False

        try:
            # Check cache first
            if not force_refresh:
                cached_data = await self._get_cached_whois(domain, "domain")
                if cached_data:
                    cache_hit = True
                    await self._log_query(
                        domain, "domain", cache_hit, time.time() - start_time, client_ip
                    )
                    return cached_data

            # Perform new WHOIS lookup
            whois_data = await self._perform_domain_whois(domain)

            # Cache the result
            await self._cache_whois_data(domain, "domain", whois_data)

            # Log the query
            await self._log_query(
                domain, "domain", cache_hit, time.time() - start_time, client_ip
            )

            return whois_data

        except Exception as e:
            logger.error(f"WHOIS lookup failed for domain {domain}: {e}")
            await self._log_query(
                domain, "domain", cache_hit, time.time() - start_time, client_ip
            )
            return {
                "error": True,
                "message": f"WHOIS lookup failed: {str(e)}",
                "domain": domain,
                "timestamp": datetime.now().isoformat(),
            }

    async def lookup_ip(
        self, ip_addr: str, client_ip: str = None, force_refresh: bool = False
    ) -> Dict:
        """
        Lookup WHOIS information for an IP address.
        Returns cached data if available and fresh, otherwise performs new lookup.
        """
        start_time = time.time()
        cache_hit = False

        try:
            # Validate IP address
            try:
                ip_address(ip_addr)
            except AddressValueError:
                return {
                    "error": True,
                    "message": f"Invalid IP address: {ip_addr}",
                    "timestamp": datetime.now().isoformat(),
                }

            # Check cache first
            if not force_refresh:
                cached_data = await self._get_cached_whois(ip_addr, "ip")
                if cached_data:
                    cache_hit = True
                    await self._log_query(
                        ip_addr, "ip", cache_hit, time.time() - start_time, client_ip
                    )
                    return cached_data

            # Perform new IP WHOIS lookup
            whois_data = await self._perform_ip_whois(ip_addr)

            # Cache the result
            await self._cache_whois_data(ip_addr, "ip", whois_data)

            # Log the query
            await self._log_query(
                ip_addr, "ip", cache_hit, time.time() - start_time, client_ip
            )

            return whois_data

        except Exception as e:
            logger.error(f"WHOIS lookup failed for IP {ip_addr}: {e}")
            await self._log_query(
                ip_addr, "ip", cache_hit, time.time() - start_time, client_ip
            )
            return {
                "error": True,
                "message": f"WHOIS lookup failed: {str(e)}",
                "ip": ip_addr,
                "timestamp": datetime.now().isoformat(),
            }

    async def _perform_domain_whois(self, domain: str) -> Dict:
        """Perform domain WHOIS lookup using python-whois library"""
        try:
            # Use python-whois library
            loop = asyncio.get_event_loop()
            whois_info = await loop.run_in_executor(None, whois.whois, domain)

            # Convert to JSON-serializable format
            parsed_data = {}

            # Handle domain name
            if hasattr(whois_info, "domain_name"):
                if isinstance(whois_info.domain_name, list):
                    parsed_data["domain_name"] = (
                        whois_info.domain_name[0] if whois_info.domain_name else domain
                    )
                else:
                    parsed_data["domain_name"] = whois_info.domain_name or domain
            else:
                parsed_data["domain_name"] = domain

            # Handle registrar
            if hasattr(whois_info, "registrar"):
                parsed_data["registrar"] = whois_info.registrar

            # Handle dates
            if hasattr(whois_info, "creation_date"):
                if isinstance(whois_info.creation_date, list):
                    parsed_data["creation_date"] = (
                        whois_info.creation_date[0].isoformat()
                        if whois_info.creation_date
                        else None
                    )
                elif whois_info.creation_date:
                    parsed_data["creation_date"] = whois_info.creation_date.isoformat()

            if hasattr(whois_info, "expiration_date"):
                if isinstance(whois_info.expiration_date, list):
                    parsed_data["expiration_date"] = (
                        whois_info.expiration_date[0].isoformat()
                        if whois_info.expiration_date
                        else None
                    )
                elif whois_info.expiration_date:
                    parsed_data["expiration_date"] = (
                        whois_info.expiration_date.isoformat()
                    )

            # Handle nameservers
            if hasattr(whois_info, "name_servers"):
                if isinstance(whois_info.name_servers, list):
                    parsed_data["nameservers"] = [
                        ns.lower() for ns in whois_info.name_servers if ns
                    ]
                elif whois_info.name_servers:
                    parsed_data["nameservers"] = [whois_info.name_servers.lower()]

            # Handle organization/registrant
            if hasattr(whois_info, "org"):
                parsed_data["organization"] = whois_info.org
            if hasattr(whois_info, "registrant"):
                parsed_data["registrant"] = whois_info.registrant

            # Handle status
            if hasattr(whois_info, "status"):
                if isinstance(whois_info.status, list):
                    parsed_data["status"] = whois_info.status
                else:
                    parsed_data["status"] = (
                        [whois_info.status] if whois_info.status else []
                    )

            # Handle emails
            if hasattr(whois_info, "emails"):
                if isinstance(whois_info.emails, list):
                    parsed_data["emails"] = whois_info.emails
                else:
                    parsed_data["emails"] = (
                        [whois_info.emails] if whois_info.emails else []
                    )

            # Add metadata
            parsed_data["query_type"] = "domain"
            parsed_data["timestamp"] = datetime.now().isoformat()
            parsed_data["source"] = "python-whois"

            return parsed_data

        except Exception as e:
            # Fallback to command line whois if python-whois fails
            return await self._perform_command_whois(domain, "domain")

    async def _perform_ip_whois(self, ip_addr: str) -> Dict:
        """Perform IP WHOIS lookup using ipwhois library"""
        try:
            # Use ipwhois library
            from ipwhois import IPWhois

            loop = asyncio.get_event_loop()

            obj = IPWhois(ip_addr)
            whois_info = await loop.run_in_executor(None, obj.lookup_rdap)

            # Parse the RDAP response
            parsed_data = {
                "ip_address": ip_addr,
                "query_type": "ip",
                "timestamp": datetime.now().isoformat(),
                "source": "ipwhois-rdap",
            }

            # Extract network information
            if "network" in whois_info:
                network = whois_info["network"]
                parsed_data["network"] = {
                    "cidr": network.get("cidr"),
                    "name": network.get("name"),
                    "handle": network.get("handle"),
                    "start_address": network.get("start_address"),
                    "end_address": network.get("end_address"),
                }

            # Extract ASN information
            if "asn" in whois_info:
                parsed_data["asn"] = whois_info["asn"]

            # Extract entities (organizations)
            if "entities" in whois_info:
                parsed_data["entities"] = []
                for entity in whois_info["entities"]:
                    entity_info = {
                        "handle": entity.get("handle"),
                        "roles": entity.get("roles", []),
                    }

                    # Extract contact information if available
                    if "contact" in entity:
                        contact = entity["contact"]
                        entity_info["contact"] = {
                            "name": contact.get("name"),
                            "organization": contact.get("organization"),
                            "email": contact.get("email"),
                            "address": contact.get("address"),
                        }

                    parsed_data["entities"].append(entity_info)

            return parsed_data

        except Exception as e:
            logger.error(f"IP WHOIS lookup failed for {ip_addr}: {e}")
            # Fallback to command line whois
            return await self._perform_command_whois(ip_addr, "ip")

    async def _perform_command_whois(self, query: str, query_type: str) -> Dict:
        """Fallback WHOIS lookup using command line whois tool"""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                subprocess.run,
                ["whois", query],
                subprocess.PIPE,
                subprocess.PIPE,
                True,  # text
                5,  # timeout
            )

            if result.returncode == 0:
                return {
                    "query": query,
                    "query_type": query_type,
                    "raw_output": result.stdout,
                    "timestamp": datetime.now().isoformat(),
                    "source": "command-line-whois",
                }
            else:
                return {
                    "error": True,
                    "message": f"WHOIS command failed: {result.stderr}",
                    "query": query,
                    "timestamp": datetime.now().isoformat(),
                }

        except subprocess.TimeoutExpired:
            return {
                "error": True,
                "message": "WHOIS lookup timed out",
                "query": query,
                "timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            return {
                "error": True,
                "message": f"WHOIS lookup failed: {str(e)}",
                "query": query,
                "timestamp": datetime.now().isoformat(),
            }

    async def _get_cached_whois(self, query: str, query_type: str) -> Optional[Dict]:
        """Get cached WHOIS data if available and fresh"""
        db = DAL(self.db_url)

        # Check if we have cached data within retention period
        cutoff_time = datetime.now() - timedelta(days=self.retention_days)

        cached = (
            db(
                (db.whois_cache.query == query)
                & (db.whois_cache.query_type == query_type)
                & (db.whois_cache.last_updated >= cutoff_time)
            )
            .select()
            .first()
        )

        db.close()

        if cached:
            return {
                "query": cached.query,
                "query_type": cached.query_type,
                "data": cached.parsed_data,
                "cached": True,
                "last_updated": cached.last_updated.isoformat(),
            }

        return None

    async def _cache_whois_data(self, query: str, query_type: str, whois_data: Dict):
        """Cache WHOIS data in database"""
        db = DAL(self.db_url)

        try:
            # Extract key fields for indexing
            registrar = None
            creation_date = None
            expiration_date = None
            nameservers = None

            if query_type == "domain":
                registrar = whois_data.get("registrar")
                creation_date = whois_data.get("creation_date")
                expiration_date = whois_data.get("expiration_date")
                nameservers = whois_data.get("nameservers")

            # Insert or update cache entry
            existing = (
                db(
                    (db.whois_cache.query == query)
                    & (db.whois_cache.query_type == query_type)
                )
                .select()
                .first()
            )

            if existing:
                existing.update_record(
                    whois_data=whois_data,
                    parsed_data=whois_data,
                    registrar=registrar,
                    creation_date=creation_date,
                    expiration_date=expiration_date,
                    nameservers=nameservers,
                    last_updated=datetime.now(),
                )
                whois_id = existing.id
            else:
                whois_id = db.whois_cache.insert(
                    query=query,
                    query_type=query_type,
                    whois_data=whois_data,
                    parsed_data=whois_data,
                    registrar=registrar,
                    creation_date=creation_date,
                    expiration_date=expiration_date,
                    nameservers=nameservers,
                )

            # Update search index
            await self._update_search_index(db, whois_id, whois_data)

            db.commit()

        except Exception as e:
            logger.error(f"Failed to cache WHOIS data for {query}: {e}")
        finally:
            db.close()

    async def _update_search_index(self, db: DAL, whois_id: int, whois_data: Dict):
        """Update search index for faster lookups"""
        try:
            # Clear existing index entries
            db(db.whois_search_index.whois_id == whois_id).delete()

            # Index common search fields
            search_fields = {
                "registrar": whois_data.get("registrar"),
                "organization": whois_data.get("organization"),
                "domain_name": whois_data.get("domain_name"),
                "asn": whois_data.get("asn"),
            }

            # Index nameservers
            if "nameservers" in whois_data and whois_data["nameservers"]:
                for ns in whois_data["nameservers"]:
                    if ns:
                        db.whois_search_index.insert(
                            whois_id=whois_id,
                            search_field="nameserver",
                            search_value=ns.lower(),
                        )

            # Index entities for IP lookups
            if "entities" in whois_data and whois_data["entities"]:
                for entity in whois_data["entities"]:
                    if "contact" in entity and entity["contact"].get("organization"):
                        db.whois_search_index.insert(
                            whois_id=whois_id,
                            search_field="organization",
                            search_value=entity["contact"]["organization"],
                        )

            # Index other fields
            for field, value in search_fields.items():
                if value:
                    db.whois_search_index.insert(
                        whois_id=whois_id,
                        search_field=field,
                        search_value=str(value).lower(),
                    )

        except Exception as e:
            logger.error(f"Failed to update search index: {e}")

    async def _log_query(
        self,
        query: str,
        query_type: str,
        cache_hit: bool,
        response_time: float,
        client_ip: str = None,
    ):
        """Log WHOIS query for analytics"""
        try:
            db = DAL(self.db_url)

            db.whois_query_log.insert(
                query=query,
                query_type=query_type,
                cache_hit=cache_hit,
                response_time_ms=response_time * 1000,
                client_ip=client_ip,
            )

            db.commit()
            db.close()

        except Exception as e:
            logger.error(f"Failed to log WHOIS query: {e}")

    async def search_whois(
        self, search_term: str, search_field: str = None, limit: int = 50
    ) -> List[Dict]:
        """
        Search cached WHOIS data.
        search_field can be: registrar, organization, nameserver, domain_name, asn
        """
        db = DAL(self.db_url)

        try:
            if search_field:
                # Search specific field
                results = db(
                    (db.whois_search_index.search_field == search_field)
                    & (db.whois_search_index.search_value.contains(search_term.lower()))
                    & (db.whois_cache.id == db.whois_search_index.whois_id)
                ).select(
                    db.whois_cache.ALL,
                    limitby=(0, limit),
                    orderby=~db.whois_cache.last_updated,
                )
            else:
                # Search all fields
                results = db(
                    (db.whois_search_index.search_value.contains(search_term.lower()))
                    & (db.whois_cache.id == db.whois_search_index.whois_id)
                ).select(
                    db.whois_cache.ALL,
                    limitby=(0, limit),
                    orderby=~db.whois_cache.last_updated,
                    distinct=True,
                )

            search_results = []
            for result in results:
                search_results.append(
                    {
                        "query": result.query,
                        "query_type": result.query_type,
                        "data": result.parsed_data,
                        "last_updated": result.last_updated.isoformat(),
                    }
                )

            return search_results

        except Exception as e:
            logger.error(f"WHOIS search failed: {e}")
            return []
        finally:
            db.close()

    async def cleanup_old_data(self):
        """Remove old WHOIS data based on retention policy"""
        db = DAL(self.db_url)

        try:
            cutoff_time = datetime.now() - timedelta(days=self.retention_days)

            # Get IDs of records to delete
            old_records = db(db.whois_cache.last_updated < cutoff_time).select(
                db.whois_cache.id
            )
            old_ids = [record.id for record in old_records]

            # Delete search index entries
            if old_ids:
                db(db.whois_search_index.whois_id.belongs(old_ids)).delete()

            # Delete old cache entries
            deleted_count = db(db.whois_cache.last_updated < cutoff_time).delete()

            db.commit()

            logger.info(f"Cleaned up {deleted_count} old WHOIS records")
            return deleted_count

        except Exception as e:
            logger.error(f"WHOIS cleanup failed: {e}")
            return 0
        finally:
            db.close()

    async def get_stats(self) -> Dict:
        """Get WHOIS service statistics"""
        db = DAL(self.db_url)

        try:
            # Cache statistics
            total_cached = db(db.whois_cache).count()
            domain_cached = db(db.whois_cache.query_type == "domain").count()
            ip_cached = db(db.whois_cache.query_type == "ip").count()

            # Query statistics (last 24 hours)
            yesterday = datetime.now() - timedelta(days=1)
            recent_queries = db(db.whois_query_log.timestamp >= yesterday).count()
            recent_cache_hits = db(
                (db.whois_query_log.timestamp >= yesterday)
                & (db.whois_query_log.cache_hit == True)
            ).count()

            cache_hit_rate = (
                (recent_cache_hits / recent_queries * 100) if recent_queries > 0 else 0
            )

            # Average response time
            avg_response_time = db.whois_query_log.response_time_ms.avg()

            return {
                "cache_stats": {
                    "total_cached_entries": total_cached,
                    "domain_entries": domain_cached,
                    "ip_entries": ip_cached,
                },
                "query_stats": {
                    "queries_24h": recent_queries,
                    "cache_hits_24h": recent_cache_hits,
                    "cache_hit_rate_percent": round(cache_hit_rate, 2),
                    "avg_response_time_ms": round(avg_response_time or 0, 2),
                },
                "retention_days": self.retention_days,
                "timestamp": datetime.now().isoformat(),
            }

        except Exception as e:
            logger.error(f"Failed to get WHOIS stats: {e}")
            return {}
        finally:
            db.close()
