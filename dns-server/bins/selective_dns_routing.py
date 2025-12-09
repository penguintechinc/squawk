#!/usr/bin/env python3
"""
Selective DNS Routing Module for Squawk DNS
Implements user/group-based DNS response filtering.

Core concept:
- Each user has a unique token generated when created
- Tokens map to groups (manual or IDP-based via SAML/LDAP)
- Groups determine which DNS zones/entries are visible
- Same DNS endpoint serves different responses based on user's group membership
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from pydal import DAL, Field
from enum import Enum

logger = logging.getLogger(__name__)


class GroupType(Enum):
    """Group classification for DNS access control"""

    INTERNAL = "internal"  # Full access to private + public DNS
    EXTERNAL = "external"  # Public DNS only
    PARTNER = "partner"  # Limited private + public DNS
    CONTRACTOR = "contractor"  # Specific private zones + public
    ADMIN = "admin"  # Full access + management


class DNSRecordVisibility(Enum):
    """DNS record visibility levels"""

    PUBLIC = "public"  # Visible to all users
    INTERNAL = "internal"  # Visible to internal groups only
    RESTRICTED = "restricted"  # Visible to specific groups only
    PRIVATE = "private"  # Visible to admin only


class SelectiveDNSRouter:
    """
    Implements selective DNS routing based on user tokens and group membership.
    Each user's token determines their group membership and thus their DNS visibility.
    """

    def __init__(self, db_url: str):
        self.db_url = db_url
        self.user_group_cache = {}  # Cache token -> groups mapping
        self.group_permissions_cache = {}  # Cache group -> permissions
        self.dns_records_cache = {}  # Cache DNS records with visibility
        self._init_database()
        self._load_initial_data()

    def _init_database(self):
        """Initialize database schema for selective routing"""
        db = DAL(self.db_url)

        # User tokens table (extends existing tokens table)
        if "tokens" not in db.tables:
            db.define_table(
                "tokens",
                Field("token", "string", unique=True),
                Field("name", "string"),
                Field("email", "string"),
                Field("active", "boolean", default=True),
                Field("created_at", "datetime", default=datetime.now),
                Field("last_used", "datetime"),
                migrate=True,
            )

        # Groups table
        db.define_table(
            "groups",
            Field("name", "string", unique=True),
            Field("group_type", "string"),  # internal, external, partner, etc.
            Field("description", "text"),
            Field("idp_group_id", "string"),  # IDP group identifier (SAML/LDAP)
            Field(
                "priority", "integer", default=0
            ),  # Higher priority groups override lower
            Field("created_at", "datetime", default=datetime.now),
            migrate=True,
        )

        # User-Group mapping (many-to-many)
        db.define_table(
            "user_groups",
            Field("token_id", "reference tokens"),
            Field("group_id", "reference groups"),
            Field("assigned_by", "string"),  # manual, saml, ldap, oauth
            Field("assigned_at", "datetime", default=datetime.now),
            migrate=True,
        )

        # DNS zones with visibility settings
        db.define_table(
            "dns_zones",
            Field("zone_name", "string", unique=True),  # e.g., "internal.company.com"
            Field("visibility", "string"),  # public, internal, restricted, private
            Field("description", "text"),
            Field("created_at", "datetime", default=datetime.now),
            migrate=True,
        )

        # DNS records with visibility
        db.define_table(
            "dns_records",
            Field("zone_id", "reference dns_zones"),
            Field("name", "string"),  # Full domain name
            Field("record_type", "string"),  # A, AAAA, CNAME, etc.
            Field("record_value", "string"),  # IP address or target
            Field("ttl", "integer", default=300),
            Field("visibility", "string"),  # Can override zone visibility
            Field("created_at", "datetime", default=datetime.now),
            migrate=True,
        )

        # Group permissions for zones
        db.define_table(
            "group_zone_permissions",
            Field("group_id", "reference groups"),
            Field("zone_id", "reference dns_zones"),
            Field("can_view", "boolean", default=True),
            Field("can_resolve", "boolean", default=True),
            Field("created_at", "datetime", default=datetime.now),
            migrate=True,
        )

        # Group permissions for specific records (overrides)
        db.define_table(
            "group_record_permissions",
            Field("group_id", "reference groups"),
            Field("record_id", "reference dns_records"),
            Field("can_view", "boolean", default=True),
            Field("created_at", "datetime", default=datetime.now),
            migrate=True,
        )

        # IDP group mappings (for SAML/LDAP integration)
        db.define_table(
            "idp_group_mappings",
            Field("idp_type", "string"),  # saml, ldap, oauth
            Field("idp_group_name", "string"),
            Field("local_group_id", "reference groups"),
            Field("auto_assign", "boolean", default=True),
            Field("created_at", "datetime", default=datetime.now),
            migrate=True,
        )

        db.commit()
        db.close()

    def _load_initial_data(self):
        """Load initial groups and permissions if empty"""
        db = DAL(self.db_url)

        # Check if we have any groups
        if db(db.groups).count() == 0:
            # Create default groups
            internal_group = db.groups.insert(
                name="internal_users",
                group_type="internal",
                description="Internal company users with full DNS access",
                priority=100,
            )

            external_group = db.groups.insert(
                name="external_users",
                group_type="external",
                description="External users with public DNS only",
                priority=10,
            )

            partner_group = db.groups.insert(
                name="partners",
                group_type="partner",
                description="Partner organizations with limited private DNS",
                priority=50,
            )

            admin_group = db.groups.insert(
                name="administrators",
                group_type="admin",
                description="DNS administrators with full access",
                priority=1000,
            )

            # Create sample DNS zones
            public_zone = db.dns_zones.insert(
                zone_name="public.company.com",
                visibility="public",
                description="Public-facing DNS entries",
            )

            internal_zone = db.dns_zones.insert(
                zone_name="internal.company.com",
                visibility="internal",
                description="Internal services DNS",
            )

            restricted_zone = db.dns_zones.insert(
                zone_name="secure.company.com",
                visibility="restricted",
                description="Restricted access DNS zone",
            )

            # Set up default permissions
            # Internal users can see internal and public zones
            db.group_zone_permissions.insert(
                group_id=internal_group,
                zone_id=public_zone,
                can_view=True,
                can_resolve=True,
            )

            db.group_zone_permissions.insert(
                group_id=internal_group,
                zone_id=internal_zone,
                can_view=True,
                can_resolve=True,
            )

            # External users can only see public zone
            db.group_zone_permissions.insert(
                group_id=external_group,
                zone_id=public_zone,
                can_view=True,
                can_resolve=True,
            )

            # Partners get public and limited internal
            db.group_zone_permissions.insert(
                group_id=partner_group,
                zone_id=public_zone,
                can_view=True,
                can_resolve=True,
            )

            # Admins get everything
            db.group_zone_permissions.insert(
                group_id=admin_group,
                zone_id=public_zone,
                can_view=True,
                can_resolve=True,
            )

            db.group_zone_permissions.insert(
                group_id=admin_group,
                zone_id=internal_zone,
                can_view=True,
                can_resolve=True,
            )

            db.group_zone_permissions.insert(
                group_id=admin_group,
                zone_id=restricted_zone,
                can_view=True,
                can_resolve=True,
            )

            db.commit()

        db.close()

    def get_user_groups(self, token: str) -> List[Dict]:
        """Get all groups for a user token"""
        if token in self.user_group_cache:
            return self.user_group_cache[token]

        db = DAL(self.db_url)

        # Get token record
        token_record = db(db.tokens.token == token).select().first()
        if not token_record:
            db.close()
            return []

        # Get user's groups
        user_groups = db(
            (db.user_groups.token_id == token_record.id)
            & (db.groups.id == db.user_groups.group_id)
        ).select(db.groups.ALL, orderby=~db.groups.priority)

        groups = []
        for group in user_groups:
            groups.append(
                {
                    "id": group.id,
                    "name": group.name,
                    "type": group.group_type,
                    "priority": group.priority,
                }
            )

        db.close()

        # Cache the result
        self.user_group_cache[token] = groups
        return groups

    def assign_user_to_group(
        self, token: str, group_name: str, assigned_by: str = "manual"
    ):
        """Assign a user token to a group"""
        db = DAL(self.db_url)

        token_record = db(db.tokens.token == token).select().first()
        if not token_record:
            db.close()
            return False

        group_record = db(db.groups.name == group_name).select().first()
        if not group_record:
            db.close()
            return False

        # Check if already assigned
        existing = (
            db(
                (db.user_groups.token_id == token_record.id)
                & (db.user_groups.group_id == group_record.id)
            )
            .select()
            .first()
        )

        if not existing:
            db.user_groups.insert(
                token_id=token_record.id,
                group_id=group_record.id,
                assigned_by=assigned_by,
            )
            db.commit()

        db.close()

        # Clear cache
        if token in self.user_group_cache:
            del self.user_group_cache[token]

        return True

    def sync_idp_groups(
        self, token: str, idp_groups: List[str], idp_type: str = "saml"
    ):
        """Sync user groups from IDP (SAML/LDAP)"""
        db = DAL(self.db_url)

        token_record = db(db.tokens.token == token).select().first()
        if not token_record:
            db.close()
            return False

        # Get IDP group mappings
        mappings = db(
            (db.idp_group_mappings.idp_type == idp_type)
            & (db.idp_group_mappings.auto_assign == True)
        ).select()

        for mapping in mappings:
            if mapping.idp_group_name in idp_groups:
                # Check if user already in this group
                existing = (
                    db(
                        (db.user_groups.token_id == token_record.id)
                        & (db.user_groups.group_id == mapping.local_group_id)
                    )
                    .select()
                    .first()
                )

                if not existing:
                    db.user_groups.insert(
                        token_id=token_record.id,
                        group_id=mapping.local_group_id,
                        assigned_by=idp_type,
                    )

        db.commit()
        db.close()

        # Clear cache
        if token in self.user_group_cache:
            del self.user_group_cache[token]

        return True

    def can_resolve_domain(self, token: str, domain: str) -> bool:
        """Check if user can resolve a specific domain"""
        groups = self.get_user_groups(token)
        if not groups:
            # No groups = external user = public only
            return self._is_public_domain(domain)

        db = DAL(self.db_url)

        # Check if domain exists in our records
        dns_record = db(db.dns_records.name == domain).select().first()
        if not dns_record:
            # Not in our records, allow resolution (will go to upstream)
            db.close()
            return True

        # Get zone for this record
        zone = db(db.dns_zones.id == dns_record.zone_id).select().first()
        if not zone:
            db.close()
            return True

        # Check visibility
        visibility = dns_record.visibility or zone.visibility

        # Public records are always visible
        if visibility == "public":
            db.close()
            return True

        # Check group permissions
        for group in groups:
            # Check zone permissions
            zone_perm = (
                db(
                    (db.group_zone_permissions.group_id == group["id"])
                    & (db.group_zone_permissions.zone_id == zone.id)
                    & (db.group_zone_permissions.can_resolve == True)
                )
                .select()
                .first()
            )

            if zone_perm:
                db.close()
                return True

            # Check specific record permissions
            record_perm = (
                db(
                    (db.group_record_permissions.group_id == group["id"])
                    & (db.group_record_permissions.record_id == dns_record.id)
                    & (db.group_record_permissions.can_view == True)
                )
                .select()
                .first()
            )

            if record_perm:
                db.close()
                return True

        db.close()
        return False

    def _is_public_domain(self, domain: str) -> bool:
        """Check if domain is in a public zone"""
        db = DAL(self.db_url)

        # Check if domain is in a public zone
        dns_record = db(db.dns_records.name == domain).select().first()
        if not dns_record:
            db.close()
            return True  # Not in our records, assume public

        zone = db(db.dns_zones.id == dns_record.zone_id).select().first()
        if not zone:
            db.close()
            return True

        is_public = zone.visibility == "public"
        db.close()
        return is_public

    def filter_dns_response(
        self, token: str, domain: str, original_response: Dict
    ) -> Dict:
        """
        Filter DNS response based on user's group permissions.
        This is the main function that implements selective routing.
        """
        # Check if user can resolve this domain
        if not self.can_resolve_domain(token, domain):
            # Return NXDOMAIN for domains user cannot access
            return {
                "Status": 3,  # NXDOMAIN
                "Answer": [],
                "Question": [{"name": domain, "type": 1}],
                "Comment": "Domain not found",  # Don't reveal it's blocked
            }

        # Check if we need to filter the response
        groups = self.get_user_groups(token)

        # Admins see everything
        if any(g["type"] == "admin" for g in groups):
            return original_response

        # Internal users see most things
        if any(g["type"] == "internal" for g in groups):
            return original_response

        # External users might need filtered responses
        if any(g["type"] == "external" for g in groups):
            # Could implement response filtering here
            # For example, removing internal IP addresses
            return self._sanitize_response_for_external(original_response)

        # Partners get limited view
        if any(g["type"] == "partner" for g in groups):
            return self._filter_response_for_partner(original_response)

        # Default: return original
        return original_response

    def _sanitize_response_for_external(self, response: Dict) -> Dict:
        """Remove internal information from response for external users"""
        # Example: Filter out RFC1918 addresses
        if response.get("Status") == 0 and "Answer" in response:
            filtered_answers = []
            for answer in response["Answer"]:
                # Check if it's an A record with private IP
                if answer.get("type") in [1, "A"]:
                    ip = answer.get("data", "")
                    if not self._is_private_ip(ip):
                        filtered_answers.append(answer)
                else:
                    filtered_answers.append(answer)

            if not filtered_answers:
                # All answers were filtered, return NXDOMAIN
                return {
                    "Status": 3,
                    "Answer": [],
                    "Question": response.get("Question", []),
                    "Comment": "Domain not found",
                }

            response["Answer"] = filtered_answers

        return response

    def _filter_response_for_partner(self, response: Dict) -> Dict:
        """Apply partner-specific filtering"""
        # Partners might see public IPs but not internal ones
        return self._sanitize_response_for_external(response)

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range (RFC1918)"""
        import ipaddress

        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private
        except:
            return False

    def get_user_accessible_zones(self, token: str) -> List[str]:
        """Get list of DNS zones accessible to user"""
        groups = self.get_user_groups(token)
        if not groups:
            return []

        db = DAL(self.db_url)

        accessible_zones = set()

        for group in groups:
            # Get zones this group can access
            permissions = db(
                (db.group_zone_permissions.group_id == group["id"])
                & (db.group_zone_permissions.can_view == True)
                & (db.dns_zones.id == db.group_zone_permissions.zone_id)
            ).select(db.dns_zones.zone_name)

            for perm in permissions:
                accessible_zones.add(perm.zone_name)

        # Always include public zones
        public_zones = db(db.dns_zones.visibility == "public").select(
            db.dns_zones.zone_name
        )
        for zone in public_zones:
            accessible_zones.add(zone.zone_name)

        db.close()
        return list(accessible_zones)

    def add_dns_record(
        self,
        zone_name: str,
        name: str,
        record_type: str,
        value: str,
        visibility: str = None,
        ttl: int = 300,
    ) -> bool:
        """Add a DNS record to a zone"""
        db = DAL(self.db_url)

        zone = db(db.dns_zones.zone_name == zone_name).select().first()
        if not zone:
            db.close()
            return False

        db.dns_records.insert(
            zone_id=zone.id,
            name=name,
            record_type=record_type,
            record_value=value,
            visibility=visibility or zone.visibility,
            ttl=ttl,
        )

        db.commit()
        db.close()
        return True

    def create_group(
        self,
        name: str,
        group_type: str,
        description: str = "",
        idp_group_id: str = None,
    ) -> bool:
        """Create a new group"""
        db = DAL(self.db_url)

        try:
            db.groups.insert(
                name=name,
                group_type=group_type,
                description=description,
                idp_group_id=idp_group_id,
            )
            db.commit()
            db.close()
            return True
        except:
            db.close()
            return False

    def create_zone(
        self, zone_name: str, visibility: str = "internal", description: str = ""
    ) -> bool:
        """Create a new DNS zone"""
        db = DAL(self.db_url)

        try:
            db.dns_zones.insert(
                zone_name=zone_name, visibility=visibility, description=description
            )
            db.commit()
            db.close()
            return True
        except:
            db.close()
            return False

    def set_group_zone_permission(
        self,
        group_name: str,
        zone_name: str,
        can_view: bool = True,
        can_resolve: bool = True,
    ) -> bool:
        """Set group permissions for a zone"""
        db = DAL(self.db_url)

        group = db(db.groups.name == group_name).select().first()
        if not group:
            db.close()
            return False

        zone = db(db.dns_zones.zone_name == zone_name).select().first()
        if not zone:
            db.close()
            return False

        # Check if permission exists
        existing = (
            db(
                (db.group_zone_permissions.group_id == group.id)
                & (db.group_zone_permissions.zone_id == zone.id)
            )
            .select()
            .first()
        )

        if existing:
            existing.update_record(can_view=can_view, can_resolve=can_resolve)
        else:
            db.group_zone_permissions.insert(
                group_id=group.id,
                zone_id=zone.id,
                can_view=can_view,
                can_resolve=can_resolve,
            )

        db.commit()
        db.close()
        return True
