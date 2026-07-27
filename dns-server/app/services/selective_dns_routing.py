#!/usr/bin/env python3
"""
Selective DNS Routing Module for Squawk DNS
Implements user/group-based DNS response filtering using penguin-dal.

Core concept:
- Each token maps to a user (token table PK)
- Tokens are assigned to groups
- Groups determine which DNS zones/entries are visible
- Same DNS endpoint serves different responses based on user's group membership
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from penguin_dal import DB

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class GroupRecord:
    """DNS access control group"""
    id: int
    name: str
    description: Optional[str] = None
    visibility_levels: List[str] = field(default_factory=list)


@dataclass(slots=True)
class ZoneRecord:
    """DNS zone with visibility level"""
    id: int
    name: str
    visibility: str
    description: Optional[str] = None


@dataclass(slots=True)
class UserAssignment:
    """User-to-group assignment"""
    id: int
    user_id: int
    group_id: int
    role: str


class SelectiveDNSRouter:
    """
    Implements selective DNS routing based on user tokens and group membership.
    Uses penguin-dal for database access; tables reflect from schema.py.
    """

    def __init__(self, db_url: str) -> None:
        """
        Initialize router with database connection.

        Args:
            db_url: Database URL (e.g., 'sqlite:///path/to/db.db')
        """
        self.db_url = db_url
        self.zone_visibility_levels = {
            'public': 'public',
            'internal': 'internal',
            'restricted': 'restricted',
            'private': 'private'
        }

    def _get_db(self) -> DB:
        """Get a penguin-dal DB instance reflecting existing tables."""
        return DB(self.db_url)

    def _get_user_id_from_token(self, token: str) -> Optional[int]:
        """
        Map a token string to a user_id (token table PK).
        Strict lookup: returns None if token not found (no auto-create).

        Args:
            token: Token string

        Returns:
            User ID (token table PK) or None if not found
        """
        db = self._get_db()

        try:
            # Look up token in the token table
            token_record = db(db.token.token == token).select().first()
            if token_record:
                return token_record.id
            return None
        finally:
            db.close()

    def create_group(
        self,
        name: str,
        description: str,
        visibility_levels: List[str]
    ) -> Dict:
        """
        Create a new DNS access control group.

        Args:
            name: Group name
            description: Group description
            visibility_levels: List of visibility levels this group can access

        Returns:
            Dict with success, group_id, and optional error message
        """
        db = self._get_db()

        try:
            # Check if group already exists
            existing = db(db.dns_group.name == name).select().first()
            if existing:
                return {
                    'success': False,
                    'error': f"Group '{name}' already exists"
                }

            # Create group
            group_id = db.dns_group.insert(
                name=name,
                description=description,
                visibility_levels=visibility_levels
            )
            db.commit()

            return {
                'success': True,
                'group_id': group_id
            }
        except Exception as e:
            logger.error(f"Error creating group '{name}': {e}")
            return {
                'success': False,
                'error': str(e)
            }
        finally:
            db.close()

    def assign_user_to_group(
        self,
        user_id: int,
        group_id: int,
        role: str
    ) -> Dict:
        """
        Assign a user to a group.
        For testing convenience: also creates a corresponding token if user_id=1.

        Args:
            user_id: User ID (token table PK)
            group_id: Group ID
            role: Role within the group

        Returns:
            Dict with success flag
        """
        db = self._get_db()

        try:
            # Check if assignment already exists
            existing = db(
                (db.user_group_assignment.user_id == user_id) &
                (db.user_group_assignment.group_id == group_id)
            ).select().first()

            if existing:
                # Update existing assignment using a query
                db(
                    (db.user_group_assignment.user_id == user_id) &
                    (db.user_group_assignment.group_id == group_id)
                ).update(role=role)
            else:
                # Create new assignment
                db.user_group_assignment.insert(
                    user_id=user_id,
                    group_id=group_id,
                    role=role
                )

            db.commit()
            return {'success': True}
        except Exception as e:
            logger.error(f"Error assigning user {user_id} to group {group_id}: {e}")
            return {'success': False}
        finally:
            db.close()

    def create_dns_zone(
        self,
        zone_name: str,
        visibility: str,
        description: str,
        created_by: str
    ) -> Dict:
        """
        Create a DNS zone with visibility level.

        Args:
            zone_name: Zone name (e.g., 'internal.company.com')
            visibility: Visibility level (public, internal, restricted, private)
            description: Zone description
            created_by: User who created the zone

        Returns:
            Dict with success, zone_id, and optional error
        """
        db = self._get_db()

        try:
            # Check if zone already exists
            existing = db(db.dns_routing_zone.name == zone_name).select().first()
            if existing:
                return {
                    'success': False,
                    'error': f"Zone '{zone_name}' already exists",
                    'zone_id': existing.id
                }

            # Validate visibility level
            if visibility not in self.zone_visibility_levels:
                return {
                    'success': False,
                    'error': f"Invalid visibility level: {visibility}"
                }

            # Create zone
            zone_id = db.dns_routing_zone.insert(
                name=zone_name,
                visibility=visibility,
                description=description
            )
            db.commit()

            return {
                'success': True,
                'zone_id': zone_id
            }
        except Exception as e:
            logger.error(f"Error creating zone '{zone_name}': {e}")
            return {
                'success': False,
                'error': str(e)
            }
        finally:
            db.close()

    def can_resolve_domain(
        self,
        token: Optional[str],
        domain: str
    ) -> bool:
        """
        Check if user can resolve a specific domain.

        Args:
            token: User authentication token
            domain: Domain name being queried

        Returns:
            True if user can resolve the domain, False otherwise
        """
        # Validate domain
        if not domain or domain is None:
            return False

        # Handle malformed domains
        if not self._is_valid_domain(domain):
            return False

        db = self._get_db()

        try:
            # Find zone for domain
            zone = self._find_zone_for_domain(domain, db)

            if not zone:
                # No custom zone rule, allow (public DNS)
                return True

            # Public zones are always accessible
            if zone.visibility == 'public':
                return True

            # Non-public zones require authentication
            if not token:
                return False

            # Get user_id from token
            user_id = self._get_user_id_from_token(token)
            if user_id is None:
                return False

            # Check user's groups and their visibility levels
            user_assignments = db(
                db.user_group_assignment.user_id == user_id
            ).select()

            if not user_assignments:
                return False

            # Check if any of user's groups can access this zone's visibility level
            for assignment in user_assignments:
                group = db(
                    db.dns_group.id == assignment.group_id
                ).select().first()
                if not group:
                    continue

                visibility_levels = group.visibility_levels or []

                # Check if group has zone visibility level
                if zone.visibility in visibility_levels:
                    return True

            # Check if group has explicit zone access grant
            for assignment in user_assignments:
                grant = db(
                    (db.group_zone_access.group_id == assignment.group_id) &
                    (db.group_zone_access.zone_id == zone.id)
                ).select().first()

                if grant:
                    return True

            return False

        finally:
            db.close()

    def _is_valid_domain(self, domain: str) -> bool:
        """Check if domain name is valid."""
        if not domain or not isinstance(domain, str):
            return False

        # Check for invalid characters
        if '..' in domain or domain.startswith('-') or domain.endswith('-'):
            return False

        # Check length
        if len(domain) > 253:
            return False

        return True

    def _find_zone_for_domain(
        self,
        domain: str,
        db: DB
    ) -> Optional[object]:
        """
        Find the zone that matches the given domain.

        Matches exact domain first, then parent domains.
        Supports wildcards (*.domain.com).

        Args:
            domain: Domain name
            db: Database connection

        Returns:
            Zone record or None
        """
        # Exact match
        zone = db(db.dns_routing_zone.name == domain).select().first()
        if zone:
            return zone

        # Check wildcard
        zone = db(db.dns_routing_zone.name == '*').select().first()
        if zone:
            return zone

        # Check parent domains
        parts = domain.split('.')
        for i in range(len(parts)):
            parent = '.'.join(parts[i:])
            zone = db(db.dns_routing_zone.name == parent).select().first()
            if zone:
                return zone

            # Check wildcard parent (e.g., *.internal.company.com)
            wildcard_parent = '*.' + parent
            zone = db(db.dns_routing_zone.name == wildcard_parent).select().first()
            if zone:
                return zone

        return None

    def filter_dns_response(
        self,
        token: Optional[str],
        domain: str,
        original_response: Dict
    ) -> Dict:
        """
        Filter DNS response based on user's permissions.

        Args:
            token: User authentication token
            domain: Domain being queried
            original_response: DNS response dict

        Returns:
            Filtered DNS response (or NXDOMAIN if not authorized)
        """
        # Check if user can resolve this domain
        if not self.can_resolve_domain(token, domain):
            # Return NXDOMAIN for domains user cannot access
            return {
                "Status": 3,  # NXDOMAIN
                "Answer": [],
                "Question": [{"name": domain, "type": 1}],
                "Comment": "Domain not found",
            }

        # User has permission, return original response
        return original_response

    def get_user_groups(self, user_id: int) -> List[Dict]:
        """
        Get all groups for a user.

        Args:
            user_id: User ID (token table PK)

        Returns:
            List of group dicts with id, name, description
        """
        db = self._get_db()

        try:
            groups: List[Dict] = []
            assignments = db(
                db.user_group_assignment.user_id == user_id
            ).select()

            for assignment in assignments:
                group = db(
                    db.dns_group.id == assignment.group_id
                ).select().first()

                if group:
                    groups.append({
                        'id': group.id,
                        'name': group.name,
                        'description': group.description,
                        'visibility_levels': group.visibility_levels or []
                    })

            return groups
        finally:
            db.close()

    def get_zone_access_level(self, domain: str) -> str:
        """
        Get the access level (visibility) for a domain.

        Args:
            domain: Domain name

        Returns:
            Visibility level (public, internal, restricted, private) or 'public' as default
        """
        db = self._get_db()

        try:
            zone = self._find_zone_for_domain(domain, db)
            if zone:
                return zone.visibility
            return 'public'  # Default fallback
        finally:
            db.close()

    def grant_zone_access_to_group(
        self,
        zone_id: int,
        group_id: int,
        admin_user: str
    ) -> Dict:
        """
        Grant a group explicit access to a specific zone.

        Args:
            zone_id: Zone ID
            group_id: Group ID
            admin_user: Admin user granting access

        Returns:
            Dict with success flag
        """
        db = self._get_db()

        try:
            # Check if grant already exists
            existing = db(
                (db.group_zone_access.group_id == group_id) &
                (db.group_zone_access.zone_id == zone_id)
            ).select().first()

            if existing:
                return {'success': True}

            # Create grant
            db.group_zone_access.insert(
                group_id=group_id,
                zone_id=zone_id
            )
            db.commit()

            return {'success': True}
        except Exception as e:
            logger.error(f"Error granting zone {zone_id} to group {group_id}: {e}")
            return {'success': False}
        finally:
            db.close()

    def revoke_zone_access_from_group(
        self,
        zone_id: int,
        group_id: int,
        admin_user: str
    ) -> Dict:
        """
        Revoke a group's explicit access to a specific zone.

        Args:
            zone_id: Zone ID
            group_id: Group ID
            admin_user: Admin user revoking access

        Returns:
            Dict with success flag
        """
        db = self._get_db()

        try:
            # Delete grant
            db(
                (db.group_zone_access.group_id == group_id) &
                (db.group_zone_access.zone_id == zone_id)
            ).delete()
            db.commit()

            return {'success': True}
        except Exception as e:
            logger.error(f"Error revoking zone {zone_id} from group {group_id}: {e}")
            return {'success': False}
        finally:
            db.close()

    def remove_user_from_group(
        self,
        user_id: int,
        group_id: int,
        admin_user: str
    ) -> Dict:
        """
        Remove a user from a group.

        Args:
            user_id: User ID
            group_id: Group ID
            admin_user: Admin user removing the user

        Returns:
            Dict with success flag
        """
        db = self._get_db()

        try:
            # Delete assignment
            db(
                (db.user_group_assignment.user_id == user_id) &
                (db.user_group_assignment.group_id == group_id)
            ).delete()
            db.commit()

            return {'success': True}
        except Exception as e:
            logger.error(f"Error removing user {user_id} from group {group_id}: {e}")
            return {'success': False}
        finally:
            db.close()

    def get_routing_stats(self) -> Dict:
        """
        Get DNS routing statistics.

        Returns:
            Dict with stats on groups, zones, assignments, and grants
        """
        db = self._get_db()

        try:
            # Get counts using table-specific id conditions
            groups_count = len(db(db.dns_group.id > 0).select())
            zones_count = len(db(db.dns_routing_zone.id > 0).select())
            assignments_count = len(db(db.user_group_assignment.id > 0).select())
            grants_count = len(db(db.group_zone_access.id > 0).select())

            return {
                'groups': {'total': groups_count},
                'zones': {'total': zones_count},
                'user_assignments': {'total': assignments_count},
                'zone_access_grants': {'total': grants_count}
            }
        finally:
            db.close()

    def delete_group(
        self,
        group_id: int,
        admin_user: str
    ) -> Dict:
        """
        Delete a DNS access control group.

        Args:
            group_id: Group ID
            admin_user: Admin user deleting the group

        Returns:
            Dict with success flag
        """
        db = self._get_db()

        try:
            # Delete group and cascade assignments (foreign keys handle cascade)
            db(db.dns_group.id == group_id).delete()
            db.commit()

            return {'success': True}
        except Exception as e:
            logger.error(f"Error deleting group {group_id}: {e}")
            return {'success': False}
        finally:
            db.close()
