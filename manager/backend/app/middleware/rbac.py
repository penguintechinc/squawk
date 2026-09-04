"""
Role-Based Access Control (RBAC) middleware.
Enforces global and team-level permissions.
"""

from functools import wraps
from flask import jsonify, current_app
from app.middleware.auth import get_current_user
from app.services.scopes import SUPERADMIN_SCOPE


def _user_scopes(user) -> set:
    """Return the set of scopes carried by the token (authz source of truth)."""
    if not user:
        return set()
    return set((user.get('scope') or '').split())


def _is_superadmin(user) -> bool:
    """True if the token holds the super-admin scope (global bypass privilege)."""
    return SUPERADMIN_SCOPE in _user_scopes(user)


def requires_scope(*required_scopes):
    """
    Decorator to enforce that the caller holds at least one of the given scopes.

    Authorization is scope-based — never role names. Roles are expanded into
    concrete scopes at token issuance (see app.services.scopes).

    Example:
        @requires_scope('servers:write')
        def create_server():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()
            if not user:
                return jsonify({'error': 'Authentication required'}), 401

            if not _user_scopes(user).intersection(required_scopes):
                return jsonify({
                    'error': 'Insufficient permissions',
                    'required_scopes': list(required_scopes),
                }), 403

            return f(*args, **kwargs)

        return decorated
    return decorator


def requires_role(*allowed_roles):
    """
    Decorator to enforce global role requirements.

    Args:
        allowed_roles: One or more global roles (SystemAdmin, OrgAdmin, UserManager, Viewer)

    Example:
        @requires_role('SystemAdmin', 'OrgAdmin')
        def create_user():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()
            if not user:
                return jsonify({'error': 'Authentication required'}), 401

            if user.get('global_role') not in allowed_roles:
                return jsonify({
                    'error': 'Insufficient permissions',
                    'required_roles': list(allowed_roles),
                    'your_role': user.get('global_role')
                }), 403

            return f(*args, **kwargs)

        return decorated
    return decorator


def requires_team_role(team_id_param='team_id', *allowed_roles):
    """
    Decorator to enforce team-level role requirements.

    Args:
        team_id_param: Name of the parameter containing team_id (in kwargs or request)
        allowed_roles: One or more team roles (TeamAdmin, TeamMember, TeamViewer)

    Example:
        @requires_team_role('team_id', 'TeamAdmin')
        def update_team(team_id):
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()
            if not user:
                return jsonify({'error': 'Authentication required'}), 401

            # System admins bypass team restrictions
            if _is_superadmin(user):
                return f(*args, **kwargs)

            # Get team_id from kwargs or route parameters
            team_id = kwargs.get(team_id_param)
            if not team_id:
                return jsonify({'error': 'Team ID required'}), 400

            # Check team membership
            team_roles = user.get('team_roles', {})
            user_role = team_roles.get(int(team_id))

            if not user_role or user_role not in allowed_roles:
                return jsonify({
                    'error': 'Insufficient team permissions',
                    'required_roles': list(allowed_roles),
                    'your_role': user_role
                }), 403

            return f(*args, **kwargs)

        return decorated
    return decorator


def can_access_team(team_id: int) -> bool:
    """
    Check if current user can access a team.

    Args:
        team_id: Team ID to check

    Returns:
        True if user has access, False otherwise
    """
    user = get_current_user()
    if not user:
        return False

    # System admins can access all teams
    if _is_superadmin(user):
        return True

    # Check team membership
    team_roles = user.get('team_roles', {})
    return int(team_id) in team_roles


def can_manage_users() -> bool:
    """
    Check if current user can manage users.

    Returns:
        True if user has permission, False otherwise
    """
    user = get_current_user()
    if not user:
        return False

    # SystemAdmin (users:write+users:admin) and UserManager (users:write).
    return bool(_user_scopes(user).intersection({'users:write', 'users:admin'}))


def can_manage_teams() -> bool:
    """
    Check if current user can create/manage teams.

    Returns:
        True if user has permission, False otherwise
    """
    user = get_current_user()
    if not user:
        return False

    # SystemAdmin and OrgAdmin both hold teams:write.
    return 'teams:write' in _user_scopes(user)


def filter_teams_by_access():
    """
    Get list of team IDs current user can access.

    Returns:
        List of team IDs
    """
    user = get_current_user()
    if not user:
        return []

    # System admins can access all teams
    if _is_superadmin(user):
        db = current_app.db
        teams = db(db.team).select(db.team.id)
        return [t.id for t in teams]

    # Return teams user is member of
    team_roles = user.get('team_roles', {})
    return list(team_roles.keys())


def requires_system_admin(f):
    """
    Decorator to require super-admin privilege (scope-based).
    Only the SystemAdmin bundle carries SUPERADMIN_SCOPE.
    """
    return requires_scope(SUPERADMIN_SCOPE)(f)


def requires_admin(f):
    """
    Decorator to require org-admin privilege (scope-based).
    SystemAdmin and OrgAdmin both hold teams:write.
    """
    return requires_scope('teams:write')(f)


def check_team_access(team_id: int) -> bool:
    """
    Check if current user can access a specific team's resources.

    Args:
        team_id: Team ID to check access for

    Returns:
        True if user has access, False otherwise
    """
    user = get_current_user()
    if not user:
        return False

    # System admins can access all teams
    if _is_superadmin(user):
        return True

    # Check if user is a member of the team
    team_roles = user.get('team_roles', {})
    return int(team_id) in team_roles


def check_zone_access(zone_id: int) -> bool:
    """
    Check if current user can access a DNS zone.

    Args:
        zone_id: DNS zone ID

    Returns:
        True if user has access, False otherwise
    """
    user = get_current_user()
    if not user:
        return False

    # System admins can access all zones
    if _is_superadmin(user):
        return True

    db = current_app.db
    zone = db.dns_zone[zone_id]
    if not zone:
        return False

    # Public zones are accessible to all
    if zone.visibility == 'public':
        return True

    # Check team membership for team-restricted zones
    if zone.team_id:
        return can_access_team(zone.team_id)

    return False


def check_zone_write_access(zone_id: int) -> bool:
    """
    Check if current user may mutate (create/update/delete) a DNS zone
    or its records.

    Unlike check_zone_access (read), public visibility never grants write —
    callers must additionally hold a zones:write/zones:admin scope, checked
    separately via @requires_scope at the route level. This only covers the
    object-level ownership check: zones with no team are org-wide (writable
    by any scope holder, mirroring _can_access_pool/_can_access_server for
    DHCP/time resources); zones with a team require actual membership.

    Args:
        zone_id: DNS zone ID

    Returns:
        True if user has write access, False otherwise
    """
    user = get_current_user()
    if not user:
        return False

    # System admins can mutate all zones
    if _is_superadmin(user):
        return True

    db = current_app.db
    zone = db.dns_zone[zone_id]
    if not zone:
        return False

    # Zones with no team are org-wide; team-scoped zones require membership
    if zone.team_id is None:
        return True

    return can_access_team(zone.team_id)


def filter_zones_by_access():
    """
    Get list of zone IDs current user can access.

    Returns:
        List of zone IDs
    """
    user = get_current_user()
    db = current_app.db

    if not user:
        # Unauthenticated: only public zones
        zones = db(db.dns_zone.visibility == 'public').select(db.dns_zone.id)
        return [z.id for z in zones]

    # System admins can access all zones
    if _is_superadmin(user):
        zones = db(db.dns_zone).select(db.dns_zone.id)
        return [z.id for z in zones]

    # Get accessible team IDs
    accessible_teams = filter_teams_by_access()

    # Get zones: public OR in accessible teams
    zones = db(
        (db.dns_zone.visibility == 'public') |
        (db.dns_zone.team_id.belongs(accessible_teams))
    ).select(db.dns_zone.id)

    return [z.id for z in zones]
