"""Scope-bundle definitions and role→scope expansion.

Authorization is **scope-based** (security standard): roles are convenience
bundles that are expanded into concrete ``resource:action`` scopes at token
issuance. Middleware checks scopes only — never role names. The ``roles``/
``global_role`` claims remain on tokens for audit/display only.

The bundles below reproduce the pre-refactor access matrix exactly:

    SystemAdmin  → every write/admin scope + admin:super + all reads
    OrgAdmin     → servers/teams/time/dhcp :write + all reads
    UserManager  → users:write + all reads
    Viewer       → all reads
"""

from __future__ import annotations

from typing import Dict, List, Optional

# Sentinel scope held only by SystemAdmin. Global bypasses that previously
# branched on the 'SystemAdmin' role name (team-membership, zone access) now
# check for this scope instead.
SUPERADMIN_SCOPE = "admin:super"

# Read scopes granted to every authenticated principal via their role bundle.
# (No endpoint gates on these today; included for forward use + audit clarity.)
_READ_SCOPES: List[str] = [
    "users:read", "servers:read", "teams:read", "time:read",
    "dhcp:read", "ioc:read", "zones:read", "tokens:read",
    "analytics:read", "whois:read", "sso:read",
]

# Global role → concrete scope bundle.
ROLE_SCOPES: Dict[str, List[str]] = {
    "SystemAdmin": [
        SUPERADMIN_SCOPE,
        "users:write", "users:admin",
        "servers:write", "servers:admin",
        "teams:write", "teams:admin",
        "time:write", "time:admin",
        "dhcp:write", "dhcp:admin",
        "ioc:admin",
        "sso:write", "sso:admin",
        "audit:read",  # SystemAdmin only (no least-privilege leak to other roles)
    ] + _READ_SCOPES,
    "OrgAdmin": [
        "servers:write", "teams:write", "time:write", "dhcp:write",
    ] + _READ_SCOPES,
    "UserManager": [
        "users:write",
    ] + _READ_SCOPES,
    "Viewer": list(_READ_SCOPES),
}


def expand_scopes(
    global_role: Optional[str], team_roles: Optional[Dict] = None
) -> List[str]:
    """Expand a global role into its concrete scope bundle (sorted, de-duped).

    Team roles are enforced per-resource via team-membership data (not flat
    token scopes), so they intentionally contribute no global scopes here.
    """
    return sorted(set(ROLE_SCOPES.get(global_role or "", [])))


def scope_string(global_role: Optional[str], team_roles: Optional[Dict] = None) -> str:
    """Space-delimited scope claim value for a token (RFC 8693 style)."""
    return " ".join(expand_scopes(global_role, team_roles))
