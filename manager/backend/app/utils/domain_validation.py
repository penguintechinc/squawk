"""Domain allowlist validation for machine_clients and oidc_trust_anchors.

Validates hostnames and wildcard patterns (*.example.com), enforces constraints
(lowercase, max 256 entries, valid syntax).
"""

import re
from typing import List, Optional


def validate_hostname(hostname: str) -> bool:
    """
    Validate a single hostname or wildcard pattern.

    Args:
        hostname: FQDN (e.g., "example.com") or wildcard (e.g., "*.example.com")

    Returns:
        True if valid, False otherwise
    """
    # Allow *.suffix or bare hostname
    if hostname.startswith('*.'):
        base = hostname[2:]
    else:
        base = hostname

    # Validate FQDN: labels 1-63 chars (alphanumeric, hyphen), hyphen not at start/end
    # Total length <= 253
    if len(base) > 253 or len(base) == 0:
        return False

    labels = base.split('.')
    if not labels or len(labels) == 0:
        return False

    for label in labels:
        if len(label) == 0 or len(label) > 63:
            return False
        # Label must start/end with alphanumeric, middle can have hyphens
        if not re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$', label):
            return False

    return True


def validate_allowed_domains(domains: Optional[List[str]]) -> tuple[bool, Optional[str]]:
    """
    Validate a list of allowed domain patterns.

    Args:
        domains: List of hostnames/wildcards, or None

    Returns:
        Tuple (is_valid, error_message):
        - (True, None) if valid or None
        - (False, error_string) if invalid
    """
    if domains is None:
        # NULL = unrestricted (valid)
        return True, None

    if not isinstance(domains, list):
        return False, "allowed_domains must be a list of hostnames or None"

    if len(domains) > 256:
        return False, f"Maximum 256 allowed domains, got {len(domains)}"

    for domain in domains:
        if not isinstance(domain, str):
            return False, f"Each domain must be a string, got {type(domain).__name__}"

        domain = domain.lower()  # Enforce lowercase

        if not validate_hostname(domain):
            return False, f"Invalid domain pattern: {domain}"

    return True, None
