"""DNS domain policy matching for per-identity allowlists.

Implements case-insensitive, trailing-dot-normalized exact and wildcard suffix
matching. Wildcards (*.example.com) match any depth under the suffix but not
the suffix itself.
"""

from typing import Optional, List


def normalize_domain(domain: str) -> str:
    """Normalize domain: lowercase, remove trailing dot."""
    return domain.lower().rstrip('.')


def matches_policy(queried_name: str, allowed_domains: Optional[List[str]]) -> bool:
    """
    Check if queried domain name matches policy allowlist.

    Args:
        queried_name: The DNS query name (e.g., "example.com", "sub.example.com")
        allowed_domains: List of allowed FQDNs or *.suffix wildcards, or None (unrestricted)
                        Empty list denies all.

    Returns:
        True if queried_name is allowed, False otherwise.

    Matching rules (case-insensitive, trailing-dot normalized):
    - None: unrestricted (returns True)
    - []: deny all (returns False)
    - Exact match: "example.com" matches exactly "example.com" (not "sub.example.com")
    - Wildcard suffix: "*.example.com" matches "sub.example.com", "a.b.example.com"
                      but NOT "example.com" itself
    """
    if allowed_domains is None:
        # NULL = unrestricted
        return True

    if not allowed_domains:
        # Empty list = deny all
        return False

    normalized_query = normalize_domain(queried_name)

    for entry in allowed_domains:
        normalized_entry = normalize_domain(entry)

        # Exact match
        if normalized_query == normalized_entry:
            return True

        # Wildcard suffix: *.example.com matches a.example.com, b.c.example.com, etc.
        if normalized_entry.startswith('*.'):
            suffix = normalized_entry[2:]  # Remove '*.'
            # Must match a subdomain: ends with .suffix but not equal to suffix
            if normalized_query.endswith('.' + suffix) or normalized_query == suffix:
                # Check: if it's exactly the suffix, wildcard doesn't match
                if normalized_query == suffix:
                    continue
                return True

    return False
