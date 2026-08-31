"""
Input validation helpers for client-supplied DHCP fields (MAC, hostname).

Centralizes the format/charset checks so every handler that accepts a
client-controlled mac_address/hostname applies the same rules before the
value is persisted, logged, or used in a lease lookup.
"""

import re
from typing import Optional

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\Z")
_HOSTNAME_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\Z"
)
_MAX_HOSTNAME_LEN = 253


def is_valid_mac(mac: str) -> bool:
    """Validate a canonical colon-separated MAC address (aa:bb:cc:dd:ee:ff)."""
    if not isinstance(mac, str):
        return False
    return bool(_MAC_RE.match(mac))


def sanitize_hostname(hostname: Optional[str]) -> Optional[str]:
    """
    Validate/normalize a client-supplied hostname.

    Returns the stripped hostname if it satisfies RFC 1123 label rules and
    the 253-character length limit, or None if it should be rejected
    (empty, too long, control characters, or invalid charset).
    """
    if not isinstance(hostname, str):
        return None
    stripped = hostname.strip()
    if not stripped or len(stripped) > _MAX_HOSTNAME_LEN:
        return None
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in stripped):
        return None
    if not _HOSTNAME_RE.match(stripped):
        return None
    return stripped
