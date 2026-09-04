"""Log injection prevention for user-controlled strings.

Strips CR/LF and other control characters from values before they are
interpolated into plaintext log lines. Without this, an attacker-controlled
domain name (or other request-derived string) containing CR/LF sequences
could forge additional, fake log entries (log injection / CRLF forging).
"""
from __future__ import annotations

import re

_CONTROL_CHARS_RE = re.compile(r'[\r\n\x00-\x1f\x7f]')


def sanitize_for_log(value: str | None) -> str:
    """Strip CR, LF, and other control characters from a value for safe logging.

    Args:
        value: A potentially attacker-controlled string (e.g. a queried domain).

    Returns:
        The value with all control characters removed; empty string if None.
    """
    if value is None:
        return ''
    return _CONTROL_CHARS_RE.sub('', str(value))
