"""
Validation utilities for Squawk DNS Manager.
"""

import re
from typing import Optional


def validate_email(email: str) -> bool:
    """
    Validate email address format.

    Args:
        email: Email address to validate

    Returns:
        True if valid, False otherwise
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_username(username: str) -> bool:
    """
    Validate username format.
    Must be 3-50 characters, alphanumeric + underscore/hyphen.

    Args:
        username: Username to validate

    Returns:
        True if valid, False otherwise
    """
    if not username or len(username) < 3 or len(username) > 50:
        return False
    pattern = r'^[a-zA-Z0-9_-]+$'
    return bool(re.match(pattern, username))


def validate_domain_name(domain: str) -> bool:
    """
    Validate DNS domain name (RFC 1035 compliant).

    Args:
        domain: Domain name to validate

    Returns:
        True if valid, False otherwise
    """
    if not domain or len(domain) > 253:
        return False

    # Remove trailing dot if present
    if domain.endswith('.'):
        domain = domain[:-1]

    # Split into labels
    labels = domain.split('.')
    if not labels:
        return False

    # Validate each label
    label_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    for label in labels:
        if not label or len(label) > 63:
            return False
        if not re.match(label_pattern, label):
            return False

    return True


def validate_ip_address(ip: str) -> bool:
    """
    Validate IPv4 or IPv6 address.

    Args:
        ip: IP address to validate

    Returns:
        True if valid, False otherwise
    """
    # IPv4
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, ip):
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)

    # IPv6
    ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$'
    if re.match(ipv6_pattern, ip):
        return True

    # IPv6 with :: abbreviation
    if '::' in ip:
        parts = ip.split('::')
        if len(parts) != 2:
            return False
        # Basic validation (simplified)
        return True

    return False


def validate_license_key(license_key: str) -> bool:
    """
    Validate license key format.
    Expected format: PENG-XXXX-XXXX-XXXX-XXXX-ABCD

    Args:
        license_key: License key to validate

    Returns:
        True if valid format, False otherwise
    """
    pattern = r'^PENG-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$'
    return bool(re.match(pattern, license_key))


def validate_dns_record_type(record_type: str) -> bool:
    """
    Validate DNS record type.

    Args:
        record_type: DNS record type (A, AAAA, CNAME, etc.)

    Returns:
        True if valid, False otherwise
    """
    valid_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR', 'SRV', 'CAA']
    return record_type.upper() in valid_types


def validate_ttl(ttl: int) -> bool:
    """
    Validate DNS TTL value.
    Must be between 0 and 2147483647 (max 32-bit signed int).

    Args:
        ttl: TTL value in seconds

    Returns:
        True if valid, False otherwise
    """
    return 0 <= ttl <= 2147483647


def validate_port(port: int) -> bool:
    """
    Validate port number.

    Args:
        port: Port number

    Returns:
        True if valid, False otherwise
    """
    return 1 <= port <= 65535


def validate_global_role(role: str) -> bool:
    """
    Validate global role value.

    Args:
        role: Global role

    Returns:
        True if valid, False otherwise
    """
    valid_roles = ['SystemAdmin', 'OrgAdmin', 'UserManager', 'Viewer']
    return role in valid_roles


def validate_team_role(role: str) -> bool:
    """
    Validate team role value.

    Args:
        role: Team role

    Returns:
        True if valid, False otherwise
    """
    valid_roles = ['TeamAdmin', 'TeamMember', 'TeamViewer']
    return role in valid_roles


def validate_visibility(visibility: str) -> bool:
    """
    Validate zone visibility value.

    Args:
        visibility: Zone visibility

    Returns:
        True if valid, False otherwise
    """
    valid_values = ['public', 'internal', 'restricted', 'private']
    return visibility in valid_values


def sanitize_string(value: str, max_length: Optional[int] = None) -> str:
    """
    Sanitize string input by stripping whitespace and limiting length.

    Args:
        value: String to sanitize
        max_length: Maximum length (optional)

    Returns:
        Sanitized string
    """
    if not value:
        return ''

    sanitized = value.strip()

    if max_length and len(sanitized) > max_length:
        sanitized = sanitized[:max_length]

    return sanitized
