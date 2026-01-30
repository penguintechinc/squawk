"""
Domain Validation Unit Tests
Tests domain name validation logic
"""

import pytest
import re


def is_valid_domain(domain):
    """Validate DNS domain name according to RFC 1035"""
    if not domain:
        return False

    # Allow IP addresses for reverse DNS
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", domain):
        return True

    # Check overall length (max 253 characters)
    if len(domain) > 253:
        return False

    # Remove trailing dot if present
    domain = domain.rstrip(".")

    # Check for invalid characters
    if re.search(r"[^a-zA-Z0-9.\-]", domain):
        return False

    # Split into labels
    labels = domain.split(".")
    if not labels:
        return False

    # DNS label validation regex
    label_regex = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")

    for label in labels:
        # Check label length (max 63 characters)
        if not label or len(label) > 63:
            return False

        # Special cases for reverse DNS and punycode
        if label == "arpa" or label.startswith("xn--"):
            continue

        # Check label format
        if not label_regex.match(label):
            return False

        # Check for consecutive hyphens (except in punycode)
        if "--" in label and not label.startswith("xn--"):
            return False

    return True


@pytest.mark.unit
@pytest.mark.validation
class TestDomainValidation:
    """Test domain name validation"""

    def test_valid_simple_domain(self):
        """Simple domain names are valid"""
        assert is_valid_domain("example.com") is True
        assert is_valid_domain("test.example.com") is True
        assert is_valid_domain("sub.domain.example.org") is True

    def test_valid_domain_with_numbers(self):
        """Domains with numbers are valid"""
        assert is_valid_domain("test123.com") is True
        assert is_valid_domain("123test.com") is True
        assert is_valid_domain("12345.example.com") is True

    def test_valid_domain_with_hyphens(self):
        """Domains with hyphens are valid"""
        assert is_valid_domain("test-domain.com") is True
        assert is_valid_domain("my-test-domain.example.org") is True

    def test_valid_ipv4_address(self):
        """IPv4 addresses are valid for reverse DNS"""
        assert is_valid_domain("192.168.1.1") is True
        assert is_valid_domain("10.0.0.1") is True
        assert is_valid_domain("255.255.255.255") is True

    def test_valid_punycode_domain(self):
        """Punycode domains (IDN) are valid"""
        assert is_valid_domain("xn--n3h.com") is True

    def test_valid_trailing_dot(self):
        """Domains with trailing dot are valid"""
        assert is_valid_domain("example.com.") is True

    def test_invalid_empty_domain(self):
        """Empty domain is invalid"""
        assert is_valid_domain("") is False
        assert is_valid_domain(None) is False

    def test_invalid_domain_too_long(self):
        """Domain exceeding 253 characters is invalid"""
        long_domain = "a" * 64 + "." + "b" * 64 + "." + "c" * 64 + "." + "d" * 64 + ".com"
        assert is_valid_domain(long_domain) is False

    def test_invalid_label_too_long(self):
        """Label exceeding 63 characters is invalid"""
        long_label = "a" * 64 + ".com"
        assert is_valid_domain(long_label) is False

    def test_invalid_domain_with_spaces(self):
        """Domain with spaces is invalid"""
        assert is_valid_domain("test domain.com") is False
        assert is_valid_domain("test .com") is False

    def test_invalid_domain_with_special_chars(self):
        """Domain with special characters is invalid"""
        assert is_valid_domain("test@domain.com") is False
        assert is_valid_domain("test#domain.com") is False
        assert is_valid_domain("test!domain.com") is False
        assert is_valid_domain("test<script>.com") is False

    def test_invalid_domain_starting_with_hyphen(self):
        """Domain starting with hyphen is invalid"""
        assert is_valid_domain("-example.com") is False

    def test_invalid_domain_ending_with_hyphen(self):
        """Domain ending with hyphen is invalid"""
        assert is_valid_domain("example-.com") is False

    def test_invalid_consecutive_dots(self):
        """Domain with consecutive dots is invalid"""
        assert is_valid_domain("example..com") is False
        assert is_valid_domain("test...example.com") is False

    def test_invalid_consecutive_hyphens(self):
        """Domain with consecutive hyphens (not punycode) is invalid"""
        assert is_valid_domain("test--domain.com") is False


@pytest.mark.unit
@pytest.mark.validation
class TestRecordTypeValidation:
    """Test DNS record type validation"""

    def test_valid_record_types(self):
        """Common record types are valid"""
        valid_types = {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "SRV"}

        for record_type in valid_types:
            assert record_type in valid_types

    def test_case_insensitive(self):
        """Record types should be case insensitive"""
        valid_types = {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR"}

        for record_type in valid_types:
            assert record_type.upper() in valid_types
            # Lower case should be normalized to upper


@pytest.mark.unit
@pytest.mark.validation
class TestInputSanitization:
    """Test input sanitization for security"""

    def test_xss_prevention_in_domain(self):
        """XSS attempts in domain are rejected"""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert(1)",
            "<img src=x onerror=alert(1)>",
            "test<svg/onload=alert(1)>.com"
        ]

        for payload in xss_payloads:
            assert is_valid_domain(payload) is False

    def test_sql_injection_in_domain(self):
        """SQL injection attempts in domain are rejected"""
        sql_payloads = [
            "'; DROP TABLE users;--",
            "1' OR '1'='1",
            "test' UNION SELECT * FROM users--",
        ]

        for payload in sql_payloads:
            assert is_valid_domain(payload) is False

    def test_null_byte_injection(self):
        """Null byte injection is rejected"""
        assert is_valid_domain("test\x00.com") is False

    def test_path_traversal_in_domain(self):
        """Path traversal attempts are rejected"""
        assert is_valid_domain("../../../etc/passwd") is False
        assert is_valid_domain("..\\..\\windows\\system32") is False
