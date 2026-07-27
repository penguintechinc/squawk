"""Tests for DNS domain policy matching."""

import pytest
from app.utils.domain_policy import matches_policy, normalize_domain


class TestDomainPolicyMatching:
    """Test domain policy matching logic."""

    def test_normalize_domain_lowercase(self):
        """Normalize domain to lowercase."""
        assert normalize_domain("Example.COM") == "example.com"
        assert normalize_domain("SUB.EXAMPLE.COM") == "sub.example.com"

    def test_normalize_domain_trailing_dot(self):
        """Normalize domain removes trailing dot."""
        assert normalize_domain("example.com.") == "example.com"
        assert normalize_domain("sub.example.com.") == "sub.example.com"

    def test_unrestricted_none(self):
        """NULL allowed_domains = unrestricted (return True)."""
        assert matches_policy("example.com", None) is True
        assert matches_policy("anything.com", None) is True
        assert matches_policy("sub.sub.example.com", None) is True

    def test_deny_all_empty_list(self):
        """Empty list = deny all (return False)."""
        assert matches_policy("example.com", []) is False
        assert matches_policy("sub.example.com", []) is False

    def test_exact_match(self):
        """Exact match: exact FQDN only."""
        allowed = ["example.com"]
        assert matches_policy("example.com", allowed) is True
        assert matches_policy("sub.example.com", allowed) is False
        assert matches_policy("example.org", allowed) is False

    def test_exact_match_case_insensitive(self):
        """Exact match is case-insensitive."""
        allowed = ["Example.COM"]
        assert matches_policy("example.com", allowed) is True
        assert matches_policy("EXAMPLE.COM", allowed) is True
        assert matches_policy("ExAmPlE.cOm", allowed) is True

    def test_exact_match_trailing_dot_normalized(self):
        """Exact match normalizes trailing dots."""
        allowed = ["example.com."]
        assert matches_policy("example.com", allowed) is True
        assert matches_policy("example.com.", allowed) is True

    def test_wildcard_suffix_match(self):
        """Wildcard suffix *.example.com matches subdomains."""
        allowed = ["*.example.com"]
        assert matches_policy("sub.example.com", allowed) is True
        assert matches_policy("a.b.example.com", allowed) is True
        assert matches_policy("a.b.c.d.example.com", allowed) is True

    def test_wildcard_suffix_does_not_match_base(self):
        """Wildcard *.example.com does NOT match example.com itself."""
        allowed = ["*.example.com"]
        assert matches_policy("example.com", allowed) is False

    def test_wildcard_suffix_case_insensitive(self):
        """Wildcard suffix matching is case-insensitive."""
        allowed = ["*.Example.COM"]
        assert matches_policy("sub.example.com", allowed) is True
        assert matches_policy("SUB.EXAMPLE.COM", allowed) is True

    def test_wildcard_suffix_trailing_dot_normalized(self):
        """Wildcard suffix normalizes trailing dots."""
        allowed = ["*.example.com."]
        assert matches_policy("sub.example.com", allowed) is True
        assert matches_policy("sub.example.com.", allowed) is True

    def test_multiple_entries(self):
        """Multiple entries in allowlist."""
        allowed = ["example.com", "*.test.org", "specific.other.net"]
        assert matches_policy("example.com", allowed) is True
        assert matches_policy("sub.test.org", allowed) is True
        assert matches_policy("specific.other.net", allowed) is True
        assert matches_policy("other.org", allowed) is False

    def test_deep_wildcard_match(self):
        """Wildcard matches arbitrarily deep subdomains."""
        allowed = ["*.example.com"]
        assert matches_policy("a.b.c.d.e.f.example.com", allowed) is True

    def test_no_match_similar_domain(self):
        """Similar domain names don't match."""
        allowed = ["example.com"]
        assert matches_policy("example.co", allowed) is False
        assert matches_policy("exampleX.com", allowed) is False
        assert matches_policy("example-com", allowed) is False

    def test_no_match_parent_domain(self):
        """Parent domain doesn't match wildcard for subdomain."""
        allowed = ["*.example.com"]
        assert matches_policy("com", allowed) is False
        assert matches_policy("example.com", allowed) is False
        # But exact match of parent should not match the wildcard

    def test_mixed_exact_and_wildcard(self):
        """Mix of exact and wildcard entries."""
        allowed = ["example.com", "*.test.org", "static.value.net"]
        assert matches_policy("example.com", allowed) is True
        assert matches_policy("sub.example.com", allowed) is False
        assert matches_policy("api.test.org", allowed) is True
        assert matches_policy("static.value.net", allowed) is True
        assert matches_policy("static.value.net.co", allowed) is False

    def test_whitespace_in_domain_not_normalized(self):
        """Domains with whitespace are not valid (not normalized)."""
        allowed = ["example.com"]
        # Whitespace is not normalized away
        assert matches_policy("example. com", allowed) is False
