"""
Coverage tests for app/services/dns_resolver.py

Exercises DNSResolver.resolve() for every dns.resolver exception branch
(invalid type, NXDOMAIN, Timeout, NoAnswer, generic Exception, and success)
plus resolve_custom_zone() match/no-match paths. The underlying
dns.resolver.Resolver.resolve call is mocked throughout, no network access.
"""
from unittest.mock import Mock, patch

import dns.rdatatype
import dns.resolver
import pytest

from app.services.dns_resolver import DNSResolver


@pytest.fixture
def resolver():
    return DNSResolver()


class TestResolveInvalidRecordType:
    @pytest.mark.asyncio
    async def test_unknown_record_type_returns_servfail(self, resolver):
        result = await resolver.resolve("example.com", "NOTAREALTYPE")

        assert result["Status"] == 2
        assert result["Question"] == [{"name": "example.com", "type": "NOTAREALTYPE"}]
        assert result["Answer"] == []


class TestResolveSuccess:
    @pytest.mark.asyncio
    async def test_successful_resolution_builds_answer_records(self, resolver):
        mock_rdata = Mock()
        mock_rdata.__str__ = Mock(return_value="93.184.216.34")

        mock_rrset = Mock()
        mock_rrset.ttl = 300

        mock_answers = Mock()
        mock_answers.__iter__ = Mock(return_value=iter([mock_rdata]))
        mock_answers.rrset = mock_rrset

        with patch.object(resolver.resolver, "resolve", return_value=mock_answers):
            result = await resolver.resolve("example.com", "A")

        assert result["Status"] == 0
        assert result["Question"] == [{"name": "example.com", "type": "A"}]
        assert len(result["Answer"]) == 1
        answer = result["Answer"][0]
        assert answer["name"] == "example.com"
        assert answer["type"] == "A"
        assert answer["TTL"] == 300
        assert answer["data"] == "93.184.216.34"

    @pytest.mark.asyncio
    async def test_lowercase_record_type_is_normalized(self, resolver):
        mock_answers = Mock()
        mock_answers.__iter__ = Mock(return_value=iter([]))
        mock_answers.rrset = Mock(ttl=60)

        with patch.object(resolver.resolver, "resolve", return_value=mock_answers) as mock_resolve:
            result = await resolver.resolve("example.com", "aaaa")

        mock_resolve.assert_called_once_with("example.com", dns.rdatatype.from_text("AAAA"))
        assert result["Status"] == 0
        assert result["Answer"] == []


class TestResolveExceptionBranches:
    @pytest.mark.asyncio
    async def test_nxdomain_returns_status_3(self, resolver):
        with patch.object(
            resolver.resolver, "resolve", side_effect=dns.resolver.NXDOMAIN()
        ):
            result = await resolver.resolve("nonexistent.example.com", "A")

        assert result["Status"] == 3
        assert result["Answer"] == []

    @pytest.mark.asyncio
    async def test_timeout_returns_servfail(self, resolver):
        with patch.object(
            resolver.resolver, "resolve", side_effect=dns.resolver.Timeout()
        ):
            result = await resolver.resolve("slow.example.com", "A")

        assert result["Status"] == 2
        assert result["Answer"] == []

    @pytest.mark.asyncio
    async def test_no_answer_returns_status_0_with_empty_answer(self, resolver):
        with patch.object(
            resolver.resolver, "resolve", side_effect=dns.resolver.NoAnswer()
        ):
            result = await resolver.resolve("example.com", "MX")

        assert result["Status"] == 0
        assert result["Answer"] == []

    @pytest.mark.asyncio
    async def test_generic_exception_returns_servfail(self, resolver):
        with patch.object(
            resolver.resolver, "resolve", side_effect=RuntimeError("boom")
        ):
            result = await resolver.resolve("example.com", "A")

        assert result["Status"] == 2
        assert result["Answer"] == []


class TestResolveCustomZone:
    def test_matching_record_returns_status_0(self, resolver):
        zone_records = [
            {"name": "example.com", "type": "A", "value": "10.0.0.1", "ttl": 120},
            {"name": "other.com", "type": "A", "value": "10.0.0.2"},
        ]

        result = resolver.resolve_custom_zone("example.com", "A", zone_records)

        assert result["Status"] == 0
        assert result["Answer"] == [
            {"name": "example.com", "type": "A", "TTL": 120, "data": "10.0.0.1"}
        ]

    def test_multiple_matching_records_all_included(self, resolver):
        zone_records = [
            {"name": "example.com", "type": "A", "value": "10.0.0.1"},
            {"name": "example.com", "type": "A", "value": "10.0.0.2"},
        ]

        result = resolver.resolve_custom_zone("example.com", "A", zone_records)

        assert result["Status"] == 0
        assert len(result["Answer"]) == 2
        # Default TTL applied when zone record omits it.
        assert all(a["TTL"] == 300 for a in result["Answer"])

    def test_no_matching_record_returns_nxdomain(self, resolver):
        zone_records = [{"name": "other.com", "type": "A", "value": "10.0.0.2"}]

        result = resolver.resolve_custom_zone("example.com", "A", zone_records)

        assert result["Status"] == 3
        assert result["Answer"] == []

    def test_empty_zone_records_returns_nxdomain(self, resolver):
        result = resolver.resolve_custom_zone("example.com", "A", [])

        assert result["Status"] == 3
        assert result["Answer"] == []

    def test_record_type_mismatch_excluded(self, resolver):
        zone_records = [{"name": "example.com", "type": "AAAA", "value": "::1"}]

        result = resolver.resolve_custom_zone("example.com", "A", zone_records)

        assert result["Status"] == 3
        assert result["Answer"] == []
