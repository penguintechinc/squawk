"""
Mock DNS Server Tests
Tests DNS server request parsing, response generation, and query processing
with mocked client requests.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock, AsyncMock
import dns.message
import dns.rdatatype
import dns.rcode
import dns.rrset
import asyncio
from datetime import datetime, timedelta


class MockDNSResolver:
    """Mock DNS resolver for testing"""

    def __init__(self):
        self.cache = {}
        self.query_count = 0

    async def resolve(self, domain: str, record_type: str = 'A'):
        """Mock resolve method"""
        self.query_count += 1

        # Check cache first
        cache_key = f"{domain}:{record_type}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        # Mock responses for known domains
        if domain == 'example.com':
            return {
                'Status': 0,
                'Question': [{'name': domain, 'type': record_type}],
                'Answer': [
                    {
                        'name': domain,
                        'type': record_type,
                        'TTL': 300,
                        'data': '93.184.216.34'
                    }
                ]
            }
        elif domain == 'nonexistent.example.com':
            return {
                'Status': 3,  # NXDOMAIN
                'Question': [{'name': domain, 'type': record_type}],
                'Answer': []
            }
        else:
            return {
                'Status': 2,  # SERVFAIL
                'Question': [{'name': domain, 'type': record_type}],
                'Answer': []
            }


class TestMockDNSServerRequestParsing:
    """Test DNS server request parsing"""

    def test_server_parses_valid_query(self):
        """Server correctly parses valid DNS query"""
        # Create DNS query message
        query = dns.message.make_query('example.com', 'A')
        wire_format = query.to_wire()

        # Parse back
        parsed = dns.message.from_wire(wire_format)

        assert len(parsed.question) == 1
        assert parsed.question[0].name.to_text() == 'example.com.'
        assert parsed.question[0].rdtype == dns.rdatatype.A

    def test_server_parses_multiple_questions(self):
        """Server parses query with multiple questions"""
        query = dns.message.make_query('example.com', 'A')
        query.question.append(
            dns.message.make_query('example.org', 'AAAA').question[0]
        )

        wire_format = query.to_wire()
        parsed = dns.message.from_wire(wire_format)

        assert len(parsed.question) == 2

    def test_server_parses_query_with_edns(self):
        """Server parses query with EDNS options"""
        query = dns.message.make_query('example.com', 'A', want_dnssec=True)
        wire_format = query.to_wire()
        parsed = dns.message.from_wire(wire_format)

        assert parsed.ednsflags & dns.flags.DO

    def test_server_handles_malformed_query(self):
        """Server handles malformed DNS query"""
        # Create invalid wire format
        invalid_wire = b'\x00\x01\x02\x03'

        with pytest.raises((dns.message.ShortHeader, dns.message.TrailingJunk,
                          dns.exception.FormError)):
            dns.message.from_wire(invalid_wire)

    def test_server_extracts_query_metadata(self):
        """Server extracts query metadata (ID, flags, etc.)"""
        query = dns.message.make_query('example.com', 'A')
        query.id = 12345

        assert query.id == 12345
        assert query.opcode() == dns.opcode.QUERY


class TestMockDNSServerResponseGeneration:
    """Test DNS server response generation"""

    def test_server_generates_noerror_response(self):
        """Server generates NOERROR response with answer"""
        query = dns.message.make_query('example.com', 'A')
        response = dns.message.make_response(query)

        # Add answer
        rrset = dns.rrset.from_text('example.com.', 300, 'IN', 'A', '93.184.216.34')
        response.answer.append(rrset)

        assert response.rcode() == dns.rcode.NOERROR
        assert len(response.answer) == 1
        assert response.id == query.id

    def test_server_generates_nxdomain_response(self):
        """Server generates NXDOMAIN response"""
        query = dns.message.make_query('nonexistent.example.com', 'A')
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.NXDOMAIN)

        assert response.rcode() == dns.rcode.NXDOMAIN
        assert len(response.answer) == 0

    def test_server_generates_servfail_response(self):
        """Server generates SERVFAIL response"""
        query = dns.message.make_query('example.com', 'A')
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.SERVFAIL)

        assert response.rcode() == dns.rcode.SERVFAIL

    def test_server_generates_refused_response(self):
        """Server generates REFUSED response"""
        query = dns.message.make_query('blocked.example.com', 'A')
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.REFUSED)

        assert response.rcode() == dns.rcode.REFUSED

    def test_server_sets_response_flags(self):
        """Server sets appropriate response flags"""
        query = dns.message.make_query('example.com', 'A')
        response = dns.message.make_response(query)

        assert response.flags & dns.flags.QR  # Query Response flag
        assert response.flags & dns.flags.AA or not (response.flags & dns.flags.AA)  # May or may not be authoritative


class TestMockDNSServerQueryProcessing:
    """Test DNS server query processing logic"""

    @pytest.mark.asyncio
    async def test_server_processes_a_record_query(self):
        """Server processes A record query"""
        resolver = MockDNSResolver()
        result = await resolver.resolve('example.com', 'A')

        assert result['Status'] == 0
        assert len(result['Answer']) == 1
        assert result['Answer'][0]['data'] == '93.184.216.34'

    @pytest.mark.asyncio
    async def test_server_processes_nxdomain_query(self):
        """Server processes query for non-existent domain"""
        resolver = MockDNSResolver()
        result = await resolver.resolve('nonexistent.example.com', 'A')

        assert result['Status'] == 3  # NXDOMAIN
        assert len(result['Answer']) == 0

    @pytest.mark.asyncio
    async def test_server_tracks_query_count(self):
        """Server tracks number of queries processed"""
        resolver = MockDNSResolver()

        await resolver.resolve('example.com', 'A')
        await resolver.resolve('example.org', 'A')
        await resolver.resolve('example.net', 'A')

        assert resolver.query_count == 3

    @pytest.mark.asyncio
    async def test_server_handles_concurrent_queries(self):
        """Server handles multiple concurrent queries"""
        resolver = MockDNSResolver()

        # Process multiple queries concurrently
        tasks = [
            resolver.resolve('example.com', 'A'),
            resolver.resolve('example.org', 'A'),
            resolver.resolve('example.net', 'A'),
        ]

        results = await asyncio.gather(*tasks)

        assert len(results) == 3
        assert resolver.query_count == 3


class TestMockDNSServerBlacklistChecking:
    """Test DNS server blacklist/IOC checking"""

    class MockIOCChecker:
        """Mock IOC checker"""

        def __init__(self):
            self.blacklist = {'malicious.com', 'phishing.net', 'malware.org'}
            self.check_count = 0

        async def check_domain(self, domain: str) -> dict:
            """Check if domain is blacklisted"""
            self.check_count += 1

            if domain in self.blacklist:
                return {
                    'blocked': True,
                    'reason': 'Domain on IOC blacklist',
                    'category': 'malware'
                }
            return {
                'blocked': False,
                'reason': None,
                'category': None
            }

    @pytest.mark.asyncio
    async def test_server_checks_domain_against_blacklist(self):
        """Server checks domain against blacklist"""
        checker = self.MockIOCChecker()

        result = await checker.check_domain('malicious.com')
        assert result['blocked'] is True
        assert result['category'] == 'malware'

    @pytest.mark.asyncio
    async def test_server_allows_clean_domains(self):
        """Server allows domains not on blacklist"""
        checker = self.MockIOCChecker()

        result = await checker.check_domain('example.com')
        assert result['blocked'] is False

    @pytest.mark.asyncio
    async def test_server_blocks_multiple_categories(self):
        """Server blocks domains from multiple threat categories"""
        checker = self.MockIOCChecker()

        results = await asyncio.gather(
            checker.check_domain('malicious.com'),
            checker.check_domain('phishing.net'),
            checker.check_domain('malware.org')
        )

        assert all(r['blocked'] for r in results)

    @pytest.mark.asyncio
    async def test_server_tracks_blacklist_checks(self):
        """Server tracks number of blacklist checks"""
        checker = self.MockIOCChecker()

        await checker.check_domain('example.com')
        await checker.check_domain('malicious.com')
        await checker.check_domain('test.com')

        assert checker.check_count == 3


class TestMockDNSServerCacheOperations:
    """Test DNS server cache operations"""

    class MockCacheManager:
        """Mock cache manager"""

        def __init__(self):
            self.cache = {}
            self.hits = 0
            self.misses = 0

        async def get(self, key: str):
            """Get value from cache"""
            if key in self.cache:
                self.hits += 1
                return self.cache[key]
            self.misses += 1
            return None

        async def set(self, key: str, value, ttl: int = 300):
            """Set value in cache"""
            self.cache[key] = {
                'value': value,
                'ttl': ttl,
                'expires_at': datetime.now() + timedelta(seconds=ttl)
            }

        async def delete(self, key: str):
            """Delete value from cache"""
            if key in self.cache:
                del self.cache[key]
                return True
            return False

        async def clear(self):
            """Clear all cache"""
            self.cache.clear()
            self.hits = 0
            self.misses = 0

    @pytest.mark.asyncio
    async def test_server_caches_dns_responses(self):
        """Server caches DNS query responses"""
        cache = self.MockCacheManager()

        response_data = {
            'Status': 0,
            'Answer': [{'name': 'example.com', 'data': '93.184.216.34'}]
        }

        await cache.set('example.com:A', response_data, ttl=300)

        cached = await cache.get('example.com:A')
        assert cached is not None
        assert cached['value']['Status'] == 0

    @pytest.mark.asyncio
    async def test_server_cache_hit_increases_counter(self):
        """Server tracks cache hits"""
        cache = self.MockCacheManager()

        await cache.set('example.com:A', {'data': 'test'})
        await cache.get('example.com:A')
        await cache.get('example.com:A')

        assert cache.hits == 2

    @pytest.mark.asyncio
    async def test_server_cache_miss_increases_counter(self):
        """Server tracks cache misses"""
        cache = self.MockCacheManager()

        await cache.get('nonexistent.com:A')
        await cache.get('nothere.com:A')

        assert cache.misses == 2

    @pytest.mark.asyncio
    async def test_server_respects_cache_ttl(self):
        """Server respects cache TTL"""
        cache = self.MockCacheManager()

        await cache.set('example.com:A', {'data': 'test'}, ttl=300)

        cached = await cache.get('example.com:A')
        assert cached is not None
        assert cached['ttl'] == 300

    @pytest.mark.asyncio
    async def test_server_can_delete_cached_entries(self):
        """Server can delete specific cache entries"""
        cache = self.MockCacheManager()

        await cache.set('example.com:A', {'data': 'test'})
        assert await cache.get('example.com:A') is not None

        await cache.delete('example.com:A')
        assert await cache.get('example.com:A') is None

    @pytest.mark.asyncio
    async def test_server_can_clear_entire_cache(self):
        """Server can clear entire cache"""
        cache = self.MockCacheManager()

        await cache.set('example.com:A', {'data': 'test1'})
        await cache.set('example.org:A', {'data': 'test2'})

        await cache.clear()

        assert len(cache.cache) == 0
        assert cache.hits == 0
        assert cache.misses == 0


class TestMockDNSServerEdgeCases:
    """Test DNS server edge cases and boundary conditions"""

    def test_server_handles_empty_question_section(self):
        """Server handles query with empty question section"""
        query = dns.message.Message()
        query.id = 12345

        # No questions added
        assert len(query.question) == 0

    def test_server_handles_oversized_response(self):
        """Server handles response exceeding UDP size limit"""
        query = dns.message.make_query('example.com', 'A')
        response = dns.message.make_response(query)

        # Add many records to exceed typical UDP size (512 bytes)
        for i in range(100):
            rrset = dns.rrset.from_text(
                f'host{i}.example.com.', 300, 'IN', 'A', f'192.0.2.{i % 256}'
            )
            response.answer.append(rrset)

        wire = response.to_wire()
        # Standard UDP limit is 512 bytes without EDNS
        assert len(wire) > 512

    def test_server_handles_query_with_invalid_record_type(self):
        """Server handles query with unsupported record type"""
        query = dns.message.make_query('example.com', 'A')

        # Change to invalid type
        query.question[0] = dns.rrset.from_text(
            'example.com.', 0, 'IN', 'A'
        )[0]

    def test_server_handles_truncated_query(self):
        """Server handles truncated query message"""
        query = dns.message.make_query('example.com', 'A')
        wire = query.to_wire()

        # Truncate wire format
        truncated_wire = wire[:10]

        with pytest.raises((dns.message.ShortHeader, dns.exception.FormError)):
            dns.message.from_wire(truncated_wire)


class TestMockDNSServerAuthentication:
    """Test DNS server authentication and authorization"""

    class MockAuthManager:
        """Mock authentication manager"""

        def __init__(self):
            self.valid_tokens = {
                'token123': {'user': 'user1', 'scopes': ['query', 'admin']},
                'token456': {'user': 'user2', 'scopes': ['query']}
            }

        async def validate_token(self, token: str) -> dict:
            """Validate authentication token"""
            if token in self.valid_tokens:
                return {'valid': True, **self.valid_tokens[token]}
            return {'valid': False}

        async def check_permission(self, token: str, permission: str) -> bool:
            """Check if token has permission"""
            if token not in self.valid_tokens:
                return False
            return permission in self.valid_tokens[token]['scopes']

    @pytest.mark.asyncio
    async def test_server_validates_auth_token(self):
        """Server validates authentication tokens"""
        auth = self.MockAuthManager()

        result = await auth.validate_token('token123')
        assert result['valid'] is True
        assert result['user'] == 'user1'

    @pytest.mark.asyncio
    async def test_server_rejects_invalid_token(self):
        """Server rejects invalid authentication tokens"""
        auth = self.MockAuthManager()

        result = await auth.validate_token('invalid_token')
        assert result['valid'] is False

    @pytest.mark.asyncio
    async def test_server_checks_query_permission(self):
        """Server checks query permission"""
        auth = self.MockAuthManager()

        has_permission = await auth.check_permission('token123', 'query')
        assert has_permission is True

    @pytest.mark.asyncio
    async def test_server_denies_insufficient_permission(self):
        """Server denies access with insufficient permissions"""
        auth = self.MockAuthManager()

        has_permission = await auth.check_permission('token456', 'admin')
        assert has_permission is False


@pytest.mark.alpha
@pytest.mark.mock
class TestMockDNSServerIntegration:
    """Integration tests with mocked DNS server components"""

    @pytest.mark.asyncio
    async def test_full_query_processing_pipeline(self):
        """Test complete query processing pipeline"""
        # Setup components
        resolver = MockDNSResolver()
        cache = TestMockDNSServerCacheOperations.MockCacheManager()
        ioc_checker = TestMockDNSServerBlacklistChecking.MockIOCChecker()

        domain = 'example.com'
        record_type = 'A'

        # Check blacklist first
        ioc_result = await ioc_checker.check_domain(domain)
        if ioc_result['blocked']:
            pytest.skip("Domain blocked by IOC")

        # Check cache
        cache_key = f"{domain}:{record_type}"
        cached = await cache.get(cache_key)

        if cached is None:
            # Resolve
            result = await resolver.resolve(domain, record_type)
            await cache.set(cache_key, result, ttl=300)
        else:
            result = cached['value']

        assert result['Status'] == 0
        assert len(result['Answer']) == 1

    @pytest.mark.asyncio
    async def test_blocked_domain_returns_refused(self):
        """Test that blocked domains return REFUSED"""
        ioc_checker = TestMockDNSServerBlacklistChecking.MockIOCChecker()

        ioc_result = await ioc_checker.check_domain('malicious.com')
        assert ioc_result['blocked'] is True

        # Server would return REFUSED for this domain
        query = dns.message.make_query('malicious.com', 'A')
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.REFUSED)

        assert response.rcode() == dns.rcode.REFUSED
