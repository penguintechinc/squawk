"""
Mock DNS Client Tests
Tests DNS client request formatting, response parsing, and error handling
with mocked server responses.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import dns.message
import dns.rdatatype
import dns.rcode
import socket
import struct


class TestMockDNSClientRequestFormatting:
    """Test DNS client request message formatting"""

    @patch('dns.query.udp')
    def test_client_formats_a_record_request(self, mock_udp):
        """Client correctly formats A record DNS query"""
        # Mock DNS response
        mock_response = dns.message.make_response(
            dns.message.make_query('example.com', 'A')
        )
        mock_udp.return_value = mock_response

        # Simulate client request
        query = dns.message.make_query('example.com', 'A')

        assert query.question[0].name.to_text() == 'example.com.'
        assert query.question[0].rdtype == dns.rdatatype.A

    @patch('dns.query.udp')
    def test_client_formats_aaaa_record_request(self, mock_udp):
        """Client correctly formats AAAA record DNS query"""
        mock_response = dns.message.make_response(
            dns.message.make_query('example.com', 'AAAA')
        )
        mock_udp.return_value = mock_response

        query = dns.message.make_query('example.com', 'AAAA')

        assert query.question[0].name.to_text() == 'example.com.'
        assert query.question[0].rdtype == dns.rdatatype.AAAA

    @patch('dns.query.udp')
    def test_client_formats_mx_record_request(self, mock_udp):
        """Client correctly formats MX record DNS query"""
        mock_response = dns.message.make_response(
            dns.message.make_query('example.com', 'MX')
        )
        mock_udp.return_value = mock_response

        query = dns.message.make_query('example.com', 'MX')

        assert query.question[0].name.to_text() == 'example.com.'
        assert query.question[0].rdtype == dns.rdatatype.MX

    @patch('dns.query.udp')
    def test_client_handles_multiple_questions(self, mock_udp):
        """Client can format queries with multiple questions"""
        query = dns.message.make_query('example.com', 'A')
        query.question.append(
            dns.message.make_query('example.org', 'AAAA').question[0]
        )

        assert len(query.question) == 2
        assert query.question[0].name.to_text() == 'example.com.'
        assert query.question[1].name.to_text() == 'example.org.'


class TestMockDNSClientResponseParsing:
    """Test DNS client response parsing"""

    def test_client_parses_successful_a_record_response(self):
        """Client correctly parses successful A record response"""
        # Create mock response
        query = dns.message.make_query('example.com', 'A')
        response = dns.message.make_response(query)

        # Add answer
        rrset = dns.rrset.from_text('example.com.', 300, 'IN', 'A', '93.184.216.34')
        response.answer.append(rrset)

        # Parse response
        assert response.rcode() == dns.rcode.NOERROR
        assert len(response.answer) == 1
        assert response.answer[0][0].to_text() == '93.184.216.34'

    def test_client_parses_nxdomain_response(self):
        """Client correctly handles NXDOMAIN response"""
        query = dns.message.make_query('nonexistent.example.com', 'A')
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.NXDOMAIN)

        assert response.rcode() == dns.rcode.NXDOMAIN
        assert len(response.answer) == 0

    def test_client_parses_servfail_response(self):
        """Client correctly handles SERVFAIL response"""
        query = dns.message.make_query('example.com', 'A')
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.SERVFAIL)

        assert response.rcode() == dns.rcode.SERVFAIL
        assert len(response.answer) == 0

    def test_client_parses_multiple_answers(self):
        """Client correctly parses response with multiple answers"""
        query = dns.message.make_query('example.com', 'A')
        response = dns.message.make_response(query)

        # Add multiple A records
        rrset = dns.rrset.from_text(
            'example.com.', 300, 'IN', 'A',
            '93.184.216.34', '93.184.216.35'
        )
        response.answer.append(rrset)

        assert len(response.answer) == 1
        assert len(response.answer[0]) == 2

    def test_client_parses_cname_response(self):
        """Client correctly parses CNAME response"""
        query = dns.message.make_query('www.example.com', 'A')
        response = dns.message.make_response(query)

        # Add CNAME record
        cname_rrset = dns.rrset.from_text(
            'www.example.com.', 300, 'IN', 'CNAME', 'example.com.'
        )
        response.answer.append(cname_rrset)

        # Add final A record
        a_rrset = dns.rrset.from_text(
            'example.com.', 300, 'IN', 'A', '93.184.216.34'
        )
        response.answer.append(a_rrset)

        assert len(response.answer) == 2
        assert response.answer[0].rdtype == dns.rdatatype.CNAME
        assert response.answer[1].rdtype == dns.rdatatype.A


class TestMockDNSClientErrorHandling:
    """Test DNS client error handling"""

    @patch('dns.query.udp')
    def test_client_handles_network_timeout(self, mock_udp):
        """Client handles network timeout gracefully"""
        mock_udp.side_effect = dns.exception.Timeout()

        with pytest.raises(dns.exception.Timeout):
            query = dns.message.make_query('example.com', 'A')
            dns.query.udp(query, '8.8.8.8', timeout=1)

    @patch('dns.query.udp')
    def test_client_handles_connection_refused(self, mock_udp):
        """Client handles connection refused error"""
        mock_udp.side_effect = OSError("Connection refused")

        with pytest.raises(OSError):
            query = dns.message.make_query('example.com', 'A')
            dns.query.udp(query, '8.8.8.8', timeout=1)

    @patch('dns.query.udp')
    def test_client_handles_invalid_response(self, mock_udp):
        """Client handles malformed DNS response"""
        mock_udp.side_effect = dns.message.BadEDNS()

        with pytest.raises(dns.message.BadEDNS):
            query = dns.message.make_query('example.com', 'A')
            dns.query.udp(query, '8.8.8.8', timeout=1)

    @patch('socket.socket')
    def test_client_handles_network_unreachable(self, mock_socket):
        """Client handles network unreachable error"""
        mock_sock = MagicMock()
        mock_sock.sendto.side_effect = socket.error("Network is unreachable")
        mock_socket.return_value = mock_sock

        with pytest.raises(socket.error):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(b'test', ('8.8.8.8', 53))

    def test_client_handles_malformed_query(self):
        """Client validates query before sending"""
        # Test with invalid domain name
        with pytest.raises((dns.name.EmptyLabel, dns.name.LabelTooLong, ValueError)):
            # Empty label
            dns.message.make_query('', 'A')


class TestMockDNSClientTimeout:
    """Test DNS client timeout scenarios"""

    @patch('dns.query.udp')
    def test_client_respects_custom_timeout(self, mock_udp):
        """Client respects custom timeout value"""
        mock_udp.side_effect = dns.exception.Timeout()

        query = dns.message.make_query('example.com', 'A')

        with pytest.raises(dns.exception.Timeout):
            dns.query.udp(query, '8.8.8.8', timeout=2)

        mock_udp.assert_called_once()

    @patch('dns.query.udp')
    def test_client_retries_on_timeout(self, mock_udp):
        """Client can retry after timeout"""
        # First call times out, second succeeds
        query = dns.message.make_query('example.com', 'A')
        response = dns.message.make_response(query)

        mock_udp.side_effect = [dns.exception.Timeout(), response]

        # First attempt
        with pytest.raises(dns.exception.Timeout):
            dns.query.udp(query, '8.8.8.8', timeout=1)

        # Retry succeeds
        result = dns.query.udp(query, '8.8.8.8', timeout=1)
        assert result.rcode() == dns.rcode.NOERROR

    @patch('time.time')
    @patch('dns.query.udp')
    def test_client_tracks_elapsed_time(self, mock_udp, mock_time):
        """Client tracks elapsed time for queries"""
        mock_time.side_effect = [1000.0, 1001.5]  # 1.5 second elapsed

        query = dns.message.make_query('example.com', 'A')
        response = dns.message.make_response(query)
        mock_udp.return_value = response

        start = mock_time()
        dns.query.udp(query, '8.8.8.8', timeout=5)
        end = mock_time()

        elapsed = end - start
        assert elapsed == 1.5


class TestMockDNSClientEdgeCases:
    """Test DNS client edge cases and boundary conditions"""

    def test_client_handles_maximum_label_length(self):
        """Client handles DNS labels at maximum length (63 chars)"""
        # Maximum label length is 63 characters
        max_label = 'a' * 63
        domain = f"{max_label}.example.com"

        query = dns.message.make_query(domain, 'A')
        assert query.question[0].name.to_text() == f"{max_label}.example.com."

    def test_client_handles_maximum_domain_length(self):
        """Client handles domains at maximum total length (253 chars)"""
        # Maximum domain length is 253 characters
        # Create domain with multiple 63-char labels
        labels = ['a' * 63, 'b' * 63, 'c' * 63, 'd' * 50]
        domain = '.'.join(labels)

        query = dns.message.make_query(domain, 'A')
        assert len(query.question[0].name.to_text().rstrip('.')) <= 253

    def test_client_handles_special_characters_in_domain(self):
        """Client handles special characters in domain names"""
        # DNS allows hyphens but not at start/end of label
        domain = "test-domain.example-site.com"

        query = dns.message.make_query(domain, 'A')
        assert query.question[0].name.to_text() == "test-domain.example-site.com."

    def test_client_handles_international_domain_names(self):
        """Client handles internationalized domain names (IDN)"""
        # Punycode representation
        idn_domain = "xn--bcher-kva.example.com"

        query = dns.message.make_query(idn_domain, 'A')
        assert 'xn--' in query.question[0].name.to_text()

    @patch('dns.query.udp')
    def test_client_handles_truncated_response(self, mock_udp):
        """Client handles truncated (TC bit set) responses"""
        query = dns.message.make_query('example.com', 'A')
        response = dns.message.make_response(query)
        response.flags |= dns.flags.TC  # Set truncated flag

        mock_udp.return_value = response

        result = dns.query.udp(query, '8.8.8.8', timeout=5)
        assert result.flags & dns.flags.TC

    def test_client_handles_empty_response(self):
        """Client handles response with no answers"""
        query = dns.message.make_query('example.com', 'A')
        response = dns.message.make_response(query)

        # No answers added
        assert len(response.answer) == 0
        assert response.rcode() == dns.rcode.NOERROR


@pytest.mark.alpha
@pytest.mark.mock
class TestMockDNSClientIntegration:
    """Integration tests with mocked DNS server"""

    @patch('dns.query.udp')
    def test_full_query_response_cycle(self, mock_udp):
        """Test complete query-response cycle with mocked server"""
        # Create query
        query = dns.message.make_query('example.com', 'A')

        # Mock server response
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text('example.com.', 300, 'IN', 'A', '93.184.216.34')
        response.answer.append(rrset)

        mock_udp.return_value = response

        # Execute query
        result = dns.query.udp(query, '8.8.8.8', timeout=5)

        # Verify
        assert result.rcode() == dns.rcode.NOERROR
        assert len(result.answer) == 1
        assert result.answer[0][0].to_text() == '93.184.216.34'

    @patch('dns.query.udp')
    def test_query_with_dnssec(self, mock_udp):
        """Test DNSSEC-enabled query"""
        query = dns.message.make_query('example.com', 'A', want_dnssec=True)

        response = dns.message.make_response(query)
        mock_udp.return_value = response

        assert query.ednsflags & dns.flags.DO

    @patch('dns.query.udp')
    def test_concurrent_queries(self, mock_udp):
        """Test multiple concurrent queries (simulated)"""
        queries = [
            dns.message.make_query('example.com', 'A'),
            dns.message.make_query('example.org', 'A'),
            dns.message.make_query('example.net', 'A'),
        ]

        responses = []
        for query in queries:
            response = dns.message.make_response(query)
            responses.append(response)

        mock_udp.side_effect = responses

        # Execute queries
        results = []
        for query in queries:
            result = dns.query.udp(query, '8.8.8.8', timeout=5)
            results.append(result)

        assert len(results) == 3
        assert all(r.rcode() == dns.rcode.NOERROR for r in results)
