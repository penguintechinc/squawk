"""
Comprehensive test suite for DNS Client
Tests DNS queries, WHOIS lookups, batch operations, and gRPC with mocking
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import sys
import os
import requests.exceptions

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'bins'))

from client import DNSOverHTTPSClient, SquawkDNSGrpcClient, DNSForwarder


class TestDNSOverHTTPSClient:
    """Test DNS-over-HTTPS client"""
    
    @patch('client.requests.Session')
    def test_client_initialization(self, mock_session):
        """Test client initialization"""
        client = DNSOverHTTPSClient(
            dns_server_url='https://dns.google/resolve',
            auth_token='test-token'
        )
        
        assert client.dns_server_url == 'https://dns.google/resolve'
        assert client.auth_token == 'test-token'
    
    @patch('client.requests.Session')
    def test_query_success(self, mock_session):
        """Test successful DNS query"""
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'Status': 0,
            'Answer': [{'name': 'example.com', 'type': 1, 'data': '93.184.216.34'}]
        }
        
        mock_session_instance = Mock()
        mock_session_instance.get.return_value = mock_response
        mock_session.return_value = mock_session_instance
        
        client = DNSOverHTTPSClient(dns_server_url='https://dns.google/resolve')
        result = client.query('example.com', 'A')
        
        assert result['Status'] == 0
        assert len(result['Answer']) > 0
    
    @patch('client.requests.Session')
    def test_query_with_auth_token(self, mock_session):
        """Test DNS query with authentication token"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'Status': 0, 'Answer': []}
        
        mock_session_instance = Mock()
        mock_session_instance.get.return_value = mock_response
        mock_session.return_value = mock_session_instance
        
        client = DNSOverHTTPSClient(
            dns_server_url='https://dns.google/resolve',
            auth_token='test-token-123'
        )
        client.query('example.com', 'A')
        
        # Verify auth header was sent
        call_args = mock_session_instance.get.call_args
        assert 'headers' in call_args[1]
        assert 'Authorization' in call_args[1]['headers']
    
    @patch('client.requests.Session')
    def test_query_failover(self, mock_session):
        """Test failover to secondary server"""
        # First server fails, second succeeds
        mock_fail_response = Mock()
        mock_fail_response.status_code = 500

        mock_success_response = Mock()
        mock_success_response.status_code = 200
        mock_success_response.json.return_value = {'Status': 0, 'Answer': []}

        mock_session_instance = Mock()
        mock_session_instance.get.side_effect = [
            requests.exceptions.RequestException("Connection failed"),
            mock_success_response
        ]
        mock_session.return_value = mock_session_instance

        client = DNSOverHTTPSClient(
            dns_server_urls=[
                'https://127.0.0.1:8053/resolve',
                'https://127.0.0.2:8053/resolve'
            ]
        )

        result = client.query('example.com', 'A')
        assert result['Status'] == 0
    
    def test_domain_validation(self):
        """Test domain name validation"""
        # Valid domains
        assert DNSOverHTTPSClient.validate_dns_name('example.com') == True
        assert DNSOverHTTPSClient.validate_dns_name('sub.example.com') == True
        assert DNSOverHTTPSClient.validate_dns_name('example.co.uk') == True
        
        # Invalid domains
        with pytest.raises(ValueError):
            DNSOverHTTPSClient.validate_dns_name('')
        
        with pytest.raises(ValueError):
            DNSOverHTTPSClient.validate_dns_name('invalid domain.com')
        
        with pytest.raises(ValueError):
            DNSOverHTTPSClient.validate_dns_name('a' * 300)  # Too long
    
    def test_record_type_validation(self):
        """Test DNS record type validation"""
        # Valid types
        assert DNSOverHTTPSClient.validate_record_type('A') == 'A'
        assert DNSOverHTTPSClient.validate_record_type('AAAA') == 'AAAA'
        assert DNSOverHTTPSClient.validate_record_type('mx') == 'MX'  # Case insensitive
        
        # Invalid type
        with pytest.raises(ValueError):
            DNSOverHTTPSClient.validate_record_type('INVALID')


class TestSquawkDNSGrpcClient:
    """Test gRPC DNS client"""

    @patch('client.PROTOBUF_AVAILABLE', True)
    @patch('client.GRPC_AVAILABLE', True)
    @patch('client.grpc.insecure_channel')
    @patch('client.DNSQueryServiceStub')
    def test_grpc_client_initialization(self, mock_stub, mock_channel):
        """Test gRPC client initialization"""
        client = SquawkDNSGrpcClient(
            server_url='grpc://localhost:50052',
            token='test-token'
        )

        assert client.server_url == 'grpc://localhost:50052'
        assert client.token == 'test-token'

    @patch('client.PROTOBUF_AVAILABLE', True)
    @patch('client.GRPC_AVAILABLE', True)
    @patch('client.QueryRequest')
    @patch('client.grpc.insecure_channel')
    @patch('client.DNSQueryServiceStub')
    def test_grpc_query(self, mock_stub, mock_channel, mock_query_request):
        """Test gRPC DNS query"""
        # Mock gRPC response
        mock_response = Mock()
        mock_response.status = 0
        mock_response.answers = []
        mock_response.authority = []
        mock_response.additional = []
        mock_response.metadata = Mock(
            timestamp='2024-01-01T00:00:00',
            response_time_ms=10.5,
            from_cache=False,
            ioc_blocked=False,
            server_id='server-1'
        )

        mock_stub_instance = Mock()
        mock_stub_instance.Query.return_value = mock_response
        mock_stub.return_value = mock_stub_instance

        client = SquawkDNSGrpcClient(
            server_url='grpc://localhost:50052',
            use_grpc=True
        )

        result = client.query('example.com', 'A')
        assert result['Status'] == 0

    @patch('client.PROTOBUF_AVAILABLE', True)
    @patch('client.GRPC_AVAILABLE', True)
    @patch('client.BatchQueryRequest')
    @patch('client.QueryRequest')
    @patch('client.grpc.insecure_channel')
    @patch('client.DNSQueryServiceStub')
    def test_grpc_batch_query(self, mock_stub, mock_channel, mock_query_request, mock_batch_query_request):
        """Test gRPC batch query"""
        mock_response = Mock()
        mock_response.responses = []

        mock_stub_instance = Mock()
        mock_stub_instance.BatchQuery.return_value = mock_response
        mock_stub.return_value = mock_stub_instance

        client = SquawkDNSGrpcClient(
            server_url='grpc://localhost:50052',
            use_grpc=True
        )

        domains = ['example1.com', 'example2.com', 'example3.com']
        results = client.batch_query(domains, 'A')

        assert isinstance(results, list)

    @patch('client.PROTOBUF_AVAILABLE', True)
    @patch('client.GRPC_AVAILABLE', True)
    @patch('client.HealthCheckRequest')
    @patch('client.grpc.insecure_channel')
    @patch('client.DNSQueryServiceStub')
    def test_grpc_health_check(self, mock_stub, mock_channel, mock_health_request):
        """Test gRPC health check"""
        mock_response = Mock()
        mock_response.status = 1  # SERVING

        mock_stub_instance = Mock()
        mock_stub_instance.HealthCheck.return_value = mock_response
        mock_stub.return_value = mock_stub_instance

        client = SquawkDNSGrpcClient(
            server_url='grpc://localhost:50052',
            use_grpc=True
        )

        health = client.health_check()
        assert health['status'] == 'serving'


class TestDNSForwarder:
    """Test DNS forwarder"""
    
    @patch('client.DNSOverHTTPSClient')
    def test_forwarder_initialization(self, mock_client):
        """Test DNS forwarder initialization"""
        forwarder = DNSForwarder(
            dns_client=mock_client,
            udp_port=5353,
            tcp_port=5353,
            listen_udp=True,
            listen_tcp=False
        )
        
        assert forwarder.udp_port == 5353
        assert forwarder.tcp_port == 5353
        assert forwarder.listen_udp == True
        assert forwarder.listen_tcp == False


class TestClientIntegration:
    """Integration tests for client operations"""
    
    @patch('client.requests.Session')
    def test_multiple_queries(self, mock_session):
        """Test multiple sequential queries"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'Status': 0, 'Answer': []}
        
        mock_session_instance = Mock()
        mock_session_instance.get.return_value = mock_response
        mock_session.return_value = mock_session_instance
        
        client = DNSOverHTTPSClient(dns_server_url='https://dns.google/resolve')
        
        domains = ['example1.com', 'example2.com', 'example3.com']
        for domain in domains:
            result = client.query(domain, 'A')
            assert result['Status'] == 0
    
    @patch('client.requests.Session')
    def test_different_record_types(self, mock_session):
        """Test queries for different record types"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'Status': 0, 'Answer': []}
        
        mock_session_instance = Mock()
        mock_session_instance.get.return_value = mock_response
        mock_session.return_value = mock_session_instance
        
        client = DNSOverHTTPSClient(dns_server_url='https://dns.google/resolve')
        
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'CNAME']
        for record_type in record_types:
            result = client.query('example.com', record_type)
            assert result['Status'] == 0
