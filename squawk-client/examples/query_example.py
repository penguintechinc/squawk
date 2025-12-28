#!/usr/bin/env python3
"""
Squawk DNS Client Query Examples

This script demonstrates how to use the Squawk DNS client for:
1. Single DNS queries via gRPC
2. Batch DNS queries via gRPC
3. Health checks
4. Fallback to REST DNS-over-HTTPS
"""

import sys
import os
import json
from pathlib import Path

# Add parent directory to path to import client module
sys.path.insert(0, str(Path(__file__).parent.parent / 'bins'))

from client import SquawkDNSGrpcClient, DNSOverHTTPSClient


def example_grpc_single_query():
    """Example: Single DNS query using gRPC"""
    print("Example 1: Single gRPC DNS Query")
    print("=" * 50)

    # Create gRPC client (will fallback to REST if gRPC unavailable)
    client = SquawkDNSGrpcClient(
        server_url='grpc://localhost:50052',
        token=os.getenv('SQUAWK_AUTH_TOKEN', ''),
        use_grpc=True
    )

    try:
        # Query a domain
        result = client.query('example.com', 'A')
        print(f"Query: example.com (type: A)")
        print(f"Response Status: {result['Status']}")

        if result['Answer']:
            print("Answers:")
            for answer in result['Answer']:
                print(f"  {answer['name']} -> {answer['data']} (TTL: {answer['TTL']})")
        else:
            print("No answers found")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.close()

    print()


def example_grpc_batch_query():
    """Example: Batch DNS queries using gRPC"""
    print("Example 2: Batch gRPC DNS Queries")
    print("=" * 50)

    client = SquawkDNSGrpcClient(
        server_url='grpc://localhost:50052',
        token=os.getenv('SQUAWK_AUTH_TOKEN', ''),
        use_grpc=True
    )

    try:
        # Batch query multiple domains
        domains = ['google.com', 'github.com', 'cloudflare.com', 'example.com']
        results = client.batch_query(domains, record_type='A', max_concurrent=10)

        print(f"Batch querying {len(domains)} domains...")
        for domain, result in zip(domains, results):
            if result['Answer']:
                ip = result['Answer'][0]['data']
                print(f"  {domain} -> {ip}")
            else:
                print(f"  {domain} -> No answer")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.close()

    print()


def example_health_check():
    """Example: Health check of DNS server"""
    print("Example 3: DNS Server Health Check")
    print("=" * 50)

    client = SquawkDNSGrpcClient(
        server_url='grpc://localhost:50052',
        token=os.getenv('SQUAWK_AUTH_TOKEN', '')
    )

    try:
        health = client.health_check()
        print(f"Server Status: {health['status']}")

        if health['status'] == 'serving':
            print("DNS server is healthy and responding")
        elif health['status'] == 'not_serving':
            print("DNS server is not serving")
        else:
            print(f"Server status: {health['status']}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.close()

    print()


def example_rest_fallback():
    """Example: Using REST DNS-over-HTTPS as fallback"""
    print("Example 4: REST DNS-over-HTTPS Fallback")
    print("=" * 50)

    # Create REST client directly
    client = DNSOverHTTPSClient(
        dns_server_url='https://localhost:8443/dns/query',
        auth_token=os.getenv('SQUAWK_AUTH_TOKEN', '')
    )

    try:
        result = client.query('example.com', 'A')
        print(f"Query: example.com (type: A)")
        print(f"Response Status: {result['Status']}")

        if result.get('Answer'):
            print("Answers:")
            for answer in result['Answer']:
                print(f"  {answer['name']} -> {answer['data']}")

    except Exception as e:
        print(f"Error: {e}")

    print()


def example_multiple_record_types():
    """Example: Query different DNS record types"""
    print("Example 5: Multiple Record Types")
    print("=" * 50)

    client = SquawkDNSGrpcClient(
        server_url='grpc://localhost:50052',
        token=os.getenv('SQUAWK_AUTH_TOKEN', '')
    )

    try:
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS']
        domain = 'example.com'

        for record_type in record_types:
            try:
                result = client.query(domain, record_type)
                print(f"{domain} ({record_type}):")

                if result['Answer']:
                    for answer in result['Answer']:
                        print(f"  {answer['data']}")
                else:
                    print(f"  No {record_type} records found")
            except Exception as e:
                print(f"  Error: {e}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.close()

    print()


def example_error_handling():
    """Example: Error handling and fallback logic"""
    print("Example 6: Error Handling and Fallback")
    print("=" * 50)

    # Try gRPC first, but provide graceful fallback
    client = SquawkDNSGrpcClient(
        server_url='grpc://nonexistent.example.com:50052',
        token=os.getenv('SQUAWK_AUTH_TOKEN', ''),
        use_grpc=True
    )

    try:
        result = client.query('example.com', 'A')
        print(f"Successfully queried: {result}")
    except Exception as e:
        print(f"Query failed: {e}")
        print("This would normally trigger fallback to REST client")

    client.close()

    print()


if __name__ == '__main__':
    print("Squawk DNS Client Examples")
    print("=" * 50)
    print()

    # Check if server is available
    print("Note: These examples assume:")
    print("  - gRPC server running on localhost:50052")
    print("  - REST server running on https://localhost:8443/dns/query")
    print("  - SQUAWK_AUTH_TOKEN environment variable (optional)")
    print()

    # Run examples
    example_grpc_single_query()
    example_grpc_batch_query()
    example_health_check()
    example_rest_fallback()
    example_multiple_record_types()
    example_error_handling()

    print("Examples completed!")
