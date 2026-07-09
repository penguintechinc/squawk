#!/usr/bin/env python3

import requests
import json
import sys
import getopt
import socket
import threading
import logging
import yaml
import os
import ssl
import ipaddress
import re
from urllib.parse import urlparse
import time

# gRPC imports (optional)
try:
    import grpc
    from concurrent import futures

    GRPC_AVAILABLE = True
except ImportError:
    GRPC_AVAILABLE = False

# Protobuf imports (optional)
try:
    from dns_query_service_pb2 import (
        QueryRequest,
        BatchQueryRequest,
        QueryResponse,
        HealthCheckRequest,
    )
    from dns_query_service_pb2_grpc import DNSQueryServiceStub

    PROTOBUF_AVAILABLE = True
except ImportError:
    PROTOBUF_AVAILABLE = False
    # Provide fallbacks so tests can mock
    DNSQueryServiceStub = None
    QueryRequest = None
    BatchQueryRequest = None
    QueryResponse = None
    HealthCheckRequest = None


class DNSOverHTTPSClient:
    # DNS label validation regex (RFC 1035)
    DNS_LABEL_REGEX = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")

    # Valid DNS record types
    VALID_RECORD_TYPES = {
        "A",
        "AAAA",
        "CNAME",
        "MX",
        "TXT",
        "NS",
        "SOA",
        "PTR",
        "SRV",
        "CAA",
        "DNSKEY",
        "DS",
        "NAPTR",
        "SSHFP",
        "TLSA",
        "ANY",
    }

    @staticmethod
    def validate_dns_name(domain):
        """Validate a DNS domain name according to RFC 1035"""
        if not domain:
            raise ValueError("DNS name cannot be empty")

        # Check overall length (max 253 characters)
        if len(domain) > 253:
            raise ValueError(f"DNS name too long: {len(domain)} characters (max 253)")

        # Remove trailing dot if present
        domain = domain.rstrip(".")

        # Check for invalid characters
        invalid_chars = set(" !@#$%^&*()+={}[]|\\:;\"'<>,?/`~")
        if any(c in invalid_chars for c in domain):
            raise ValueError("DNS name contains invalid characters")

        # Split into labels and validate each
        labels = domain.split(".")
        if not labels:
            raise ValueError("DNS name has no labels")

        for i, label in enumerate(labels):
            # Check label length (max 63 characters)
            if not label:
                raise ValueError(f"DNS name contains empty label at position {i}")
            if len(label) > 63:
                raise ValueError(f"DNS label '{label}' too long: {len(label)} characters (max 63)")

            # Special case: .arpa domains for reverse DNS
            if i == len(labels) - 1 and label == "arpa":
                continue

            # Check label format
            if not DNSOverHTTPSClient.DNS_LABEL_REGEX.match(label):
                # Special case for IDN/punycode domains
                if label.startswith("xn--"):
                    continue
                raise ValueError(
                    f"Invalid DNS label '{label}': must start/end with alphanumeric "
                    f"and contain only letters, digits, and hyphens"
                )

            # Check for consecutive hyphens (except in punycode)
            if "--" in label and not label.startswith("xn--"):
                raise ValueError(f"Invalid DNS label '{label}': contains consecutive hyphens")

        return True

    @staticmethod
    def validate_record_type(record_type):
        """Validate DNS record type"""
        record_type = record_type.upper()
        if record_type not in DNSOverHTTPSClient.VALID_RECORD_TYPES:
            raise ValueError(
                f"Invalid DNS record type '{record_type}': must be one of "
                f"{', '.join(sorted(DNSOverHTTPSClient.VALID_RECORD_TYPES))}"
            )
        return record_type

    @staticmethod
    def _validate_server_url(dns_server_url):
        """Validate that the server URL uses an IP address to prevent DNS loops"""
        if not dns_server_url:
            raise ValueError("DNS server URL cannot be empty")

        try:
            parsed_url = urlparse(dns_server_url)
        except Exception as e:
            raise ValueError(f"Invalid DNS server URL format: {e}")

        if parsed_url.scheme not in ["http", "https"]:
            raise ValueError(f"DNS server URL must use http or https scheme, got: {parsed_url.scheme}")

        if not parsed_url.hostname:
            raise ValueError("DNS server URL must include a hostname")

        host = parsed_url.hostname.lower()

        # Try to parse as IP address
        try:
            ipaddress.ip_address(host)
            return  # Valid IP address
        except ValueError:
            pass  # Not an IP address, continue with hostname checks

        # Special case: allow localhost for development
        if host == "localhost":
            return

        # Special case: allow well-known public DNS providers
        allowed_hosts = [
            "dns.google",
            "dns.google.com",  # Legacy Google DNS domain
            "cloudflare-dns.com",
            "1.1.1.1",  # Cloudflare primary
            "1.0.0.1",  # Cloudflare secondary
            "dns.quad9.net",
            "dns.opendns.com",
            "doh.opendns.com",
            "dns.nextdns.io",
            "doh.cleanbrowsing.org",
        ]

        # Check if host matches or is subdomain of allowed hosts
        for allowed in allowed_hosts:
            if host == allowed or host.startswith(allowed + "."):
                # Don't show warning for major public DNS providers
                if "google" not in host and "cloudflare" not in host and host not in ["1.1.1.1", "1.0.0.1"]:
                    print(f"INFO: Using public DNS provider '{host}'")
                return

        raise ValueError(
            f"DNS server URL must use an IP address (not hostname '{host}') to prevent DNS resolution loops. Use the IP address of your DNS server instead"
        )

    @staticmethod
    def _normalize_server_url(server_url):
        """Normalize URLs for known public DNS providers"""
        parsed_url = urlparse(server_url)
        host = parsed_url.hostname.lower() if parsed_url.hostname else ""

        # Google DNS - ensure correct path
        if "dns.google" in host:
            if not parsed_url.path or parsed_url.path == "/":
                parsed_url = parsed_url._replace(path="/resolve")

        # Cloudflare DNS - ensure correct path
        elif "cloudflare" in host or host in ["1.1.1.1", "1.0.0.1"]:
            if not parsed_url.path or parsed_url.path == "/":
                parsed_url = parsed_url._replace(path="/dns-query")

        # Quad9 DNS
        elif "dns.quad9.net" in host:
            if not parsed_url.path or parsed_url.path == "/":
                parsed_url = parsed_url._replace(path="/dns-query")

        return parsed_url.geturl()

    def __init__(
        self,
        dns_server_url="https://dns.google/dns-query",
        auth_token=None,
        client_cert=None,
        client_key=None,
        ca_cert=None,
        verify_ssl=True,
        dns_server_urls=None,
        max_retries=None,
        retry_delay=2,
    ):
        # Handle multiple server URLs
        if dns_server_urls and isinstance(dns_server_urls, list):
            self.dns_server_urls = dns_server_urls
        elif dns_server_url:
            self.dns_server_urls = [dns_server_url]
        else:
            raise ValueError("Must provide either dns_server_url or dns_server_urls")

        # Validate and normalize all server URLs
        normalized_urls = []
        for i, url in enumerate(self.dns_server_urls):
            try:
                self._validate_server_url(url)
                normalized_urls.append(self._normalize_server_url(url))
            except ValueError as e:
                raise ValueError(f"Invalid server URL at index {i}: {e}")
        self.dns_server_urls = normalized_urls

        # Legacy support
        self.dns_server_url = self.dns_server_urls[0]

        self.auth_token = auth_token
        self.client_cert = client_cert
        self.client_key = client_key
        self.ca_cert = ca_cert
        self.verify_ssl = verify_ssl

        # Failover configuration
        self.max_retries = max_retries if max_retries is not None else len(self.dns_server_urls) * 2
        self.retry_delay = retry_delay
        self.current_server_index = 0

        # Create requests session with mTLS support
        self.session = requests.Session()
        self._configure_ssl()

    def _configure_ssl(self):
        """Configure SSL settings for the session"""
        # Configure certificate verification
        if self.ca_cert and os.path.exists(self.ca_cert):
            # Use custom CA bundle
            self.session.verify = self.ca_cert
        elif self.verify_ssl:
            # TLS verification enabled (default and recommended)
            self.session.verify = True
        else:
            # TLS verification explicitly disabled - log prominent warning
            self.session.verify = False
            logging.warning(
                "TLS VERIFICATION DISABLED: SSL/TLS certificate verification is disabled. "
                "This is insecure and should only be used for development/testing. "
                "To enable verification, set SQUAWK_VERIFY_SSL=true or use --verify flag."
            )

        # Configure client certificate for mTLS
        if self.client_cert and self.client_key:
            if os.path.exists(self.client_cert) and os.path.exists(self.client_key):
                self.session.cert = (self.client_cert, self.client_key)
                logging.info(f"mTLS enabled with client certificate: {self.client_cert}")
            else:
                logging.warning("Client certificate or key file not found, mTLS disabled")
        elif self.client_cert and os.path.exists(self.client_cert):
            # Single file containing both cert and key
            self.session.cert = self.client_cert
            logging.info(f"mTLS enabled with combined certificate file: {self.client_cert}")

    def _next_server(self):
        """Advance to the next server in the list (round-robin)"""
        self.current_server_index = (self.current_server_index + 1) % len(self.dns_server_urls)

    def query(self, domain, record_type="A"):
        """Query DNS using failover logic across multiple servers"""
        # Validate domain name
        try:
            self.validate_dns_name(domain)
        except ValueError as e:
            logging.error(f"Invalid domain name: {e}")
            raise

        # Validate and normalize record type
        try:
            record_type = self.validate_record_type(record_type)
        except ValueError as e:
            logging.error(f"Invalid record type: {e}")
            raise

        params = {"name": domain, "type": record_type}
        headers = {"Accept": "application/dns-json"}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        last_error = None
        errors = []

        # Try each server with retry logic
        for attempt in range(self.max_retries):
            current_server = self.dns_server_urls[self.current_server_index]

            try:
                response = self.session.get(current_server, headers=headers, params=params, timeout=30)
                if response.status_code == 200:
                    return response.json()
                else:
                    error_msg = f"HTTP {response.status_code} from {current_server}: {response.text}"
                    last_error = error_msg
                    errors.append(error_msg)
                    logging.warning(error_msg)

            except requests.exceptions.SSLError as e:
                error_msg = f"SSL Error for {current_server}: {e}"
                last_error = error_msg
                errors.append(error_msg)
                logging.warning(error_msg)

            except requests.exceptions.RequestException as e:
                error_msg = f"Request Error for {current_server}: {e}"
                last_error = error_msg
                errors.append(error_msg)
                logging.warning(error_msg)

            # Move to next server
            self._next_server()

            # Add delay between retries (except for the last attempt)
            if attempt < self.max_retries - 1:
                import time

                time.sleep(self.retry_delay)

        # All servers failed
        error_summary = f"All {len(self.dns_server_urls)} DNS servers failed after {self.max_retries} attempts"
        if len(errors) > 1:
            error_summary += f": {'; '.join(errors)}"
        else:
            error_summary += f": {last_error}" if last_error else ""

        logging.error(error_summary)
        raise Exception(error_summary)


class SquawkDNSGrpcClient:
    """gRPC DNS Query Client for Squawk DNS Server"""

    def __init__(self, server_url, token=None, use_grpc=True, timeout=30, verify_ssl=True, ca_cert=None):
        """
        Initialize gRPC DNS client

        Args:
            server_url: Server address (grpc://host:port or https://host:port)
            token: Optional authentication token
            use_grpc: Whether to use gRPC (if False, falls back to REST)
            timeout: Request timeout in seconds
            verify_ssl: Verify the server TLS certificate (default True)
            ca_cert: Optional path to a CA bundle for TLS verification
        """
        self.server_url = server_url
        self.token = token
        self.use_grpc = use_grpc and GRPC_AVAILABLE and PROTOBUF_AVAILABLE
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.ca_cert = ca_cert
        self.channel = None
        self.stub = None
        self.rest_client = None

        if self.use_grpc:
            self._init_grpc()
        else:
            self._init_rest()

    def _init_grpc(self):
        """Initialize gRPC connection"""
        if not GRPC_AVAILABLE or not PROTOBUF_AVAILABLE:
            logging.warning("gRPC not available, falling back to REST")
            self.use_grpc = False
            self._init_rest()
            return

        try:
            # Extract host and port from server_url
            parsed_url = urlparse(self.server_url.replace("grpc://", "http://"))
            host = parsed_url.hostname or "localhost"
            port = parsed_url.port or 50052

            target = f"{host}:{port}"
            logging.debug(f"Connecting to gRPC server at {target}")

            # Create gRPC channel. Loopback targets may use a plaintext channel
            # for local development; every other target MUST use TLS so the bearer
            # token is never transmitted in the clear. The token is attached as
            # per-call credentials, which gRPC only permits over a secure channel.
            is_loopback = host in ("localhost", "127.0.0.1", "::1") or host.startswith("127.")
            if is_loopback:
                self.channel = grpc.insecure_channel(target)
            else:
                if self.ca_cert:
                    with open(self.ca_cert, "rb") as ca:
                        ssl_creds = grpc.ssl_channel_credentials(root_certificates=ca.read())
                else:
                    ssl_creds = grpc.ssl_channel_credentials()
                if self.token:
                    call_creds = grpc.access_token_call_credentials(self.token)
                    channel_creds = grpc.composite_channel_credentials(ssl_creds, call_creds)
                else:
                    channel_creds = ssl_creds
                self.channel = grpc.secure_channel(target, channel_creds)
            self.stub = DNSQueryServiceStub(self.channel)
            logging.info(f"gRPC client initialized for {target} (tls={not is_loopback})")
        except Exception as e:
            logging.warning(f"Failed to initialize gRPC: {e}, falling back to REST")
            self.use_grpc = False
            self._init_rest()

    def _init_rest(self):
        """Initialize REST client as fallback"""
        # Convert grpc:// to https:// if needed
        rest_url = self.server_url
        if rest_url.startswith("grpc://"):
            rest_url = rest_url.replace("grpc://", "https://", 1)
        elif rest_url.startswith("grpc:"):
            rest_url = rest_url.replace("grpc:", "https:", 1)

        self.rest_client = DNSOverHTTPSClient(dns_server_url=rest_url, auth_token=self.token)

    def query(self, domain, record_type="A"):
        """
        Query a single domain

        Args:
            domain: Domain name to query
            record_type: DNS record type (A, AAAA, CNAME, etc.)

        Returns:
            Query response as dict
        """
        if self.use_grpc:
            return self._query_grpc(domain, record_type)
        else:
            return self._query_rest(domain, record_type)

    def _query_grpc(self, domain, record_type="A"):
        """Execute gRPC query"""
        try:
            request = QueryRequest(name=domain, type=record_type, token=self.token or "")

            # Token travels as channel call-credentials over TLS (see _init_grpc)
            # and in the request body for the loopback plaintext case.
            response = self.stub.Query(request, timeout=self.timeout)

            return self._convert_grpc_response(response)
        except grpc.RpcError as e:
            logging.error(f"gRPC query failed: {e.code()} - {e.details()}")
            raise Exception(f"gRPC query failed: {e.details()}")
        except Exception as e:
            logging.error(f"Unexpected error in gRPC query: {e}")
            raise

    def _query_rest(self, domain, record_type="A"):
        """Execute REST query as fallback"""
        if self.rest_client:
            return self.rest_client.query(domain, record_type)
        else:
            raise Exception("No REST client available")

    def batch_query(self, domains, record_type="A", max_concurrent=10):
        """
        Query multiple domains efficiently

        Args:
            domains: List of domain names
            record_type: DNS record type for all queries
            max_concurrent: Maximum concurrent gRPC streams

        Returns:
            List of query responses
        """
        if not self.use_grpc:
            # Fallback: sequential REST queries
            logging.warning("Batch queries require gRPC, falling back to sequential REST queries")
            return [self._query_rest(domain, record_type) for domain in domains]

        try:
            queries = [QueryRequest(name=d, type=record_type, token=self.token or "") for d in domains]

            request = BatchQueryRequest(queries=queries, max_concurrent=max_concurrent)

            response = self.stub.BatchQuery(request, timeout=self.timeout * len(domains) // 10 + 30)

            return [self._convert_grpc_response(r) for r in response.responses]
        except grpc.RpcError as e:
            logging.error(f"gRPC batch query failed: {e.code()} - {e.details()}")
            raise Exception(f"gRPC batch query failed: {e.details()}")

    def health_check(self):
        """Check if DNS server is healthy"""
        if not self.use_grpc:
            logging.warning("Health check requires gRPC")
            return {"status": "unknown"}

        try:
            request = HealthCheckRequest(service="dns")
            response = self.stub.HealthCheck(request, timeout=self.timeout)

            status_map = {
                0: "unknown",
                1: "serving",
                2: "not_serving",
                3: "service_unknown",
            }

            return {
                "status": status_map.get(response.status, "unknown"),
                "timestamp": time.time(),
            }
        except Exception as e:
            logging.warning(f"Health check failed: {e}")
            return {"status": "unhealthy", "error": str(e)}

    @staticmethod
    def _convert_grpc_response(grpc_response):
        """Convert gRPC response to JSON-like dict"""
        answers = []
        for answer in grpc_response.answers:
            answers.append(
                {
                    "name": answer.name,
                    "type": answer.type,
                    "TTL": answer.ttl,
                    "data": answer.data,
                }
            )

        authority = []
        for auth in grpc_response.authority:
            authority.append(
                {
                    "name": auth.name,
                    "type": auth.type,
                    "TTL": auth.ttl,
                    "data": auth.data,
                }
            )

        additional = []
        for add in grpc_response.additional:
            additional.append({"name": add.name, "type": add.type, "TTL": add.ttl, "data": add.data})

        metadata = {}
        if grpc_response.metadata:
            metadata = {
                "timestamp": grpc_response.metadata.timestamp,
                "response_time_ms": grpc_response.metadata.response_time_ms,
                "from_cache": grpc_response.metadata.from_cache,
                "ioc_blocked": grpc_response.metadata.ioc_blocked,
                "server_id": grpc_response.metadata.server_id,
            }

        return {
            "Status": grpc_response.status,
            "Answer": answers,
            "Authority": authority,
            "Additional": additional,
            "Comment": f'Server ID: {metadata.get("server_id", "unknown")}',
            "metadata": metadata,
        }

    def close(self):
        """Close the gRPC channel"""
        if self.channel:
            self.channel.close()
            logging.debug("gRPC channel closed")


class DNSForwarder:
    def __init__(self, dns_client, udp_port=53, tcp_port=53, listen_udp=False, listen_tcp=False):
        self.dns_client = dns_client
        self.udp_port = udp_port
        self.tcp_port = tcp_port
        self.listen_udp = listen_udp
        self.listen_tcp = listen_tcp

    def start(self):
        threads = []
        if self.listen_udp:
            udp_thread = threading.Thread(target=self.start_udp_server)
            threads.append(udp_thread)
        if self.listen_tcp:
            tcp_thread = threading.Thread(target=self.start_tcp_server)
            threads.append(tcp_thread)

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    def start_udp_server(self):
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.bind(("127.0.0.1", self.udp_port))
        logging.debug(f"UDP server listening on 127.0.0.1:{self.udp_port}")
        while True:
            data, addr = udp_sock.recvfrom(512)
            response = self.handle_request(data)
            udp_sock.sendto(response, addr)

    def start_tcp_server(self):
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.bind(("127.0.0.1", self.tcp_port))
        tcp_sock.listen(5)
        logging.debug(f"TCP server listening on 127.0.0.1:{self.tcp_port}")
        while True:
            conn, addr = tcp_sock.accept()
            data = conn.recv(512)
            response = self.handle_request(data)
            conn.sendall(response)
            conn.close()

    def handle_request(self, data):
        domain = "example.com"  # Extract the domain from the DNS request
        record_type = "A"  # Extract the record type from the DNS request
        result = self.dns_client.query(domain, record_type)
        response = b""  # Create a proper DNS response
        return response


def load_config(config_file):
    with open(config_file, "r") as file:
        return yaml.safe_load(file)


def main(argv):
    logging.basicConfig(level=logging.DEBUG)

    domain = ""
    record_type = "A"
    dns_server_url = "https://dns.google/resolve"
    auth_token = None
    config_file = None
    listen_udp = False
    listen_tcp = False
    client_cert = None
    client_key = None
    ca_cert = None
    verify_ssl = True
    use_grpc = True
    batch_domains = None

    try:
        opts, args = getopt.getopt(
            argv,
            "hd:t:s:a:c:uTk:C:K:vgb:",
            [
                "domain=",
                "type=",
                "server=",
                "auth=",
                "config=",
                "udp",
                "tcp",
                "ca-cert=",
                "client-cert=",
                "client-key=",
                "verify",
                "grpc",
                "batch=",
                "no-grpc",
            ],
        )
    except getopt.GetoptError:
        print(
            "client.py -d <domain> -t <record_type> -s <dns_server_url> -a <auth_token> -c <config_file> [-u] [-T] [--ca-cert=<ca.crt>] [--client-cert=<client.crt>] [--client-key=<client.key>] [--verify] [--grpc] [--batch=<file>]"
        )
        sys.exit(2)
    for opt, arg in opts:
        if opt == "-h":
            logging.debug(
                "client.py -d <domain> -t <record_type> -s <dns_server_url> -a <auth_token> -c <config_file> [-u] [-T]"
            )
            sys.exit()
        elif opt in ("-d", "--domain"):
            domain = arg
        elif opt in ("-t", "--type"):
            record_type = arg
        elif opt in ("-s", "--server"):
            dns_server_url = arg
        elif opt in ("-a", "--auth"):
            auth_token = arg
        elif opt in ("-c", "--config"):
            config_file = arg
        elif opt in ("-u", "--udp"):
            listen_udp = True
        elif opt in ("-T", "--tcp"):
            listen_tcp = True
        elif opt in ("-k", "--ca-cert"):
            ca_cert = arg
        elif opt in ("-C", "--client-cert"):
            client_cert = arg
        elif opt in ("-K", "--client-key"):
            client_key = arg
        elif opt in ("-v", "--verify"):
            verify_ssl = True
        elif opt == "-g" or opt == "--grpc":
            use_grpc = True
        elif opt == "--no-grpc":
            use_grpc = False
        elif opt in ("-b", "--batch"):
            batch_domains = arg

    if config_file:
        config = load_config(config_file)
        domain = config.get("domain", domain)
        record_type = config.get("type", record_type)
        dns_server_url = config.get("server", dns_server_url)
        auth_token = config.get("auth", auth_token)
        client_cert = config.get("client_cert", client_cert)
        client_key = config.get("client_key", client_key)
        ca_cert = config.get("ca_cert", ca_cert)
        verify_ssl = config.get("verify_ssl", verify_ssl)

    # Check environment variables for all configuration options
    if not dns_server_url or dns_server_url == "https://dns.google/resolve":
        dns_server_url = os.getenv("SQUAWK_SERVER_URL", dns_server_url)
    if not auth_token:
        auth_token = os.getenv("SQUAWK_AUTH_TOKEN")
    if not client_cert:
        client_cert = os.getenv("SQUAWK_CLIENT_CERT", os.getenv("CLIENT_CERT_PATH"))
    if not client_key:
        client_key = os.getenv("SQUAWK_CLIENT_KEY", os.getenv("CLIENT_KEY_PATH"))
    if not ca_cert:
        ca_cert = os.getenv("SQUAWK_CA_CERT", os.getenv("CA_CERT_PATH"))

    # Additional environment variables
    if not domain:
        domain = os.getenv("SQUAWK_DOMAIN")
    if record_type == "A":
        record_type = os.getenv("SQUAWK_RECORD_TYPE", "A")

    # Override verify_ssl from environment if not explicitly set
    verify_ssl_env = os.getenv("SQUAWK_VERIFY_SSL", "").lower()
    if verify_ssl_env in ["true", "1", "yes"]:
        verify_ssl = True
    elif verify_ssl_env in ["false", "0", "no"]:
        verify_ssl = False

    if not domain and not batch_domains and not (listen_udp or listen_tcp):
        logging.debug("Domain is required. Use -d <domain> or -b <file> to specify domains.")
        sys.exit(2)

    # Try gRPC client first if enabled
    if use_grpc and (dns_server_url.startswith("grpc://") or dns_server_url.startswith("grpc:")):
        try:
            client = SquawkDNSGrpcClient(server_url=dns_server_url, token=auth_token, use_grpc=True)
            logging.info(f"Using gRPC client for {dns_server_url}")
        except Exception as e:
            logging.warning(f"Failed to create gRPC client: {e}, falling back to REST")
            client = DNSOverHTTPSClient(
                dns_server_url,
                auth_token,
                client_cert=client_cert,
                client_key=client_key,
                ca_cert=ca_cert,
                verify_ssl=verify_ssl,
            )
    else:
        client = DNSOverHTTPSClient(
            dns_server_url,
            auth_token,
            client_cert=client_cert,
            client_key=client_key,
            ca_cert=ca_cert,
            verify_ssl=verify_ssl,
        )

    # Handle batch queries
    if batch_domains:
        if os.path.isfile(batch_domains):
            with open(batch_domains, "r") as f:
                domains = [line.strip() for line in f if line.strip()]
            logging.info(f"Batch querying {len(domains)} domains from {batch_domains}")
            if isinstance(client, SquawkDNSGrpcClient):
                results = client.batch_query(domains, record_type)
            else:
                results = [client.query(d, record_type) for d in domains]
            for domain_name, result in zip(domains, results):
                print(f"{domain_name}: {json.dumps(result, indent=2)}")
        else:
            logging.error(f"Batch file not found: {batch_domains}")
            sys.exit(1)
    else:
        # Single domain query
        if domain:
            result = client.query(domain, record_type)
            logging.debug(json.dumps(result, indent=4))
            print(json.dumps(result, indent=2))

    # Only start forwarder if forwarding is enabled
    if listen_udp or listen_tcp:
        if isinstance(client, SquawkDNSGrpcClient):
            # Forwarder requires REST client
            logging.warning("DNS forwarding requires REST client, using REST instead")
            rest_client = DNSOverHTTPSClient(
                (
                    dns_server_url
                    if not dns_server_url.startswith("grpc")
                    else dns_server_url.replace("grpc://", "https://")
                ),
                auth_token,
                client_cert=client_cert,
                client_key=client_key,
                ca_cert=ca_cert,
                verify_ssl=verify_ssl,
            )
            forwarder = DNSForwarder(rest_client, listen_udp=listen_udp, listen_tcp=listen_tcp)
        else:
            forwarder = DNSForwarder(client, listen_udp=listen_udp, listen_tcp=listen_tcp)
        forwarder.start()


if __name__ == "__main__":
    main(sys.argv[1:])
