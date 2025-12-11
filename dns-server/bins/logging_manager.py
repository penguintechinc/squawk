#!/usr/bin/env python3
"""
Logging Manager for Squawk DNS Server
Handles request logging, client IP detection, and syslog forwarding
"""

import os
import sys
import json
import socket
import logging
import logging.handlers
from datetime import datetime
from typing import Optional, Dict, Any
import asyncio
import re


class ClientIPExtractor:
    """Extract real client IP from various headers"""

    def __init__(self):
        # Trusted proxy IP ranges (configurable via environment)
        self.trusted_proxies = self._parse_trusted_proxies()

    def _parse_trusted_proxies(self) -> list:
        """Parse trusted proxy ranges from environment"""
        trusted = os.getenv(
            "TRUSTED_PROXIES", "127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
        )
        proxies = []

        for proxy_range in trusted.split(","):
            proxy_range = proxy_range.strip()
            if proxy_range:
                proxies.append(proxy_range)

        return proxies

    def _is_trusted_proxy(self, ip: str) -> bool:
        """Check if IP is in trusted proxy ranges"""
        try:
            import ipaddress

            client_ip = ipaddress.ip_address(ip)

            for proxy_range in self.trusted_proxies:
                try:
                    if "/" in proxy_range:
                        # CIDR notation
                        if client_ip in ipaddress.ip_network(proxy_range, strict=False):
                            return True
                    else:
                        # Single IP
                        if client_ip == ipaddress.ip_address(proxy_range):
                            return True
                except:
                    continue

            return False
        except:
            return False

    def extract_real_ip(self, request) -> str:
        """Extract real client IP from request headers"""
        # Get the direct connection IP
        direct_ip = getattr(request, "remote_addr", None) or request.environ.get(
            "REMOTE_ADDR", "unknown"
        )

        # If direct IP is not trusted, use it
        if not self._is_trusted_proxy(direct_ip):
            return direct_ip

        # Check various forwarding headers in order of preference
        forwarding_headers = [
            "CF-Connecting-IP",  # Cloudflare
            "True-Client-IP",  # Cloudflare Enterprise
            "X-Real-IP",  # Nginx
            "X-Forwarded-For",  # Standard
            "X-Client-IP",  # Apache
            "X-Cluster-Client-IP",  # Load balancers
            "Forwarded-For",  # RFC 7239
            "Forwarded",  # RFC 7239
        ]

        for header in forwarding_headers:
            value = request.headers.get(header)
            if value:
                # Handle comma-separated IPs (X-Forwarded-For can have multiple)
                if header in ["X-Forwarded-For", "Forwarded-For"]:
                    ips = [ip.strip() for ip in value.split(",")]
                    # Return the first non-trusted proxy IP
                    for ip in ips:
                        if ip and not self._is_trusted_proxy(ip):
                            return self._clean_ip(ip)
                elif header == "Forwarded":
                    # RFC 7239 format: for=192.0.2.60;proto=http;by=203.0.113.43
                    match = re.search(r"for=([^;,\s]+)", value)
                    if match:
                        ip = match.group(1).strip('"[]')
                        if not self._is_trusted_proxy(ip):
                            return self._clean_ip(ip)
                else:
                    # Single IP headers
                    ip = self._clean_ip(value)
                    if ip and not self._is_trusted_proxy(ip):
                        return ip

        # Fallback to direct IP
        return direct_ip

    def _clean_ip(self, ip: str) -> str:
        """Clean and validate IP address"""
        # Remove quotes and brackets
        ip = ip.strip('"[]')

        # Handle IPv6 with port (e.g., [::1]:8080)
        if ":" in ip and not ip.count(":") == 1:
            # Likely IPv6
            if ip.startswith("[") and "]:" in ip:
                ip = ip.split("]:")[0][1:]
        else:
            # Handle IPv4 with port
            if ":" in ip:
                ip = ip.split(":")[0]

        return ip.strip()


class SyslogHandler:
    """UDP Syslog handler for remote logging"""

    def __init__(self, host: str, port: int = 514, facility: int = 16):
        self.host = host
        self.port = port
        self.facility = facility  # Local use facility
        self.socket = None
        self._setup_socket()

    def _setup_socket(self):
        """Setup UDP socket for syslog"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except Exception as e:
            logging.error(f"Failed to create syslog socket: {e}")

    def send(self, message: str, severity: int = 6):
        """Send message to syslog server"""
        if not self.socket:
            return False

        try:
            # Calculate priority (facility * 8 + severity)
            priority = self.facility * 8 + severity

            # Format syslog message (RFC 3164)
            timestamp = datetime.now().strftime("%b %d %H:%M:%S")
            hostname = socket.gethostname()
            tag = "squawk-dns"

            syslog_msg = f"<{priority}>{timestamp} {hostname} {tag}: {message}"

            # Ensure message is not too long (max 1024 bytes for UDP)
            if len(syslog_msg.encode()) > 1024:
                syslog_msg = syslog_msg[:1020] + "..."

            self.socket.sendto(syslog_msg.encode(), (self.host, self.port))
            return True

        except Exception as e:
            logging.error(f"Failed to send syslog message: {e}")
            return False

    def close(self):
        """Close syslog connection"""
        if self.socket:
            self.socket.close()


class DNSRequestLogger:
    """Comprehensive DNS request logger"""

    def __init__(self):
        self.ip_extractor = ClientIPExtractor()
        self.syslog_handler = None
        self.local_logger = None

        # Configuration
        self.log_level = getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper())
        self.log_format = os.getenv("LOG_FORMAT", "json")  # json or text
        self.log_file = os.getenv("LOG_FILE", "")
        self.enable_syslog = os.getenv("ENABLE_SYSLOG", "false").lower() == "true"
        self.syslog_host = os.getenv("SYSLOG_HOST", "localhost")
        self.syslog_port = int(os.getenv("SYSLOG_PORT", "514"))
        self.syslog_facility = int(os.getenv("SYSLOG_FACILITY", "16"))

        self._setup_logging()

    def _setup_logging(self):
        """Setup local and remote logging"""
        # Setup local logger
        self.local_logger = logging.getLogger("squawk.dns.requests")
        self.local_logger.setLevel(self.log_level)

        # Remove existing handlers
        for handler in self.local_logger.handlers[:]:
            self.local_logger.removeHandler(handler)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(self.log_level)

        # File handler if specified
        if self.log_file:
            try:
                file_handler = logging.FileHandler(self.log_file)
                file_handler.setLevel(self.log_level)

                if self.log_format == "json":
                    formatter = logging.Formatter("%(message)s")
                else:
                    formatter = logging.Formatter(
                        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
                    )

                file_handler.setFormatter(formatter)
                self.local_logger.addHandler(file_handler)
            except Exception as e:
                logging.error(f"Failed to setup file logging: {e}")

        # Console formatter
        if self.log_format == "json":
            console_formatter = logging.Formatter("%(message)s")
        else:
            console_formatter = logging.Formatter(
                "%(asctime)s - %(levelname)s - %(message)s"
            )
        console_handler.setFormatter(console_formatter)
        self.local_logger.addHandler(console_handler)

        # Setup syslog handler
        if self.enable_syslog and self.syslog_host:
            try:
                self.syslog_handler = SyslogHandler(
                    self.syslog_host, self.syslog_port, self.syslog_facility
                )
                logging.info(f"Syslog enabled: {self.syslog_host}:{self.syslog_port}")
            except Exception as e:
                logging.error(f"Failed to setup syslog: {e}")

    def log_dns_request(
        self,
        request,
        query_name: str,
        query_type: str,
        response_status: str,
        response_code: int,
        token: Optional[str] = None,
        client_cert: Optional[str] = None,
        processing_time: float = 0.0,
        response_size: int = 0,
        cache_hit: bool = False,
        blocked: bool = False,
    ):
        """Log a DNS request with full context"""

        # Extract client IP
        client_ip = self.ip_extractor.extract_real_ip(request)

        # Get additional request info
        user_agent = request.headers.get("User-Agent", "")
        request_id = request.headers.get("X-Request-ID", "")

        # Build log entry
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": "dns_query",
            "client_ip": client_ip,
            "query_name": query_name,
            "query_type": query_type,
            "response_status": response_status,
            "response_code": response_code,
            "processing_time_ms": round(processing_time * 1000, 2),
            "response_size_bytes": response_size,
            "cache_hit": cache_hit,
            "blocked": blocked,
            "user_agent": user_agent,
            "request_id": request_id,
        }

        # Add authentication info (sanitized)
        if token:
            log_entry["auth_token_prefix"] = (
                token[:8] + "..." if len(token) > 8 else "short"
            )
            log_entry["auth_method"] = "bearer_token"

        if client_cert:
            log_entry["client_cert_subject"] = client_cert
            log_entry["auth_method"] = log_entry.get("auth_method", "") + "+client_cert"

        # Add forwarding headers for debugging
        forwarding_headers = {}
        for header in [
            "X-Forwarded-For",
            "X-Real-IP",
            "CF-Connecting-IP",
            "True-Client-IP",
        ]:
            value = request.headers.get(header)
            if value:
                forwarding_headers[header.lower()] = value

        if forwarding_headers:
            log_entry["forwarding_headers"] = forwarding_headers

        # Log locally
        if self.log_format == "json":
            log_message = json.dumps(log_entry)
        else:
            log_message = (
                f"DNS Query: {client_ip} -> {query_name} ({query_type}) "
                f"-> {response_status} ({response_code}) "
                f"[{processing_time*1000:.2f}ms]"
                f"{' [CACHED]' if cache_hit else ''}"
                f"{' [BLOCKED]' if blocked else ''}"
            )

        # Determine log level based on response
        if response_code >= 400:
            log_level = logging.ERROR
            syslog_severity = 3  # Error
        elif blocked:
            log_level = logging.WARNING
            syslog_severity = 4  # Warning
        else:
            log_level = logging.INFO
            syslog_severity = 6  # Info

        self.local_logger.log(log_level, log_message)

        # Send to syslog if enabled
        if self.syslog_handler:
            # Create syslog-friendly message
            syslog_message = (
                f"client_ip={client_ip} query={query_name} "
                f"type={query_type} status={response_status} "
                f"code={response_code} time={processing_time*1000:.2f}ms"
                f"{' cached=true' if cache_hit else ''}"
                f"{' blocked=true' if blocked else ''}"
            )

            self.syslog_handler.send(syslog_message, syslog_severity)

    def log_security_event(
        self, request, event_type: str, details: str, severity: str = "WARNING"
    ):
        """Log security-related events"""

        client_ip = self.ip_extractor.extract_real_ip(request)

        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": "security_event",
            "security_event_type": event_type,
            "client_ip": client_ip,
            "details": details,
            "severity": severity,
            "user_agent": request.headers.get("User-Agent", ""),
        }

        # Log locally
        if self.log_format == "json":
            log_message = json.dumps(log_entry)
        else:
            log_message = f"Security Event: {event_type} from {client_ip} - {details}"

        log_level = getattr(logging, severity.upper(), logging.WARNING)
        self.local_logger.log(log_level, log_message)

        # Send to syslog if enabled
        if self.syslog_handler:
            syslog_message = (
                f"security_event={event_type} client_ip={client_ip} details={details}"
            )
            syslog_severity = 4 if severity == "WARNING" else 3  # Warning or Error
            self.syslog_handler.send(syslog_message, syslog_severity)

    def close(self):
        """Close logging resources"""
        if self.syslog_handler:
            self.syslog_handler.close()


# Global logger instance
request_logger = None


def get_request_logger() -> DNSRequestLogger:
    """Get or create the global request logger instance"""
    global request_logger
    if request_logger is None:
        request_logger = DNSRequestLogger()
    return request_logger
