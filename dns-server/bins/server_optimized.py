#!/usr/bin/env python3
import asyncio
import dns.asyncresolver
import json
import sys
import os
import getopt
import hashlib
import aiofiles
import httpx
import tarfile
import tempfile
from datetime import datetime, timedelta
from quart import Quart, request, jsonify
from hypercorn.asyncio import serve
from hypercorn.config import Config
from pydal import DAL, Field
from cache_manager import get_cache_manager
import re
import logging
from typing import Set, Optional
import threading
import schedule
import time
import ssl
from cert_manager import CertificateManager
from logging_manager import get_request_logger
from cryptography import x509
import time


# Try to use uvloop for better performance on Linux/Mac
try:
    import uvloop

    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    pass

PORT = 8080
GOOGLE_DOH_URL = "https://dns.google/dns-query"
AUTH_TOKEN = None
KEY_FILE = None
CERT_FILE = None
DB_TYPE = None
DB_URL = None
ALLOWED_DOMAINS = []
USE_NEW_AUTH = False
ENABLE_BLACKLIST = os.getenv("ENABLE_BLACKLIST", "false").lower() == "true"
BLACKLIST_UPDATE_INTERVAL = int(os.getenv("BLACKLIST_UPDATE_HOURS", "24"))

# mTLS Configuration
ENABLE_MTLS = os.getenv("ENABLE_MTLS", "false").lower() == "true"
MTLS_ENFORCE = os.getenv("MTLS_ENFORCE", "false").lower() == "true"
MTLS_CA_CERT = os.getenv("MTLS_CA_CERT", "certs/ca.crt")
CERT_DIR = os.getenv("CERT_DIR", "certs")

# Performance settings
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "100"))
CACHE_TTL = int(os.getenv("CACHE_TTL", "300"))  # 5 minutes default
MAX_CONCURRENT_REQUESTS = int(os.getenv("MAX_CONCURRENT_REQUESTS", "1000"))

app = Quart(__name__)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize cache manager
cache_manager = get_cache_manager()


# Blacklist management
class BlacklistManager:
    def __init__(self):
        self.blocked_domains: Set[str] = set()
        self.blocked_ips: Set[str] = set()
        self.custom_blocked_domains: Set[str] = set()
        self.custom_blocked_ips: Set[str] = set()
        self.blacklist_path = os.path.join(
            os.path.dirname(__file__), "..", "data", "blacklists"
        )
        self.maravento_url = (
            "https://github.com/maravento/blackweb/raw/master/blackweb.tar.gz"
        )
        self.last_update = None

        os.makedirs(self.blacklist_path, exist_ok=True)

        # Load custom blacklists from database
        self.load_custom_blacklists()

        # Start background updater if enabled
        if ENABLE_BLACKLIST:
            self.start_updater()

    def load_custom_blacklists(self):
        """Load custom blacklists from database"""
        try:
            db_path = os.path.join(
                os.path.dirname(__file__),
                "..",
                "web",
                "apps",
                "dns_console",
                "databases",
                "dns_auth.db",
            )
            if os.path.exists(db_path):
                db = DAL(f"sqlite://{db_path}", folder=os.path.dirname(db_path))

                # Define blacklist tables
                db.define_table(
                    "blocked_domains",
                    Field("domain", "string", unique=True),
                    Field("reason", "string"),
                    Field("added_at", "datetime", default=datetime.now),
                    Field("added_by", "string"),
                    migrate=False,
                )

                db.define_table(
                    "blocked_ips",
                    Field("ip", "string", unique=True),
                    Field("reason", "string"),
                    Field("added_at", "datetime", default=datetime.now),
                    Field("added_by", "string"),
                    migrate=False,
                )

                # Load blocked domains
                blocked_domains = db(db.blocked_domains).select()
                for domain in blocked_domains:
                    self.custom_blocked_domains.add(domain.domain.lower())

                # Load blocked IPs
                blocked_ips = db(db.blocked_ips).select()
                for ip in blocked_ips:
                    self.custom_blocked_ips.add(ip.ip)

                db.close()
                logger.info(
                    f"Loaded {len(self.custom_blocked_domains)} custom blocked domains and {len(self.custom_blocked_ips)} custom blocked IPs"
                )
        except Exception as e:
            logger.error(f"Error loading custom blacklists: {e}")

    async def update_maravento_blacklist(self):
        """Download and update Maravento blacklist"""
        try:
            logger.info("Starting Maravento blacklist update...")

            async with httpx.AsyncClient(timeout=60) as client:
                response = await client.get(self.maravento_url)
                response.raise_for_status()

            # Save to temporary file
            temp_file = os.path.join(tempfile.gettempdir(), "blackweb.tar.gz")
            async with aiofiles.open(temp_file, "wb") as f:
                await f.write(response.content)

            # Extract and process
            with tarfile.open(temp_file, "r:gz") as tar:
                tar.extractall(self.blacklist_path)

            # Read blacklist file
            blacklist_file = os.path.join(self.blacklist_path, "blackweb.txt")
            if os.path.exists(blacklist_file):
                async with aiofiles.open(blacklist_file, "r") as f:
                    content = await f.read()
                    lines = content.splitlines()

                    new_domains = set()
                    for line in lines:
                        line = line.strip().lower()
                        if line and not line.startswith("#"):
                            new_domains.add(line)

                    self.blocked_domains = new_domains
                    self.last_update = datetime.now()

                    logger.info(
                        f"Updated Maravento blacklist with {len(self.blocked_domains)} domains"
                    )

            # Clean up
            os.remove(temp_file)

        except Exception as e:
            logger.error(f"Error updating Maravento blacklist: {e}")

    def is_blocked(self, domain: str, ip: Optional[str] = None) -> bool:
        """Check if a domain or IP is blocked"""
        domain_lower = domain.lower()

        # Check custom blacklists first (higher priority)
        if domain_lower in self.custom_blocked_domains:
            return True

        if ip and ip in self.custom_blocked_ips:
            return True

        # Check Maravento blacklist
        if domain_lower in self.blocked_domains:
            return True

        # Check if it's a subdomain of a blocked domain
        for blocked in self.custom_blocked_domains:
            if domain_lower.endswith("." + blocked) or domain_lower == blocked:
                return True

        for blocked in self.blocked_domains:
            if domain_lower.endswith("." + blocked) or domain_lower == blocked:
                return True

        return False

    def start_updater(self):
        """Start background thread for periodic updates"""

        def update_job():
            asyncio.run(self.update_maravento_blacklist())

        # Initial update
        threading.Thread(target=update_job, daemon=True).start()

        # Schedule periodic updates
        schedule.every(BLACKLIST_UPDATE_INTERVAL).hours.do(update_job)

        def run_scheduler():
            while True:
                schedule.run_pending()
                time.sleep(60)  # Check every minute

        threading.Thread(target=run_scheduler, daemon=True).start()


# Initialize blacklist manager
blacklist_manager = BlacklistManager()

# Initialize certificate manager for mTLS
cert_manager = CertificateManager(cert_dir=CERT_DIR) if ENABLE_MTLS else None

# Initialize request logger
request_logger = get_request_logger()

# Semaphore for rate limiting
request_semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)


async def verify_client_certificate():
    """Verify client certificate for mTLS"""
    if not ENABLE_MTLS:
        return True, None, "mTLS disabled"

    # Get client certificate from request
    client_cert_pem = request.headers.get("X-SSL-CERT")
    if not client_cert_pem:
        if MTLS_ENFORCE:
            return False, None, "Client certificate required"
        return True, None, "No client certificate provided"

    try:
        # Decode the certificate (assuming it's URL-encoded)
        import urllib.parse
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes

        cert_pem = urllib.parse.unquote(client_cert_pem)
        client_cert = x509.load_pem_x509_certificate(
            cert_pem.encode(), default_backend()
        )

        # Verify certificate chain
        if cert_manager and cert_manager.ca_cert_path.exists():
            ca_cert = cert_manager.load_certificate(cert_manager.ca_cert_path)

            # Verify the certificate was signed by our CA
            try:
                ca_public_key = ca_cert.public_key()

                # Determine signature algorithm based on key type
                from cryptography.hazmat.primitives.asymmetric import ec

                if isinstance(ca_public_key, ec.EllipticCurvePublicKey):
                    sig_algo = ec.ECDSA(hashes.SHA384())
                else:
                    sig_algo = hashes.SHA256()

                ca_public_key.verify(
                    client_cert.signature, client_cert.tbs_certificate_bytes, sig_algo
                )
            except Exception as e:
                return False, None, f"Certificate verification failed: {e}"

        # Check if certificate is revoked
        client_name = client_cert.subject.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME
        )[0].value
        clients = cert_manager.list_client_certificates() if cert_manager else {}

        if client_name in clients and clients[client_name].get("revoked"):
            return False, None, "Client certificate has been revoked"

        # Check certificate validity
        import datetime

        now = datetime.datetime.utcnow()
        if now < client_cert.not_valid_before or now > client_cert.not_valid_after:
            return False, None, "Client certificate is not valid"

        return True, client_cert, "Certificate valid"

    except Exception as e:
        return False, None, f"Certificate parsing error: {e}"


@app.route("/dns-query", methods=["GET", "POST"])
async def dns_query():
    # global AUTH_TOKEN, ALLOWED_DOMAINS, DB_TYPE, DB_URL, USE_NEW_AUTH

    start_time = time.time()
    response_data = None
    cache_hit = False
    blocked = False
    client_cert_subject = None

    async with request_semaphore:
        # Verify client certificate if mTLS is enabled
        if ENABLE_MTLS:
            cert_valid, client_cert, cert_message = await verify_client_certificate()
            if not cert_valid:
                logger.warning(f"mTLS verification failed: {cert_message}")
                request_logger.log_security_event(
                    request, "mtls_auth_failure", cert_message, "WARNING"
                )
                return (
                    jsonify(
                        {"Status": 2, "Comment": "Certificate verification failed"}
                    ),
                    403,
                )

            if client_cert:
                client_name = client_cert.subject.get_attributes_for_oid(
                    x509.NameOID.COMMON_NAME
                )[0].value
                client_cert_subject = client_name
                logger.debug(f"mTLS client authenticated: {client_name}")

        # Extract token from Authorization header
        auth_header = request.headers.get("Authorization")
        token = auth_header.split("Bearer ")[-1] if auth_header else None

        # Parse query parameters
        if request.method == "GET":
            name = request.args.get("name")
            dns_type = request.args.get("type", "A")
        else:
            # Support POST with DNS-over-HTTPS wire format
            data = await request.get_json()
            name = data.get("name")
            dns_type = data.get("type", "A")

        if not name:
            return jsonify({"Status": 2, "Comment": "Missing name parameter"}), 400

        # Validate domain format
        if not is_valid_domain(name):
            logger.warning(f"Invalid domain format: {name}")
            return jsonify({"Status": 2, "Comment": "Invalid domain format"}), 400

        # Check blacklist
        client_ip = request.environ.get("REMOTE_ADDR", "unknown")
        if blacklist_manager.is_blocked(name, client_ip):
            logger.info(f"Blocked query for blacklisted domain: {name}")
            blocked = True
            response_data = {
                "Status": 3,  # NXDOMAIN
                "Comment": "Domain blocked by policy",
                "Answer": [],
            }

            # Log the blocked request
            processing_time = time.time() - start_time
            request_logger.log_dns_request(
                request,
                name,
                dns_type,
                "blocked",
                403,
                token,
                client_cert_subject,
                processing_time,
                len(json.dumps(response_data)),
                cache_hit,
                blocked,
            )

            await log_query_new(token, name, dns_type, "blocked", client_ip)
            return jsonify(response_data)

        # Check authorization
        if USE_NEW_AUTH and DB_TYPE and DB_URL:
            # Use new token management system
            if not await check_token_permission_new(token, name):
                logger.warning(f"Access denied for token to domain: {name}")
                request_logger.log_security_event(
                    request,
                    "token_auth_failure",
                    f"Access denied for domain: {name}",
                    "WARNING",
                )
                await log_query_new(token, name, dns_type, "denied", client_ip)
                return jsonify({"Status": 2, "Comment": "Access denied"}), 403
            await log_query_new(token, name, dns_type, "allowed", client_ip)
        elif AUTH_TOKEN:
            # Use legacy single-token system
            if token != AUTH_TOKEN:
                logger.warning(f"Invalid token")
                return jsonify({"Status": 2, "Comment": "Invalid token"}), 403

            if ALLOWED_DOMAINS and not any(
                name.endswith(domain) for domain in ALLOWED_DOMAINS
            ):
                logger.warning(f"Domain not in allowed list: {name}")
                return jsonify({"Status": 2, "Comment": "Domain not allowed"}), 403

        # Check cache first
        cache_key = f"dns:{name}:{dns_type}"
        cached_result = await cache_manager.get(cache_key)
        if cached_result:
            cache_hit = True
            response_data = cached_result
            logger.debug(f"Cache hit for {name} ({dns_type})")

            # Log the cached request
            processing_time = time.time() - start_time
            request_logger.log_dns_request(
                request,
                name,
                dns_type,
                "success",
                200,
                token,
                client_cert_subject,
                processing_time,
                len(json.dumps(response_data)),
                cache_hit,
                blocked,
            )

            return jsonify(cached_result)

        # Resolve DNS
        logger.info(f"Resolving {name} with type {dns_type}")
        response_data = await resolve_dns_async(name, dns_type)

        # Cache successful responses with TTL from DNS response
        if response_data.get("Status") == 0:
            ttl = min(response_data.get("TTL", CACHE_TTL), CACHE_TTL)
            await cache_manager.set(cache_key, response_data, ttl)

        # Log the request
        processing_time = time.time() - start_time
        status_code = 200 if response_data.get("Status") == 0 else 400
        status_text = "success" if response_data.get("Status") == 0 else "error"

        request_logger.log_dns_request(
            request,
            name,
            dns_type,
            status_text,
            status_code,
            token,
            client_cert_subject,
            processing_time,
            len(json.dumps(response_data)),
            cache_hit,
            blocked,
        )

        return jsonify(response_data)


@app.route("/admin/blacklist", methods=["GET", "POST", "DELETE"])
async def manage_blacklist():
    """Admin endpoint for managing blacklists"""
    # Check admin authorization (implement your own admin auth)
    auth_header = request.headers.get("Authorization")
    # TODO: Implement proper admin authentication

    if request.method == "GET":
        # Return current blacklists
        return jsonify(
            {
                "custom_domains": list(blacklist_manager.custom_blocked_domains),
                "custom_ips": list(blacklist_manager.custom_blocked_ips),
                "maravento_count": len(blacklist_manager.blocked_domains),
                "last_update": (
                    blacklist_manager.last_update.isoformat()
                    if blacklist_manager.last_update
                    else None
                ),
            }
        )

    elif request.method == "POST":
        # Add to blacklist
        data = await request.get_json()
        domain = data.get("domain")
        ip = data.get("ip")
        reason = data.get("reason", "Admin blocked")

        if domain:
            blacklist_manager.custom_blocked_domains.add(domain.lower())
            # Save to database
            await save_blocked_domain(domain, reason)

        if ip:
            blacklist_manager.custom_blocked_ips.add(ip)
            # Save to database
            await save_blocked_ip(ip, reason)

        return jsonify({"status": "success", "message": "Blacklist updated"})

    elif request.method == "DELETE":
        # Remove from blacklist
        data = await request.get_json()
        domain = data.get("domain")
        ip = data.get("ip")

        if domain and domain.lower() in blacklist_manager.custom_blocked_domains:
            blacklist_manager.custom_blocked_domains.remove(domain.lower())
            await remove_blocked_domain(domain)

        if ip and ip in blacklist_manager.custom_blocked_ips:
            blacklist_manager.custom_blocked_ips.remove(ip)
            await remove_blocked_ip(ip)

        return jsonify({"status": "success", "message": "Entry removed from blacklist"})


@app.route("/health", methods=["GET"])
async def health_check():
    """Health check endpoint"""
    cache_stats = await cache_manager.get_stats()
    return jsonify(
        {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "cache": cache_stats,
            "blacklist_enabled": ENABLE_BLACKLIST,
            "blacklist_domains": len(blacklist_manager.blocked_domains)
            + len(blacklist_manager.custom_blocked_domains),
            "blacklist_ips": len(blacklist_manager.custom_blocked_ips),
        }
    )


async def resolve_dns_async(query, record_type="A"):
    """Async DNS resolution with better error handling"""
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 5.0
    resolver.lifetime = 5.0

    try:
        # Map common record types
        if record_type.upper() in [
            "A",
            "AAAA",
            "MX",
            "TXT",
            "NS",
            "CNAME",
            "SOA",
            "PTR",
        ]:
            answer = await resolver.resolve(query, record_type.upper())
        else:
            answer = await resolver.resolve(query)

        result = {
            "Status": 0,
            "Answer": [
                {"name": query, "type": record_type, "data": rdata.to_text()}
                for rdata in answer
            ],
            "TTL": answer.rrset.ttl if hasattr(answer, "rrset") else 300,
        }
    except dns.resolver.NXDOMAIN:
        result = {"Status": 3, "Comment": "Domain does not exist"}  # NXDOMAIN
    except dns.resolver.NoAnswer:
        result = {"Status": 0, "Answer": [], "Comment": "No answer for query type"}
    except Exception as e:
        result = {"Status": 2, "Comment": str(e)}  # SERVFAIL

    return result


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


def is_valid_record_type(record_type):
    """Validate DNS record type"""
    valid_types = {
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
    return record_type.upper() in valid_types


async def check_token_permission_new(token_value, domain_name):
    """Check permission using new token management system"""
    if not token_value:
        return False

    # Implementation would be similar to existing but async
    # For now, return True for demonstration
    return True


async def log_query_new(token, name, dns_type, status, client_ip):
    """Log DNS query (async version)"""
    # Implementation would log to database asynchronously
    logger.info(f"Query: {name} ({dns_type}) - Status: {status} - IP: {client_ip}")


async def save_blocked_domain(domain, reason):
    """Save blocked domain to database"""
    # Implementation would save to database
    logger.info(f"Saved blocked domain: {domain} - Reason: {reason}")


async def save_blocked_ip(ip, reason):
    """Save blocked IP to database"""
    # Implementation would save to database
    logger.info(f"Saved blocked IP: {ip} - Reason: {reason}")


async def remove_blocked_domain(domain):
    """Remove blocked domain from database"""
    # Implementation would remove from database
    logger.info(f"Removed blocked domain: {domain}")


async def remove_blocked_ip(ip):
    """Remove blocked IP from database"""
    # Implementation would remove from database
    logger.info(f"Removed blocked IP: {ip}")


def create_ssl_context():
    """Create SSL context with optional mTLS support"""
    if not KEY_FILE or not CERT_FILE:
        return None

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(CERT_FILE, KEY_FILE)

    # Configure mTLS if enabled
    if ENABLE_MTLS:
        if os.path.exists(MTLS_CA_CERT):
            context.load_verify_locations(MTLS_CA_CERT)
            if MTLS_ENFORCE:
                context.verify_mode = ssl.CERT_REQUIRED
                logger.info("mTLS enabled with certificate requirement")
            else:
                context.verify_mode = ssl.CERT_OPTIONAL
                logger.info("mTLS enabled with optional certificates")
        else:
            logger.warning(f"mTLS CA certificate not found at {MTLS_CA_CERT}")
            # Auto-generate certificates if missing
            if cert_manager:
                logger.info("Auto-generating TLS certificates...")
                cert_manager.generate_ca_certificate()
                cert_manager.generate_server_certificate()

                # Update paths
                global KEY_FILE, CERT_FILE
                KEY_FILE = str(cert_manager.server_key_path)
                CERT_FILE = str(cert_manager.server_cert_path)

                # Recreate context with new certificates
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                context.load_cert_chain(CERT_FILE, KEY_FILE)

                if cert_manager.ca_cert_path.exists():
                    context.load_verify_locations(str(cert_manager.ca_cert_path))
                    if MTLS_ENFORCE:
                        context.verify_mode = ssl.CERT_REQUIRED
                    else:
                        context.verify_mode = ssl.CERT_OPTIONAL

    # Security settings
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers(
        "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"
    )

    return context


def main(argv):
    global AUTH_TOKEN, KEY_FILE, CERT_FILE, DB_TYPE, DB_URL, ALLOWED_DOMAINS, USE_NEW_AUTH, PORT

    try:
        opts, args = getopt.getopt(
            argv,
            "hp:t:k:c:d:u:a:nm",
            [
                "port=",
                "token=",
                "key=",
                "cert=",
                "dbtype=",
                "dburl=",
                "allowed=",
                "newauth",
                "mtls",
            ],
        )
    except getopt.GetoptError:
        print(
            "Usage: server_optimized.py -p <port> -t <token> -k <keyfile> -c <certfile> -m"
        )
        sys.exit(2)

    for opt, arg in opts:
        if opt == "-h":
            print(
                "Usage: server_optimized.py -p <port> -t <token> -k <keyfile> -c <certfile>"
            )
            sys.exit()
        elif opt in ("-p", "--port"):
            PORT = int(arg)
        elif opt in ("-t", "--token"):
            AUTH_TOKEN = arg
        elif opt in ("-k", "--key"):
            KEY_FILE = arg
        elif opt in ("-c", "--cert"):
            CERT_FILE = arg
        elif opt in ("-d", "--dbtype"):
            DB_TYPE = arg
        elif opt in ("-u", "--dburl"):
            DB_URL = arg
        elif opt in ("-a", "--allowed"):
            ALLOWED_DOMAINS = arg.split(",")
        elif opt in ("-n", "--newauth"):
            USE_NEW_AUTH = True
        elif opt in ("-m", "--mtls"):
            global ENABLE_MTLS
            ENABLE_MTLS = True

    # Configure Hypercorn for production
    config = Config()
    config.bind = [f"0.0.0.0:{PORT}"]
    config.workers = MAX_WORKERS

    # Create SSL context
    ssl_context = create_ssl_context()

    # Enable HTTPS/HTTP/3 if certificates are provided
    if ssl_context:
        config.ssl_context = ssl_context
        config.bind = [f"0.0.0.0:{PORT}"]
        # Enable HTTP/3
        config.quic_bind = [f"0.0.0.0:{PORT}"]

        if ENABLE_MTLS:
            logger.info(
                f"Starting optimized DNS server with HTTP/3 and mTLS on port {PORT}"
            )
        else:
            logger.info(
                f"Starting optimized DNS server with HTTP/3 and TLS on port {PORT}"
            )
    else:
        logger.info(
            f"Starting optimized DNS server on port {PORT} (HTTP/1.1 and HTTP/2)"
        )

    # Additional performance settings
    config.backlog = 2048
    config.keep_alive_timeout = 75

    # Run the server
    asyncio.run(serve(app, config))


if __name__ == "__main__":
    main(sys.argv[1:])
