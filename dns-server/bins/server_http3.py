#!/usr/bin/env python3
import asyncio
import dns.resolver
import json
import sys
import os
import getopt
from quart import Quart, request, jsonify
from hypercorn.asyncio import serve
from hypercorn.config import Config
from pydal import DAL, Field
from pydal.validators import IS_NOT_EMPTY, IS_IN_SET, IS_MATCH
from datetime import datetime
import re

PORT = 8080
GOOGLE_DOH_URL = "https://dns.google/dns-query"
AUTH_TOKEN = None
KEY_FILE = None
CERT_FILE = None
DB_TYPE = None
DB_URL = None
ALLOWED_DOMAINS = []
USE_NEW_AUTH = False  # Flag to use new token management system

app = Quart(__name__)


@app.route("/dns-query", methods=["GET"])
async def dns_query():
    global AUTH_TOKEN, ALLOWED_DOMAINS, DB_TYPE, DB_URL, USE_NEW_AUTH

    # Extract token from Authorization header (strict parsing: require "Bearer " prefix)
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:]  # Strip "Bearer " prefix (7 chars)
    else:
        token = None

    # Parse query parameters
    name = request.args.get("name")
    dns_type = request.args.get("type", "A")

    if not name:
        return jsonify({"Status": 2, "Comment": "Missing name parameter"}), 400

    # Validate domain format
    if not is_valid_domain(name):
        print(f"Invalid domain: {name}")
        return jsonify({"Status": 2, "Comment": "Invalid domain format"}), 400

    # Check authorization
    client_ip = request.environ.get("REMOTE_ADDR", "unknown")

    if USE_NEW_AUTH and DB_TYPE and DB_URL:
        # Use new token management system
        if not await check_token_permission_new(token, name):
            print(f"Access denied for token to domain: {name}")
            await log_query_new(token, name, dns_type, "denied", client_ip)
            return jsonify({"Status": 2, "Comment": "Access denied"}), 403
        await log_query_new(token, name, dns_type, "allowed", client_ip)
    elif AUTH_TOKEN:
        # Use legacy single-token system
        if token != AUTH_TOKEN:
            print(f"Invalid token: {token}")
            return jsonify({"Status": 2, "Comment": "Invalid token"}), 403

        if ALLOWED_DOMAINS and not any(
            name.endswith(domain) for domain in ALLOWED_DOMAINS
        ):
            print(f"Domain not in allowed list: {name}")
            return jsonify({"Status": 2, "Comment": "Domain not allowed"}), 403

    # Resolve DNS
    print(f"Resolving {name} with type {dns_type}")
    response_data = await resolve_dns(name, dns_type)
    return jsonify(response_data)


async def resolve_dns(query, record_type="A"):
    resolver = dns.resolver.Resolver()
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
            answer = resolver.resolve(query, record_type.upper())
        else:
            answer = resolver.resolve(query)

        result = {
            "Status": 0,
            "Answer": [
                {"name": query, "type": record_type, "data": rdata.to_text()}
                for rdata in answer
            ],
        }
    except Exception as e:
        result = {"Status": 2, "Comment": str(e)}
    return result


def is_valid_domain(domain):
    pattern = re.compile(
        r"^(?:[a-zA-Z0-9]"  # First character of the domain
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"  # Sub domain + hostname
        r"+[a-zA-Z]{2,6}\.?$"  # First level TLD
    )
    return pattern.match(domain) is not None


async def check_token_permission_new(token_value, domain_name):
    """Check permission using new token management system"""
    if not token_value:
        return False

    # Connect to the same database as the web console
    db_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "web",
        "apps",
        "dns_console",
        "databases",
        "dns_auth.db",
    )
    db = DAL(f"sqlite://{db_path}", folder=os.path.dirname(db_path))

    # Define tables (must match console schema)
    db.define_table(
        "tokens",
        Field("token", "string"),
        Field("name", "string"),
        Field("active", "boolean"),
        Field("last_used", "datetime"),
        migrate=False,
    )

    db.define_table("domains", Field("name", "string"), migrate=False)

    db.define_table(
        "token_domains",
        Field("token_id", "reference tokens"),
        Field("domain_id", "reference domains"),
        migrate=False,
    )

    # Check if token exists and is active
    # Security: Token lookup is indexed in DB; timing surface is the database query, not Python comparison
    token_record = db(db.tokens.token == token_value).select().first()
    if not token_record or not token_record.active:
        db.close()
        return False

    # Check for wildcard domain permission
    wildcard = (
        db(
            (db.token_domains.token_id == token_record.id)
            & (db.domains.id == db.token_domains.domain_id)
            & (db.domains.name == "*")
        )
        .select()
        .first()
    )
    if wildcard:
        # Update last_used timestamp
        token_record.update_record(last_used=datetime.now())
        db.commit()
        db.close()
        return True

    # Check for specific domain or parent domain permission
    parts = domain_name.split(".")
    for i in range(len(parts)):
        check_domain = ".".join(parts[i:])
        permission = (
            db(
                (db.token_domains.token_id == token_record.id)
                & (db.domains.id == db.token_domains.domain_id)
                & (db.domains.name == check_domain)
            )
            .select()
            .first()
        )
        if permission:
            # Update last_used timestamp
            token_record.update_record(last_used=datetime.now())
            db.commit()
            db.close()
            return True

    db.close()
    return False


async def log_query_new(token_value, domain, query_type, status, client_ip):
    """Log query using new system"""
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
        db = DAL(f"sqlite://{db_path}", folder=os.path.dirname(db_path))

        db.define_table("tokens", Field("token", "string"), migrate=False)

        db.define_table(
            "query_logs",
            Field("token_id", "reference tokens"),
            Field("domain_queried", "string"),
            Field("query_type", "string"),
            Field("status", "string"),
            Field("client_ip", "string"),
            Field("timestamp", "datetime"),
            migrate=False,
        )

        token_record = (
            db(db.tokens.token == token_value).select().first() if token_value else None
        )

        db.query_logs.insert(
            token_id=token_record.id if token_record else None,
            domain_queried=domain,
            query_type=query_type,
            status=status,
            client_ip=client_ip,
            timestamp=datetime.now(),
        )
        db.commit()
        db.close()
    except Exception as e:
        print(f"Error logging query: {e}")


def get_token_from_db(db_type, db_url, domain="*"):
    """Legacy function for single-token system"""
    db = DAL(f"{db_type}://{db_url}")
    db.define_table(
        "auth",
        Field("token", requires=IS_NOT_EMPTY()),
        Field("domain", requires=[IS_NOT_EMPTY(), IS_MATCH(r"^[a-zA-Z0-9.-]+$")]),
    )
    row = db((db.auth.domain == domain) | (db.auth.domain == "*")).select().first()
    db.close()
    return (row.token, row.domain.split(",")) if row else (None, [])


def main(argv):
    global AUTH_TOKEN, PORT, KEY_FILE, CERT_FILE, DB_TYPE, DB_URL, ALLOWED_DOMAINS, USE_NEW_AUTH

    try:
        opts, args = getopt.getopt(
            argv,
            "a:p:k:c:d:u:n",
            ["auth=", "port=", "key=", "cert=", "dbtype=", "dburl=", "new-auth"],
        )
    except getopt.GetoptError:
        print(
            "server.py -a <authtoken> -p <port> -k <keyfile> -c <certfile> -d <dbtype> -u <dburl> [-n|--new-auth]"
        )
        print("  -n, --new-auth : Use new token management system with web console")
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-a", "--auth"):
            AUTH_TOKEN = arg
        elif opt in ("-p", "--port"):
            PORT = int(arg)
        elif opt in ("-k", "--key"):
            KEY_FILE = arg
        elif opt in ("-c", "--cert"):
            CERT_FILE = arg
        elif opt in ("-d", "--dbtype"):
            DB_TYPE = arg
        elif opt in ("-u", "--dburl"):
            DB_URL = arg
        elif opt in ("-n", "--new-auth"):
            USE_NEW_AUTH = True

    # If using new auth system, ensure database exists
    if USE_NEW_AUTH:
        print("Using new token management system with web console")
        # Set default database if not specified
        if not DB_TYPE:
            DB_TYPE = "sqlite"
        if not DB_URL:
            DB_URL = "dns_auth.db"
    elif DB_TYPE and DB_URL and not USE_NEW_AUTH:
        # Legacy mode
        AUTH_TOKEN, ALLOWED_DOMAINS = get_token_from_db(DB_TYPE, DB_URL)


async def create_app():
    """Create and configure the Quart app"""
    return app


if __name__ == "__main__":
    main(sys.argv[1:])

    # Configure Hypercorn for HTTP/3
    config = Config()
    config.bind = [f"0.0.0.0:{PORT}"]

    # Enable HTTP/3 and HTTP/2 with fallback
    if KEY_FILE and CERT_FILE:
        config.certfile = CERT_FILE
        config.keyfile = KEY_FILE
        config.alpn_protocols = ["h3", "h2", "http/1.1"]  # HTTP/3, HTTP/2, HTTP/1.1
        print(
            f"Serving DNS-over-HTTPS on port {PORT} with TLS (HTTP/3, HTTP/2, HTTP/1.1)"
        )
    else:
        config.alpn_protocols = [
            "h2",
            "http/1.1",
        ]  # HTTP/2, HTTP/1.1 (no TLS = no HTTP/3)
        print(f"Serving DNS-over-HTTPS on port {PORT} (HTTP/2, HTTP/1.1)")

    if USE_NEW_AUTH:
        print(f"Web console available at: http://localhost:{PORT}/dns_console")

    asyncio.run(serve(app, config))
