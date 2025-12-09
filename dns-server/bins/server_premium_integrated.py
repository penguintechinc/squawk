#!/usr/bin/env python3
"""
Integrated Premium DNS Server for Squawk DNS
Combines the optimized server with all premium features under license control.
"""

import asyncio
import json
import logging
import os
import ssl
import sys
import time
import getopt
from datetime import datetime
from functools import wraps
from quart import Quart, request, jsonify
from hypercorn.asyncio import serve
from hypercorn.config import Config
from pydal import DAL, Field
from cache_manager import get_cache_manager
from cert_manager import CertificateManager
from logging_manager import get_request_logger
from premium_features import init_premium_features
from selective_dns_routing import SelectiveDNSRouter
import re
import logging
from typing import Dict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Quart(__name__)

# Configuration from environment variables
PORT = int(os.environ.get("PORT", 8080))
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", 100))
MAX_CONCURRENT_REQUESTS = int(os.environ.get("MAX_CONCURRENT_REQUESTS", 1000))
AUTH_TOKEN = os.environ.get("AUTH_TOKEN", "")
USE_NEW_AUTH = os.environ.get("USE_NEW_AUTH", "false").lower() == "true"
DB_TYPE = os.environ.get("DB_TYPE", "sqlite")
DB_URL = os.environ.get("DB_URL", "storage.db")
CACHE_ENABLED = os.environ.get("CACHE_ENABLED", "true").lower() == "true"
CACHE_TTL = int(os.environ.get("CACHE_TTL", 300))

# Premium/License configuration
USE_LICENSE_SERVER = os.environ.get("USE_LICENSE_SERVER", "false").lower() == "true"
LICENSE_SERVER_URL = os.environ.get(
    "LICENSE_SERVER_URL", "https://license.squawkdns.com"
)
LICENSE_KEY = os.environ.get("LICENSE_KEY", "")

# mTLS configuration
ENABLE_MTLS = os.environ.get("ENABLE_MTLS", "false").lower() == "true"
MTLS_ENFORCE = os.environ.get("MTLS_ENFORCE", "false").lower() == "true"
CERT_DIR = os.environ.get("CERT_DIR", "certs")

# Initialize managers
cache_manager = get_cache_manager() if CACHE_ENABLED else None
cert_manager = CertificateManager(cert_dir=CERT_DIR) if ENABLE_MTLS else None
request_logger = get_request_logger()

@app.before_serving
async def startup():
    """Initialize async components"""
    if cache_manager:
        await cache_manager.initialize()

# Initialize premium features
premium_manager = None
selective_router = None

if USE_LICENSE_SERVER:
    premium_manager = init_premium_features(
        db_url=f"{DB_TYPE}://{DB_URL}",
        license_server_url=LICENSE_SERVER_URL,
        base_cache_manager=cache_manager,
    )
    selective_router = SelectiveDNSRouter(f"{DB_TYPE}://{DB_URL}")

# Semaphore for rate limiting
request_semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)


async def check_license_status(token: str = None) -> Dict:
    """Check license status for a token or global license"""
    if not USE_LICENSE_SERVER:
        return {"is_licensed": False, "features": []}

    # Check token-specific license
    if token and premium_manager:
        return await premium_manager.check_license(token)

    # Check global license
    if LICENSE_KEY:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{LICENSE_SERVER_URL}/api/validate",
                    json={"license_key": LICENSE_KEY},
                    timeout=5.0,
                )
                if response.status_code == 200:
                    data = response.json()
                    return {
                        "is_licensed": data.get("valid", False),
                        "license_type": data.get("license_type", "community"),
                        "features": data.get("features", []),
                    }
        except Exception as e:
            logger.error(f"License check failed: {e}")

    return {"is_licensed": False, "features": []}


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
            "Question": [{"name": query, "type": record_type}],
            "TTL": getattr(answer.rrset, "ttl", CACHE_TTL),
        }
        return result
    except dns.resolver.NXDOMAIN:
        return {
            "Status": 3,  # NXDOMAIN
            "Answer": [],
            "Question": [{"name": query, "type": record_type}],
        }
    except dns.resolver.NoAnswer:
        return {
            "Status": 0,
            "Answer": [],
            "Question": [{"name": query, "type": record_type}],
        }
    except Exception as e:
        logger.error(f"DNS resolution error for {query}: {e}")
        return {
            "Status": 2,  # SERVFAIL
            "Answer": [],
            "Question": [{"name": query, "type": record_type}],
            "Comment": str(e),
        }


def validate_token_advanced(token_value, domain):
    """Validate token with advanced permissions (premium feature)"""
    if not USE_NEW_AUTH or not token_value:
        return False

    try:
        db = DAL(f"{DB_TYPE}://{DB_URL}")

        # Define tables
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
            db(db.tokens.id == token_record.id).update(last_used=datetime.now())
            db.commit()
            db.close()
            return True

        # Check specific domain permission
        domain_parts = domain.split(".")
        for i in range(len(domain_parts)):
            check_domain = ".".join(domain_parts[i:])
            domain_allowed = (
                db(
                    (db.token_domains.token_id == token_record.id)
                    & (db.domains.id == db.token_domains.domain_id)
                    & (db.domains.name == check_domain)
                )
                .select()
                .first()
            )
            if domain_allowed:
                # Update last_used timestamp
                db(db.tokens.id == token_record.id).update(last_used=datetime.now())
                db.commit()
                db.close()
                return True

        db.close()
        return False

    except Exception as e:
        logger.error(f"Token validation error: {e}")
        return False


@app.route("/dns-query", methods=["GET", "POST"])
async def dns_query():
    """Main DNS query endpoint with premium features"""
    # global AUTH_TOKEN, USE_NEW_AUTH, USE_LICENSE_SERVER

    start_time = time.time()
    response_data = None
    cache_hit = False
    blocked = False
    client_cert_subject = None
    token = None

    async with request_semaphore:
        # Parse DNS query
        if request.method == "GET":
            dns_param = request.args.get("dns")
            name = request.args.get("name", "")
            dns_type = request.args.get("type", "A")
        else:
            data = await request.get_data()
            dns_param = data.decode() if data else None
            name = request.args.get("name", "")
            dns_type = request.args.get("type", "A")

        # Decode DNS over HTTPS query if present
        if dns_param:
            import base64

            try:
                decoded = base64.urlsafe_b64decode(dns_param + "==")
                # Parse DNS message - simplified for this example
                name = name or "example.com"  # Would parse from DNS message
                dns_type = dns_type or "A"
            except Exception:
                pass

        # Validate domain name
        if not name or not re.match(r"^[a-zA-Z0-9.-]+$", name):
            return jsonify({"Status": 1, "Comment": "Invalid domain name"}), 400

        # Authentication check
        auth_header = request.headers.get("X-Auth-Token") or request.headers.get(
            "Authorization"
        )
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]
        else:
            token = auth_header

        # Check legacy auth
        if not USE_NEW_AUTH and AUTH_TOKEN:
            if token != AUTH_TOKEN:
                return jsonify({"Status": 4, "Comment": "Authentication required"}), 401
        elif USE_NEW_AUTH:
            if not validate_token_advanced(token, name):
                return jsonify({"Status": 4, "Comment": "Authentication required"}), 401

        # Check license and get features
        license_info = await check_license_status(token)
        is_licensed = license_info.get("is_licensed", False)
        features = license_info.get("features", [])

        # Premium: Priority resolution
        if is_licensed and premium_manager and "priority_resolution" in features:
            request_id = await premium_manager.priority_resolver.queue_request(
                name, dns_type, token, is_licensed
            )
            logger.info(f"Priority request queued: {request_id}")

        # Check cache (with premium enhancement)
        cache_key = f"dns:{name}:{dns_type}"
        if cache_manager:
            if (
                premium_manager
                and premium_manager.enhanced_cache
                and "enhanced_cache" in features
            ):
                cached_result = await premium_manager.enhanced_cache.get(
                    cache_key, is_premium=is_licensed
                )
            else:
                cached_result = await cache_manager.get(cache_key)

            if cached_result:
                cache_hit = True
                response_data = cached_result

        # Resolve DNS if not cached
        if not response_data:
            # Premium: Multi-tenant isolation
            query_domain = name
            if is_licensed and premium_manager and "multi_tenant" in features:
                tenant = premium_manager.multi_tenant.get_tenant_by_token(token)
                if tenant:
                    query_domain = premium_manager.multi_tenant.apply_tenant_isolation(
                        name, tenant
                    )

            # Perform DNS resolution
            response_data = await resolve_dns_async(query_domain, dns_type)

            # Cache successful responses
            if response_data.get("Status") == 0 and cache_manager:
                ttl = min(response_data.get("TTL", CACHE_TTL), CACHE_TTL)
                if (
                    premium_manager
                    and premium_manager.enhanced_cache
                    and "enhanced_cache" in features
                ):
                    await premium_manager.enhanced_cache.set(
                        cache_key, response_data, ttl, is_premium=is_licensed
                    )
                else:
                    await cache_manager.set(cache_key, response_data, ttl)

        # Premium: Selective DNS routing
        if is_licensed and selective_router and "selective_routing" in features:
            response_data = selective_router.filter_dns_response(
                token, name, response_data
            )

        # Premium: Analytics tracking
        if is_licensed and premium_manager and "analytics" in features:
            processing_time = time.time() - start_time
            client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
            await premium_manager.analytics.track_query(
                token,
                name,
                dns_type,
                processing_time,
                cache_hit,
                blocked,
                response_data.get("Status", 0),
                client_ip,
            )

        # Premium: Enterprise monitoring
        if is_licensed and premium_manager and "enterprise_monitoring" in features:
            if response_data.get("Status", 0) != 0:
                client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
                await premium_manager.monitoring.log_security_event(
                    "dns_error",
                    "warning",
                    token,
                    {"query": name, "error": response_data.get("Status")},
                    client_ip,
                )

        # Log the request
        processing_time = time.time() - start_time
        status_code = 200 if response_data.get("Status") == 0 else 400
        status_text = "success" if response_data.get("Status") == 0 else "error"
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)

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


@app.route("/api/groups", methods=["GET", "POST"])
async def manage_groups():
    """API endpoint for group management (Premium feature)"""
    # Check if licensed for this feature
    auth_token = request.headers.get("X-Auth-Token")
    license_info = await check_license_status(auth_token)

    if not license_info.get(
        "is_licensed"
    ) or "selective_routing" not in license_info.get("features", []):
        return jsonify({"error": "Premium feature not available"}), 403

    if not selective_router:
        return jsonify({"error": "Selective routing not configured"}), 500

    if request.method == "GET":
        # Get user's groups
        token = request.args.get("token")
        if not token:
            return jsonify({"error": "Token required"}), 400

        groups = selective_router.get_user_groups(token)
        return jsonify({"groups": groups})

    elif request.method == "POST":
        # Assign user to group
        data = await request.get_json()
        token = data.get("token")
        group_name = data.get("group")

        if not token or not group_name:
            return jsonify({"error": "Token and group required"}), 400

        success = selective_router.assign_user_to_group(token, group_name)
        if success:
            return jsonify({"status": "success"})
        else:
            return jsonify({"error": "Failed to assign group"}), 500


@app.route("/api/analytics/report", methods=["GET"])
async def get_analytics_report():
    """Get analytics report (Premium feature)"""
    auth_token = request.headers.get("X-Auth-Token")
    license_info = await check_license_status(auth_token)

    if not license_info.get("is_licensed") or "analytics" not in license_info.get(
        "features", []
    ):
        return jsonify({"error": "Premium feature not available"}), 403

    if not premium_manager:
        return jsonify({"error": "Premium features not configured"}), 500

    report_type = request.args.get("type", "daily")
    report = await premium_manager.analytics.generate_report(auth_token, report_type)

    return jsonify(report)


@app.route("/api/zones", methods=["GET"])
async def get_accessible_zones():
    """Get DNS zones accessible to user (Premium feature)"""
    auth_token = request.headers.get("X-Auth-Token")
    license_info = await check_license_status(auth_token)

    if not license_info.get(
        "is_licensed"
    ) or "selective_routing" not in license_info.get("features", []):
        # Return public zones only for non-premium users
        return jsonify({"zones": ["public"]})

    if not selective_router:
        return jsonify({"error": "Selective routing not configured"}), 500

    zones = selective_router.get_user_accessible_zones(auth_token)
    return jsonify({"zones": zones})


@app.route("/api/sso/saml", methods=["POST"])
async def saml_sso():
    """SAML SSO endpoint (Enterprise feature only)"""
    auth_token = request.headers.get("X-Auth-Token")
    license_info = await check_license_status(auth_token)

    # Check if this is an enterprise license
    if (
        not license_info.get("is_licensed")
        or license_info.get("license_type") != "enterprise"
    ):
        return jsonify({"error": "SAML SSO is an enterprise-only feature"}), 403

    # Handle SAML assertion
    data = await request.get_json()
    saml_response = data.get("SAMLResponse")

    if not saml_response:
        return jsonify({"error": "SAML response required"}), 400

    # Would implement actual SAML processing here
    # For now, return a mock response
    return jsonify(
        {
            "status": "success",
            "message": "SAML SSO is available for enterprise customers",
            "user": {
                "email": "user@enterprise.com",
                "groups": ["internal_users", "developers"],
            },
        }
    )


@app.route("/api/scim/v2/Users", methods=["GET", "POST"])
async def scim_users():
    """SCIM user provisioning endpoint (Enterprise feature only)"""
    auth_token = request.headers.get("Authorization")
    if auth_token and auth_token.startswith("Bearer "):
        auth_token = auth_token[7:]

    license_info = await check_license_status(auth_token)

    # Check if this is an enterprise license
    if (
        not license_info.get("is_licensed")
        or license_info.get("license_type") != "enterprise"
    ):
        return (
            jsonify(
                {
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                    "detail": "SCIM provisioning is an enterprise-only feature",
                    "status": "403",
                }
            ),
            403,
        )

    # Would implement actual SCIM processing here
    if request.method == "GET":
        return jsonify(
            {
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                "totalResults": 0,
                "Resources": [],
                "message": "SCIM provisioning is available for enterprise customers",
            }
        )
    elif request.method == "POST":
        return jsonify(
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "id": "new-user-id",
                "message": "SCIM user provisioning is available for enterprise customers",
            }
        )


@app.route("/health", methods=["GET"])
async def health_check():
    """Health check endpoint"""
    status = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "features": {
            "cache": CACHE_ENABLED,
            "mtls": ENABLE_MTLS,
            "new_auth": USE_NEW_AUTH,
            "license_server": USE_LICENSE_SERVER,
        },
    }

    # Check license status
    if USE_LICENSE_SERVER:
        license_info = await check_license_status()
        status["license"] = {
            "active": license_info.get("is_licensed", False),
            "type": license_info.get("license_type", "community"),
            "features": license_info.get("features", []),
        }

    return jsonify(status)


def main(argv):
    """Main entry point"""
    global PORT, AUTH_TOKEN, USE_NEW_AUTH, USE_LICENSE_SERVER, DB_TYPE, DB_URL

    try:
        opts, args = getopt.getopt(
            argv,
            "p:a:d:u:nl",
            ["port=", "auth=", "dbtype=", "dburl=", "new-auth", "license-server"],
        )
    except getopt.GetoptError:
        print(
            "Usage: server_premium_integrated.py [-p port] [-a auth_token] [-d dbtype] [-u dburl] [-n] [-l]"
        )
        print("  -n, --new-auth : Use new token management system")
        print("  -l, --license-server : Enable license server for premium features")
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-p", "--port"):
            PORT = int(arg)
        elif opt in ("-a", "--auth"):
            AUTH_TOKEN = arg
        elif opt in ("-d", "--dbtype"):
            DB_TYPE = arg
        elif opt in ("-u", "--dburl"):
            DB_URL = arg
        elif opt in ("-n", "--new-auth"):
            USE_NEW_AUTH = True
        elif opt in ("-l", "--license-server"):
            USE_LICENSE_SERVER = True

    # Configure Hypercorn
    config = Config()
    config.bind = [f"0.0.0.0:{PORT}"]
    config.workers = MAX_WORKERS

    # Log configuration
    logger.info(f"Starting Squawk DNS Server (Premium Integrated)")
    logger.info(f"Port: {PORT}")
    logger.info(f"New Auth: {USE_NEW_AUTH}")
    logger.info(f"License Server: {USE_LICENSE_SERVER}")
    logger.info(f"Cache: {CACHE_ENABLED}")
    logger.info(f"mTLS: {ENABLE_MTLS}")

    if USE_LICENSE_SERVER:
        logger.info("Premium features enabled - checking license...")

    # Run the server
    asyncio.run(serve(app, config))


if __name__ == "__main__":
    main(sys.argv[1:])
