"""
Test configuration and fixtures for DHCP server tests.
Builds manager DHCP schema into temp SQLite database.
"""

import pytest
import asyncio
import tempfile
import os
import sys
import logging
import jwt
from datetime import datetime, timedelta
from sqlalchemy import (
    create_engine,
    MetaData,
    Table,
    Column,
    Integer,
    String,
    DateTime,
    Boolean,
    Text,
    ForeignKey,
    JSON,
)
from sqlalchemy.sql import func
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Setup paths
manager_models_path = os.path.join(os.path.dirname(__file__), "..", "..", "manager", "backend", "app", "models")
if manager_models_path not in sys.path:
    sys.path.insert(0, os.path.dirname(manager_models_path))

# Add app to path so imports work
app_path = os.path.join(os.path.dirname(__file__), "..")
if app_path not in sys.path:
    sys.path.insert(0, app_path)


@pytest.fixture(scope="function")
def event_loop():
    """Create asyncio event loop for tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="function", autouse=True)
def setup_env(monkeypatch, jwt_keypair):
    """Setup environment variables for all tests."""
    # Set defaults so modules can import without error
    monkeypatch.setenv("JWT_SECRET_KEY", "test-jwt-secret-key-do-not-use-in-production")
    # Public key for asymmetric user-token verification (read at call time by auth.py)
    monkeypatch.setenv("JWT_PUBLIC_KEY", jwt_keypair["public"])
    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    monkeypatch.setenv("LOG_LEVEL", "WARNING")
    monkeypatch.setenv("POSTHOG_KEY", "")
    yield


@pytest.fixture(scope="function")
def temp_db():
    """Create temporary SQLite database with manager DHCP schema."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    # Create SQLAlchemy engine
    engine = create_engine(f"sqlite:///{db_path}")

    # Define DHCP tables (mirror of manager schema)
    metadata = MetaData()

    # DHCP Pool table
    dhcp_pool = Table(
        "dhcp_pool",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("name", String(100), nullable=False),
        Column("network", String(50), nullable=False),
        Column("range_start", String(50), nullable=False),
        Column("range_end", String(50), nullable=False),
        Column("gateway", String(50)),
        Column("subnet_mask", String(50), default="255.255.255.0"),
        Column("dns_servers", JSON),
        Column("ntp_servers", JSON),
        Column("domain_name", String(255)),
        Column("lease_duration", Integer, default=86400, nullable=False),
        Column("team_id", Integer),  # Reference to team (not created in test)
        Column("active", Boolean, default=True, nullable=False),
        Column("enable_ddns", Boolean, default=False, nullable=False),
        Column("ddns_zone_id", Integer),  # Reference to dns_zone (not created in test)
        Column("created_at", DateTime, default=func.now(), nullable=False),
        Column("updated_at", DateTime, onupdate=func.now()),
    )

    # DHCP Reservation table (static IP assignments)
    dhcp_reservation = Table(
        "dhcp_reservation",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("pool_id", Integer, ForeignKey("dhcp_pool.id", ondelete="CASCADE"), nullable=False),
        Column("mac_address", String(17), nullable=False),
        Column("ip_address", String(50), nullable=False),
        Column("hostname", String(255)),
        Column("description", Text),
        Column("created_at", DateTime, default=func.now(), server_default=func.now(), nullable=False),
        Column("updated_at", DateTime, onupdate=func.now()),
    )

    # DHCP Lease table (active and historical leases)
    dhcp_lease = Table(
        "dhcp_lease",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("pool_id", Integer, ForeignKey("dhcp_pool.id", ondelete="CASCADE"), nullable=False),
        Column("mac_address", String(17), nullable=False),
        Column("ip_address", String(50), nullable=False),
        Column("hostname", String(255)),
        Column("lease_start", DateTime, nullable=False),
        Column("lease_end", DateTime, nullable=False),
        Column("status", String(20), nullable=False, default="active"),
        Column("created_at", DateTime, default=func.now(), server_default=func.now(), nullable=False),
    )

    # Create all tables
    metadata.create_all(engine)

    # Insert default pool
    with engine.connect() as conn:
        conn.execute(
            dhcp_pool.insert().values(
                name="test-pool",
                network="192.168.1.0/24",
                range_start="192.168.1.100",
                range_end="192.168.1.200",
                gateway="192.168.1.1",
                dns_servers=["8.8.8.8", "8.8.4.4"],
                lease_duration=86400,
                active=True,
            )
        )
        conn.commit()

    yield db_path

    # Cleanup
    try:
        os.unlink(db_path)
    except Exception as e:
        logging.warning(f"Failed to clean up temp db: {e}")


@pytest.fixture(scope="session")
def jwt_keypair():
    """Generate an ephemeral ES256 keypair for testing."""
    # Generate EC private key (P-256)
    private_key = ec.generate_private_key(
        ec.SECP256R1(), default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    # Extract public key
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return {
        'private': private_pem,
        'public': public_pem
    }


@pytest.fixture
def jwt_secret_key():
    """JWT secret key for test tokens (legacy server tokens)."""
    return "test-jwt-secret-key-do-not-use-in-production"


@pytest.fixture
def test_token_read(jwt_keypair):
    """Create valid test JWT with dhcp:read scope (ES256)."""
    payload = {
        "sub": "test-user-id",
        "iss": "squawk-manager",
        "aud": "squawk",
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=1),
        "scope": "dhcp:read",
        "tenant": "test-tenant",
        "team_roles": {"test-team": "Member"},
        "global_role": "Viewer",
    }
    return jwt.encode(payload, jwt_keypair['private'], algorithm="ES256")


@pytest.fixture
def test_token_admin(jwt_keypair):
    """Create valid test JWT with dhcp:admin scope (ES256)."""
    payload = {
        "sub": "test-admin-id",
        "iss": "squawk-manager",
        "aud": "squawk",
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=1),
        "scope": "dhcp:admin",
        "tenant": "test-tenant",
        "team_roles": {"test-team": "Admin"},
        "global_role": "SystemAdmin",
    }
    return jwt.encode(payload, jwt_keypair['private'], algorithm="ES256")


@pytest.fixture
def test_token_expired(jwt_keypair):
    """Create expired test JWT (ES256)."""
    payload = {
        "sub": "test-user-id",
        "iss": "squawk-manager",
        "aud": "squawk",
        "iat": datetime.utcnow() - timedelta(hours=2),
        "exp": datetime.utcnow() - timedelta(hours=1),
        "scope": "dhcp:read",
        "tenant": "test-tenant",
        "team_roles": {"test-team": "Member"},
        "global_role": "Viewer",
    }
    return jwt.encode(payload, jwt_keypair['private'], algorithm="ES256")


@pytest.fixture
async def app_client(monkeypatch, temp_db, jwt_keypair, jwt_secret_key):
    """Create Quart test client with mocked database and JWT keys."""
    # Set environment variables BEFORE importing app
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{temp_db}")
    monkeypatch.setenv("JWT_PUBLIC_KEY", jwt_keypair['public'])  # For user token verification
    monkeypatch.setenv("JWT_SECRET_KEY", jwt_secret_key)  # Legacy: for server tokens only
    monkeypatch.setenv("POSTHOG_KEY", "")  # Disable PostHog in tests
    monkeypatch.setenv("DHCP_PORT", "8081")
    monkeypatch.setenv("DHCP_POOL_START", "192.168.1.100")
    monkeypatch.setenv("DHCP_POOL_END", "192.168.1.200")
    monkeypatch.setenv("LOG_LEVEL", "WARNING")

    # Import app after env vars set
    import importlib
    import sys

    # Remove app modules from cache to force reimport with new env vars
    for module_name in list(sys.modules.keys()):
        if module_name.startswith("app") or module_name == "bins.server":
            del sys.modules[module_name]

    from bins.server import app

    return app.test_client()
