#!/usr/bin/env python3
"""
Database initialization using SQLAlchemy.

This module creates the database schema for the Squawk DNS server.
SQLAlchemy handles schema creation while pyDAL handles day-to-day operations.
"""

import os
import logging
from datetime import datetime
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Boolean,
    DateTime,
    Text,
    ForeignKey,
    UniqueConstraint,
    Index,
    event,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

logger = logging.getLogger(__name__)

Base = declarative_base()


# ============================================================================
# Token Management Tables
# ============================================================================


class Token(Base):
    """Authentication tokens for API access."""

    __tablename__ = "tokens"

    id = Column(Integer, primary_key=True, autoincrement=True)
    token = Column(String(256), nullable=False, unique=True, index=True)
    name = Column(String(256), nullable=True)
    description = Column(Text, nullable=True)
    active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)

    # Relationships
    domains = relationship(
        "TokenDomain", back_populates="token", cascade="all, delete-orphan"
    )


class Domain(Base):
    """Domains that tokens can access."""

    __tablename__ = "domains"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(256), nullable=False, unique=True, index=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    tokens = relationship("TokenDomain", back_populates="domain")


class TokenDomain(Base):
    """Many-to-many relationship between tokens and domains."""

    __tablename__ = "token_domains"

    id = Column(Integer, primary_key=True, autoincrement=True)
    token_id = Column(Integer, ForeignKey("tokens.id", ondelete="CASCADE"), nullable=False)
    domain_id = Column(Integer, ForeignKey("domains.id", ondelete="CASCADE"), nullable=False)

    # Relationships
    token = relationship("Token", back_populates="domains")
    domain = relationship("Domain", back_populates="tokens")

    __table_args__ = (
        UniqueConstraint("token_id", "domain_id", name="uq_token_domain"),
    )


# ============================================================================
# User and Group Management Tables
# ============================================================================


class User(Base):
    """Users for enterprise features."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(256), nullable=False, unique=True, index=True)
    email = Column(String(256), nullable=True)
    password_hash = Column(String(512), nullable=True)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

    # Relationships
    groups = relationship("UserGroup", back_populates="user", cascade="all, delete-orphan")


class Group(Base):
    """Groups for permission management."""

    __tablename__ = "groups"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(256), nullable=False, unique=True, index=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    users = relationship("UserGroup", back_populates="group")
    zone_permissions = relationship("GroupZonePermission", back_populates="group")


class UserGroup(Base):
    """Many-to-many relationship between users and groups."""

    __tablename__ = "user_groups"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    group_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), nullable=False)

    # Relationships
    user = relationship("User", back_populates="groups")
    group = relationship("Group", back_populates="users")

    __table_args__ = (
        UniqueConstraint("user_id", "group_id", name="uq_user_group"),
    )


# ============================================================================
# DNS Zone Management Tables
# ============================================================================


class DnsZone(Base):
    """DNS zones with visibility settings."""

    __tablename__ = "dns_zones"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(256), nullable=False, unique=True, index=True)
    visibility = Column(String(64), default="PUBLIC")  # PUBLIC, INTERNAL, RESTRICTED, PRIVATE
    primary_ns = Column(String(256), nullable=True)
    admin_email = Column(String(256), nullable=True)
    ttl = Column(Integer, default=3600)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    records = relationship("DnsRecord", back_populates="zone", cascade="all, delete-orphan")
    permissions = relationship("GroupZonePermission", back_populates="zone")


class DnsRecord(Base):
    """DNS records within zones."""

    __tablename__ = "dns_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    zone_id = Column(Integer, ForeignKey("dns_zones.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(256), nullable=False, index=True)
    record_type = Column(String(16), nullable=False)  # A, AAAA, CNAME, MX, TXT, etc.
    value = Column(Text, nullable=False)
    ttl = Column(Integer, default=3600)
    priority = Column(Integer, nullable=True)  # For MX/SRV records
    visibility = Column(String(64), default="INHERIT")  # INHERIT from zone or override
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    zone = relationship("DnsZone", back_populates="records")

    __table_args__ = (
        Index("ix_dns_records_name_type", "name", "record_type"),
    )


class GroupZonePermission(Base):
    """Group permissions for DNS zones."""

    __tablename__ = "group_zone_permissions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    group_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), nullable=False)
    zone_id = Column(Integer, ForeignKey("dns_zones.id", ondelete="CASCADE"), nullable=False)
    can_read = Column(Boolean, default=True)
    can_write = Column(Boolean, default=False)
    can_admin = Column(Boolean, default=False)

    # Relationships
    group = relationship("Group", back_populates="zone_permissions")
    zone = relationship("DnsZone", back_populates="permissions")

    __table_args__ = (
        UniqueConstraint("group_id", "zone_id", name="uq_group_zone"),
    )


# ============================================================================
# Query Logging Table
# ============================================================================


class QueryLog(Base):
    """DNS query logs for analytics."""

    __tablename__ = "query_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    domain = Column(String(256), nullable=False, index=True)
    record_type = Column(String(16), nullable=False)
    client_ip = Column(String(64), nullable=True)
    token_id = Column(Integer, ForeignKey("tokens.id", ondelete="SET NULL"), nullable=True)
    response_code = Column(Integer, default=0)
    response_time_ms = Column(Integer, nullable=True)
    cache_hit = Column(Boolean, default=False)
    blocked = Column(Boolean, default=False)


# ============================================================================
# Database Initialization
# ============================================================================


def get_database_url():
    """Get database URL from environment variables."""
    db_type = os.getenv("DB_TYPE", "sqlite")
    db_url = os.getenv("DB_URL", "storage.db")

    if db_type == "sqlite":
        return f"sqlite:///{db_url}"
    elif db_type == "postgres" or db_type == "postgresql":
        return db_url if db_url.startswith("postgresql://") else f"postgresql://{db_url}"
    else:
        return f"{db_type}://{db_url}"


def init_database(db_url=None):
    """
    Initialize the database schema using SQLAlchemy.

    This creates all tables if they don't exist. Safe to call multiple times.
    """
    if db_url is None:
        db_url = get_database_url()

    logger.info(f"Initializing database: {db_url.split('@')[-1] if '@' in db_url else db_url}")

    try:
        engine = create_engine(db_url, echo=False)

        # Enable foreign keys for SQLite
        if "sqlite" in db_url:
            @event.listens_for(engine, "connect")
            def set_sqlite_pragma(dbapi_connection, connection_record):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()

        # Create all tables
        Base.metadata.create_all(engine)

        # Create session for seeding
        Session = sessionmaker(bind=engine)
        session = Session()

        # Seed default data if tables are empty
        _seed_default_data(session)

        session.commit()
        session.close()

        logger.info("Database initialized successfully")
        return True

    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        return False


def _seed_default_data(session):
    """Seed default data if tables are empty."""
    # Check if we need to seed tokens
    token_count = session.query(Token).count()
    if token_count == 0:
        logger.info("Seeding default token and domain...")

        # Create wildcard domain
        wildcard_domain = Domain(
            name="*",
            description="Wildcard domain - allows access to all domains",
        )
        session.add(wildcard_domain)

        # Create default test token with wildcard access
        import secrets

        default_token = Token(
            token=os.getenv("AUTH_TOKEN") or secrets.token_hex(32),
            name="default",
            description="Default API token with full access",
            active=True,
        )
        session.add(default_token)
        session.flush()  # Get IDs

        # Associate token with wildcard domain
        token_domain = TokenDomain(
            token_id=default_token.id,
            domain_id=wildcard_domain.id,
        )
        session.add(token_domain)

        logger.info(f"Created default token: {default_token.token[:16]}...")

    # Check if we need to seed groups
    group_count = session.query(Group).count()
    if group_count == 0:
        logger.info("Seeding default groups...")

        groups = [
            Group(name="INTERNAL", description="Full access to private + public DNS"),
            Group(name="EXTERNAL", description="Public DNS only"),
            Group(name="PARTNER", description="Limited private zones + public DNS"),
            Group(name="ADMIN", description="Full access + management capabilities"),
        ]
        session.add_all(groups)


if __name__ == "__main__":
    # Allow running directly for testing
    logging.basicConfig(level=logging.INFO)
    init_database()
