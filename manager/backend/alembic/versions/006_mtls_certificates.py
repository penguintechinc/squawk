"""Add mTLS certificate management schema — mtls_certificate, mtls_revocation.

Revision ID: 006_mtls_certificates
Revises: 005_selective_dns_routing
"""
import os
import sys

from alembic import op
from sqlalchemy import (
    Boolean, Column, DateTime, Index, Integer, String,
    Table, MetaData, Text, func
)

# Add project root to path for imports
sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "..", "..")
)

revision = "006_mtls_certificates"
down_revision = "005_selective_dns_routing"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add mTLS certificate management schema."""
    # Create mtls_certificate table
    op.create_table(
        'mtls_certificate',
        Column('id', Integer, primary_key=True, autoincrement=True),
        Column('cert_type', String(20), nullable=False),  # 'ca' | 'server' | 'client'
        Column('common_name', String(255), nullable=False),
        Column('serial_number', String(255), nullable=False, unique=True),
        Column('fingerprint_sha256', String(64), nullable=False, unique=True),
        Column('pem_certificate', Text, nullable=False),
        Column('issued_at', DateTime, nullable=False, server_default=func.now()),
        Column('not_valid_before', DateTime, nullable=False),
        Column('not_valid_after', DateTime, nullable=False),
        Column('is_revoked', Boolean, nullable=False, server_default='0'),
        Column('revoked_at', DateTime),
        Column('revocation_reason', String(255)),
        Column('subject_dn', String(512), nullable=False),
        Column('issuer_dn', String(512), nullable=False),
        Column('created_at', DateTime, nullable=False, server_default=func.now()),
        Column('updated_at', DateTime, onupdate=func.now()),
    )
    op.create_index('idx_mtls_certificate_type', 'mtls_certificate', ['cert_type'])
    op.create_index('idx_mtls_certificate_serial', 'mtls_certificate', ['serial_number'], unique=True)
    op.create_index('idx_mtls_certificate_fingerprint', 'mtls_certificate', ['fingerprint_sha256'], unique=True)
    op.create_index('idx_mtls_certificate_expiry', 'mtls_certificate', ['not_valid_after'])

    # Create mtls_revocation table
    op.create_table(
        'mtls_revocation',
        Column('id', Integer, primary_key=True, autoincrement=True),
        Column('serial_number', String(255), nullable=False, unique=True),
        Column('common_name', String(255), nullable=False),
        Column('revoked_at', DateTime, nullable=False, server_default=func.now()),
        Column('revocation_reason', String(255)),
        Column('created_at', DateTime, nullable=False, server_default=func.now()),
    )
    op.create_index('idx_mtls_revocation_serial', 'mtls_revocation', ['serial_number'], unique=True)


def downgrade() -> None:
    """Drop mTLS certificate management schema."""
    op.drop_table('mtls_revocation')
    op.drop_table('mtls_certificate')
