"""Add SAML 2.0 providers table for Enterprise SAML 2.0 SP configuration.

Revision ID: 012_add_saml_providers
Revises: 011_allow_null_password_hash
"""
from alembic import op
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, func

revision = "012_add_saml_providers"
down_revision = "011_allow_null_password_hash"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create saml_providers table for Enterprise SAML 2.0 SP configuration."""
    op.create_table(
        'saml_providers',
        Column('id', Integer, primary_key=True, autoincrement=True),
        Column('name', String(100), unique=True, nullable=False),  # slug (e.g. 'shibboleth')
        Column('display_name', String(255), nullable=False),  # User-facing name
        Column('idp_entity_id', String(500), nullable=False),  # IdP EntityID (must match Issuer in assertions)
        Column('idp_sso_url', String(500), nullable=False),  # IdP SSO endpoint (HTTP-Redirect binding)
        Column('idp_x509_cert', Text, nullable=False),  # IdP X.509 certificate (PEM, validates assertion XML signatures)
        Column('sp_entity_id', String(500), nullable=False),  # Our SAML SP EntityID
        Column('sp_acs_url', String(500), nullable=False),  # Our Assertion Consumer Service URL (must be https://)
        Column('name_id_format', String(255), nullable=False,
               server_default='urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'),
        Column('want_assertions_signed', Boolean, nullable=False, server_default='1'),  # Require signed assertions
        Column('enabled', Boolean, nullable=False, server_default='0'),
        Column('tenant', String(100), nullable=False, server_default='default'),
        Column('created_at', DateTime, nullable=False, server_default=func.now()),
        Column('updated_at', DateTime, onupdate=func.now()),
    )


def downgrade() -> None:
    """Drop saml_providers table."""
    op.drop_table('saml_providers')
