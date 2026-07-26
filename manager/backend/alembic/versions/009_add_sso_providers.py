"""Add SSO OIDC providers table for Enterprise SSO feature.

SAML 2.0 is deliberately deferred to a later revision.

Revision ID: 009_add_sso_providers
Revises: 008_add_mfa_fields
"""
from alembic import op
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, func

revision = "009_add_sso_providers"
down_revision = "008_add_mfa_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create sso_providers table for Enterprise OIDC configuration."""
    op.create_table(
        'sso_providers',
        Column('id', Integer, primary_key=True, autoincrement=True),
        Column('name', String(100), unique=True, nullable=False),  # slug (e.g. 'okta')
        Column('display_name', String(255), nullable=False),  # User-facing name
        Column('issuer', String(500), nullable=False),  # IdP issuer URL (iss claim)
        Column('client_id', String(255), nullable=False),
        Column('client_secret', Text, nullable=False),  # Fernet-encrypted at rest
        Column('authorization_endpoint', String(500), nullable=False),  # Must be https:// at validation time
        Column('token_endpoint', String(500), nullable=False),  # Must be https:// at validation time
        Column('jwks_url', String(500), nullable=False),  # OIDC JWKS endpoint for ID token sig verification
        Column('scopes', String(500), nullable=False, server_default='openid email profile'),
        Column('enabled', Boolean, nullable=False, server_default='0'),
        Column('tenant', String(100), nullable=False, server_default='default'),
        Column('created_at', DateTime, nullable=False, server_default=func.now()),
        Column('updated_at', DateTime, onupdate=func.now()),
    )


def downgrade() -> None:
    """Drop sso_providers table."""
    op.drop_table('sso_providers')
