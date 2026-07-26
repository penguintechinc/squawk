"""Add server-side login-attempt store for OIDC CSRF + state/nonce binding.

Replaces front-channel JWT state with opaque tokens. Addresses:
- CRITICAL: code_verifier leak in state JWT
- HIGH: CSRF via missing browser binding
- MEDIUM: nonce persistence and validation

Revision ID: 010_add_sso_login_attempts
Revises: 009_add_sso_providers
"""
from alembic import op
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, Index, func

revision = "010_add_sso_login_attempts"
down_revision = "009_add_sso_providers"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create sso_login_attempts table for server-side state binding."""
    op.create_table(
        'sso_login_attempts',
        Column('id', Integer, primary_key=True, autoincrement=True),
        Column('opaque_state', String(100), unique=True, nullable=False, index=True),  # random secrets.token_urlsafe(32)
        Column('provider', String(100), nullable=False),
        Column('code_verifier', String(200), nullable=False),  # PKCE verifier
        Column('nonce', String(200), nullable=False),  # ID token nonce validation
        Column('browser_binding_hash', String(64), nullable=False),  # SHA-256 of binding cookie
        Column('created_at', DateTime, nullable=False, server_default=func.now()),
        Column('used', Boolean, nullable=False, server_default='0'),  # single-use enforcement
    )


def downgrade() -> None:
    """Drop sso_login_attempts table."""
    op.drop_table('sso_login_attempts')
