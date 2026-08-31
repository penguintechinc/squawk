"""Add account lockout tracking columns to auth_user.

Backs exponential-backoff lockout after repeated failed logins
(app.services.auth_service.AuthService.authenticate_user).

Revision ID: 014_add_login_lockout
Revises: 013_add_saml_assertion_ids
"""
from alembic import op
import sqlalchemy as sa

revision = "014_add_login_lockout"
down_revision = "013_add_saml_assertion_ids"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add failed_login_count and locked_until to auth_user."""
    op.add_column(
        'auth_user',
        sa.Column('failed_login_count', sa.Integer(), nullable=False, server_default='0'),
    )
    op.add_column(
        'auth_user',
        sa.Column('locked_until', sa.DateTime(), nullable=True),
    )


def downgrade() -> None:
    """Drop account lockout columns from auth_user."""
    op.drop_column('auth_user', 'locked_until')
    op.drop_column('auth_user', 'failed_login_count')
