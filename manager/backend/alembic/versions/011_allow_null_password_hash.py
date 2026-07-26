"""Make password_hash nullable for SSO-provisioned users (no local login).

Revision ID: 011_allow_null_password_hash
Revises: 010_add_sso_login_attempts
"""
from alembic import op
from sqlalchemy import String

revision = "011_allow_null_password_hash"
down_revision = "010_add_sso_login_attempts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Make auth_user.password_hash nullable."""
    op.alter_column('auth_user', 'password_hash', nullable=True)


def downgrade() -> None:
    """Revert password_hash to not null."""
    op.alter_column('auth_user', 'password_hash', nullable=False)
