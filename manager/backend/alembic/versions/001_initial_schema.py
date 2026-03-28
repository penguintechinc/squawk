"""Initial schema — create all manager/backend tables.

Revision ID: 001_initial
Revises: None
"""
import os
import sys

from alembic import op

# Add project root to path for imports
sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "..", "..")
)
from app.schema import metadata  # noqa: E402

revision = "001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    metadata.create_all(op.get_bind())


def downgrade() -> None:
    metadata.drop_all(op.get_bind())
