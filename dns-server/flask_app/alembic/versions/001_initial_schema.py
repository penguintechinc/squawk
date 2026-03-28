"""Initial schema — create all dns-server tables.

Revision ID: 001_initial
Revises: None
"""
from __future__ import annotations

import os
import sys

from alembic import op

revision = "001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create all tables defined in schema.py."""
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from schema import metadata  # noqa: E402

    metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    """Drop all tables defined in schema.py."""
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from schema import metadata  # noqa: E402

    metadata.drop_all(bind=op.get_bind())
