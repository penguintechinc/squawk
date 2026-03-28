"""Initial schema — create all manager/backend tables.

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
    sys.path.insert(
        0,
        os.path.join(os.path.dirname(__file__), "..", "..", "..")
    )
    from app.schema import metadata  # noqa: E402

    metadata.create_all(op.get_bind())


def downgrade() -> None:
    sys.path.insert(
        0,
        os.path.join(os.path.dirname(__file__), "..", "..", "..")
    )
    from app.schema import metadata  # noqa: E402

    metadata.drop_all(op.get_bind())
