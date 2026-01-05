"""
Team management models for Squawk DNS Manager.
Defines team and team_member tables with team-level roles.
"""

from pydal import Field
from datetime import datetime


def define_team_tables(db):
    """Define team-related tables."""

    # Team table
    db.define_table('team',
        Field('name', 'string', unique=True, notnull=True, length=100),
        Field('description', 'text'),
        Field('created_at', 'datetime', default=lambda: datetime.utcnow(), notnull=True),
        Field('updated_at', 'datetime', update=lambda: datetime.utcnow()),
        format='%(name)s'
    )

    # Team membership with team-level roles
    # Note: Unique constraint on (team_id, user_id) is enforced at application level
    # as PyDAL doesn't support compound unique constraints directly
    db.define_table('team_member',
        Field('team_id', 'reference team', notnull=True, ondelete='CASCADE'),
        Field('user_id', 'reference auth_user', notnull=True, ondelete='CASCADE'),
        Field('role', 'string', notnull=True, default='TeamMember',
              requires=lambda value: value in ['TeamAdmin', 'TeamMember', 'TeamViewer']),
        Field('joined_at', 'datetime', default=lambda: datetime.utcnow(), notnull=True),
        Field('updated_at', 'datetime', update=lambda: datetime.utcnow())
    )

    return db
