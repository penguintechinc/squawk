"""
Authentication models for Squawk DNS Manager.
Defines user, auth_user table with global roles.
"""

from pydal import Field
from datetime import datetime


def define_auth_tables(db):
    """Define authentication-related tables."""

    # User table with global roles
    db.define_table('auth_user',
        Field('username', 'string', unique=True, notnull=True, length=100),
        Field('email', 'string', unique=True, notnull=True, length=255),
        Field('password_hash', 'string', notnull=True, length=255),
        Field('global_role', 'string', notnull=True, default='Viewer',
              requires=lambda value: value in ['SystemAdmin', 'OrgAdmin', 'UserManager', 'Viewer']),
        Field('active', 'boolean', default=True, notnull=True),
        Field('created_at', 'datetime', default=lambda: datetime.utcnow(), notnull=True),
        Field('updated_at', 'datetime', update=lambda: datetime.utcnow()),
        format='%(username)s'
    )

    return db
