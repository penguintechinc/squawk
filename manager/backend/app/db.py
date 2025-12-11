"""
PyDAL database initialization for Squawk DNS Manager.
"""

from pydal import DAL, Field
from datetime import datetime
import os


def init_db(app):
    """Initialize PyDAL database connection."""

    db_url = app.config['DB_URL']

    # Create DAL instance
    db = DAL(
        db_url,
        folder=os.path.join(os.path.dirname(__file__), '..', 'databases'),
        migrate=True,
        fake_migrate_all=False,
        pool_size=10
    )

    # Define tables from models
    from app.models.auth import define_auth_tables
    from app.models.team import define_team_tables
    from app.models.dns_server import define_dns_server_tables
    from app.models.dns import define_dns_tables
    from app.models.config import define_config_tables

    define_auth_tables(db)
    define_team_tables(db)
    define_dns_server_tables(db)
    define_dns_tables(db)
    define_config_tables(db)

    return db


def get_current_timestamp():
    """Get current timestamp for database defaults."""
    return datetime.utcnow()
