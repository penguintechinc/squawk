"""
Squawk DNS Manager — database connection via penguin-dal.

penguin-dal reflects all tables from the existing schema.
Schema is managed by Alembic migrations in manager/backend/alembic/.
"""

from penguin_dal import DB


def init_db(app) -> DB:
    """Create a penguin-dal DB connected to the configured URL."""
    db_url = app.config["DB_URL"]
    db = DB(db_url, pool_size=10)
    return db
