"""
Squawk DNS Server — database connection via penguin-dal.

penguin-dal auto-reflects existing tables from the database.
Schema is defined in schema.py. Alembic creates/migrates tables.
"""

import os
from penguin_dal import DB

# penguin-dal connects and reflects all tables defined by Alembic migrations.
# For tests, the test conftest creates the schema before this module is imported.
db = DB(
    os.environ.get("DATABASE_URI", "sqlite:///storage.db"),
    pool_size=10,
)
