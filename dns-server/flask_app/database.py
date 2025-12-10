"""
Shared PyDAL Database Instance
Centralized database connection for the Flask application
"""

import os
from pydal import DAL

# Initialize PyDAL database instance
# This will be shared across all modules
db = DAL(
    os.environ.get('DATABASE_URI', 'sqlite://storage.db'),
    folder=os.path.join(os.path.dirname(__file__), 'databases'),
    migrate=True,
    fake_migrate_all=False
)

# Define tables
from models import define_tables
define_tables(db)
