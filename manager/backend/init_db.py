#!/usr/bin/env python3
"""
Database initialization script for Squawk DNS Manager.
Creates initial admin user and sets up tables.
"""

import os
import sys
import secrets
from datetime import datetime
from typing import Optional

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

from app import create_app
from app.services.auth_service import AuthService


def init_database():
    """Initialize database with tables and default admin user."""
    print("Initializing Squawk DNS Manager database...")

    app = create_app()

    with app.app_context():
        db = app.db

        # Tables are automatically created by PyDAL migrations
        print("✓ Database tables created")

        # Check if admin user already exists
        admin_exists = db(db.auth_user.username == 'admin').count() > 0

        if not admin_exists:
            # Read admin password from env or generate random strong password
            admin_password: Optional[str] = os.getenv('SQUAWK_ADMIN_PASSWORD')
            if not admin_password:
                admin_password = secrets.token_urlsafe(16)
                print("\n⚠️  ADMIN PASSWORD GENERATED (not from env)")

            password_hash = AuthService.hash_password(admin_password)

            insert_data = {
                'username': 'admin',
                'email': 'admin@squawkdns.local',
                'password_hash': password_hash,
                'global_role': 'SystemAdmin',
                'active': True,
                'created_at': datetime.utcnow()
            }

            # Check if must_change_password column exists in auth_user table
            try:
                if hasattr(db.auth_user, 'must_change_password'):
                    insert_data['must_change_password'] = True
            except (AttributeError, TypeError):
                # Column does not exist; skip it (should be added to schema separately)
                pass

            admin_id = db.auth_user.insert(**insert_data)
            db.commit()

            print("✓ Created default admin user")
            print("  Username: admin")
            # SECURITY: never print the password literal -- it persists in
            # container/CI logs. Only a masked note is safe to emit here.
            if os.getenv('SQUAWK_ADMIN_PASSWORD'):
                print("  Password: set from SQUAWK_ADMIN_PASSWORD env var")
            else:
                print("  Password: generated -- retrieve via a secure channel (not logged)")
            print("  Role: SystemAdmin")
            print("\n⚠️  IMPORTANT: Change the admin password immediately after first login!")
        else:
            print("✓ Admin user already exists")

        # Create example team
        team_exists = db(db.team.name == 'Default Team').count() > 0
        if not team_exists:
            team_id = db.team.insert(
                name='Default Team',
                description='Default team for new users',
                created_at=datetime.utcnow()
            )
            db.commit()
            print("✓ Created default team")

        # Create example public zone
        zone_exists = db(db.dns_zone.name == 'example.com').count() > 0
        if not zone_exists:
            zone_id = db.dns_zone.insert(
                name='example.com',
                visibility='public',
                description='Example public DNS zone',
                created_at=datetime.utcnow()
            )

            # Add example DNS records
            db.dns_record.insert(
                zone_id=zone_id,
                name='example.com',
                type='A',
                value='93.184.216.34',
                ttl=300,
                created_at=datetime.utcnow()
            )

            db.dns_record.insert(
                zone_id=zone_id,
                name='www.example.com',
                type='CNAME',
                value='example.com',
                ttl=300,
                created_at=datetime.utcnow()
            )

            db.commit()
            print("✓ Created example DNS zone and records")

        print("\n✅ Database initialization complete!")
        print("\nNext steps:")
        print("1. Change the admin password: POST /api/v1/auth/change-password")
        print("2. Create additional users: POST /api/v1/users")
        print("3. Create DNS servers: POST /api/v1/dns-servers")
        print("\nStart the server with: gunicorn wsgi:app")


if __name__ == '__main__':
    try:
        init_database()
    except Exception as e:
        print(f"\n❌ Error initializing database: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
