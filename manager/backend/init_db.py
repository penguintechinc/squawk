#!/usr/bin/env python3
"""
Database initialization script for Squawk DNS Manager.
Creates initial admin user and sets up tables.
"""

import os
import sys
from datetime import datetime

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
            # Create default admin user
            password_hash = AuthService.hash_password('admin123')

            admin_id = db.auth_user.insert(
                username='admin',
                email='admin@squawkdns.local',
                password_hash=password_hash,
                global_role='SystemAdmin',
                active=True,
                created_at=datetime.utcnow()
            )

            db.commit()

            print("✓ Created default admin user")
            print("  Username: admin")
            print("  Password: admin123")
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
