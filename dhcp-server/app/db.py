"""
Database Module for DHCP Server
Uses penguin-dal for all runtime database operations.
"""
import asyncio
import logging
import ipaddress
from datetime import datetime, timedelta
from typing import Optional, List, Tuple

from penguin_dal import DB
from app.config import LEASE_TIME, POOL_START, POOL_END
from app.models import DHCPLease, DHCPReservation

logger = logging.getLogger(__name__)


class DHCPDatabase:
    """
    Manages DHCP lease persistence using penguin-dal.
    All runtime database operations go through this class (never raw SQLAlchemy).
    """

    def __init__(self, db_url: Optional[str] = None) -> None:
        """
        Initialize database connection.

        Args:
            db_url: Database URL (defaults to DATABASE_URL from config)
        """
        if db_url is None:
            # Read from config at init time (allows test override)
            from app.config import DATABASE_URL
            db_url = DATABASE_URL
        self.db_url = db_url
        self._db: Optional[DB] = None

    def _get_db(self) -> DB:
        """Get or create database connection."""
        if not self._db:
            self._db = DB(self.db_url)
        return self._db

    def close(self) -> None:
        """Close database connection."""
        if self._db:
            self._db.close()
            self._db = None

    def get_offer(self, pool_id: int, mac: str, requested_ip: Optional[str] = None) -> Optional[str]:
        """
        Get an available IP for DHCP Discover.
        Honors static reservations first, then picks free IP.

        Args:
            pool_id: DHCP pool ID
            mac: Client MAC address
            requested_ip: IP requested by client (optional)

        Returns:
            Available IP address or None
        """
        db = self._get_db()

        try:
            # Check for existing active lease
            existing_lease = db(
                (db.dhcp_lease.mac_address == mac) &
                (db.dhcp_lease.pool_id == pool_id) &
                (db.dhcp_lease.status == 'active')
            ).select().first()

            if existing_lease and not self._is_expired(existing_lease):
                return existing_lease.ip_address

            # Check for static reservation for this MAC
            reservation = db(
                (db.dhcp_reservation.mac_address == mac) &
                (db.dhcp_reservation.pool_id == pool_id)
            ).select().first()

            if reservation:
                return reservation.ip_address

            # Check if requested IP is available
            if requested_ip:
                # Verify it's in pool range
                if self._is_in_range(requested_ip):
                    # Check if already leased to someone else
                    conflicting = db(
                        (db.dhcp_lease.ip_address == requested_ip) &
                        (db.dhcp_lease.pool_id == pool_id) &
                        (db.dhcp_lease.status == 'active')
                    ).select().first()

                    if not conflicting:
                        return requested_ip

            # Find first available IP in range
            available_ip = self._find_free_ip(pool_id)
            return available_ip

        finally:
            pass  # Don't close db here, keep connection open

    def _is_in_range(self, ip: str) -> bool:
        """Check if IP is in the pool range."""
        try:
            ip_int = int(ipaddress.IPv4Address(ip))
            start_int = int(ipaddress.IPv4Address(POOL_START))
            end_int = int(ipaddress.IPv4Address(POOL_END))
            return start_int <= ip_int <= end_int
        except ValueError:
            return False

    def _find_free_ip(self, pool_id: int) -> Optional[str]:
        """Find first free IP in pool range."""
        db = self._get_db()

        try:
            start_int = int(ipaddress.IPv4Address(POOL_START))
            end_int = int(ipaddress.IPv4Address(POOL_END))

            for ip_int in range(start_int, end_int + 1):
                ip_str = str(ipaddress.IPv4Address(ip_int))

                # Check if this IP is in active lease
                existing = db(
                    (db.dhcp_lease.ip_address == ip_str) &
                    (db.dhcp_lease.pool_id == pool_id) &
                    (db.dhcp_lease.status == 'active')
                ).select().first()

                if not existing:
                    return ip_str

            return None
        finally:
            pass

    def create_lease(self, pool_id: int, mac: str, ip: str,
                     hostname: Optional[str] = None) -> DHCPLease:
        """
        Create or renew a lease.
        Upserts into dhcp_lease table with status='active'.

        Args:
            pool_id: DHCP pool ID
            mac: MAC address
            ip: Assigned IP
            hostname: Optional hostname

        Returns:
            DHCPLease object
        """
        db = self._get_db()

        try:
            now = datetime.utcnow()
            lease_end = now + timedelta(seconds=LEASE_TIME)

            # Check for existing lease
            existing = db(
                (db.dhcp_lease.mac_address == mac) &
                (db.dhcp_lease.pool_id == pool_id)
            ).select().first()

            if existing:
                # Update existing lease
                db(
                    (db.dhcp_lease.mac_address == mac) &
                    (db.dhcp_lease.pool_id == pool_id)
                ).update(
                    ip_address=ip,
                    hostname=hostname,
                    lease_start=now,
                    lease_end=lease_end,
                    status='active'
                )
                logger.info(f'Renewed lease: {mac} -> {ip}')
            else:
                # Create new lease
                db.dhcp_lease.insert(
                    pool_id=pool_id,
                    mac_address=mac,
                    ip_address=ip,
                    hostname=hostname,
                    lease_start=now,
                    lease_end=lease_end,
                    status='active'
                )
                logger.info(f'Created lease: {mac} -> {ip}')

            # Get pool config for full lease details
            pool = db(db.dhcp_pool.id == pool_id).select().first()
            if not pool:
                raise ValueError(f'Pool {pool_id} not found')

            dns_servers = pool.dns_servers or ['8.8.8.8', '8.8.4.4']
            return DHCPLease(
                mac_address=mac,
                ip_address=ip,
                hostname=hostname,
                lease_start=now,
                lease_end=lease_end,
                status='active',
                subnet_mask=pool.subnet_mask or '255.255.255.0',
                gateway=pool.gateway,
                dns_servers=dns_servers,
                lease_time=pool.lease_duration,
                renewal_time=pool.lease_duration // 2,
                rebinding_time=int(pool.lease_duration * 0.875)
            )

        finally:
            pass

    def release_lease(self, pool_id: int, mac: str) -> bool:
        """
        Release a lease, mark as 'released'.

        Args:
            pool_id: DHCP pool ID
            mac: MAC address

        Returns:
            True if release successful, False if lease not found
        """
        db = self._get_db()

        try:
            existing = db(
                (db.dhcp_lease.mac_address == mac) &
                (db.dhcp_lease.pool_id == pool_id)
            ).select().first()

            if not existing:
                logger.warning(f'Release: lease not found for {mac}')
                return False

            db(
                (db.dhcp_lease.mac_address == mac) &
                (db.dhcp_lease.pool_id == pool_id)
            ).update(status='released')

            logger.info(f'Released lease: {mac}')
            return True

        finally:
            pass

    def get_lease(self, pool_id: int, mac: str) -> Optional[DHCPLease]:
        """
        Get current lease for MAC, return None if expired.

        Args:
            pool_id: DHCP pool ID
            mac: MAC address

        Returns:
            DHCPLease object or None
        """
        db = self._get_db()

        try:
            lease = db(
                (db.dhcp_lease.mac_address == mac) &
                (db.dhcp_lease.pool_id == pool_id)
            ).select().first()

            if not lease:
                return None

            # Check expiration
            if self._is_expired(lease):
                # Mark as expired
                db(
                    (db.dhcp_lease.id == lease.id)
                ).update(status='expired')
                return None

            # Get pool config
            pool = db(db.dhcp_pool.id == pool_id).select().first()
            if not pool:
                return None

            dns_servers = pool.dns_servers or ['8.8.8.8', '8.8.4.4']
            return DHCPLease(
                mac_address=lease.mac_address,
                ip_address=lease.ip_address,
                hostname=lease.hostname,
                lease_start=lease.lease_start,
                lease_end=lease.lease_end,
                status=lease.status,
                subnet_mask=pool.subnet_mask or '255.255.255.0',
                gateway=pool.gateway,
                dns_servers=dns_servers,
                lease_time=pool.lease_duration,
                renewal_time=pool.lease_duration // 2,
                rebinding_time=int(pool.lease_duration * 0.875)
            )

        finally:
            pass

    def _is_expired(self, lease) -> bool:
        """Check if lease is expired."""
        return datetime.utcnow() > lease.lease_end

    def expire_old_leases(self, pool_id: int) -> int:
        """
        Mark expired leases as 'expired'.
        Called by background task.

        Args:
            pool_id: DHCP pool ID

        Returns:
            Number of leases expired
        """
        db = self._get_db()

        try:
            now = datetime.utcnow()
            expired = db(
                (db.dhcp_lease.pool_id == pool_id) &
                (db.dhcp_lease.status == 'active') &
                (db.dhcp_lease.lease_end < now)
            ).select()

            count = len(expired)
            if count > 0:
                db(
                    (db.dhcp_lease.pool_id == pool_id) &
                    (db.dhcp_lease.status == 'active') &
                    (db.dhcp_lease.lease_end < now)
                ).update(status='expired')
                logger.info(f'Expired {count} old leases from pool {pool_id}')

            return count

        finally:
            pass

    def get_pool_stats(self, pool_id: int) -> Tuple[int, int, int]:
        """
        Get pool statistics.

        Args:
            pool_id: DHCP pool ID

        Returns:
            (active_count, available_count, total_count)
        """
        db = self._get_db()

        try:
            now = datetime.utcnow()

            # Count active leases
            active = db(
                (db.dhcp_lease.pool_id == pool_id) &
                (db.dhcp_lease.status == 'active') &
                (db.dhcp_lease.lease_end > now)
            ).count()

            # Total IPs in range
            total = int(ipaddress.IPv4Address(POOL_END)) - int(ipaddress.IPv4Address(POOL_START)) + 1

            available = total - active

            return active, available, total

        finally:
            pass
