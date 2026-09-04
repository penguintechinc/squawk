"""
Tests for DHCP lease allocation logic.
Covers discover (offer), request (ack), release, and expiry.
"""

import pytest
from datetime import datetime, timedelta
from app.db import DHCPDatabase
from app.models import DHCPLease


@pytest.mark.asyncio
async def test_discover_returns_available_ip(temp_db):
    """Test DHCP Discover returns an available IP from the pool."""
    db = DHCPDatabase(f"sqlite:///{temp_db}")
    mac = "aa:bb:cc:dd:ee:01"
    pool_id = 1

    offered_ip = db.get_offer(pool_id, mac)

    assert offered_ip is not None
    assert "192.168.1." in offered_ip
    assert int(offered_ip.split(".")[-1]) >= 100
    assert int(offered_ip.split(".")[-1]) <= 200


@pytest.mark.asyncio
async def test_discover_honors_static_reservation(temp_db):
    """Test DHCP Discover honors static IP reservations."""
    from penguin_dal import DB

    # Insert a static reservation
    db_dal = DB(f"sqlite:///{temp_db}")
    reserved_ip = "192.168.1.150"
    mac = "aa:bb:cc:dd:ee:02"
    db_dal.dhcp_reservation.insert(pool_id=1, mac_address=mac, ip_address=reserved_ip, hostname="reserved-device")
    db_dal.commit()
    db_dal.close()

    # Check if DHCP Discover honors reservation
    db = DHCPDatabase(f"sqlite:///{temp_db}")
    offered_ip = db.get_offer(1, mac)

    assert offered_ip == reserved_ip


@pytest.mark.asyncio
async def test_discover_reuses_active_lease(temp_db):
    """Test DHCP Discover returns existing active lease for same MAC."""
    from penguin_dal import DB

    mac = "aa:bb:cc:dd:ee:03"
    leased_ip = "192.168.1.101"
    pool_id = 1

    # Insert an active lease
    db_dal = DB(f"sqlite:///{temp_db}")
    now = datetime.utcnow()
    db_dal.dhcp_lease.insert(
        pool_id=pool_id,
        mac_address=mac,
        ip_address=leased_ip,
        hostname="test-device",
        lease_start=now,
        lease_end=now + timedelta(hours=1),
        status="active",
        created_at=now,
    )
    db_dal.commit()
    db_dal.close()

    # Check if same MAC gets same IP
    db = DHCPDatabase(f"sqlite:///{temp_db}")
    offered_ip = db.get_offer(pool_id, mac)

    assert offered_ip == leased_ip


@pytest.mark.asyncio
async def test_request_creates_persistent_lease(temp_db):
    """Test DHCP Request creates a persistent lease in database."""
    db = DHCPDatabase(f"sqlite:///{temp_db}")
    mac = "aa:bb:cc:dd:ee:04"
    ip = "192.168.1.102"
    hostname = "my-device"
    pool_id = 1

    lease = db.create_lease(pool_id, mac, ip, hostname)

    assert lease.mac_address == mac
    assert lease.ip_address == ip
    assert lease.hostname == hostname
    assert lease.status == "active"
    assert lease.lease_start <= datetime.utcnow()
    assert lease.lease_end > datetime.utcnow()


@pytest.mark.asyncio
async def test_request_renews_existing_lease(temp_db):
    """Test DHCP Request renews an existing lease (updates not inserts)."""
    from penguin_dal import DB

    mac = "aa:bb:cc:dd:ee:05"
    old_ip = "192.168.1.103"
    new_ip = "192.168.1.104"
    pool_id = 1

    # Insert initial lease
    db_dal = DB(f"sqlite:///{temp_db}")
    now = datetime.utcnow()
    db_dal.dhcp_lease.insert(
        pool_id=pool_id,
        mac_address=mac,
        ip_address=old_ip,
        hostname="test-device",
        lease_start=now,
        lease_end=now + timedelta(hours=1),
        status="active",
        created_at=now,
    )
    db_dal.commit()
    db_dal.close()

    # Renew with new IP
    db = DHCPDatabase(f"sqlite:///{temp_db}")
    lease = db.create_lease(pool_id, mac, new_ip, "test-device")

    assert lease.ip_address == new_ip

    # Verify only one lease exists for this MAC (renewal, not new lease)
    db_dal = DB(f"sqlite:///{temp_db}")
    leases = db_dal(db_dal.dhcp_lease.mac_address == mac).select()
    assert len(leases) == 1
    db_dal.close()


@pytest.mark.asyncio
async def test_release_marks_lease_released(temp_db):
    """Test DHCP Release marks lease as released."""
    from penguin_dal import DB

    mac = "aa:bb:cc:dd:ee:06"
    pool_id = 1

    # Insert a lease
    db_dal = DB(f"sqlite:///{temp_db}")
    now = datetime.utcnow()
    db_dal.dhcp_lease.insert(
        pool_id=pool_id,
        mac_address=mac,
        ip_address="192.168.1.105",
        hostname="test-device",
        lease_start=now,
        lease_end=now + timedelta(hours=1),
        status="active",
        created_at=now,
    )
    db_dal.commit()
    db_dal.close()

    # Release the lease
    db = DHCPDatabase(f"sqlite:///{temp_db}")
    success = db.release_lease(pool_id, mac)

    assert success is True

    # Verify status changed to released
    db_dal = DB(f"sqlite:///{temp_db}")
    lease = db_dal(db_dal.dhcp_lease.mac_address == mac).select().first()
    assert lease.status == "released"
    db_dal.close()


@pytest.mark.asyncio
async def test_release_nonexistent_lease_returns_false(temp_db):
    """Test DHCP Release returns False for nonexistent lease."""
    db = DHCPDatabase(f"sqlite:///{temp_db}")
    success = db.release_lease(1, "aa:bb:cc:dd:ee:ff")

    assert success is False


@pytest.mark.asyncio
async def test_expire_old_leases_marks_expired(temp_db):
    """Test background task marks expired leases."""
    from penguin_dal import DB

    mac = "aa:bb:cc:dd:ee:07"
    pool_id = 1

    # Insert an expired lease
    db_dal = DB(f"sqlite:///{temp_db}")
    now = datetime.utcnow()
    db_dal.dhcp_lease.insert(
        pool_id=pool_id,
        mac_address=mac,
        ip_address="192.168.1.106",
        hostname="expired-device",
        lease_start=now - timedelta(hours=25),
        lease_end=now - timedelta(hours=1),  # Expired
        status="active",
        created_at=now - timedelta(hours=25),
    )
    db_dal.commit()
    db_dal.close()

    # Run expiry task
    db = DHCPDatabase(f"sqlite:///{temp_db}")
    count = db.expire_old_leases(pool_id)

    assert count == 1

    # Verify status changed to expired
    db_dal = DB(f"sqlite:///{temp_db}")
    lease = db_dal(db_dal.dhcp_lease.mac_address == mac).select().first()
    assert lease.status == "expired"
    db_dal.close()


@pytest.mark.asyncio
async def test_get_lease_returns_none_if_expired(temp_db):
    """Test get_lease returns None for expired leases."""
    from penguin_dal import DB

    mac = "aa:bb:cc:dd:ee:08"
    pool_id = 1

    # Insert an expired lease
    db_dal = DB(f"sqlite:///{temp_db}")
    now = datetime.utcnow()
    db_dal.dhcp_lease.insert(
        pool_id=pool_id,
        mac_address=mac,
        ip_address="192.168.1.107",
        hostname="expired-device",
        lease_start=now - timedelta(hours=25),
        lease_end=now - timedelta(hours=1),
        status="active",
        created_at=now - timedelta(hours=25),
    )
    db_dal.commit()
    db_dal.close()

    # get_lease should return None and mark as expired
    db = DHCPDatabase(f"sqlite:///{temp_db}")
    lease = db.get_lease(pool_id, mac)

    assert lease is None

    # Verify it was marked expired
    db_dal = DB(f"sqlite:///{temp_db}")
    record = db_dal(db_dal.dhcp_lease.mac_address == mac).select().first()
    assert record.status == "expired"
    db_dal.close()


@pytest.mark.asyncio
async def test_get_pool_stats(temp_db):
    """Test pool statistics calculations."""
    from penguin_dal import DB

    mac1 = "aa:bb:cc:dd:ee:09"
    mac2 = "aa:bb:cc:dd:ee:0a"
    pool_id = 1

    # Insert active leases
    db_dal = DB(f"sqlite:///{temp_db}")
    now = datetime.utcnow()
    db_dal.dhcp_lease.insert(
        pool_id=pool_id,
        mac_address=mac1,
        ip_address="192.168.1.100",
        hostname="device1",
        lease_start=now,
        lease_end=now + timedelta(hours=1),
        status="active",
        created_at=now,
    )
    db_dal.dhcp_lease.insert(
        pool_id=pool_id,
        mac_address=mac2,
        ip_address="192.168.1.101",
        hostname="device2",
        lease_start=now,
        lease_end=now + timedelta(hours=1),
        status="active",
        created_at=now,
    )
    db_dal.commit()
    db_dal.close()

    db = DHCPDatabase(f"sqlite:///{temp_db}")
    active, available, total = db.get_pool_stats(pool_id)

    assert active == 2
    assert total == 101  # 192.168.1.100 to 192.168.1.200 = 101 IPs
    assert available == 99
