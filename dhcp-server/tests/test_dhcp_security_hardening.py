"""
Regression tests for DHCP server security hardening fixes.

Covers:
- (c) /dhcp/request with an out-of-range or conflicting IP is rejected
  (DHCPDatabase.validate_requested_ip -- the check the /dhcp/request
  handler now applies before create_lease).
- (d) invalid MAC address / hostname are rejected (app.validation).
"""

from datetime import datetime, timedelta

import pytest

from app.db import DHCPDatabase
from app.validation import is_valid_mac, sanitize_hostname


# ---------------------------------------------------------------------------
# (c) /dhcp/request IP validation -- out of range / lease conflict
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_validate_requested_ip_accepts_in_range_unleased_ip(temp_db):
    """A requested IP that is in range and not leased to anyone is accepted."""
    db = DHCPDatabase(f"sqlite:///{temp_db}")

    reason = db.validate_requested_ip(1, "aa:bb:cc:dd:ee:10", "192.168.1.120")

    assert reason is None


@pytest.mark.asyncio
async def test_validate_requested_ip_rejects_out_of_range(temp_db):
    """Regression: a client-supplied IP outside the pool range must be rejected."""
    db = DHCPDatabase(f"sqlite:///{temp_db}")

    reason = db.validate_requested_ip(1, "aa:bb:cc:dd:ee:11", "10.0.0.5")

    assert reason is not None
    assert "range" in reason


@pytest.mark.asyncio
async def test_validate_requested_ip_rejects_malformed_ip(temp_db):
    db = DHCPDatabase(f"sqlite:///{temp_db}")

    reason = db.validate_requested_ip(1, "aa:bb:cc:dd:ee:12", "not-an-ip")

    assert reason is not None
    assert "invalid" in reason.lower()


@pytest.mark.asyncio
async def test_validate_requested_ip_rejects_active_conflict(temp_db):
    """Regression: an IP already actively leased to a DIFFERENT MAC must be
    rejected -- this is the lease-hijack path /dhcp/request previously
    allowed by passing requested_ip straight to create_lease."""
    from penguin_dal import DB

    pool_id = 1
    leased_ip = "192.168.1.150"
    owner_mac = "aa:bb:cc:dd:ee:13"
    attacker_mac = "aa:bb:cc:dd:ee:14"

    db_dal = DB(f"sqlite:///{temp_db}")
    now = datetime.utcnow()
    db_dal.dhcp_lease.insert(
        pool_id=pool_id,
        mac_address=owner_mac,
        ip_address=leased_ip,
        hostname="owner-device",
        lease_start=now,
        lease_end=now + timedelta(hours=1),
        status="active",
        created_at=now,
    )
    db_dal.commit()
    db_dal.close()

    db = DHCPDatabase(f"sqlite:///{temp_db}")
    reason = db.validate_requested_ip(pool_id, attacker_mac, leased_ip)

    assert reason is not None
    assert "leased" in reason


@pytest.mark.asyncio
async def test_validate_requested_ip_allows_same_mac_renewal(temp_db):
    """A MAC renewing its OWN active lease for the same IP is not a conflict."""
    from penguin_dal import DB

    pool_id = 1
    ip = "192.168.1.151"
    mac = "aa:bb:cc:dd:ee:15"

    db_dal = DB(f"sqlite:///{temp_db}")
    now = datetime.utcnow()
    db_dal.dhcp_lease.insert(
        pool_id=pool_id,
        mac_address=mac,
        ip_address=ip,
        hostname="my-device",
        lease_start=now,
        lease_end=now + timedelta(hours=1),
        status="active",
        created_at=now,
    )
    db_dal.commit()
    db_dal.close()

    db = DHCPDatabase(f"sqlite:///{temp_db}")
    reason = db.validate_requested_ip(pool_id, mac, ip)

    assert reason is None


@pytest.mark.asyncio
async def test_validate_requested_ip_allows_conflict_with_expired_lease(temp_db):
    """An IP leased to another MAC, but whose lease has already expired, is
    available again (not treated as a live conflict)."""
    from penguin_dal import DB

    pool_id = 1
    ip = "192.168.1.152"
    old_mac = "aa:bb:cc:dd:ee:16"
    new_mac = "aa:bb:cc:dd:ee:17"

    db_dal = DB(f"sqlite:///{temp_db}")
    now = datetime.utcnow()
    db_dal.dhcp_lease.insert(
        pool_id=pool_id,
        mac_address=old_mac,
        ip_address=ip,
        hostname="old-device",
        lease_start=now - timedelta(hours=25),
        lease_end=now - timedelta(hours=1),  # expired
        status="active",
        created_at=now - timedelta(hours=25),
    )
    db_dal.commit()
    db_dal.close()

    db = DHCPDatabase(f"sqlite:///{temp_db}")
    reason = db.validate_requested_ip(pool_id, new_mac, ip)

    assert reason is None


# ---------------------------------------------------------------------------
# (d) MAC address / hostname validation
# ---------------------------------------------------------------------------
class TestMacValidation:
    @pytest.mark.parametrize(
        "mac",
        [
            "aa:bb:cc:dd:ee:ff",
            "AA:BB:CC:DD:EE:FF",
            "00:11:22:33:44:55",
        ],
    )
    def test_valid_mac_accepted(self, mac):
        assert is_valid_mac(mac) is True

    @pytest.mark.parametrize(
        "mac",
        [
            "",
            "not-a-mac",
            "aa:bb:cc:dd:ee",  # too short
            "aa:bb:cc:dd:ee:ff:11",  # too long
            "aa:bb:cc:dd:ee:gg",  # invalid hex
            "aabbccddeeff",  # missing separators
            "aa-bb-cc-dd-ee-ff",  # wrong separator
            "aa:bb:cc:dd:ee:ff; DROP TABLE dhcp_lease;",  # injection attempt
            "aa:bb:cc:dd:ee:ff\n",  # trailing control char
        ],
    )
    def test_invalid_mac_rejected(self, mac):
        assert is_valid_mac(mac) is False

    def test_non_string_mac_rejected(self):
        assert is_valid_mac(None) is False  # type: ignore[arg-type]
        assert is_valid_mac(12345) is False  # type: ignore[arg-type]


class TestHostnameValidation:
    @pytest.mark.parametrize(
        "hostname,expected",
        [
            ("my-device", "my-device"),
            ("device1", "device1"),
            ("host.example.com", "host.example.com"),
            ("  padded-host  ", "padded-host"),
        ],
    )
    def test_valid_hostname_normalized(self, hostname, expected):
        assert sanitize_hostname(hostname) == expected

    @pytest.mark.parametrize(
        "hostname",
        [
            "",
            "   ",
            "-starts-with-hyphen",
            "ends-with-hyphen-",
            "has a space",
            "control\x00char",
            "control\nchar",
            "a" * 254,  # exceeds 253-char limit
            "<script>alert(1)</script>",
        ],
    )
    def test_invalid_hostname_rejected(self, hostname):
        assert sanitize_hostname(hostname) is None

    def test_non_string_hostname_rejected(self):
        assert sanitize_hostname(None) is None
        assert sanitize_hostname(12345) is None  # type: ignore[arg-type]
