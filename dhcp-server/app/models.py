"""
Data Models for DHCP Server
Slotted dataclasses for memory efficiency and type safety.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional


@dataclass(slots=True, frozen=True)
class DHCPOffer:
    """DHCP Discover response (offer)."""

    status: str
    offered_ip: str
    subnet_mask: str
    gateway: str
    dns_servers: List[str]
    lease_time: int
    server_id: str
    transaction_id: str


@dataclass(slots=True, frozen=True)
class DHCPAck:
    """DHCP Request response (acknowledgment)."""

    status: str
    assigned_ip: str
    subnet_mask: str
    gateway: str
    dns_servers: List[str]
    lease_time: int
    renewal_time: int  # T1 (50% of lease_time)
    rebinding_time: int  # T2 (87.5% of lease_time)


@dataclass(slots=True, frozen=True)
class DHCPLease:
    """Active or historical DHCP lease."""

    mac_address: str
    ip_address: str
    hostname: Optional[str]
    lease_start: datetime
    lease_end: datetime
    status: str  # 'active', 'expired', 'released'
    subnet_mask: str
    gateway: str
    dns_servers: List[str]
    lease_time: int
    renewal_time: int
    rebinding_time: int


@dataclass(slots=True)
class DHCPReservation:
    """Static IP reservation (MAC -> IP mapping)."""

    mac_address: str
    ip_address: str
    hostname: Optional[str] = None
    description: Optional[str] = None


@dataclass(slots=True)
class DHCPPoolConfig:
    """DHCP pool configuration snapshot."""

    name: str
    network: str
    range_start: str
    range_end: str
    gateway: str
    dns_servers: List[str]
    lease_duration: int
    subnet_mask: str = "255.255.255.0"
