"""SPIFFE service identity (preferred over static per-server JWT secrets).

Service-to-service authentication standard: SPIFFE/SPIRE is preferred — a peer
proves its identity with a short-lived X.509-SVID over mTLS, never a long-lived
shared secret. In a mesh (Envoy/Istio) the sidecar terminates mTLS and forwards
the verified peer SPIFFE ID in the ``X-Forwarded-Client-Cert`` (XFCC) header.

SPIFFE ID scheme (see penguintech infra standard):

    spiffe://<trust_domain>/<env>/<service>[/<instance>]

DNS servers authenticating to the manager present:

    spiffe://penguintech.io/<env>/dns-server/<server_id>

This module is pure (no Flask/DB) so it is fully unit-testable; the middleware
performs the DB lookup for the resolved ``server_id``.

Security note: XFCC is only trustworthy when injected by the mesh sidecar and
the application is not directly reachable by clients. Never trust XFCC on a
directly-exposed listener.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

_SPIFFE_SCHEME = "spiffe://"
DNS_SERVER_SERVICE = "dns-server"


@dataclass(frozen=True, slots=True)
class SpiffeId:
    """A parsed SPIFFE ID: trust domain + hierarchical path segments."""

    trust_domain: str
    segments: tuple

    @classmethod
    def parse(cls, uri: str) -> "SpiffeId":
        """Parse a ``spiffe://`` URI. Raises ValueError on malformed input."""
        if not uri or not uri.startswith(_SPIFFE_SCHEME):
            raise ValueError("not a spiffe:// URI")
        rest = uri[len(_SPIFFE_SCHEME):]
        # Trust domain is everything up to the first '/'.
        if "/" in rest:
            trust_domain, path = rest.split("/", 1)
        else:
            trust_domain, path = rest, ""
        if not trust_domain:
            raise ValueError("empty SPIFFE trust domain")
        segments = tuple(s for s in path.split("/") if s)
        return cls(trust_domain=trust_domain, segments=segments)

    def in_trust_domain(self, trust_domain: str) -> bool:
        return bool(trust_domain) and self.trust_domain == trust_domain

    def __str__(self) -> str:  # noqa: D105
        path = "/".join(self.segments)
        return f"{_SPIFFE_SCHEME}{self.trust_domain}" + (f"/{path}" if path else "")


@dataclass(frozen=True, slots=True)
class DnsServerIdentity:
    """A SPIFFE identity resolved to a specific DNS server."""

    env: str
    server_id: int
    spiffe_id: str


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def extract_spiffe_ids_from_xfcc(header: str) -> List[str]:
    """Extract SPIFFE URIs from an Envoy XFCC header.

    XFCC is a comma-separated list of elements; each element is a set of
    ``Key=Value`` pairs joined by ``;`` (values may be double-quoted). The
    peer identity is the ``URI`` key, e.g.::

        By=spiffe://td/mgr;Hash=abc;URI=spiffe://td/beta/dns-server/12

    Returns every ``URI=spiffe://...`` value found (order preserved).
    """
    if not header:
        return []
    uris: List[str] = []
    for element in header.split(","):
        for pair in element.split(";"):
            if "=" not in pair:
                continue
            key, _, value = pair.partition("=")
            if key.strip().lower() == "uri":
                value = _unquote(value)
                if value.startswith(_SPIFFE_SCHEME):
                    uris.append(value)
    return uris


def resolve_dns_server_identity(
    xfcc_header: Optional[str], trust_domain: str
) -> Optional[DnsServerIdentity]:
    """Resolve a DNS-server SPIFFE identity from an XFCC header.

    Returns a :class:`DnsServerIdentity` only when the peer presents a SPIFFE ID
    that is in the configured trust domain and matches the DNS-server path
    scheme ``<env>/dns-server/<server_id>`` with a numeric server id. Returns
    ``None`` (fail closed) for any mismatch — the caller then falls back to the
    legacy server JWT.
    """
    if not xfcc_header or not trust_domain:
        return None

    for uri in extract_spiffe_ids_from_xfcc(xfcc_header):
        try:
            sid = SpiffeId.parse(uri)
        except ValueError:
            continue
        if not sid.in_trust_domain(trust_domain):
            continue
        # Expect exactly: <env>/dns-server/<server_id>
        if len(sid.segments) != 3 or sid.segments[1] != DNS_SERVER_SERVICE:
            continue
        env, _service, server_id_str = sid.segments
        if not server_id_str.isdigit():
            continue
        return DnsServerIdentity(
            env=env, server_id=int(server_id_str), spiffe_id=str(sid)
        )
    return None
