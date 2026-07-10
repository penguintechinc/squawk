"""Tests for SPIFFE/mTLS service identity and the prefer-SPIFFE server auth path.

Covers SPIFFE ID parsing, Envoy XFCC extraction, DNS-server identity resolution
(fail-closed on any mismatch), and the middleware preferring SPIFFE over the
legacy static-secret server JWT.
"""

from __future__ import annotations

import pytest
from flask import g

from app.services.spiffe import (
    DnsServerIdentity,
    SpiffeId,
    extract_spiffe_ids_from_xfcc,
    resolve_dns_server_identity,
)

TD = "penguintech.io"


# ---------------------------------------------------------------------------
# SpiffeId parsing
# ---------------------------------------------------------------------------
def test_parse_valid_spiffe_id():
    sid = SpiffeId.parse("spiffe://penguintech.io/beta/dns-server/12")
    assert sid.trust_domain == "penguintech.io"
    assert sid.segments == ("beta", "dns-server", "12")
    assert str(sid) == "spiffe://penguintech.io/beta/dns-server/12"


def test_parse_trust_domain_only():
    sid = SpiffeId.parse("spiffe://penguintech.io")
    assert sid.trust_domain == "penguintech.io"
    assert sid.segments == ()
    assert str(sid) == "spiffe://penguintech.io"


@pytest.mark.parametrize("bad", ["", "https://penguintech.io/x", "spiffe://", "spiffe:///path"])
def test_parse_rejects_malformed(bad):
    with pytest.raises(ValueError):
        SpiffeId.parse(bad)


def test_in_trust_domain():
    sid = SpiffeId.parse("spiffe://penguintech.io/beta/dns-server/1")
    assert sid.in_trust_domain("penguintech.io") is True
    assert sid.in_trust_domain("evil.example") is False
    assert sid.in_trust_domain("") is False


# ---------------------------------------------------------------------------
# XFCC header extraction
# ---------------------------------------------------------------------------
def test_extract_single_uri():
    hdr = "By=spiffe://td/mgr;Hash=abc123;URI=spiffe://penguintech.io/beta/dns-server/3"
    assert extract_spiffe_ids_from_xfcc(hdr) == ["spiffe://penguintech.io/beta/dns-server/3"]


def test_extract_quoted_uri_and_case_insensitive_key():
    hdr = 'uri="spiffe://penguintech.io/prod/dns-server/9";Hash=xyz'
    assert extract_spiffe_ids_from_xfcc(hdr) == ["spiffe://penguintech.io/prod/dns-server/9"]


def test_extract_multiple_xfcc_elements():
    hdr = (
        "By=spiffe://td/a;URI=spiffe://penguintech.io/beta/dns-server/1,"
        "By=spiffe://td/b;URI=spiffe://penguintech.io/beta/dns-server/2"
    )
    assert extract_spiffe_ids_from_xfcc(hdr) == [
        "spiffe://penguintech.io/beta/dns-server/1",
        "spiffe://penguintech.io/beta/dns-server/2",
    ]


def test_extract_ignores_non_uri_and_empty():
    assert extract_spiffe_ids_from_xfcc("By=spiffe://td/mgr;Hash=abc") == []
    assert extract_spiffe_ids_from_xfcc("") == []
    assert extract_spiffe_ids_from_xfcc("URI=https://not-spiffe") == []


# ---------------------------------------------------------------------------
# DNS-server identity resolution (fail-closed)
# ---------------------------------------------------------------------------
def test_resolve_valid_identity():
    hdr = "URI=spiffe://penguintech.io/beta/dns-server/42"
    ident = resolve_dns_server_identity(hdr, TD)
    assert ident == DnsServerIdentity(
        env="beta", server_id=42, spiffe_id="spiffe://penguintech.io/beta/dns-server/42"
    )


@pytest.mark.parametrize(
    "uri",
    [
        "spiffe://evil.example/beta/dns-server/1",   # wrong trust domain
        "spiffe://penguintech.io/beta/dns-client/1",  # wrong service
        "spiffe://penguintech.io/beta/dns-server/abc",  # non-numeric id
        "spiffe://penguintech.io/beta/dns-server",      # missing id segment
        "spiffe://penguintech.io/beta/dns-server/1/x",  # extra segment
    ],
)
def test_resolve_rejects_mismatches(uri):
    assert resolve_dns_server_identity(f"URI={uri}", TD) is None


def test_resolve_none_on_empty_header_or_trust_domain():
    assert resolve_dns_server_identity(None, TD) is None
    assert resolve_dns_server_identity("URI=spiffe://penguintech.io/beta/dns-server/1", "") is None


def test_resolve_picks_first_valid_of_multiple():
    hdr = (
        "URI=spiffe://evil.example/beta/dns-server/1,"
        "URI=spiffe://penguintech.io/beta/dns-server/7"
    )
    ident = resolve_dns_server_identity(hdr, TD)
    assert ident is not None and ident.server_id == 7


# ---------------------------------------------------------------------------
# Middleware: SPIFFE preferred over legacy JWT
# ---------------------------------------------------------------------------
class _FakeServer:
    id = 5
    name = "edge-1"
    region = "us-east"


class _FakeTable:
    def __getitem__(self, key):
        return _FakeServer() if key == 5 else None


class _FakeDB:
    dns_server = _FakeTable()


def _dummy_view():
    return "reached", 200


def test_server_auth_prefers_spiffe(app, monkeypatch):
    from app.middleware import auth as auth_mod

    monkeypatch.setitem(app.config, "SPIFFE_ENABLED", True)  # opt-in required
    monkeypatch.setattr(app, "db", _FakeDB(), raising=False)
    view = auth_mod.server_token_required(_dummy_view)
    hdr = {"X-Forwarded-Client-Cert": "URI=spiffe://penguintech.io/beta/dns-server/5"}
    with app.test_request_context(headers=hdr):
        result = view()
        assert result == ("reached", 200)
        assert g.current_server["auth_method"] == "spiffe"
        assert g.current_server["server_id"] == 5


def test_spiffe_off_by_default_ignores_xfcc(app, monkeypatch):
    """Fail-safe: with SPIFFE disabled (the default), a spoofed XFCC header is
    ignored — the caller cannot forge a server identity via the header alone."""
    from app.middleware import auth as auth_mod

    assert app.config.get("SPIFFE_ENABLED") is False  # default off
    monkeypatch.setattr(app, "db", _FakeDB(), raising=False)
    hdr = {"X-Forwarded-Client-Cert": "URI=spiffe://penguintech.io/beta/dns-server/5"}
    with app.test_request_context(headers=hdr):
        assert auth_mod._authenticate_server_via_spiffe() is None


def test_server_auth_falls_back_to_jwt_when_no_spiffe(app, monkeypatch):
    """No SPIFFE identity → fall through to the JWT path (401 with no token)."""
    from app.middleware import auth as auth_mod

    monkeypatch.setattr(app, "db", _FakeDB(), raising=False)
    view = auth_mod.server_token_required(_dummy_view)
    with app.test_request_context():  # no XFCC, no Authorization
        _body, status = view()
    assert status == 401


def test_spiffe_disabled_skips_spiffe(app, monkeypatch):
    from app.middleware import auth as auth_mod

    monkeypatch.setitem(app.config, "SPIFFE_ENABLED", False)
    monkeypatch.setattr(app, "db", _FakeDB(), raising=False)
    hdr = {"X-Forwarded-Client-Cert": "URI=spiffe://penguintech.io/beta/dns-server/5"}
    with app.test_request_context(headers=hdr):
        assert auth_mod._authenticate_server_via_spiffe() is None
