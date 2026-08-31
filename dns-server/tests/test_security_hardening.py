"""
Regression tests for DNS server security hardening fixes:

- Raw bearer tokens must never leak into Prometheus metric labels.
- The `type=` query param must not create unbounded metric cardinality.
- /metrics and /status must require a valid bearer JWT.
- /dns-query (RFC 8484) must be a working alias for /dns/query.
"""
import hashlib

import pytest

from app.main import (
    VALID_DNS_RECORD_TYPES,
    _metric_record_type,
    _metrics_source,
    app,
    metrics_reporter,
)


class TestMetricSourceNeverLeaksToken:
    """regression: raw bearer JWT must never become a metric label value."""

    def test_no_token_returns_anonymous(self):
        assert _metrics_source(token=None, token_identity=None) == 'anonymous'

    def test_verified_identity_used_when_available(self):
        raw_token = "header.payload.signature-should-not-be-used"
        assert _metrics_source(token=raw_token, token_identity="user-123") == "user-123"

    def test_unverified_token_is_hashed_not_raw(self):
        raw_token = "header.payload.signature-super-secret-bearer-value"
        source = _metrics_source(token=raw_token, token_identity=None)

        assert source != raw_token
        assert raw_token not in source
        assert source == hashlib.sha256(raw_token.encode()).hexdigest()[:8]

    def test_prometheus_metrics_defense_in_depth_hashes_raw_token(self):
        """Even if a caller mistakenly passes a raw token as source=,
        PrometheusMetrics.record_query must never emit it verbatim as a
        label value."""
        raw_token = "eyFAKEHEADER.eyFAKEPAYLOAD.FAKESIGNATUREVALUEFAKESIGNATUREVALUE"

        metrics_reporter.record_query(
            domain="regression-test-domain.example",
            record_type="A",
            status="success",
            response_time=0.01,
            cache_hit=False,
            source=raw_token,
        )

        output, _ = metrics_reporter.get_metrics_endpoint()
        text = output.decode() if isinstance(output, bytes) else output

        assert raw_token not in text


class TestRecordTypeCardinalityBounded:
    """regression: unvalidated type= must not create unbounded label cardinality."""

    @pytest.mark.parametrize("valid_type", sorted(VALID_DNS_RECORD_TYPES))
    def test_allowlisted_types_pass_through_uppercased(self, valid_type):
        assert _metric_record_type(valid_type.lower()) == valid_type
        assert _metric_record_type(valid_type) == valid_type

    def test_missing_type_defaults_to_a(self):
        assert _metric_record_type(None) == 'A'
        assert _metric_record_type('') == 'A'

    def test_unknown_type_maps_to_other(self):
        assert _metric_record_type('BOGUS') == 'OTHER'
        assert _metric_record_type('<script>alert(1)</script>') == 'OTHER'
        assert _metric_record_type('A; DROP TABLE') == 'OTHER'

    def test_arbitrary_types_never_leak_as_distinct_labels(self):
        """A flood of distinct, attacker-chosen type= values must all
        collapse onto the single 'OTHER' bucket rather than each creating
        a new time series."""
        distinct_junk_types = [f"JUNKTYPE{i}" for i in range(50)]
        mapped = {_metric_record_type(t) for t in distinct_junk_types}
        assert mapped == {'OTHER'}


class TestMetricsAndStatusRequireAuth:
    """regression: /metrics and /status must not be reachable anonymously."""

    @pytest.mark.asyncio
    async def test_metrics_rejects_missing_token(self):
        async with app.test_client() as client:
            response = await client.get('/metrics')
            assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_metrics_rejects_invalid_token(self):
        async with app.test_client() as client:
            response = await client.get(
                '/metrics', headers={'Authorization': 'Bearer not-a-real-token'}
            )
            assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_metrics_accepts_valid_token(self, jwt_token_factory):
        token = jwt_token_factory(user_id=1)
        async with app.test_client() as client:
            response = await client.get(
                '/metrics', headers={'Authorization': f'Bearer {token}'}
            )
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_status_rejects_missing_token(self):
        async with app.test_client() as client:
            response = await client.get('/status')
            assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_status_accepts_valid_token(self, jwt_token_factory):
        token = jwt_token_factory(user_id=1)
        async with app.test_client() as client:
            response = await client.get(
                '/status', headers={'Authorization': f'Bearer {token}'}
            )
            assert response.status_code == 200


class TestDnsQueryAliasRoute:
    """regression: RFC 8484 clients hitting /dns-query must not 404."""

    def test_dns_query_alias_routes_to_same_handler(self):
        """Both /dns/query and /dns-query must resolve to the dns_query view."""
        adapter = app.url_map.bind('localhost')

        native_endpoint, _ = adapter.match('/dns/query', method='GET')
        alias_endpoint, _ = adapter.match('/dns-query', method='GET')

        assert native_endpoint == alias_endpoint == 'dns_query'

    @pytest.mark.asyncio
    async def test_dns_query_alias_behaves_identically_for_missing_domain(self):
        """Without touching the resolver: both routes must reject a
        missing `name` param identically, proving they share a handler."""
        async with app.test_client() as client:
            native_response = await client.get('/dns/query')
            alias_response = await client.get('/dns-query')

            assert native_response.status_code == alias_response.status_code == 400
            native_body = await native_response.get_json()
            alias_body = await alias_response.get_json()
            assert native_body == alias_body
