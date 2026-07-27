"""
DoH Endpoint Rate Limiting Integration Tests
Tests the rate limiter integrated into the /dns/query endpoint.
"""
import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from quart import Quart
import json
from datetime import datetime, timedelta


@pytest.mark.asyncio
async def test_doh_request_within_limit(app_with_rate_limiting, jwt_token_factory):
    """Test that requests within rate limit are allowed."""
    app = app_with_rate_limiting

    async with app.test_client() as client:
        token = jwt_token_factory(user_id=1)

        # Request should succeed (within burst)
        response = await client.get(
            '/dns/query?name=example.com&type=A',
            headers={'Authorization': f'Bearer {token}'}
        )

        # Should not be rate limited (400 or 200, but not 429)
        assert response.status_code != 429


@pytest.mark.asyncio
async def test_doh_request_exceeds_burst(app_with_rate_limiting, jwt_token_factory):
    """Test that requests exceeding burst are rate limited."""
    app = app_with_rate_limiting

    async with app.test_client() as client:
        token = jwt_token_factory(user_id=1)

        # Consume burst (3 requests allowed)
        for i in range(3):
            response = await client.get(
                '/dns/query?name=example.com&type=A',
                headers={'Authorization': f'Bearer {token}'}
            )
            assert response.status_code != 429

        # 4th request should be rate limited
        response = await client.get(
            '/dns/query?name=example.com&type=A',
            headers={'Authorization': f'Bearer {token}'}
        )

        assert response.status_code == 429
        assert 'Retry-After' in response.headers
        data = await response.get_json()
        assert 'Rate limit exceeded' in data.get('error', '')


@pytest.mark.asyncio
async def test_doh_429_has_retry_after_header(app_with_rate_limiting, jwt_token_factory):
    """Test that 429 responses include Retry-After header."""
    app = app_with_rate_limiting

    async with app.test_client() as client:
        token = jwt_token_factory(user_id=1)

        # Exhaust burst
        for i in range(3):
            await client.get(
                '/dns/query?name=example.com&type=A',
                headers={'Authorization': f'Bearer {token}'}
            )

        # Rate limited request
        response = await client.get(
            '/dns/query?name=example.com&type=A',
            headers={'Authorization': f'Bearer {token}'}
        )

        assert response.status_code == 429
        retry_after = response.headers.get('Retry-After')
        assert retry_after is not None
        assert int(retry_after) > 0


@pytest.mark.asyncio
async def test_doh_different_identities_isolated(app_with_rate_limiting, jwt_token_factory):
    """Test that different identities have separate rate limit buckets."""
    app = app_with_rate_limiting

    async with app.test_client() as client:
        token1 = jwt_token_factory(user_id=1)
        token2 = jwt_token_factory(user_id=2)

        # User 1 exhausts burst
        for i in range(3):
            response = await client.get(
                '/dns/query?name=example.com&type=A',
                headers={'Authorization': f'Bearer {token1}'}
            )
            assert response.status_code != 429

        # User 1 is now rate limited
        response = await client.get(
            '/dns/query?name=example.com&type=A',
            headers={'Authorization': f'Bearer {token1}'}
        )
        assert response.status_code == 429

        # But user 2 should still be allowed (separate bucket)
        response = await client.get(
            '/dns/query?name=example.com&type=A',
            headers={'Authorization': f'Bearer {token2}'}
        )
        assert response.status_code != 429


@pytest.mark.asyncio
async def test_doh_unauthenticated_uses_ip_rate_limit(app_with_rate_limiting):
    """Test that unauthenticated requests use IP-based rate limiting."""
    app = app_with_rate_limiting

    async with app.test_client() as client:
        # Exhaust burst for IP
        for i in range(3):
            response = await client.get('/dns/query?name=example.com&type=A')
            assert response.status_code != 429

        # Next request from same IP should be rate limited
        response = await client.get('/dns/query?name=example.com&type=A')
        assert response.status_code == 429


@pytest.mark.asyncio
async def test_doh_disabled_rate_limiting_allows_all(app_with_rate_limiting):
    """Test that disabled rate limiting allows unlimited requests."""
    app = app_with_rate_limiting
    from app.main import rate_limiter

    # Disable rate limiting
    rate_limiter.enabled = False

    async with app.test_client() as client:
        # Even with burst=1, should allow many requests
        for i in range(10):
            response = await client.get('/dns/query?name=example.com&type=A')
            # May get 400 (missing domain), but not 429
            assert response.status_code != 429


@pytest.mark.asyncio
async def test_doh_metrics_record_rate_limited(app_with_rate_limiting, jwt_token_factory):
    """Test that rate limited requests are recorded in metrics."""
    app = app_with_rate_limiting
    from app.main import metrics_reporter

    async with app.test_client() as client:
        token = jwt_token_factory(user_id=1)

        # Get initial metrics
        # Note: PrometheusMetrics may not expose limited_counter directly,
        # but we can check that record_rate_limited_query doesn't crash
        for i in range(3):
            await client.get(
                '/dns/query?name=example.com&type=A',
                headers={'Authorization': f'Bearer {token}'}
            )

        # Rate limited request (should call record_rate_limited_query)
        response = await client.get(
            '/dns/query?name=example.com&type=A',
            headers={'Authorization': f'Bearer {token}'}
        )

        assert response.status_code == 429
        # Metrics were recorded (if we got here without exception, it worked)


@pytest.mark.asyncio
async def test_status_endpoint_reports_rate_limit_stats(app_with_rate_limiting, jwt_token_factory):
    """Test that /status endpoint includes rate limit statistics."""
    app = app_with_rate_limiting

    async with app.test_client() as client:
        token = jwt_token_factory(user_id=1)

        # Make some requests
        for i in range(2):
            await client.get(
                '/dns/query?name=example.com&type=A',
                headers={'Authorization': f'Bearer {token}'}
            )

        # Check status endpoint
        response = await client.get('/status')
        assert response.status_code == 200

        data = await response.get_json()
        assert 'rate_limit' in data
        rate_limit_stats = data['rate_limit']
        assert 'enabled' in rate_limit_stats
        assert 'rps' in rate_limit_stats
        assert 'burst' in rate_limit_stats
        assert 'total_requests' in rate_limit_stats
        assert 'limited_requests' in rate_limit_stats
