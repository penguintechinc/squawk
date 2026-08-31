"""
Regression tests: WHOIS and IOC-feed blueprint error responses must never
leak raw exception text (str(e)) to the client -- only a generic message,
with full detail logged server-side via app.utils.responses.internal_error.
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from app.services.posthog_client import PostHogClient
from app.services.whois_service import WHOISManager


@pytest.fixture
def mock_posthog(app):
    """Mock PostHog client that reports every flag enabled."""
    mock = Mock(spec=PostHogClient)
    mock.feature_enabled.return_value = True
    app.posthog = mock
    return mock


@pytest.fixture
def mock_whois_manager(app):
    """Mock WHOIS manager."""
    mock = AsyncMock(spec=WHOISManager)
    app.whois_manager = mock
    return mock


class TestWhoisErrorResponsesAreGeneric:
    """WHOIS endpoints must return a generic 500 body, not str(e)."""

    def test_lookup_domain_failure_hides_exception_detail(
        self, client, jwt_token_factory, mock_posthog, mock_whois_manager
    ):
        mock_whois_manager.lookup_domain.side_effect = RuntimeError(
            'internal db connection string leaked'
        )
        token = jwt_token_factory(user_id=1, username='tester')

        resp = client.get(
            '/api/v1/whois/domain/example.com',
            headers={'Authorization': f'Bearer {token}'}
        )

        assert resp.status_code == 500
        body = resp.get_json()
        assert 'internal db connection string leaked' not in body['error']
        assert body['error'] == 'WHOIS domain lookup failed'

    def test_lookup_ip_failure_hides_exception_detail(
        self, client, jwt_token_factory, mock_posthog, mock_whois_manager
    ):
        mock_whois_manager.lookup_ip.side_effect = RuntimeError('stack trace with secrets')
        token = jwt_token_factory(user_id=1, username='tester')

        resp = client.get(
            '/api/v1/whois/ip/192.0.2.1',
            headers={'Authorization': f'Bearer {token}'}
        )

        assert resp.status_code == 500
        body = resp.get_json()
        assert 'stack trace with secrets' not in body['error']
        assert body['error'] == 'WHOIS IP lookup failed'

    def test_search_failure_hides_exception_detail(
        self, client, jwt_token_factory, mock_posthog, mock_whois_manager
    ):
        mock_whois_manager.search_whois.side_effect = RuntimeError('sql error: table x')
        token = jwt_token_factory(user_id=1, username='tester')

        resp = client.get(
            '/api/v1/whois/search?q=example',
            headers={'Authorization': f'Bearer {token}'}
        )

        assert resp.status_code == 500
        body = resp.get_json()
        assert 'sql error' not in body['error']
        assert body['error'] == 'WHOIS search failed'

    def test_stats_failure_hides_exception_detail(
        self, client, jwt_token_factory, mock_posthog, mock_whois_manager
    ):
        mock_whois_manager.get_stats.side_effect = RuntimeError('redis://user:pass@host')
        token = jwt_token_factory(user_id=1, username='tester')

        resp = client.get(
            '/api/v1/whois/stats',
            headers={'Authorization': f'Bearer {token}'}
        )

        assert resp.status_code == 500
        body = resp.get_json()
        assert 'redis://' not in body['error']
        assert body['error'] == 'WHOIS stats lookup failed'


class TestIOCFeedSyncErrorResponseIsGeneric:
    """IOC feed /sync endpoint must return a generic 500 body, not str(e)."""

    def test_sync_failure_hides_exception_detail(
        self, client, app, db, jwt_token_factory, mock_posthog
    ):
        with app.app_context():
            feed_id = db.ioc_feed.insert(
                name='RegressionTestFeed',
                url='https://example.com/feed.txt',
                feed_type='domain',
                format='txt',
                active=True,
            )
            db.commit()

        token = jwt_token_factory(user_id=1, username='admin', global_role='SystemAdmin')

        with patch(
            'app.services.ioc_ingestion_service._assert_feed_url_safe',
            new=AsyncMock(side_effect=RuntimeError('internal db connection string leaked')),
        ):
            resp = client.post(
                f'/api/v1/ioc-feeds/{feed_id}/sync',
                headers={'Authorization': f'Bearer {token}'}
            )

        assert resp.status_code == 500
        body = resp.get_json()
        assert 'internal db connection string leaked' not in body['error']
        assert body['error'] == 'IOC feed sync failed'
