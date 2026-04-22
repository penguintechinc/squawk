"""
Web Console API Smoke Tests
Verifies all REST API endpoints in the Flask web console
"""

import pytest
import requests


@pytest.mark.smoke
@pytest.mark.api
class TestWebConsoleHealth:
    """Test web console health and readiness endpoints"""

    def test_ready_endpoint(self, config, fresh_http_session):
        """GET /ready returns readiness status"""
        url = f"{config.web_console_url}/ready"

        response = fresh_http_session.get(url, timeout=config.request_timeout)

        assert response.status_code == 200
        data = response.json()
        assert data.get("status") in ("ready", "ok", "healthy")


@pytest.mark.smoke
@pytest.mark.api
@pytest.mark.auth
class TestQueryAPI:
    """Test query-related API endpoints"""

    def test_get_queries_api(self, authenticated_client):
        """GET /api/v1/queries returns query list"""
        response = authenticated_client.get("/api/v1/queries")

        assert response.status_code == 200
        data = response.json()
        assert "queries" in data
        assert "total" in data
        assert isinstance(data["queries"], list)

    def test_get_queries_with_pagination(self, authenticated_client):
        """GET /api/v1/queries supports pagination"""
        response = authenticated_client.get("/api/v1/queries?limit=10&offset=0")

        assert response.status_code == 200
        data = response.json()
        assert "queries" in data
        assert len(data["queries"]) <= 10


@pytest.mark.smoke
@pytest.mark.api
@pytest.mark.auth
class TestIOCFeedsAPI:
    """Test IOC feed management API endpoints"""

    def test_get_ioc_feeds(self, authenticated_client):
        """GET /api/v1/ioc/feeds returns feed list"""
        response = authenticated_client.get("/api/v1/ioc/feeds")

        assert response.status_code == 200
        data = response.json()
        assert "feeds" in data
        assert isinstance(data["feeds"], list)

    def test_create_ioc_feed(self, authenticated_client):
        """POST /api/v1/ioc/feeds creates a new feed"""
        feed_data = {
            "name": "Test Feed",
            "url": "https://example.com/feed.txt",
            "feed_type": "domain",
            "is_active": True,
            "update_frequency_hours": 24
        }

        response = authenticated_client.post("/api/v1/ioc/feeds", json=feed_data)

        # Should succeed or require admin
        assert response.status_code in [201, 403]

    def test_get_single_ioc_feed(self, authenticated_client):
        """GET /api/v1/ioc/feeds/<id> returns feed details"""
        # First get all feeds
        response = authenticated_client.get("/api/v1/ioc/feeds")

        if response.status_code == 200:
            data = response.json()
            if data.get("feeds"):
                feed_id = data["feeds"][0].get("id")
                if feed_id:
                    detail_response = authenticated_client.get(f"/api/v1/ioc/feeds/{feed_id}")
                    assert detail_response.status_code in [200, 404]


@pytest.mark.smoke
@pytest.mark.api
@pytest.mark.auth
class TestStatsAPI:
    """Test statistics API endpoints"""

    def test_dashboard_stats_endpoint(self, authenticated_client):
        """GET /api/v1/dashboard/stats returns dashboard statistics"""
        response = authenticated_client.get("/api/v1/dashboard/stats")

        assert response.status_code == 200
        data = response.json()
        # Dashboard stats should have basic statistics
        assert isinstance(data, dict)


@pytest.mark.smoke
@pytest.mark.api
@pytest.mark.auth
class TestSearchAPI:
    """Test autocomplete/search API endpoints"""

    def test_groups_search_api(self, authenticated_client):
        """GET /api/v1/search/groups returns groups"""
        response = authenticated_client.get("/api/v1/search/groups?q=test")

        assert response.status_code == 200
        data = response.json()
        assert "groups" in data

    def test_users_search_api(self, authenticated_client):
        """GET /api/v1/search/users returns users"""
        response = authenticated_client.get("/api/v1/search/users?q=admin")

        assert response.status_code == 200
        data = response.json()
        assert "users" in data


@pytest.mark.smoke
@pytest.mark.api
@pytest.mark.auth
class TestFeedManagementAPI:
    """Test feed management API"""

    def test_update_feeds_endpoint(self, authenticated_client):
        """POST /api/v1/feeds/update triggers feed update"""
        response = authenticated_client.post("/api/v1/feeds/update")

        assert response.status_code in [200, 201]
        data = response.json()
        assert "success" in data or "message" in data


@pytest.mark.smoke
@pytest.mark.api
@pytest.mark.auth
class TestBlockedManagementAPI:
    """Test blocked queries management API"""

    def test_clear_blocked_endpoint(self, authenticated_client):
        """POST /api/v1/blocked/clear clears blocked history"""
        response = authenticated_client.post("/api/v1/blocked/clear")

        assert response.status_code == 200
        data = response.json()
        assert "success" in data


@pytest.mark.smoke
@pytest.mark.api
@pytest.mark.auth
class TestLogsManagementAPI:
    """Test logs management API"""

    def test_clear_logs_endpoint(self, authenticated_client):
        """POST /api/v1/logs/clear clears logs"""
        response = authenticated_client.post("/api/v1/logs/clear")

        assert response.status_code == 200
        data = response.json()
        assert "success" in data


@pytest.mark.smoke
@pytest.mark.api
@pytest.mark.auth
class TestQueryFilterParams:
    """Test filter and pagination params on query/domain/log endpoints"""

    def test_queries_pagination_params(self, authenticated_client):
        """GET /api/v1/queries supports page and limit params"""
        response = authenticated_client.get("/api/v1/queries", params={"page": 1, "limit": 10})

        assert response.status_code == 200
        data = response.json()
        assert "queries" in data
        assert len(data["queries"]) <= 10

    def test_queries_empty_far_page(self, authenticated_client):
        """GET /api/v1/queries with a far-out page returns empty list, not error"""
        response = authenticated_client.get("/api/v1/queries", params={"page": 99999, "limit": 10})

        assert response.status_code == 200
        data = response.json()
        items = data.get("queries", data.get("items", data.get("data", [])))
        assert isinstance(items, list)

    def test_domains_filter_active(self, authenticated_client):
        """GET /api/v1/domains?active=true returns only active domains"""
        response = authenticated_client.get("/api/v1/domains", params={"active": "true"})

        assert response.status_code == 200

    def test_domains_filter_inactive(self, authenticated_client):
        """GET /api/v1/domains?active=false returns only inactive domains"""
        response = authenticated_client.get("/api/v1/domains", params={"active": "false"})

        assert response.status_code == 200

    def test_logs_pagination_params(self, authenticated_client):
        """GET /api/v1/logs supports page and limit params"""
        response = authenticated_client.get("/api/v1/logs", params={"page": 1, "limit": 50})

        assert response.status_code == 200

    def test_ioc_feed_invalid_id_returns_404(self, authenticated_client):
        """GET /api/v1/ioc/feeds/<invalid_id> returns 404"""
        response = authenticated_client.get("/api/v1/ioc/feeds/nonexistent-feed-id-000")

        assert response.status_code == 404


@pytest.mark.smoke
@pytest.mark.api
class TestUnauthenticatedAPIAccess:
    """Test that API endpoints require authentication"""

    def test_queries_api_requires_auth(self, config, fresh_http_session):
        """GET /api/v1/queries requires authentication"""
        url = f"{config.web_console_url}/api/v1/queries"

        response = fresh_http_session.get(
            url,
            timeout=config.request_timeout,
            allow_redirects=False
        )

        assert response.status_code == 401

    def test_ioc_feeds_api_requires_auth(self, config, fresh_http_session):
        """GET /api/v1/ioc/feeds requires authentication"""
        url = f"{config.web_console_url}/api/v1/ioc/feeds"

        response = fresh_http_session.get(
            url,
            timeout=config.request_timeout,
            allow_redirects=False
        )

        assert response.status_code == 401

    def test_stats_api_requires_auth(self, config, fresh_http_session):
        """GET /api/v1/dashboard/stats requires authentication"""
        url = f"{config.web_console_url}/api/v1/dashboard/stats"

        response = fresh_http_session.get(
            url,
            timeout=config.request_timeout,
            allow_redirects=False
        )

        assert response.status_code == 401
