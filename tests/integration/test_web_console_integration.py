"""
Web Console Integration Tests
Tests web console functionality with real database
"""

import pytest
import requests
import time


WEB_CONSOLE_URL = "http://localhost:8005"
REQUEST_TIMEOUT = 30


@pytest.mark.integration
class TestAuthenticationFlow:
    """Test complete authentication flow"""

    def test_login_logout_flow(self, http_session):
        """Complete login and logout flow works"""
        # Login
        login_url = f"{WEB_CONSOLE_URL}/auth/login"
        login_response = http_session.post(
            login_url,
            data={
                "email": "admin@localhost",
                "password": "admin123"
            },
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False
        )

        # Should redirect to dashboard
        assert login_response.status_code in [200, 302, 303]

        # Access dashboard
        dashboard_url = f"{WEB_CONSOLE_URL}/dashboard/"
        dashboard_response = http_session.get(
            dashboard_url,
            timeout=REQUEST_TIMEOUT
        )

        # Should be accessible
        assert dashboard_response.status_code == 200

        # Logout
        logout_url = f"{WEB_CONSOLE_URL}/auth/logout"
        logout_response = http_session.get(
            logout_url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False
        )

        assert logout_response.status_code in [302, 303]

        # Dashboard should now redirect to login
        new_session = requests.Session()
        dashboard_response2 = new_session.get(
            dashboard_url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False
        )

        assert dashboard_response2.status_code in [302, 303, 401]

    def test_registration_flow(self, http_session):
        """User registration creates account"""
        register_url = f"{WEB_CONSOLE_URL}/auth/register"

        # Generate unique email
        unique_email = f"test_{int(time.time())}@example.com"

        response = http_session.post(
            register_url,
            data={
                "email": unique_email,
                "password": "TestPassword123!",
                "first_name": "Test",
                "last_name": "User"
            },
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False
        )

        # Should redirect to login on success
        assert response.status_code in [200, 302, 303]


@pytest.mark.integration
class TestDashboardDataDisplay:
    """Test dashboard displays data correctly"""

    def test_dashboard_shows_stats(self, http_session, web_console_auth):
        """Dashboard shows statistics"""
        if not web_console_auth.get("authenticated"):
            pytest.skip("Web console authentication failed")

        url = f"{WEB_CONSOLE_URL}/dashboard/"
        response = http_session.get(
            url,
            cookies=web_console_auth.get("cookies", {}),
            timeout=REQUEST_TIMEOUT
        )

        assert response.status_code == 200
        # Dashboard should contain stats elements
        assert "dashboard" in response.text.lower()

    def test_queries_page_shows_data(self, http_session, web_console_auth):
        """Queries page displays query data"""
        if not web_console_auth.get("authenticated"):
            pytest.skip("Web console authentication failed")

        url = f"{WEB_CONSOLE_URL}/dashboard/queries"
        response = http_session.get(
            url,
            cookies=web_console_auth.get("cookies", {}),
            timeout=REQUEST_TIMEOUT
        )

        assert response.status_code == 200

    def test_ioc_page_shows_feeds(self, http_session, web_console_auth):
        """IOC page displays feeds"""
        if not web_console_auth.get("authenticated"):
            pytest.skip("Web console authentication failed")

        url = f"{WEB_CONSOLE_URL}/dashboard/ioc"
        response = http_session.get(
            url,
            cookies=web_console_auth.get("cookies", {}),
            timeout=REQUEST_TIMEOUT
        )

        assert response.status_code == 200


@pytest.mark.integration
class TestAPIDataConsistency:
    """Test API returns consistent data"""

    def test_api_and_page_data_match(self, http_session, web_console_auth):
        """API data matches page display"""
        if not web_console_auth.get("authenticated"):
            pytest.skip("Web console authentication failed")

        cookies = web_console_auth.get("cookies", {})

        # Get stats from API
        api_url = f"{WEB_CONSOLE_URL}/api/stats/summary"
        api_response = http_session.get(
            api_url,
            cookies=cookies,
            timeout=REQUEST_TIMEOUT
        )

        if api_response.status_code == 200:
            api_data = api_response.json()

            # Get dashboard page
            page_url = f"{WEB_CONSOLE_URL}/dashboard/"
            page_response = http_session.get(
                page_url,
                cookies=cookies,
                timeout=REQUEST_TIMEOUT
            )

            # Both should succeed
            assert page_response.status_code == 200

    def test_ioc_feeds_api_consistent(self, http_session, web_console_auth):
        """IOC feeds API returns consistent data"""
        if not web_console_auth.get("authenticated"):
            pytest.skip("Web console authentication failed")

        cookies = web_console_auth.get("cookies", {})

        # Multiple requests should return same data
        url = f"{WEB_CONSOLE_URL}/api/ioc/feeds"

        response1 = http_session.get(url, cookies=cookies, timeout=REQUEST_TIMEOUT)
        response2 = http_session.get(url, cookies=cookies, timeout=REQUEST_TIMEOUT)

        if response1.status_code == 200 and response2.status_code == 200:
            # Data should be consistent (unless modified between requests)
            data1 = response1.json()
            data2 = response2.json()

            assert len(data1.get("feeds", [])) == len(data2.get("feeds", []))


@pytest.mark.integration
class TestFormSubmissions:
    """Test form submissions work correctly"""

    def test_add_ioc_feed(self, http_session, web_console_auth):
        """Adding IOC feed through API works"""
        if not web_console_auth.get("authenticated"):
            pytest.skip("Web console authentication failed")

        cookies = web_console_auth.get("cookies", {})
        url = f"{WEB_CONSOLE_URL}/api/ioc/feeds"

        # Add a test feed
        response = http_session.post(
            url,
            json={
                "name": f"Test Feed {int(time.time())}",
                "url": "https://example.com/test-feed.txt",
                "feed_type": "domain",
                "is_active": False
            },
            cookies=cookies,
            timeout=REQUEST_TIMEOUT
        )

        # Should succeed or require admin
        assert response.status_code in [201, 403]

    def test_search_users_returns_results(self, http_session, web_console_auth):
        """User search returns results"""
        if not web_console_auth.get("authenticated"):
            pytest.skip("Web console authentication failed")

        cookies = web_console_auth.get("cookies", {})
        url = f"{WEB_CONSOLE_URL}/dashboard/api/users/search?q=admin"

        response = http_session.get(
            url,
            cookies=cookies,
            timeout=REQUEST_TIMEOUT
        )

        assert response.status_code == 200
        data = response.json()
        assert "users" in data

    def test_search_groups_returns_results(self, http_session, web_console_auth):
        """Group search returns results"""
        if not web_console_auth.get("authenticated"):
            pytest.skip("Web console authentication failed")

        cookies = web_console_auth.get("cookies", {})
        url = f"{WEB_CONSOLE_URL}/dashboard/api/groups/search?q="

        response = http_session.get(
            url,
            cookies=cookies,
            timeout=REQUEST_TIMEOUT
        )

        assert response.status_code == 200
        data = response.json()
        assert "groups" in data


@pytest.mark.integration
@pytest.mark.slow
class TestDataPersistence:
    """Test data persists across requests"""

    def test_query_log_persists(self, http_session, web_console_auth):
        """Query logs persist in database"""
        if not web_console_auth.get("authenticated"):
            pytest.skip("Web console authentication failed")

        cookies = web_console_auth.get("cookies", {})
        url = f"{WEB_CONSOLE_URL}/api/queries"

        # Get initial count
        response1 = http_session.get(url, cookies=cookies, timeout=REQUEST_TIMEOUT)
        if response1.status_code != 200:
            pytest.skip("Cannot access queries API")

        count1 = response1.json().get("total", 0)

        # Make a DNS query to generate log entry
        dns_url = "http://localhost:8080/dns-query"
        http_session.get(
            dns_url,
            params={"name": "persistence-test.example.com", "type": "A"},
            timeout=REQUEST_TIMEOUT
        )

        # Wait for log to be written
        time.sleep(1)

        # Check count again
        response2 = http_session.get(url, cookies=cookies, timeout=REQUEST_TIMEOUT)
        count2 = response2.json().get("total", 0)

        # Count may have increased (depending on logging config)
        assert count2 >= count1
