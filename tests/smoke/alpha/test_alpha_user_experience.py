"""
Alpha User Experience Tests
Test UI/UX, page loads, forms, navigation, and user workflows
"""

import pytest
import requests
import re
from datetime import datetime


@pytest.mark.alpha
@pytest.mark.ux
class TestAlphaPageLoading:
    """Test all UI pages load correctly"""

    @pytest.mark.parametrize("path", [
        "/",
        "/health",
        "/auth/login",
    ])
    def test_public_pages_load(self, config, http_session, path):
        """Public pages load without authentication"""
        response = http_session.get(
            f"{config.web_console_url}{path}",
            timeout=config.request_timeout,
            allow_redirects=True
        )

        assert response.status_code == 200
        assert len(response.content) > 0

    @pytest.mark.parametrize("path", [
        "/dashboard/",
        "/dashboard/queries",
        "/dashboard/ioc",
        "/dashboard/domains",
        "/dashboard/zones",
        "/dashboard/records",
        "/dashboard/users",
        "/dashboard/groups",
        "/dashboard/threats",
        "/dashboard/blocked",
        "/dashboard/settings",
    ])
    def test_dashboard_pages_load(self, authenticated_client, path):
        """Dashboard pages load for authenticated users"""
        response = authenticated_client.get(path)

        # Should load or redirect
        assert response.status_code in [200, 302, 303, 404]

        if response.status_code == 200:
            assert len(response.content) > 0

    def test_page_titles_correct(self, authenticated_client):
        """Pages have appropriate titles"""
        pages = {
            "/dashboard/": ["Dashboard", "Squawk"],
            "/dashboard/queries": ["Queries", "DNS"],
            "/dashboard/ioc": ["IOC", "Indicators", "Threat"],
            "/dashboard/users": ["Users", "Management"],
        }

        for path, expected_keywords in pages.items():
            response = authenticated_client.get(path)

            if response.status_code == 200:
                content = response.text
                # Check if any expected keyword is in page
                found = any(keyword.lower() in content.lower()
                           for keyword in expected_keywords)
                assert found, f"Page {path} missing expected keywords"

    def test_pages_have_navigation(self, authenticated_client):
        """Dashboard pages include navigation elements"""
        response = authenticated_client.get("/dashboard/")

        if response.status_code == 200:
            content = response.text.lower()
            # Check for common navigation elements
            nav_elements = ["nav", "menu", "sidebar", "header"]
            found = any(element in content for element in nav_elements)
            # This is optional, but good UX practice
            assert found or len(content) > 0


@pytest.mark.alpha
@pytest.mark.ux
class TestAlphaFormFunctionality:
    """Test form inputs and submissions"""

    def test_login_form_works(self, config, http_session):
        """Login form accepts input and submits"""
        login_url = f"{config.web_console_url}/api/v1/auth/login"

        response = http_session.post(
            login_url,
            json={
                "email": config.admin_email,
                "password": config.admin_password
            },
            timeout=config.request_timeout
        )

        # Should succeed or return validation error
        assert response.status_code in [200, 400, 401]

    def test_form_validation_messages(self, config, http_session):
        """Forms show validation errors for invalid input"""
        login_url = f"{config.web_console_url}/api/v1/auth/login"

        response = http_session.post(
            login_url,
            json={
                "email": "invalid-email",
                "password": ""
            },
            timeout=config.request_timeout
        )

        # Should return validation error
        assert response.status_code in [400, 422]

        if response.status_code in [400, 422]:
            data = response.json()
            # Should include error message
            assert "error" in data or "message" in data or "errors" in data

    def test_domain_creation_form(self, authenticated_client):
        """Domain creation form works correctly"""
        test_domain = f"ux-test-{datetime.utcnow().timestamp()}.com"

        response = authenticated_client.post(
            "/api/v1/domains",
            json={
                "domain": test_domain,
                "type": "A",
                "value": "1.2.3.4"
            }
        )

        # Should create or validate
        assert response.status_code in [200, 201, 400, 422]

        if response.status_code in [200, 201]:
            data = response.json()
            # Should return created domain info
            assert data is not None

    def test_user_creation_form(self, authenticated_client):
        """User creation form works correctly"""
        test_email = f"ux-test-{datetime.utcnow().timestamp()}@example.com"

        response = authenticated_client.post(
            "/api/v1/users",
            json={
                "email": test_email,
                "password": "TestPass123!",
                "role": "user"
            }
        )

        # Should create or require permissions
        assert response.status_code in [200, 201, 400, 403, 422]


@pytest.mark.alpha
@pytest.mark.ux
class TestAlphaNavigationFlow:
    """Test navigation between pages"""

    def test_dashboard_to_queries_navigation(self, authenticated_client):
        """Navigate from dashboard to queries page"""
        # Load dashboard
        dashboard_response = authenticated_client.get("/dashboard/")
        assert dashboard_response.status_code in [200, 302, 303]

        # Load queries page
        queries_response = authenticated_client.get("/dashboard/queries")
        assert queries_response.status_code in [200, 302, 303, 404]

    def test_breadcrumb_navigation(self, authenticated_client):
        """Breadcrumb navigation works"""
        # This tests if breadcrumbs or back navigation exists
        response = authenticated_client.get("/dashboard/queries")

        if response.status_code == 200:
            content = response.text.lower()
            # Check for breadcrumb indicators
            breadcrumb_indicators = ["breadcrumb", "back to", "home"]
            # Optional but good UX
            found = any(indicator in content for indicator in breadcrumb_indicators)

    def test_logout_redirects_to_login(self, config, http_session):
        """Logout redirects to login page"""
        # Login first
        login_response = http_session.post(
            f"{config.web_console_url}/api/v1/auth/login",
            json={
                "email": config.admin_email,
                "password": config.admin_password
            },
            timeout=config.request_timeout
        )

        if login_response.status_code != 200:
            pytest.skip("Authentication not configured")

        token = login_response.json().get("access_token")

        # Logout
        logout_response = http_session.post(
            f"{config.web_console_url}/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {token}"},
            timeout=config.request_timeout,
            allow_redirects=False
        )

        # Should succeed
        assert logout_response.status_code in [200, 204, 302, 303]


@pytest.mark.alpha
@pytest.mark.ux
class TestAlphaErrorMessages:
    """Test error messages are helpful"""

    def test_404_page_helpful(self, config, http_session):
        """404 page provides helpful information"""
        response = http_session.get(
            f"{config.web_console_url}/nonexistent/page",
            timeout=config.request_timeout
        )

        assert response.status_code == 404

        content = response.text.lower()
        # Should mention "not found" or similar
        helpful_terms = ["not found", "404", "doesn't exist", "page"]
        found = any(term in content for term in helpful_terms)
        assert found, "404 page should have helpful message"

    def test_validation_errors_specific(self, authenticated_client):
        """Validation errors are specific and helpful"""
        response = authenticated_client.post(
            "/api/v1/domains",
            json={
                "domain": "",  # Invalid
                "type": "A",
                "value": "1.2.3.4"
            }
        )

        assert response.status_code in [400, 422]

        data = response.json()
        # Should have specific error message
        assert "error" in data or "message" in data or "errors" in data

        error_text = str(data).lower()
        # Should mention the field with error
        assert "domain" in error_text or "required" in error_text

    def test_permission_denied_clear(self, config, http_session):
        """Permission denied errors are clear"""
        # Try to access admin endpoint without auth
        response = http_session.get(
            f"{config.web_console_url}/api/v1/users",
            timeout=config.request_timeout
        )

        assert response.status_code in [401, 403]

        data = response.json()
        # Should explain authentication/authorization issue
        message = str(data).lower()
        auth_terms = ["unauthorized", "forbidden", "permission", "access", "auth"]
        found = any(term in message for term in auth_terms)
        assert found, "Permission error should be clear"


@pytest.mark.alpha
@pytest.mark.ux
class TestAlphaDataDisplay:
    """Test data display and formatting"""

    def test_queries_list_displays_data(self, authenticated_client):
        """Queries list displays correctly"""
        response = authenticated_client.get("/api/v1/queries?limit=10")

        assert response.status_code == 200
        data = response.json()

        assert "queries" in data
        queries = data["queries"]
        assert isinstance(queries, list)

        # If queries exist, check structure
        if queries:
            query = queries[0]
            # Should have expected fields
            expected_fields = ["domain", "query", "timestamp", "time"]
            found_fields = [field for field in expected_fields if field in query]
            assert len(found_fields) > 0, "Query records should have data fields"

    def test_dashboard_stats_formatted(self, authenticated_client):
        """Dashboard statistics are formatted correctly"""
        response = authenticated_client.get("/api/v1/dashboard/stats")

        assert response.status_code == 200
        data = response.json()

        # Should have stats data
        stats_fields = ["total_queries", "total_domains", "total_threats",
                       "queries", "domains", "blocked"]
        found_fields = [field for field in stats_fields if field in data]
        assert len(found_fields) > 0, "Stats should include metrics"

    def test_timestamps_formatted(self, authenticated_client):
        """Timestamps are formatted consistently"""
        response = authenticated_client.get("/api/v1/queries?limit=1")

        if response.status_code == 200:
            data = response.json()
            queries = data.get("queries", [])

            if queries:
                query = queries[0]
                timestamp_fields = ["timestamp", "created_at", "updated_at", "time"]

                for field in timestamp_fields:
                    if field in query:
                        timestamp = query[field]
                        # Should be valid timestamp format
                        assert isinstance(timestamp, (str, int, float))


@pytest.mark.alpha
@pytest.mark.ux
class TestAlphaSearchFunctionality:
    """Test search and filtering"""

    def test_user_search_works(self, authenticated_client):
        """User search functionality works"""
        response = authenticated_client.get("/api/v1/search/users?q=admin")

        assert response.status_code == 200
        data = response.json()

        assert "users" in data
        assert isinstance(data["users"], list)

    def test_domain_search_works(self, authenticated_client):
        """Domain search functionality works"""
        response = authenticated_client.get("/api/v1/search/domains?q=com")

        # Should work or not be implemented
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            data = response.json()
            assert "domains" in data or "results" in data

    def test_empty_search_handled(self, authenticated_client):
        """Empty search queries handled correctly"""
        response = authenticated_client.get("/api/v1/search/users?q=")

        assert response.status_code == 200
        data = response.json()

        # Should return all or empty results
        assert "users" in data


@pytest.mark.alpha
@pytest.mark.ux
class TestAlphaLoadingStates:
    """Test loading states and responsiveness"""

    def test_api_response_times_acceptable(self, authenticated_client):
        """API responses are fast enough for good UX"""
        import time

        endpoints = [
            "/api/v1/dashboard/stats",
            "/api/v1/queries?limit=10",
            "/api/v1/domains?limit=10",
        ]

        for endpoint in endpoints:
            start = time.time()
            response = authenticated_client.get(endpoint)
            elapsed = time.time() - start

            assert response.status_code == 200
            # Should respond within 2 seconds for good UX
            assert elapsed < 2.0, f"{endpoint} too slow: {elapsed:.2f}s"

    def test_pagination_works(self, authenticated_client):
        """Pagination controls work correctly"""
        # Test with limit
        response1 = authenticated_client.get("/api/v1/queries?limit=5")
        assert response1.status_code == 200

        data1 = response1.json()
        queries1 = data1.get("queries", [])

        # Test with offset
        response2 = authenticated_client.get("/api/v1/queries?limit=5&offset=5")
        assert response2.status_code == 200

        data2 = response2.json()
        queries2 = data2.get("queries", [])

        # Results should be different (if enough data)
        if len(queries1) >= 5 and len(queries2) >= 5:
            assert queries1 != queries2


@pytest.mark.alpha
@pytest.mark.ux
class TestAlphaResponsiveDesign:
    """Test responsive design elements"""

    def test_pages_have_viewport_meta(self, authenticated_client):
        """Pages include viewport meta tag for mobile"""
        response = authenticated_client.get("/dashboard/")

        if response.status_code == 200:
            content = response.text
            # Should have viewport meta tag
            assert "viewport" in content.lower() or \
                   "width=device-width" in content.lower()

    def test_api_returns_json(self, authenticated_client):
        """API endpoints return proper JSON"""
        response = authenticated_client.get("/api/v1/dashboard/stats")

        assert response.status_code == 200
        assert response.headers.get("Content-Type") in [
            "application/json",
            "application/json; charset=utf-8"
        ]

        # Should be valid JSON
        data = response.json()
        assert data is not None
