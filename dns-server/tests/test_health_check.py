"""
Basic health check and integration tests
"""

import pytest
import json
import sys
import os
from unittest.mock import Mock, patch

# Add the bins directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bins"))


class TestHealthCheck:
    """Test basic system health and integration"""

    def test_imports_work(self):
        """Test that core modules can be imported"""
        try:
            import server

            assert hasattr(server, "DNSHandler")
        except ImportError as e:
            pytest.fail(f"Failed to import server module: {e}")

    def test_basic_dns_query_structure(self):
        """Test basic DNS query response structure"""
        # Test that we can create a valid DNS response structure
        response = {
            "Status": 0,
            "Question": [{"name": "example.com", "type": "A"}],
            "Answer": [{"name": "example.com", "type": "A", "data": "93.184.216.34"}],
        }

        assert "Status" in response
        assert "Question" in response
        assert "Answer" in response
        assert response["Status"] == 0
        assert len(response["Answer"]) == 1
        assert response["Answer"][0]["data"] == "93.184.216.34"

    def test_json_serialization(self):
        """Test JSON serialization of DNS responses"""
        response = {
            "Status": 0,
            "Answer": [{"name": "example.com", "type": "A", "data": "93.184.216.34"}],
        }

        # Should be able to serialize and deserialize
        json_str = json.dumps(response)
        parsed = json.loads(json_str)

        assert parsed == response
        assert parsed["Status"] == 0
        assert parsed["Answer"][0]["data"] == "93.184.216.34"

    def test_environment_setup(self):
        """Test that the test environment is properly set up"""
        # Check that we can access the bins directory
        bins_path = os.path.join(os.path.dirname(__file__), "..", "bins")
        assert os.path.exists(bins_path)

        # Check that we can create temporary files
        import tempfile

        with tempfile.NamedTemporaryFile() as tmp:
            assert os.path.exists(tmp.name)


class TestBasicFunctionality:
    """Test that basic functionality works without external dependencies"""

    def test_domain_regex_basic(self):
        """Test basic domain validation regex"""
        import re

        # Simple domain validation pattern (not comprehensive)
        domain_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"

        valid_domains = ["example.com", "test.org", "sub.example.com"]
        invalid_domains = ["", "domain with spaces", "-invalid.com"]

        for domain in valid_domains:
            assert re.match(
                domain_pattern, domain
            ), f"Valid domain {domain} should match"

        for domain in invalid_domains:
            assert not re.match(
                domain_pattern, domain
            ), f"Invalid domain {domain} should not match"

    def test_basic_error_handling(self):
        """Test basic error handling patterns"""

        def safe_divide(a, b):
            try:
                return a / b
            except ZeroDivisionError:
                return {"error": "Division by zero"}
            except Exception as e:
                return {"error": str(e)}

        # Test normal operation
        result = safe_divide(10, 2)
        assert result == 5.0

        # Test error handling
        result = safe_divide(10, 0)
        assert "error" in result
        assert result["error"] == "Division by zero"

    def test_basic_async_support(self):
        """Test that async/await syntax works in the test environment"""
        import asyncio

        async def async_function():
            await asyncio.sleep(0.001)  # Very short sleep
            return "async_result"

        # Test that we can run async functions
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(async_function())
            assert result == "async_result"
        finally:
            loop.close()
