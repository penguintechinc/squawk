
import pytest
import sys
import os
import json
from unittest.mock import Mock, patch
import responses

# Add bins to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bins"))

# Mock dependencies before importing server
# We mock pydal, redis, etc. to avoid side effects during import if possible
# But server_premium_integrated imports them at top level.
# We hope they don't crash without config.

from server_premium_integrated import app

@pytest.mark.asyncio
async def test_health_check():
    """Test health check endpoint"""
    async with app.test_client() as client:
        response = await client.get("/health")
        assert response.status_code == 200
        data = await response.get_json()
        assert data["status"] == "healthy"

@pytest.mark.asyncio
async def test_dns_query_public():
    """Test public DNS query endpoint"""
    async with app.test_client() as client:
        # We need to mock resolve_dns_async which is used in the route
        with patch("server_premium_integrated.resolve_dns_async") as mock_resolve:
            mock_resolve.return_value = {
                "Status": 0,
                "Answer": [{"name": "google.com", "type": "A", "data": "1.2.3.4", "ttl": 300}],
                "TTL": 300
            }
            
            response = await client.get("/dns-query?name=google.com&type=A")
            assert response.status_code == 200
            data = await response.get_json()
            assert data["Status"] == 0
            assert data["Answer"][0]["data"] == "1.2.3.4"

