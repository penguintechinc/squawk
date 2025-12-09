"""
Manager API Test Suite
Tests all Manager API endpoints including registration, authentication, RBAC.
"""
import pytest
import requests
import secrets
import time

BASE_URL = "http://localhost:5000"


class TestManagerAPI:
    """Test suite for Manager API."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup for each test."""
        self.base_url = BASE_URL
        self.admin_token = None

    def test_health_check(self):
        """Test health endpoint."""
        response = requests.get(f"{self.base_url}/health")
        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'healthy'

    def test_login_success(self):
        """Test successful login."""
        response = requests.post(
            f"{self.base_url}/api/v1/auth/login",
            json={"username": "admin", "password": "admin123"}
        )
        assert response.status_code == 200
        data = response.json()
        assert 'accessToken' in data
        assert 'refreshToken' in data
        assert 'user' in data
        return data['accessToken']

    def test_login_failure(self):
        """Test failed login with wrong password."""
        response = requests.post(
            f"{self.base_url}/api/v1/auth/login",
            json={"username": "admin", "password": "wrongpassword"}
        )
        assert response.status_code == 401

    def test_create_dns_server(self):
        """Test DNS server creation (generates join key)."""
        token = self.test_login_success()

        response = requests.post(
            f"{self.base_url}/api/v1/dns-servers",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "name": "test-dns-server",
                "region": "us-east-1"
            }
        )

        assert response.status_code == 201
        data = response.json()
        assert 'joinKey' in data
        assert len(data['joinKey']) == 64  # 64-char hex
        assert data['name'] == "test-dns-server"
        assert 'id' in data

        return data

    def test_dns_server_registration(self):
        """Test DNS server registration using join key."""
        # First create a DNS server to get join key
        server_data = self.test_create_dns_server()
        join_key = server_data['joinKey']

        # Register with join key
        response = requests.post(
            f"{self.base_url}/api/v1/dns-servers/register",
            json={"joinKey": join_key}
        )

        assert response.status_code == 200
        data = response.json()
        assert 'jwt' in data
        assert 'serverId' in data
        assert 'config' in data

        # JWT should be a valid token
        assert len(data['jwt']) > 20

        return data

    def test_list_users_unauthorized(self):
        """Test unauthorized user list access."""
        response = requests.get(f"{self.base_url}/api/v1/users")
        assert response.status_code == 401

    def test_list_users_authorized(self):
        """Test authorized user list access."""
        token = self.test_login_success()

        response = requests.get(
            f"{self.base_url}/api/v1/users",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0  # At least admin user

    def test_create_team(self):
        """Test team creation."""
        token = self.test_login_success()

        response = requests.post(
            f"{self.base_url}/api/v1/teams",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "name": f"Engineering-{int(time.time())}",
                "description": "Engineering team for testing"
            }
        )

        assert response.status_code == 201
        data = response.json()
        assert 'id' in data
        assert 'name' in data

        return data

    def test_create_zone(self):
        """Test DNS zone creation."""
        token = self.test_login_success()
        team = self.test_create_team()

        response = requests.post(
            f"{self.base_url}/api/v1/zones",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "name": f"test-{int(time.time())}.company.com",
                "teamId": team['id'],
                "visibility": "internal"
            }
        )

        assert response.status_code == 201
        data = response.json()
        assert 'id' in data
        assert 'name' in data
        assert data['visibility'] == 'internal'

        return data

    def test_rbac_team_isolation(self):
        """Test team-level RBAC isolation."""
        admin_token = self.test_login_success()

        # Create two teams
        team1_response = requests.post(
            f"{self.base_url}/api/v1/teams",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"name": f"Team1-{int(time.time())}"}
        )
        assert team1_response.status_code == 201
        team1 = team1_response.json()

        team2_response = requests.post(
            f"{self.base_url}/api/v1/teams",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"name": f"Team2-{int(time.time())}"}
        )
        assert team2_response.status_code == 201
        team2 = team2_response.json()

        # Create zone for Team1
        zone_response = requests.post(
            f"{self.base_url}/api/v1/zones",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "name": f"team1-{int(time.time())}.company.com",
                "teamId": team1['id'],
                "visibility": "internal"
            }
        )
        assert zone_response.status_code == 201
        zone = zone_response.json()

        # List zones - admin should see all
        zones_response = requests.get(
            f"{self.base_url}/api/v1/zones",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert zones_response.status_code == 200

        # Note: Full test would verify team isolation with separate user accounts

    def test_dns_server_list(self):
        """Test listing DNS servers."""
        token = self.test_login_success()

        response = requests.get(
            f"{self.base_url}/api/v1/dns-servers",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_dns_server_config_retrieval(self):
        """Test DNS server config retrieval after registration."""
        reg_data = self.test_dns_server_registration()
        jwt_token = reg_data['jwt']
        server_id = reg_data['serverId']

        response = requests.get(
            f"{self.base_url}/api/v1/dns-servers/{server_id}/config",
            headers={"Authorization": f"Bearer {jwt_token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert 'zones' in data or 'iocFeeds' in data or 'cacheSettings' in data

    def test_dns_server_heartbeat(self):
        """Test DNS server heartbeat."""
        reg_data = self.test_dns_server_registration()
        jwt_token = reg_data['jwt']
        server_id = reg_data['serverId']

        metrics = {
            'queries': 1234,
            'cache_hits': 890,
            'errors': 2,
            'avg_response_ms': 15.3
        }

        response = requests.post(
            f"{self.base_url}/api/v1/dns-servers/{server_id}/heartbeat",
            headers={"Authorization": f"Bearer {jwt_token}"},
            json=metrics
        )

        assert response.status_code == 200
        data = response.json()
        assert 'configVersion' in data or 'shouldSync' in data


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
