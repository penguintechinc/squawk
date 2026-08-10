#!/usr/bin/env python3
"""
Regression tests for cross-tenant IDOR vulnerabilities in ClientConfigManager.

These tests verify that clients registered in one domain cannot be overwritten
or assigned configs from another domain by an attacker with the second domain's JWT.

Regression: cross-tenant IDOR in register_client/assign_config_to_client
See issue: https://github.com/penguintechinc/squawk/security/advisories/...
"""

import pytest
from client_config_api import ClientConfigManager


class TestClientConfigTenantIsolation:
    """Test tenant isolation (hard boundary) in client config operations."""

    @pytest.fixture
    def config_manager(self, temp_db, test_jwt_secret):
        """Create client config manager instance with test database"""
        db_url = f"sqlite://{temp_db._uri[9:]}"
        return ClientConfigManager(db_url, test_jwt_secret)

    def test_cannot_overwrite_client_from_different_domain(self, config_manager, mock_client_config):
        """Regression: client_id registered in domain A cannot be hijacked using domain B's JWT.

        This tests the IDOR fix where register_client must scope the client_instance
        lookup by BOTH client_id AND domain_id to prevent cross-domain overwrites.
        """
        # Create domain A
        domain_a = config_manager.create_deployment_domain("domain-a", "Domain A")
        domain_a_jwt = domain_a['jwt_token']
        domain_a_id = domain_a['id']

        # Create domain B
        domain_b = config_manager.create_deployment_domain("domain-b", "Domain B")
        domain_b_jwt = domain_b['jwt_token']
        domain_b_id = domain_b['id']

        # Create a default config in domain A
        config_a = config_manager.create_client_config(
            "default",
            domain_a_id,
            mock_client_config,
            "Default config for domain A",
            "admin"
        )
        assert config_a['success'] is True

        # Register client "shared-client" in domain A
        reg_a = config_manager.register_client(
            "shared-client",
            domain_a_jwt,
            "host-a",
            "192.168.1.100",
            "v1.0.0",
            "Linux A"
        )
        assert reg_a['success'] is True
        assert reg_a['domain_name'] == "domain-a"

        # Attempt to hijack "shared-client" using domain B's JWT
        # Should FAIL with error about client already registered in another domain
        reg_b_hijack = config_manager.register_client(
            "shared-client",
            domain_b_jwt,
            "host-b-hijacked",
            "192.168.1.200",
            "v2.0.0",
            "Linux B Attacker"
        )

        # Verify the hijack attempt was blocked
        assert reg_b_hijack['success'] is False
        assert 'another domain' in reg_b_hijack['error'].lower(), \
            f"Expected 'another domain' error, got: {reg_b_hijack['error']}"

        # Verify domain A's client data was not modified - should still have original config
        verify = config_manager.pull_client_config("shared-client", domain_a_jwt)
        assert verify['success'] is True
        assert verify['config'] == mock_client_config

    def test_cannot_assign_config_across_domains(self, config_manager, mock_client_config):
        """Regression: config from domain A cannot be assigned to a client in domain B.

        This tests the IDOR fix where assign_config_to_client must verify that
        the config's domain_id matches the client's domain_id.
        """
        # Create two domains
        domain_a = config_manager.create_deployment_domain("domain-a", "Domain A")
        domain_a_jwt = domain_a['jwt_token']
        domain_a_id = domain_a['id']

        domain_b = config_manager.create_deployment_domain("domain-b", "Domain B")
        domain_b_jwt = domain_b['jwt_token']
        domain_b_id = domain_b['id']

        # Create a config in domain A
        config_a = config_manager.create_client_config(
            "config-a",
            domain_a_id,
            mock_client_config,
            "Config for domain A",
            "admin"
        )
        assert config_a['success'] is True
        config_a_id = config_a['config_id']

        # Create a config in domain B
        config_b_data = mock_client_config.copy()
        config_b_data['dns_port'] = 5353
        config_b = config_manager.create_client_config(
            "config-b",
            domain_b_id,
            config_b_data,
            "Config for domain B",
            "admin"
        )
        assert config_b['success'] is True
        config_b_id = config_b['config_id']

        # Register a client in domain B
        client_b = config_manager.register_client(
            "client-b",
            domain_b_jwt,
            "host-b",
            "192.168.1.100"
        )
        assert client_b['success'] is True

        # Attempt to assign domain A's config to domain B's client
        # Should FAIL because configs must belong to the same domain
        assign_cross = config_manager.assign_config_to_client(
            "client-b",
            config_a_id,
            "attacker"
        )

        assert assign_cross['success'] is False
        assert 'different domain' in assign_cross['error'].lower(), \
            f"Expected 'different domain' error, got: {assign_cross['error']}"

        # Verify domain B's client can still use domain B's config
        assign_same = config_manager.assign_config_to_client(
            "client-b",
            config_b_id,
            "admin"
        )
        assert assign_same['success'] is True
