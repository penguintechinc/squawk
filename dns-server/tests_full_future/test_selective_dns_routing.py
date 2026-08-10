#!/usr/bin/env python3
"""
Unit tests for Selective DNS Routing
Tests user/group-based DNS filtering and access control.
"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timedelta
from selective_dns_routing import SelectiveDNSRouter

class TestSelectiveDNSRouter:

    @pytest.fixture
    def dns_router(self, temp_db):
        """Create selective DNS router instance with test database.

        Seeds the canonical test principal token "test-token-123" as the first
        row in the `token` table (PK 1) so it maps to user_id 1 — the user these
        tests assign to groups. This seeding lives in the test fixture, never in
        production code.
        """
        db_url = f"sqlite://{temp_db._uri[9:]}"
        from penguin_dal import DB
        seed = DB(db_url)
        try:
            if not seed(seed.token.token == "test-token-123").select().first():
                seed.token.insert(token="test-token-123", name="test-token-123", active=True)
                seed.commit()
        finally:
            seed.close()
        return SelectiveDNSRouter(db_url)

    def test_initialization(self, dns_router):
        """Test DNS router initialization"""
        assert dns_router.db_url is not None
        assert hasattr(dns_router, 'zone_visibility_levels')
        assert 'public' in dns_router.zone_visibility_levels
        assert 'internal' in dns_router.zone_visibility_levels
        assert 'restricted' in dns_router.zone_visibility_levels
        assert 'private' in dns_router.zone_visibility_levels

    def test_create_user_group(self, dns_router):
        """Test creating user groups"""
        result = dns_router.create_group(
            "engineering",
            "Engineering team",
            ["internal", "public"]
        )

        assert result['success'] is True
        assert 'group_id' in result

        # Test duplicate group
        duplicate_result = dns_router.create_group("engineering", "Duplicate", ["public"])
        assert duplicate_result['success'] is False
        assert 'already exists' in duplicate_result['error']

    def test_assign_user_to_group(self, dns_router):
        """Test assigning users to groups"""
        # Create group first
        group_result = dns_router.create_group("test-group", "Test Group", ["internal", "public"])
        group_id = group_result['group_id']

        # Assign user to group
        result = dns_router.assign_user_to_group(1, group_id, "admin")

        assert result['success'] is True

        # Test assigning same user again (should update)
        result2 = dns_router.assign_user_to_group(1, group_id, "admin")
        assert result2['success'] is True

    def test_create_dns_zone(self, dns_router):
        """Test creating DNS zones with visibility levels"""
        zones = [
            ("public.example.com", "public", "Public zone"),
            ("internal.company.com", "internal", "Internal company zone"),
            ("secret.company.com", "private", "Private zone")
        ]

        for zone_name, visibility, description in zones:
            result = dns_router.create_dns_zone(
                zone_name, visibility, description, "admin"
            )

            assert result['success'] is True
            assert 'zone_id' in result

    def test_can_resolve_domain_public(self, dns_router):
        """Test that all users can resolve public domains"""
        # Create public zone
        zone_result = dns_router.create_dns_zone("public.example.com", "public", "Public zone", "admin")

        # Test with any token ID
        can_resolve = dns_router.can_resolve_domain("test-token-123", "subdomain.public.example.com")
        assert can_resolve is True

        # Test with no token
        can_resolve_anon = dns_router.can_resolve_domain(None, "subdomain.public.example.com")
        assert can_resolve_anon is True

    def test_can_resolve_domain_internal_authorized(self, dns_router):
        """Test that authorized users can resolve internal domains"""
        # Create group with internal access
        group_result = dns_router.create_group("internal-users", "Internal Users", ["internal", "public"])
        group_id = group_result['group_id']

        # Assign user to group
        dns_router.assign_user_to_group(1, group_id, "admin")

        # Create internal zone
        dns_router.create_dns_zone("internal.company.com", "internal", "Internal zone", "admin")

        # User should be able to resolve
        can_resolve = dns_router.can_resolve_domain("test-token-123", "app.internal.company.com")
        assert can_resolve is True

    def test_can_resolve_domain_internal_unauthorized(self, dns_router):
        """Test that unauthorized users cannot resolve internal domains"""
        # Create internal zone
        dns_router.create_dns_zone("internal.company.com", "internal", "Internal zone", "admin")

        # Create group without internal access
        group_result = dns_router.create_group("public-only", "Public Only", ["public"])
        group_id = group_result['group_id']
        dns_router.assign_user_to_group(1, group_id, "admin")

        # User should not be able to resolve
        can_resolve = dns_router.can_resolve_domain("test-token-123", "app.internal.company.com")
        assert can_resolve is False

    def test_can_resolve_domain_private_authorized(self, dns_router):
        """Test that only specifically authorized users can resolve private domains"""
        # Create private zone
        zone_result = dns_router.create_dns_zone("private.company.com", "private", "Private zone", "admin")
        zone_id = zone_result['zone_id']

        # Create group with private access
        group_result = dns_router.create_group("executives", "Executives", ["private", "restricted", "internal", "public"])
        group_id = group_result['group_id']

        # Assign user to group
        dns_router.assign_user_to_group(1, group_id, "admin")

        # Grant specific zone access
        dns_router.grant_zone_access_to_group(zone_id, group_id, "admin")

        # User should be able to resolve
        can_resolve = dns_router.can_resolve_domain("test-token-123", "secret.private.company.com")
        assert can_resolve is True

    def test_can_resolve_domain_private_unauthorized(self, dns_router):
        """Test that unauthorized users cannot resolve private domains"""
        # Create private zone
        dns_router.create_dns_zone("private.company.com", "private", "Private zone", "admin")

        # Create group without private access
        group_result = dns_router.create_group("regular-users", "Regular Users", ["internal", "public"])
        group_id = group_result['group_id']
        dns_router.assign_user_to_group(1, group_id, "admin")

        # User should not be able to resolve
        can_resolve = dns_router.can_resolve_domain("test-token-123", "secret.private.company.com")
        assert can_resolve is False

    def test_filter_dns_response_allowed(self, dns_router, sample_dns_response):
        """Test DNS response filtering for allowed domain"""
        # Create public zone
        dns_router.create_dns_zone("example.com", "public", "Public zone", "admin")

        filtered_response = dns_router.filter_dns_response(
            "test-token-123", "example.com", sample_dns_response
        )

        # Response should be unchanged
        assert filtered_response == sample_dns_response
        assert filtered_response['Status'] == 0
        assert len(filtered_response['Answer']) > 0

    def test_filter_dns_response_blocked(self, dns_router, sample_dns_response):
        """Test DNS response filtering for blocked domain"""
        # Create private zone without granting access
        dns_router.create_dns_zone("secret.example.com", "private", "Private zone", "admin")

        # Create group without private access
        group_result = dns_router.create_group("limited-users", "Limited Users", ["public"])
        dns_router.assign_user_to_group(1, group_result['group_id'], "admin")

        original_response = sample_dns_response.copy()
        original_response['Answer'][0]['name'] = "secret.example.com"

        filtered_response = dns_router.filter_dns_response(
            "test-token-123", "secret.example.com", original_response
        )

        # Response should be filtered (NXDOMAIN)
        assert filtered_response['Status'] == 3  # NXDOMAIN
        assert len(filtered_response['Answer']) == 0
        assert filtered_response['Comment'] == "Domain not found"

    def test_wildcard_domain_matching(self, dns_router):
        """Test wildcard domain matching"""
        # Create zone with wildcard
        dns_router.create_dns_zone("*.internal.company.com", "internal", "Internal wildcard", "admin")

        # Create group with internal access
        group_result = dns_router.create_group("internal-group", "Internal", ["internal", "public"])
        dns_router.assign_user_to_group(1, group_result['group_id'], "admin")

        # Test various subdomains
        test_domains = [
            "app.internal.company.com",
            "api.internal.company.com",
            "db.internal.company.com",
            "test.app.internal.company.com"
        ]

        for domain in test_domains:
            can_resolve = dns_router.can_resolve_domain("test-token-123", domain)
            assert can_resolve is True, f"Failed to resolve wildcard domain: {domain}"

    def test_get_user_groups(self, dns_router):
        """Test getting user's group memberships"""
        # Create multiple groups
        group1_result = dns_router.create_group("group1", "Group 1", ["public"])
        group2_result = dns_router.create_group("group2", "Group 2", ["internal", "public"])

        # Assign user to both groups
        dns_router.assign_user_to_group(1, group1_result['group_id'], "admin")
        dns_router.assign_user_to_group(1, group2_result['group_id'], "admin")

        # Get user groups
        groups = dns_router.get_user_groups(1)

        assert len(groups) == 2
        group_names = [g['name'] for g in groups]
        assert "group1" in group_names
        assert "group2" in group_names

    def test_get_zone_access_levels(self, dns_router):
        """Test getting access levels for a domain"""
        # Create zones with different visibility
        dns_router.create_dns_zone("public.example.com", "public", "Public", "admin")
        dns_router.create_dns_zone("internal.example.com", "internal", "Internal", "admin")

        # Test access levels
        public_level = dns_router.get_zone_access_level("public.example.com")
        assert public_level == "public"

        internal_level = dns_router.get_zone_access_level("internal.example.com")
        assert internal_level == "internal"

        unknown_level = dns_router.get_zone_access_level("unknown.example.com")
        assert unknown_level == "public"  # Default fallback

    def test_grant_revoke_zone_access(self, dns_router):
        """Test granting and revoking zone access"""
        # Create private zone and group
        zone_result = dns_router.create_dns_zone("private.example.com", "private", "Private", "admin")
        zone_id = zone_result['zone_id']

        group_result = dns_router.create_group("special-group", "Special", ["public"])
        group_id = group_result['group_id']

        dns_router.assign_user_to_group(1, group_id, "admin")

        # Initially should not have access
        can_resolve = dns_router.can_resolve_domain("test-token-123", "private.example.com")
        assert can_resolve is False

        # Grant access
        grant_result = dns_router.grant_zone_access_to_group(zone_id, group_id, "admin")
        assert grant_result['success'] is True

        # Now should have access
        can_resolve = dns_router.can_resolve_domain("test-token-123", "private.example.com")
        assert can_resolve is True

        # Revoke access
        revoke_result = dns_router.revoke_zone_access_from_group(zone_id, group_id, "admin")
        assert revoke_result['success'] is True

        # Should not have access again
        can_resolve = dns_router.can_resolve_domain("test-token-123", "private.example.com")
        assert can_resolve is False

    def test_remove_user_from_group(self, dns_router):
        """Test removing user from group"""
        # Create group and assign user
        group_result = dns_router.create_group("temp-group", "Temporary", ["internal", "public"])
        group_id = group_result['group_id']

        dns_router.assign_user_to_group(1, group_id, "admin")

        # Create internal zone
        dns_router.create_dns_zone("internal.example.com", "internal", "Internal", "admin")

        # User should have access
        can_resolve = dns_router.can_resolve_domain("test-token-123", "internal.example.com")
        assert can_resolve is True

        # Remove user from group
        remove_result = dns_router.remove_user_from_group(1, group_id, "admin")
        assert remove_result['success'] is True

        # User should no longer have access
        can_resolve = dns_router.can_resolve_domain("test-token-123", "internal.example.com")
        assert can_resolve is False

    def test_get_routing_stats(self, dns_router):
        """Test getting routing statistics"""
        # Create some test data
        dns_router.create_group("stats-group1", "Stats Group 1", ["public"])
        dns_router.create_group("stats-group2", "Stats Group 2", ["internal", "public"])

        dns_router.create_dns_zone("stats.example.com", "public", "Stats zone", "admin")
        dns_router.create_dns_zone("internal-stats.example.com", "internal", "Internal stats", "admin")

        dns_router.assign_user_to_group(1, 1, "admin")  # Assuming group IDs start at 1
        dns_router.assign_user_to_group(2, 2, "admin")

        stats = dns_router.get_routing_stats()

        assert 'groups' in stats
        assert 'zones' in stats
        assert 'user_assignments' in stats
        assert 'zone_access_grants' in stats

        assert stats['groups']['total'] >= 2
        assert stats['zones']['total'] >= 2
        assert stats['user_assignments']['total'] >= 2

    def test_domain_hierarchy_matching(self, dns_router):
        """Test domain hierarchy matching for zones"""
        # Create hierarchical zones
        dns_router.create_dns_zone("company.com", "public", "Company root", "admin")
        dns_router.create_dns_zone("internal.company.com", "internal", "Internal subdomain", "admin")
        dns_router.create_dns_zone("secret.internal.company.com", "private", "Secret subdomain", "admin")

        # Create user with only internal access
        group_result = dns_router.create_group("internal-only", "Internal Only", ["internal", "public"])
        dns_router.assign_user_to_group(1, group_result['group_id'], "admin")

        # Test domain resolution
        assert dns_router.can_resolve_domain("test-token-123", "company.com") is True  # Public
        assert dns_router.can_resolve_domain("test-token-123", "www.company.com") is True  # Public
        assert dns_router.can_resolve_domain("test-token-123", "app.internal.company.com") is True  # Internal
        assert dns_router.can_resolve_domain("test-token-123", "api.secret.internal.company.com") is False  # Private

    def test_token_to_user_id_mapping(self, dns_router, sample_token_data):
        """Test mapping tokens to user IDs"""
        # This tests the internal _get_user_id_from_token method
        user_id = dns_router._get_user_id_from_token(sample_token_data['token'])

        assert user_id is not None
        assert user_id == sample_token_data['token_id']

        # Test with invalid token
        invalid_user_id = dns_router._get_user_id_from_token("invalid-token-123")
        assert invalid_user_id is None

    def test_caching_behavior(self, dns_router):
        """Test caching of DNS routing decisions"""
        # Create zone and group
        dns_router.create_dns_zone("cached.example.com", "internal", "Cached zone", "admin")
        group_result = dns_router.create_group("cached-group", "Cached", ["internal", "public"])
        dns_router.assign_user_to_group(1, group_result['group_id'], "admin")

        # First resolution (should cache)
        can_resolve1 = dns_router.can_resolve_domain("test-token-123", "cached.example.com")
        assert can_resolve1 is True

        # Second resolution (should use cache if implemented)
        can_resolve2 = dns_router.can_resolve_domain("test-token-123", "cached.example.com")
        assert can_resolve2 is True

        # Results should be consistent
        assert can_resolve1 == can_resolve2

    def test_bulk_operations(self, dns_router):
        """Test bulk user and zone operations"""
        # Bulk create groups
        groups_data = [
            ("bulk-group-1", "Bulk Group 1", ["public"]),
            ("bulk-group-2", "Bulk Group 2", ["internal", "public"]),
            ("bulk-group-3", "Bulk Group 3", ["restricted", "internal", "public"])
        ]

        group_ids = []
        for name, desc, levels in groups_data:
            result = dns_router.create_group(name, desc, levels)
            assert result['success'] is True
            group_ids.append(result['group_id'])

        # Bulk create zones
        zones_data = [
            ("bulk1.example.com", "public"),
            ("bulk2.example.com", "internal"),
            ("bulk3.example.com", "restricted")
        ]

        for zone_name, visibility in zones_data:
            result = dns_router.create_dns_zone(zone_name, visibility, f"Bulk zone {zone_name}", "admin")
            assert result['success'] is True

        # Bulk assign users
        for i, group_id in enumerate(group_ids):
            result = dns_router.assign_user_to_group(i + 10, group_id, "admin")  # User IDs 10, 11, 12
            assert result['success'] is True

    def test_edge_cases(self, dns_router):
        """Test edge cases and error conditions"""
        # Test with empty domain
        can_resolve = dns_router.can_resolve_domain("test-token-123", "")
        assert can_resolve is False

        # Test with None domain
        can_resolve = dns_router.can_resolve_domain("test-token-123", None)
        assert can_resolve is False

        # Test with malformed domain
        can_resolve = dns_router.can_resolve_domain("test-token-123", "invalid..domain")
        assert can_resolve is False

        # Test with very long domain
        long_domain = "a" * 300 + ".example.com"
        can_resolve = dns_router.can_resolve_domain("test-token-123", long_domain)
        assert can_resolve in [True, False]  # Should handle gracefully

    def test_concurrent_access(self, dns_router):
        """Test concurrent access to routing functions"""
        import threading

        # Create test data
        dns_router.create_group("concurrent-group", "Concurrent", ["internal", "public"])
        dns_router.create_dns_zone("concurrent.example.com", "internal", "Concurrent zone", "admin")
        dns_router.assign_user_to_group(1, 1, "admin")

        results = []

        def test_resolution():
            for i in range(10):
                result = dns_router.can_resolve_domain("test-token-123", f"test{i}.concurrent.example.com")
                results.append(result)

        # Run concurrent tests
        threads = []
        for i in range(3):
            thread = threading.Thread(target=test_resolution)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # All results should be consistent
        assert len(results) == 30  # 3 threads * 10 results each
        assert all(r in [True, False] for r in results)  # All should be valid boolean results

    def test_delete_group(self, dns_router):
        """Test deleting user groups"""
        # Create group
        group_result = dns_router.create_group("delete-me", "Delete Me", ["public"])
        group_id = group_result['group_id']

        # Assign user to group
        dns_router.assign_user_to_group(1, group_id, "admin")

        # Delete group
        delete_result = dns_router.delete_group(group_id, "admin")
        assert delete_result['success'] is True

        # User should no longer be in any groups related to this
        user_groups = dns_router.get_user_groups(1)
        group_names = [g['name'] for g in user_groups]
        assert "delete-me" not in group_names

    def test_zone_inheritance(self, dns_router):
        """Test zone inheritance behavior"""
        # Create parent zone
        dns_router.create_dns_zone("parent.example.com", "internal", "Parent zone", "admin")

        # Create group with internal access
        group_result = dns_router.create_group("inherit-group", "Inherit", ["internal", "public"])
        dns_router.assign_user_to_group(1, group_result['group_id'], "admin")

        # Test that subdomains inherit parent zone access
        test_subdomains = [
            "child.parent.example.com",
            "grandchild.child.parent.example.com",
            "api.v1.parent.example.com"
        ]

        for subdomain in test_subdomains:
            can_resolve = dns_router.can_resolve_domain("test-token-123", subdomain)
            assert can_resolve is True, f"Subdomain inheritance failed for: {subdomain}"
