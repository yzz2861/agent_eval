from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser, Group
from django.core.cache import cache
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext

from guardian.backends import ObjectPermissionBackend, check_user_support
from guardian.conf import settings as guardian_settings
from guardian.core import ObjectPermissionChecker
from guardian.shortcuts import assign_perm, remove_perm
from guardian.testapp.models import Project

User = get_user_model()


class ObjectPermissionBackendTest(TestCase):
    def setUp(self):
        self.backend = ObjectPermissionBackend()
        self.user = User.objects.create_user(username="testuser", password="testpass")
        self.superuser = User.objects.create_superuser(username="superuser", password="superpass")
        self.inactive_user = User.objects.create_user(username="inactive", password="inactive")
        self.inactive_user.is_active = False
        self.inactive_user.save()

        self.group = Group.objects.create(name="testgroup")
        self.user.groups.add(self.group)

        self.project = Project.objects.create(name="Test Project")

        # Create anonymous user if it doesn't exist
        try:
            self.anonymous_user = User.objects.get(username=guardian_settings.ANONYMOUS_USER_NAME)
        except User.DoesNotExist:
            self.anonymous_user = User.objects.create_user(username=guardian_settings.ANONYMOUS_USER_NAME)

    def test_authenticate_returns_none(self):
        """Backend should not authenticate users (returns None)"""
        result = self.backend.authenticate(request=None, username="test", password="test")
        self.assertIsNone(result)

    def test_has_perm_with_object(self):
        """Test has_perm method with object permissions"""
        # No permission initially
        self.assertFalse(self.backend.has_perm(self.user, "change_project", self.project))

        # Assign permission
        assign_perm("change_project", self.user, self.project)
        self.assertTrue(self.backend.has_perm(self.user, "change_project", self.project))

    def test_has_perm_without_object(self):
        """Test has_perm method without object (should return False)"""
        # ObjectPermissionBackend only handles object-level permissions
        self.assertFalse(self.backend.has_perm(self.user, "change_project"))

    def test_has_perm_superuser(self):
        """Test has_perm method with superuser"""
        self.assertTrue(self.backend.has_perm(self.superuser, "change_project", self.project))

    def test_has_perm_inactive_user(self):
        """Test has_perm method with inactive user"""
        assign_perm("change_project", self.inactive_user, self.project)
        self.assertFalse(self.backend.has_perm(self.inactive_user, "change_project", self.project))

    def test_get_group_permissions_with_object(self):
        """Test get_group_permissions method with object"""
        # No permissions initially
        perms = self.backend.get_group_permissions(self.user, self.project)
        self.assertEqual(set(), perms)

        # Assign permission to group
        assign_perm("change_project", self.group, self.project)
        perms = self.backend.get_group_permissions(self.user, self.project)
        self.assertIn("change_project", perms)

    def test_get_group_permissions_without_object(self):
        """Test get_group_permissions method without object (should return empty set)"""
        perms = self.backend.get_group_permissions(self.user)
        self.assertEqual(set(), perms)

    def test_get_group_permissions_inactive_user(self):
        """Test get_group_permissions method with inactive user"""
        assign_perm("change_project", self.group, self.project)
        perms = self.backend.get_group_permissions(self.inactive_user, self.project)
        self.assertEqual(set(), perms)

    def test_get_group_permissions_anonymous_user(self):
        """Test get_group_permissions method with anonymous user"""
        anonymous = AnonymousUser()
        perms = self.backend.get_group_permissions(anonymous, self.project)
        # Should return empty set for anonymous users (unless configured)
        self.assertEqual(set(), perms)

    def test_get_all_permissions_with_object(self):
        """Test get_all_permissions method with object"""
        # No permissions initially
        perms = self.backend.get_all_permissions(self.user, self.project)
        self.assertEqual(set(), perms)

        # Assign user permission
        assign_perm("change_project", self.user, self.project)
        perms = self.backend.get_all_permissions(self.user, self.project)
        self.assertIn("change_project", perms)

        # Assign group permission
        assign_perm("delete_project", self.group, self.project)
        perms = self.backend.get_all_permissions(self.user, self.project)
        self.assertIn("change_project", perms)
        self.assertIn("delete_project", perms)

    def test_get_all_permissions_without_object(self):
        """Test get_all_permissions method without object"""
        perms = self.backend.get_all_permissions(self.user)
        self.assertEqual(set(), perms)

    def test_get_all_permissions_superuser(self):
        """Test get_all_permissions method with superuser"""
        perms = self.backend.get_all_permissions(self.superuser, self.project)
        # Superuser should have all permissions for the content type
        self.assertGreater(len(list(perms)), 0)

    def test_mixed_user_and_group_permissions(self):
        """Test that both user and group permissions are returned correctly"""
        # Assign different permissions to user and group
        assign_perm("change_project", self.user, self.project)
        assign_perm("delete_project", self.group, self.project)

        # get_group_permissions should only return group permissions
        group_perms = self.backend.get_group_permissions(self.user, self.project)
        self.assertIn("delete_project", group_perms)
        self.assertNotIn("change_project", group_perms)

        # get_all_permissions should return both
        all_perms = self.backend.get_all_permissions(self.user, self.project)
        self.assertIn("change_project", all_perms)
        self.assertIn("delete_project", all_perms)

    def test_permission_removal(self):
        """Test that permission removal works correctly"""
        # Assign permissions
        assign_perm("change_project", self.user, self.project)
        assign_perm("delete_project", self.group, self.project)

        # Verify they exist
        self.assertTrue(self.backend.has_perm(self.user, "change_project", self.project))
        group_perms = self.backend.get_group_permissions(self.user, self.project)
        self.assertIn("delete_project", group_perms)

        # Remove permissions
        remove_perm("change_project", self.user, self.project)
        remove_perm("delete_project", self.group, self.project)

        # Verify they're gone
        self.assertFalse(self.backend.has_perm(self.user, "change_project", self.project))
        group_perms = self.backend.get_group_permissions(self.user, self.project)
        self.assertEqual(set(), group_perms)

    def test_user_in_multiple_groups(self):
        """Test permissions when user belongs to multiple groups"""
        group1 = Group.objects.create(name="group1")
        group2 = Group.objects.create(name="group2")

        self.user.groups.add(group1, group2)

        # Assign different permissions to different groups
        assign_perm("change_project", group1, self.project)
        assign_perm("delete_project", group2, self.project)

        # User should get permissions from both groups
        group_perms = self.backend.get_group_permissions(self.user, self.project)
        self.assertIn("change_project", group_perms)
        self.assertIn("delete_project", group_perms)

    def test_backend_attributes(self):
        """Test that backend has correct attributes"""
        self.assertTrue(self.backend.supports_object_permissions)
        self.assertTrue(self.backend.supports_anonymous_user)
        self.assertTrue(self.backend.supports_inactive_user)

    def test_explain_perm_matches_has_perm_and_reports_real_sources(self):
        assign_perm("change_project", self.user, self.project)
        direct = self.backend.explain_perm(self.user, "change_project", self.project)
        self.assertEqual(direct["result"], self.backend.has_perm(self.user, "change_project", self.project))
        self.assertEqual(direct["source"], "direct_user")

        other_project = Project.objects.create(name="group-project")
        assign_perm("delete_project", self.group, other_project)
        inherited = self.backend.explain_perm(self.user, "delete_project", other_project)
        self.assertTrue(inherited["result"])
        self.assertEqual(inherited["source"], "group")
        self.assertEqual(inherited["group_paths"], [self.group.name])
        self.assertTrue(self.backend.has_perm(self.user, "delete_project", other_project))

        denied = self.backend.explain_perm(self.user, "change_project", other_project)
        self.assertFalse(denied["result"])
        self.assertFalse(self.backend.has_perm(self.user, "change_project", other_project))
        self.assertEqual(denied["denial_reason"], "no_matching_permission")

    def test_explain_perm_global_semantics(self):
        assign_perm("testapp.change_project", self.user)

        ignored = self.backend.explain_perm(
            self.user,
            "change_project",
            self.project,
            accept_global_perms=False,
        )
        self.assertFalse(ignored["result"])

        accepted = self.backend.explain_perm(
            self.user,
            "change_project",
            self.project,
            accept_global_perms=True,
        )
        self.assertTrue(accepted["result"])
        self.assertEqual(accepted["source"], "global")

        checker = ObjectPermissionChecker(self.user)
        checker_result = checker.explain_perm(
            "change_project",
            self.project,
            accept_global_perms=True,
        )
        self.assertEqual(accepted["result"], checker_result["result"])
        self.assertEqual(accepted["source"], checker_result["source"])

    def test_explain_perm_inactive_superuser_and_anonymous_special_paths(self):
        assign_perm("change_project", self.inactive_user, self.project)
        inactive = self.backend.explain_perm(self.inactive_user, "change_project", self.project)
        self.assertFalse(inactive["result"])
        self.assertEqual(inactive["source"], "inactive_user")

        superuser = self.backend.explain_perm(self.superuser, "change_project", self.project)
        self.assertTrue(superuser["result"])
        self.assertEqual(superuser["source"], "superuser")
        self.assertEqual(superuser["special_path"], "superuser")

        anonymous_group = Group.objects.create(name="anonymous-group")
        self.anonymous_user.groups.add(anonymous_group)
        assign_perm("view_project", anonymous_group, self.project)
        anonymous = self.backend.explain_perm(AnonymousUser(), "view_project", self.project)
        self.assertTrue(anonymous["result"])
        self.assertTrue(anonymous["is_anonymous"])
        self.assertEqual(anonymous["special_path"], "anonymous")
        self.assertEqual(anonymous["group_paths"], [anonymous_group.name])

    def test_explain_perms_batch_reuses_group_source_queries(self):
        projects = [Project.objects.create(name=f"batch-backend-{index}") for index in range(5)]
        assign_perm("change_project", self.user, projects[0])
        assign_perm("change_project", self.group, projects[1])

        with CaptureQueriesContext(connection) as queries:
            results = self.backend.explain_perms(self.user, "change_project", projects)

        self.assertEqual([result["result"] for result in results], [True, True, False, False, False])
        self.assertEqual(results[0]["source"], "direct_user")
        self.assertEqual(results[1]["source"], "group")
        # One group-membership query, one direct-row query and one group-row
        # query, regardless of the number of objects in the batch.
        self.assertLessEqual(len(queries), 5)

    def test_explain_perm_anonymous_support_disabled_is_explicit(self):
        with patch("guardian.backends.settings.ANONYMOUS_USER_NAME", None):
            result = self.backend.explain_perm(AnonymousUser(), "view_project", self.project)

        self.assertFalse(result["result"])
        self.assertTrue(result["is_anonymous"])
        self.assertEqual(result["denial_reason"], "anonymous_not_supported")


class CheckUserSupportAnonymousCacheTest(TestCase):
    """check_user_support() resolves anonymous users through get_anonymous_user() (#1050)."""

    def setUp(self):
        cache.clear()
        self.anonymous_user = User.objects.get_or_create(username=guardian_settings.ANONYMOUS_USER_NAME)[0]

    def tearDown(self):
        cache.clear()

    def test_uses_get_anonymous_user(self):
        with patch("guardian.backends.get_anonymous_user", return_value=self.anonymous_user) as mock_get:
            supported, user_obj = check_user_support(AnonymousUser())

        mock_get.assert_called_once_with()
        self.assertTrue(supported)
        self.assertEqual(user_obj, self.anonymous_user)

    def test_anonymous_lookup_is_cached_when_ttl_is_set(self):
        with patch("guardian.conf.settings.ANONYMOUS_USER_CACHE_TTL", 300):
            check_user_support(AnonymousUser())
            with self.assertNumQueries(0):
                supported, user_obj = check_user_support(AnonymousUser())

        self.assertTrue(supported)
        self.assertEqual(user_obj.pk, self.anonymous_user.pk)

    def test_anonymous_lookup_hits_database_without_cache(self):
        with patch("guardian.conf.settings.ANONYMOUS_USER_CACHE_TTL", 0), self.assertNumQueries(1):
            check_user_support(AnonymousUser())
