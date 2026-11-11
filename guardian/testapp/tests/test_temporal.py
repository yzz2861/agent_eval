from datetime import datetime, timedelta, timezone as dt_timezone
from unittest.mock import patch

from django.contrib.auth.models import AnonymousUser, Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase

from guardian.backends import ObjectPermissionBackend
from guardian.conf import settings as guardian_settings
from guardian.core import ObjectPermissionChecker
from guardian.models import GroupObjectPermission, UserObjectPermission
from guardian.shortcuts import assign_perm, get_objects_for_group, get_objects_for_user, remove_perm
from guardian.testapp.models import Post


class TemporaryPermissionTests(TestCase):
    def setUp(self):
        self.user = UserObjectPermission.user.field.related_model.objects.create_user(
            username="temporary-user", password="x"
        )
        self.other_user = UserObjectPermission.user.field.related_model.objects.create_user(
            username="other-user", password="x"
        )
        self.group = Group.objects.create(name="temporary-group")
        self.post = Post.objects.create(title="temporary")
        self.other_post = Post.objects.create(title="permanent")
        self.now = datetime(2026, 11, 12, 9, 0, 0, tzinfo=dt_timezone.utc)
        self.start = self.now
        self.end = self.now + timedelta(hours=2)

    def _objects_at(self, at, **kwargs):
        with patch("django.utils.timezone.now", return_value=at):
            return list(get_objects_for_user(self.user, "change_post", klass=Post, **kwargs))

    def test_half_open_boundary_is_consistent_across_all_entry_points(self):
        permission = Permission.objects.get(content_type=ContentType.objects.get_for_model(Post), codename="change_post")
        with patch("django.utils.timezone.now", return_value=self.now):
            assign_perm("change_post", self.user, self.post, valid_from=self.start, valid_until=self.end)

        checker = ObjectPermissionChecker(self.user)
        backend = ObjectPermissionBackend()

        with patch("django.utils.timezone.now", return_value=self.start):
            self.assertTrue(checker.has_perm(permission.codename, self.post))
            self.assertTrue(backend.has_perm(self.user, "change_post", self.post))
            self.assertEqual(self._objects_at(self.start), [self.post])

        just_before_end = self.end - timedelta(microseconds=1)
        with patch("django.utils.timezone.now", return_value=just_before_end):
            self.assertTrue(checker.has_perm(permission.codename, self.post))
            self.assertEqual(self._objects_at(just_before_end), [self.post])

        # valid_until is exclusive: at the exact boundary every entry point flips.
        with patch("django.utils.timezone.now", return_value=self.end):
            self.assertFalse(checker.has_perm(permission.codename, self.post))
            self.assertFalse(backend.has_perm(self.user, "change_post", self.post))
            self.assertEqual(self._objects_at(self.end), [])

    def test_valid_from_boundary_activates_future_grant_and_refreshes_cache(self):
        start = self.now + timedelta(hours=1)
        end = start + timedelta(hours=2)
        with patch("django.utils.timezone.now", return_value=self.now):
            assign_perm("change_post", self.user, self.post, valid_from=start, valid_until=end)

        checker = ObjectPermissionChecker(self.user)
        with patch("django.utils.timezone.now", return_value=self.now):
            self.assertFalse(checker.has_perm("change_post", self.post))
            self.assertEqual(self._objects_at(self.now), [])

        with patch("django.utils.timezone.now", return_value=start):
            self.assertTrue(checker.has_perm("change_post", self.post))
            self.assertEqual(self._objects_at(start), [self.post])

    def test_permanent_and_temporary_grants_mix_in_same_queryset(self):
        with patch("django.utils.timezone.now", return_value=self.now):
            assign_perm("change_post", self.user, self.post, valid_until=self.end)
            assign_perm("change_post", self.user, self.other_post)

        with patch("django.utils.timezone.now", return_value=self.end):
            self.assertEqual(self._objects_at(self.end), [self.other_post])

        checker = ObjectPermissionChecker(self.user)
        with patch("django.utils.timezone.now", return_value=self.end):
            self.assertFalse(checker.has_perm("change_post", self.post))
            self.assertTrue(checker.has_perm("change_post", self.other_post))

    def test_group_inheritance_uses_same_window(self):
        self.user.groups.add(self.group)
        with patch("django.utils.timezone.now", return_value=self.now):
            assign_perm("change_post", self.group, self.post, valid_from=self.start, valid_until=self.end)

        checker = ObjectPermissionChecker(self.user)
        with patch("django.utils.timezone.now", return_value=self.start):
            self.assertTrue(checker.has_perm("change_post", self.post))
            self.assertEqual(self._objects_at(self.start), [self.post])

        with patch("django.utils.timezone.now", return_value=self.end):
            self.assertFalse(checker.has_perm("change_post", self.post))
            self.assertEqual(self._objects_at(self.end), [])

    def test_get_objects_for_group_uses_same_window(self):
        with patch("django.utils.timezone.now", return_value=self.now):
            assign_perm("change_post", self.group, self.post, valid_until=self.end)

        with patch("django.utils.timezone.now", return_value=self.start):
            self.assertEqual(list(get_objects_for_group(self.group, "change_post", klass=Post)), [self.post])

        with patch("django.utils.timezone.now", return_value=self.end):
            self.assertEqual(list(get_objects_for_group(self.group, "change_post", klass=Post)), [])

    def test_renewal_extends_and_early_revoke_invalidates_existing_checker(self):
        first_end = self.now + timedelta(hours=1)
        renewed_end = self.now + timedelta(hours=3)
        with patch("django.utils.timezone.now", return_value=self.now):
            assign_perm("change_post", self.user, self.post, valid_until=first_end)

        checker = ObjectPermissionChecker(self.user)
        with patch("django.utils.timezone.now", return_value=self.now):
            self.assertTrue(checker.has_perm("change_post", self.post))
            assign_perm("change_post", self.user, self.post, valid_until=renewed_end)
            self.assertTrue(checker.has_perm("change_post", self.post))

        with patch("django.utils.timezone.now", return_value=first_end):
            self.assertTrue(checker.has_perm("change_post", self.post))
            # Revoking an active grant must also be visible to an initialized checker.
            remove_perm("change_post", self.user, self.post)
            self.assertFalse(checker.has_perm("change_post", self.post))
            self.assertEqual(self._objects_at(first_end), [])

    def test_prefetched_cache_does_not_survive_expiry(self):
        with patch("django.utils.timezone.now", return_value=self.now):
            assign_perm("change_post", self.user, self.post, valid_until=self.end)

        checker = ObjectPermissionChecker(self.user)
        with patch("django.utils.timezone.now", return_value=self.now):
            self.assertTrue(checker.prefetch_perms([self.post]))
            self.assertTrue(checker.has_perm("change_post", self.post))

        with patch("django.utils.timezone.now", return_value=self.end):
            self.assertFalse(checker.has_perm("change_post", self.post))

    def test_auto_prefetch_cache_does_not_survive_expiry(self):
        guardian_settings.AUTO_PREFETCH = True
        try:
            with patch("django.utils.timezone.now", return_value=self.now):
                assign_perm("change_post", self.user, self.post, valid_until=self.end)

            checker = ObjectPermissionChecker(self.user)
            with patch("django.utils.timezone.now", return_value=self.now):
                self.assertTrue(checker.has_perm("change_post", self.post))

            with patch("django.utils.timezone.now", return_value=self.end):
                self.assertFalse(checker.has_perm("change_post", self.post))
        finally:
            guardian_settings.AUTO_PREFETCH = False

    def test_bulk_assign_deduplicates_and_rolls_back_on_partial_failure(self):
        original_end = self.now + timedelta(hours=1)
        with patch("django.utils.timezone.now", return_value=self.now - timedelta(hours=1)):
            assign_perm("change_post", self.user, self.post, valid_until=original_end)

        group = Group.objects.create(name="cross-type")
        posts = [self.post, self.post, self.other_post]
        with patch("django.utils.timezone.now", return_value=self.now):
            UserObjectPermission.objects.bulk_assign_perm("change_post", self.user, posts, valid_until=self.end)

        self.assertEqual(
            UserObjectPermission.objects.filter(user=self.user, permission__codename="change_post").count(), 2
        )
        self.assertTrue(UserObjectPermission.objects.get(user=self.user, object_pk=str(self.post.pk)).is_active(self.now))

        # The Group content type has no "change_post" permission.  The first
        # content-type group has already been renewed when this raises, but the
        # surrounding transaction must restore the original window.
        with patch("django.utils.timezone.now", return_value=self.now), self.assertRaises(Permission.DoesNotExist):
            UserObjectPermission.objects.bulk_assign_perm(
                "change_post", self.user, [self.post, group], valid_until=self.now + timedelta(hours=3)
            )

        grant = UserObjectPermission.objects.get(user=self.user, object_pk=str(self.post.pk))
        self.assertEqual(grant.valid_until, self.end)

    def test_bulk_revoke_and_delete_group_cascade(self):
        self.user.groups.add(self.group)
        with patch("django.utils.timezone.now", return_value=self.now):
            assign_perm("change_post", self.group, self.post, valid_until=self.end)
            assign_perm("change_post", self.group, self.other_post, valid_until=self.end)

        with patch("django.utils.timezone.now", return_value=self.now):
            removed, _ = remove_perm("change_post", self.group, [self.post, self.other_post])
            self.assertEqual(removed, 2)
            self.assertFalse(GroupObjectPermission.objects.exists())

        with patch("django.utils.timezone.now", return_value=self.now):
            assign_perm("change_post", self.group, self.post, valid_until=self.end)
            checker = ObjectPermissionChecker(self.user)
            self.assertTrue(checker.has_perm("change_post", self.post))
            self.group.delete()
            # deleting the group cascades object-permission rows and invalidates caches
            self.assertFalse(checker.has_perm("change_post", self.post))
        self.assertFalse(GroupObjectPermission.objects.exists())

    def test_inactive_anonymous_and_superuser_paths(self):
        superuser = UserObjectPermission.user.field.related_model.objects.create_user(
            username="temporary-superuser", password="x", is_superuser=True
        )
        checker = ObjectPermissionChecker(superuser)
        with patch("django.utils.timezone.now", return_value=self.end):
            self.assertTrue(checker.has_perm("change_post", self.post))
            self.assertEqual(
                set(get_objects_for_user(superuser, "change_post", klass=Post)), {self.post, self.other_post}
            )

        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        with patch("django.utils.timezone.now", return_value=self.now):
            assign_perm("change_post", self.user, self.post, valid_from=self.start, valid_until=self.end)
            self.assertFalse(ObjectPermissionChecker(self.user).has_perm("change_post", self.post))
            self.assertEqual(self._objects_at(self.end), [])

        with patch("django.utils.timezone.now", return_value=self.end):
            anonymous_user = AnonymousUser()
            self.assertEqual(list(get_objects_for_user(anonymous_user, "change_post", klass=Post)), [])

    def test_accept_global_perms_does_not_bypass_expired_object_grants(self):
        ctype = ContentType.objects.get_for_model(Post)
        self.user.user_permissions.add(Permission.objects.get(content_type=ctype, codename="change_post"))
        with patch("django.utils.timezone.now", return_value=self.now):
            assign_perm("change_post", self.user, self.post, valid_until=self.end)

        with patch("django.utils.timezone.now", return_value=self.end):
            self.assertEqual(self._objects_at(self.end, accept_global_perms=True), [self.post, self.other_post])
            self.assertEqual(self._objects_at(self.end, accept_global_perms=False), [])
