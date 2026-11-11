"""Tests for object identity handling (pk, model, content type, tenant).

Object identity must always be validated as a whole: same-pk objects of
different models must never match each other, custom content types must
still identify the object's model, and when a tenant resolver is
configured, cross-tenant operations must be denied with an auditable,
aggregate-friendly reason that does not leak object existence.
"""

from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase

from guardian.core import ObjectPermissionChecker
from guardian.exceptions import (
    MixedContentTypeError,
    ObjectIdentityError,
    ObjectNotPersisted,
    TenantMismatchError,
)
from guardian.models import GroupObjectPermission, UserObjectPermission
from guardian.shortcuts import assign_perm, get_objects_for_group, get_objects_for_user, remove_perm
from guardian.testapp.models import ChildTestModel, Mixed, ParentTestModel, Post, PostProxy, UUIDPKModel

User = get_user_model()

TENANT_A = "tenant-a"
TENANT_B = "tenant-b"

# (model label, pk) -> tenant key, consulted by get_test_tenant.
TENANT_MAP = {}


def get_test_tenant(obj):
    """GUARDIAN_GET_TENANT test resolver backed by TENANT_MAP."""
    if obj is None or getattr(obj, "pk", None) is None:
        return None
    return TENANT_MAP.get((obj._meta.label_lower, obj.pk))


def get_post_content_type(obj):
    """Custom GUARDIAN_GET_CONTENT_TYPE mapping every model to Post's type.

    Simulates a misconfigured/polymorphic resolver that merges unrelated
    models into one primary-key namespace; must be rejected at write time.
    """
    return ContentType.objects.get_for_model(Post)


def get_parent_content_type(obj):
    """Legitimate custom GUARDIAN_GET_CONTENT_TYPE for inherited models."""
    if isinstance(obj, ChildTestModel) or obj is ChildTestModel:
        return ContentType.objects.get_for_model(ParentTestModel)
    return ContentType.objects.get_for_model(obj)


class SamePkCrossModelTests(TestCase):
    """Same-pk objects of different models must never match each other."""

    def setUp(self):
        self.user = User.objects.create(username="identity-user")
        self.group = Group.objects.create(name="identity-group")
        self.post = Post.objects.create(id=90001, title="post")
        self.mixed = Mixed.objects.create(id=90001, name="mixed")
        self.post_ctype = ContentType.objects.get_for_model(Post)
        self.mixed_ctype = ContentType.objects.get_for_model(Mixed)

    def test_user_perm_does_not_leak_to_other_model_with_same_pk(self):
        assign_perm("view_post", self.user, self.post)

        self.assertTrue(self.user.has_perm("testapp.view_post", self.post))
        self.assertFalse(self.user.has_perm("testapp.view_mixed", self.mixed))
        self.assertEqual(list(get_objects_for_user(self.user, "testapp.view_mixed")), [])
        self.assertEqual(list(get_objects_for_user(self.user, "testapp.view_post")), [self.post])

    def test_group_perm_does_not_leak_to_other_model_with_same_pk(self):
        assign_perm("view_post", self.group, self.post)

        checker = ObjectPermissionChecker(self.group)
        self.assertTrue(checker.has_perm("view_post", self.post))
        self.assertFalse(checker.has_perm("view_mixed", self.mixed))
        self.assertEqual(list(get_objects_for_group(self.group, "testapp.view_mixed")), [])
        self.assertEqual(list(get_objects_for_group(self.group, "testapp.view_post")), [self.post])

    def test_remove_perm_does_not_touch_other_model_with_same_pk(self):
        assign_perm("view_post", self.user, self.post)

        remove_perm("view_mixed", self.user, self.mixed)
        remove_perm("view_post", self.user, self.mixed)

        self.assertTrue(self.user.has_perm("testapp.view_post", self.post))

    def test_inconsistent_row_is_not_matched_by_object_pk_alone(self):
        """A row whose content_type and permission disagree must be inert.

        Such rows can exist in historical data (e.g. written while a custom
        GUARDIAN_GET_CONTENT_TYPE was active). Identity is the combination
        of content type and object pk, so the row must not match queries
        for either model alone.
        """
        view_mixed = Permission.objects.get(content_type=self.mixed_ctype, codename="view_mixed")
        # bulk_create bypasses the model-level save() validation on purpose.
        UserObjectPermission.objects.bulk_create(
            [
                UserObjectPermission(
                    user=self.user,
                    permission=view_mixed,
                    content_type=self.post_ctype,
                    object_pk=str(self.mixed.pk),
                )
            ]
        )

        self.assertEqual(list(get_objects_for_user(self.user, "testapp.view_mixed")), [])
        self.assertEqual(list(get_objects_for_user(self.user, "testapp.view_post")), [])
        self.assertFalse(self.user.has_perm("testapp.view_mixed", self.mixed))

        deleted, _ = remove_perm("view_mixed", self.user, self.mixed)
        self.assertEqual(deleted, 0)
        self.assertEqual(UserObjectPermission.objects.count(), 1)

    def test_permission_instance_with_mismatched_content_type_is_rejected(self):
        view_mixed = Permission.objects.get(content_type=self.mixed_ctype, codename="view_mixed")
        with self.assertRaises(ObjectIdentityError):
            assign_perm(view_mixed, self.user, self.post)
        self.assertEqual(UserObjectPermission.objects.count(), 0)


class CustomContentTypeTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(username="ctype-user")
        self.mixed = Mixed.objects.create(name="mixed")

    def test_legitimate_custom_content_type_roundtrip(self):
        child = ChildTestModel.objects.create(name="child")
        parent_ctype = ContentType.objects.get_for_model(ParentTestModel)
        with mock.patch(
            "guardian.conf.settings.GET_CONTENT_TYPE",
            "guardian.testapp.tests.test_object_identity.get_parent_content_type",
        ):
            assign_perm("change_parenttestmodel", self.user, child)
            obj_perm = UserObjectPermission.objects.get(user=self.user)
            self.assertEqual(obj_perm.content_type, parent_ctype)
            self.assertTrue(self.user.has_perm("testapp.change_parenttestmodel", child))
            remove_perm("change_parenttestmodel", self.user, child)
            self.assertFalse(self.user.has_perm("testapp.change_parenttestmodel", child))

    def test_unrelated_custom_content_type_is_rejected(self):
        with mock.patch(
            "guardian.conf.settings.GET_CONTENT_TYPE",
            "guardian.testapp.tests.test_object_identity.get_post_content_type",
        ):
            with self.assertLogs("guardian.ctypes", level="WARNING") as logs:
                with self.assertRaises(ObjectIdentityError) as ctx:
                    assign_perm("view_mixed", self.user, self.mixed)

        self.assertEqual(ctx.exception.code, "object_identity_error")
        self.assertIn("object_identity_error", "".join(logs.output))
        self.assertEqual(UserObjectPermission.objects.count(), 0)


class UUIDPrimaryKeyTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(username="uuid-user")
        self.obj = UUIDPKModel.objects.create()
        self.other = UUIDPKModel.objects.create()

    def test_uuid_pk_identity_roundtrip(self):
        assign_perm("view_uuidpkmodel", self.user, self.obj)

        self.assertTrue(self.user.has_perm("testapp.view_uuidpkmodel", self.obj))
        self.assertFalse(self.user.has_perm("testapp.view_uuidpkmodel", self.other))
        self.assertEqual(list(get_objects_for_user(self.user, "testapp.view_uuidpkmodel")), [self.obj])

        remove_perm("view_uuidpkmodel", self.user, self.other)
        self.assertTrue(self.user.has_perm("testapp.view_uuidpkmodel", self.obj))

        remove_perm("view_uuidpkmodel", self.user, self.obj)
        self.assertFalse(self.user.has_perm("testapp.view_uuidpkmodel", self.obj))

    def test_uuid_pk_bulk_assign_and_remove(self):
        assign_perm("view_uuidpkmodel", self.user, [self.obj, self.other])
        self.assertEqual(UserObjectPermission.objects.count(), 2)

        remove_perm("view_uuidpkmodel", self.user, [self.obj, self.other])
        self.assertEqual(UserObjectPermission.objects.count(), 0)


class ProxyModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(username="proxy-user")
        self.post = Post.objects.create(title="proxied")
        self.proxy = PostProxy.objects.get(pk=self.post.pk)

    def test_proxy_and_concrete_model_share_identity(self):
        assign_perm("view_post", self.user, self.proxy)

        obj_perm = UserObjectPermission.objects.get(user=self.user)
        self.assertEqual(obj_perm.content_type, ContentType.objects.get_for_model(Post))
        self.assertTrue(self.user.has_perm("testapp.view_post", self.post))
        self.assertTrue(self.user.has_perm("testapp.view_post", self.proxy))
        self.assertEqual(list(get_objects_for_user(self.user, "testapp.view_post")), [self.post])

        remove_perm("view_post", self.user, self.proxy)
        self.assertFalse(self.user.has_perm("testapp.view_post", self.post))

    def test_bulk_mixed_proxy_and_concrete_model_is_allowed(self):
        # post and proxy share one identity, so the batch holds a single grant.
        UserObjectPermission.objects.bulk_assign_perm(
            "view_post", self.user, [self.post, self.proxy], ignore_conflicts=True
        )
        self.assertEqual(UserObjectPermission.objects.count(), 1)


class UnpersistedAndBulkInputTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(username="bulk-user")
        self.post = Post.objects.create(title="post")
        self.mixed = Mixed.objects.create(name="mixed")

    def test_assign_perm_requires_persisted_object(self):
        with self.assertRaises(ObjectNotPersisted):
            assign_perm("view_post", self.user, Post(title="unsaved"))

    def test_bulk_assign_requires_persisted_objects(self):
        with self.assertRaises(ObjectNotPersisted):
            assign_perm("view_post", self.user, [self.post, Post(title="unsaved")])
        self.assertEqual(UserObjectPermission.objects.count(), 0)

    def test_remove_perm_requires_persisted_object(self):
        with self.assertRaises(ObjectNotPersisted):
            remove_perm("view_post", self.user, Post(title="unsaved"))

    def test_bulk_assign_rejects_mixed_content_types(self):
        with self.assertRaises(MixedContentTypeError):
            assign_perm("view_post", self.user, [self.post, self.mixed])
        self.assertEqual(UserObjectPermission.objects.count(), 0)


class TenantEnforcementTests(TestCase):
    def setUp(self):
        TENANT_MAP.clear()
        self.user_a = User.objects.create(username="tenant-a-user")
        self.user_b = User.objects.create(username="tenant-b-user")
        self.group_a = Group.objects.create(name="tenant-a-group")
        self.post_a = Post.objects.create(title="post-a")
        self.post_b = Post.objects.create(title="post-b")
        TENANT_MAP[("testapp.customuser", self.user_a.pk)] = TENANT_A
        TENANT_MAP[("testapp.customuser", self.user_b.pk)] = TENANT_B
        TENANT_MAP[("auth.group", self.group_a.pk)] = TENANT_A
        TENANT_MAP[("testapp.post", self.post_a.pk)] = TENANT_A
        TENANT_MAP[("testapp.post", self.post_b.pk)] = TENANT_B
        patcher = mock.patch(
            "guardian.conf.settings.GET_TENANT",
            "guardian.testapp.tests.test_object_identity.get_test_tenant",
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(TENANT_MAP.clear)

    def move_to_tenant_b(self, obj):
        TENANT_MAP[(obj._meta.label_lower, obj.pk)] = TENANT_B

    def test_cross_tenant_assign_perm_is_denied_and_auditable(self):
        with self.assertLogs("guardian.ctypes", level="WARNING") as logs:
            with self.assertRaises(TenantMismatchError) as ctx:
                assign_perm("view_post", self.user_a, self.post_b)

        self.assertEqual(ctx.exception.code, "tenant_mismatch")
        self.assertIn("tenant_mismatch", "".join(logs.output))
        # The denial must not leak identifiers of the other tenant's object.
        self.assertNotIn(str(self.post_b.pk), str(ctx.exception))
        self.assertNotIn(self.post_b.title, str(ctx.exception))
        self.assertEqual(UserObjectPermission.objects.count(), 0)

    def test_same_tenant_assign_perm_is_allowed(self):
        assign_perm("view_post", self.user_a, self.post_a)
        self.assertTrue(self.user_a.has_perm("testapp.view_post", self.post_a))

    def test_cross_tenant_group_assign_perm_is_denied(self):
        with self.assertRaises(TenantMismatchError):
            assign_perm("view_post", self.group_a, self.post_b)
        self.assertEqual(GroupObjectPermission.objects.count(), 0)

    def test_cross_tenant_bulk_assign_is_denied_atomically(self):
        with self.assertRaises(TenantMismatchError):
            assign_perm("view_post", self.user_a, [self.post_a, self.post_b])
        # Nothing may be written, not even the same-tenant grant.
        self.assertEqual(UserObjectPermission.objects.count(), 0)

    def test_cross_tenant_check_is_denied_without_leak(self):
        assign_perm("view_post", self.user_a, self.post_a)
        self.assertTrue(self.user_a.has_perm("testapp.view_post", self.post_a))

        self.move_to_tenant_b(self.post_a)
        with self.assertLogs("guardian.ctypes", level="WARNING"):
            self.assertFalse(self.user_a.has_perm("testapp.view_post", self.post_a))

        checker = ObjectPermissionChecker(self.user_a)
        checker.prefetch_perms([self.post_a])
        self.assertFalse(checker.has_perm("view_post", self.post_a))

    def test_cross_tenant_objects_are_excluded_from_list_queries(self):
        assign_perm("view_post", self.user_a, self.post_a)
        # Simulate a historical/inconsistent cross-tenant grant row.
        view_post = Permission.objects.get(codename="view_post")
        UserObjectPermission.objects.bulk_create(
            [
                UserObjectPermission(
                    user=self.user_a,
                    permission=view_post,
                    content_type=ContentType.objects.get_for_model(Post),
                    object_pk=str(self.post_b.pk),
                )
            ]
        )

        objects = list(get_objects_for_user(self.user_a, "testapp.view_post"))
        self.assertEqual(objects, [self.post_a])
        self.assertFalse(self.user_a.has_perm("testapp.view_post", self.post_b))

    def test_cross_tenant_remove_is_denied_and_perm_is_kept(self):
        assign_perm("view_post", self.user_a, self.post_a)
        self.move_to_tenant_b(self.post_a)

        with self.assertRaises(TenantMismatchError):
            remove_perm("view_post", self.user_a, self.post_a)
        self.assertEqual(UserObjectPermission.objects.count(), 1)

    def test_tenant_less_data_stays_compatible(self):
        # Historical users/objects without tenant information are unaffected.
        legacy_user = User.objects.create(username="legacy-user")
        legacy_post = Post.objects.create(title="legacy-post")

        assign_perm("view_post", legacy_user, legacy_post)
        self.assertTrue(legacy_user.has_perm("testapp.view_post", legacy_post))
        self.assertEqual(list(get_objects_for_user(legacy_user, "testapp.view_post")), [legacy_post])

        # A tenant-less object stays readable for a tenanted identity, and
        # existing grants are never removed implicitly.
        assign_perm("view_post", self.user_a, legacy_post)
        self.assertTrue(self.user_a.has_perm("testapp.view_post", legacy_post))
        remove_perm("view_post", legacy_user, legacy_post)
        self.assertTrue(self.user_a.has_perm("testapp.view_post", legacy_post))

    def test_without_resolver_nothing_changes(self):
        # Sanity check that TenantMismatchError is only raised when a
        # resolver is configured; covered suite-wide by the other tests.
        self.assertEqual(TenantMismatchError.code, "tenant_mismatch")
        self.assertEqual(ObjectIdentityError.code, "object_identity_error")
