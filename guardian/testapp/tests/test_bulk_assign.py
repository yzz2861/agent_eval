from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.db import IntegrityError, transaction
from django.test import TestCase, TransactionTestCase

from guardian.exceptions import (
    BulkAssignmentError,
    DuplicateBulkAssignmentError,
    MixedContentTypeError,
    ObjectNotPersisted,
)
from guardian.managers import BulkAssignResult
from guardian.models import GroupObjectPermission, UserObjectPermission
from guardian.shortcuts import assign_perm, bulk_assign_perm
from guardian.testapp.models import ChildTestModel, Post, Project, ProjectUserObjectPermission
from guardian.utils import get_group_obj_perms_model, get_user_obj_perms_model

User = get_user_model()


class BulkAssignBaseMixin:
    perm_model = UserObjectPermission
    identity_attr = "user"

    def setUp(self):
        self.user = User.objects.create_user(username="bulk-jack")
        self.group = Group.objects.create(name="bulk-group")
        self.posts = [Post.objects.create(title=f"post-{i}") for i in range(3)]
        self.projects = [Project.objects.create(name=f"project-{i}") for i in range(2)]
        self.post_ctype = ContentType.objects.get_for_model(Post)
        self.permission = Permission.objects.get(content_type=self.post_ctype, codename="change_post")

    @property
    def identity(self):
        return self.user if self.perm_model is UserObjectPermission else self.group

    def model_for(self, obj):
        if self.perm_model is UserObjectPermission:
            return get_user_obj_perms_model(obj)
        return get_group_obj_perms_model(obj)

    def perm_count(self):
        return self.perm_model.objects.count()


class GenericBulkAssignTests(BulkAssignBaseMixin, TestCase):
    perm_model = UserObjectPermission

    def test_full_success_creates_every_row_and_reports_empty_skips(self):
        before = self.perm_count()
        result = self.perm_model.objects.bulk_assign_perm(self.permission, self.user, self.posts)

        self.assertIsInstance(result, BulkAssignResult)
        self.assertEqual(len(result.created), 3)
        self.assertEqual(result.skipped, [])
        self.assertEqual(self.perm_count(), before + 3)
        for post in self.posts:
            self.assertTrue(
                self.perm_model.objects.filter(
                    user=self.user, permission=self.permission, content_type=self.post_ctype, object_pk=str(post.pk)
                ).exists()
            )

    def test_works_with_queryset_and_codename_string(self):
        result = self.perm_model.objects.bulk_assign_perm("change_post", self.user, Post.objects.all())
        self.assertEqual(len(result.created), 3)
        self.assertEqual(result.skipped, [])

    def test_empty_batch_is_stable_noop_without_writes(self):
        before = self.perm_count()
        result = self.perm_model.objects.bulk_assign_perm(self.permission, self.user, [])
        self.assertIsInstance(result, BulkAssignResult)
        self.assertEqual(result.created, [])
        self.assertEqual(result.skipped, [])
        self.assertEqual(self.perm_count(), before)

        qs_result = self.perm_model.objects.bulk_assign_perm(self.permission, self.user, Post.objects.none())
        self.assertEqual(qs_result.created, [])
        self.assertEqual(qs_result.skipped, [])
        self.assertEqual(self.perm_count(), before)

    def test_cross_model_mix_fails_and_leaves_table_untouched(self):
        before = self.perm_count()
        mixed = [self.posts[0], self.projects[0]]

        with self.assertRaises(MixedContentTypeError):
            self.perm_model.objects.bulk_assign_perm(self.permission, self.user, mixed)

        self.assertEqual(self.perm_count(), before)
        # And via the shortcut, same guarantee.
        with self.assertRaises(MixedContentTypeError):
            bulk_assign_perm("change_post", self.user, mixed)
        self.assertEqual(self.perm_count(), before)

    def test_cross_model_mix_after_valid_prefix_never_writes_half_batch(self):
        # Regression for the original incident: the first dozens of objects
        # are valid but an object of another model sits later in the batch.
        before = self.perm_count()
        mixed = [*self.posts, self.projects[0]]

        with self.assertRaises(MixedContentTypeError):
            self.perm_model.objects.bulk_assign_perm(self.permission, self.user, mixed)

        self.assertEqual(self.perm_count(), before)
        self.assertFalse(
            self.perm_model.objects.filter(
                **{self.identity_attr: self.identity, "permission": self.permission}
            ).exists()
        )

    def test_unpersisted_object_fails_before_any_insert(self):
        before = self.perm_count()
        unsaved = Post(title="not-saved")
        with self.assertRaises(ObjectNotPersisted):
            self.perm_model.objects.bulk_assign_perm(self.permission, self.user, [self.posts[0], unsaved])
        self.assertEqual(self.perm_count(), before)

    def test_unknown_codename_rolls_back_and_keeps_context(self):
        before = self.perm_count()
        with self.assertRaises(BulkAssignmentError) as ctx:
            self.perm_model.objects.bulk_assign_perm("not_a_real_codename", self.user, self.posts)
        self.assertIsInstance(ctx.exception.original_error, Permission.DoesNotExist)
        self.assertIs(ctx.exception.__cause__, ctx.exception.original_error)
        self.assertEqual(self.perm_count(), before)

    def test_inactive_user_is_rejected_without_writes(self):
        before = self.perm_count()
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        with self.assertRaises(BulkAssignmentError):
            self.perm_model.objects.bulk_assign_perm(self.permission, self.user, self.posts)
        self.assertEqual(self.perm_count(), before)

    def test_duplicate_object_in_batch_fails_mode_rolls_everything_back(self):
        before = self.perm_count()
        with self.assertRaises(DuplicateBulkAssignmentError):
            self.perm_model.objects.bulk_assign_perm(
                self.permission, self.user, [self.posts[0], self.posts[1], self.posts[0]]
            )
        self.assertEqual(self.perm_count(), before)

    def test_already_existing_permission_fails_mode_changes_nothing(self):
        self.perm_model.objects.bulk_assign_perm(self.permission, self.user, [self.posts[0]])
        before = self.perm_count()

        with self.assertRaises(DuplicateBulkAssignmentError):
            self.perm_model.objects.bulk_assign_perm(self.permission, self.user, self.posts)
        self.assertEqual(self.perm_count(), before)

    def test_ignore_mode_skips_existing_and_only_creates_missing(self):
        first = self.perm_model.objects.bulk_assign_perm(self.permission, self.user, [self.posts[0]])
        self.assertEqual(len(first.created), 1)

        result = self.perm_model.objects.bulk_assign_perm(self.permission, self.user, self.posts, ignore_existing=True)
        self.assertEqual(len(result.created), 2)
        self.assertEqual(result.skipped, [self.posts[0]])
        created_pks = {row.object_pk for row in result.created}
        self.assertEqual(created_pks, {str(self.posts[1].pk), str(self.posts[2].pk)})

        # Re-running is fully idempotent: everything is skipped, nothing duplicated.
        again = self.perm_model.objects.bulk_assign_perm(self.permission, self.user, self.posts, ignore_existing=True)
        self.assertEqual(again.created, [])
        self.assertEqual(len(again.skipped), 3)
        self.assertEqual(self.perm_model.objects.count(), 3)

    def test_ignore_mode_deduplicates_repeated_object_in_batch(self):
        result = self.perm_model.objects.bulk_assign_perm(
            self.permission, self.user, [self.posts[0], self.posts[0]], ignore_existing=True
        )
        self.assertEqual(len(result.created), 1)
        self.assertEqual(result.skipped, [])
        self.assertEqual(self.perm_model.objects.count(), 1)

    def test_modes_return_distinct_shapes_never_mixed(self):
        fail_result = self.perm_model.objects.bulk_assign_perm(self.permission, self.user, self.posts)
        self.assertIsInstance(fail_result, BulkAssignResult)

        # Legacy shortcut returns a plain list of created rows.
        legacy = assign_perm("change_post", self.user, Post.objects.all())
        self.assertIsInstance(legacy, list)
        self.assertEqual(len(legacy), 0)

        # Explicit shortcut always returns the audit structure.
        audit = bulk_assign_perm("change_post", self.user, Post.objects.all(), ignore_existing=True)
        self.assertIsInstance(audit, BulkAssignResult)
        self.assertEqual(audit.created, [])
        self.assertEqual(len(audit.skipped), 3)

    def test_concurrent_duplicate_commit_rolls_back_in_fail_mode(self):
        before = self.perm_count()
        from django.db.models import Manager as _Manager

        real_bulk_create = _Manager.bulk_create.__get__(
            UserObjectPermission.objects, type(UserObjectPermission.objects)
        )

        def racing_bulk_create(objs, *args, **kwargs):
            # Simulate another transaction committing the same unique rows
            # between our pre-check and the INSERT.
            real_bulk_create(objs, ignore_conflicts=True)
            raise IntegrityError("UNIQUE constraint failed: duplicate concurrent submit")

        with mock.patch.object(UserObjectPermission.objects, "bulk_create", side_effect=racing_bulk_create):
            with self.assertRaises(DuplicateBulkAssignmentError) as ctx:
                self.perm_model.objects.bulk_assign_perm(self.permission, self.user, self.posts)

        self.assertIsInstance(ctx.exception.original_error, IntegrityError)
        # The racing rows were inserted inside the mocked call but our outer
        # transaction must have rolled them back as well.
        self.assertEqual(self.perm_count(), before)

    def test_rollback_then_requery_shows_no_partial_rows(self):
        before = self.perm_count()
        with self.assertRaises(MixedContentTypeError):
            with transaction.atomic():
                self.perm_model.objects.bulk_assign_perm(self.permission, self.user, [self.posts[0]])
                # Second, invalid call inside the same outer transaction.
                self.perm_model.objects.bulk_assign_perm(self.permission, self.user, [self.posts[1], self.projects[0]])
        self.assertEqual(self.perm_count(), before)
        self.assertFalse(UserObjectPermission.objects.filter(user=self.user, permission=self.permission).exists())

        # The table is still usable for a clean retry after the rollback.
        result = self.perm_model.objects.bulk_assign_perm(self.permission, self.user, self.posts)
        self.assertEqual(len(result.created), 3)
        self.assertEqual(self.perm_count(), before + 3)

    def test_wrong_identity_type_is_rejected(self):
        with self.assertRaises(BulkAssignmentError):
            self.perm_model.objects.bulk_assign_perm(self.permission, self.group, self.posts)
        self.assertEqual(self.perm_model.objects.count(), 0)

    def test_deprecated_ignore_conflicts_alias_still_works(self):
        self.perm_model.objects.bulk_assign_perm(self.permission, self.user, [self.posts[0]])
        with self.assertWarns(DeprecationWarning):
            result = self.perm_model.objects.bulk_assign_perm(
                self.permission, self.user, self.posts, ignore_conflicts=True
            )
        self.assertEqual(len(result.skipped), 1)
        self.assertEqual(len(result.created), 2)


class GroupBulkAssignTests(BulkAssignBaseMixin, TestCase):
    perm_model = GroupObjectPermission

    def test_group_full_success_and_skip_audit(self):
        result = self.perm_model.objects.bulk_assign_perm(self.permission, self.group, self.posts)
        self.assertEqual(len(result.created), 3)
        self.assertEqual(result.skipped, [])

        again = bulk_assign_perm("change_post", self.group, self.posts, ignore_existing=True)
        self.assertEqual(again.created, [])
        self.assertEqual(len(again.skipped), 3)

    def test_group_cross_model_failure_changes_nothing(self):
        before = self.perm_count()
        with self.assertRaises(MixedContentTypeError):
            self.perm_model.objects.bulk_assign_perm(self.permission, self.group, [self.posts[0], self.projects[0]])
        self.assertEqual(self.perm_count(), before)

    def test_group_requires_persisted_group_and_correct_identity(self):
        unsaved_group = Group(name="never-saved")
        with self.assertRaises(ObjectNotPersisted):
            self.perm_model.objects.bulk_assign_perm(self.permission, unsaved_group, self.posts)
        self.assertEqual(self.perm_count(), 0)

        with self.assertRaises(BulkAssignmentError):
            self.perm_model.objects.bulk_assign_perm(self.permission, self.user, self.posts)
        self.assertEqual(self.perm_count(), 0)

    def test_non_model_elements_are_rejected_atomically(self):
        with self.assertRaises(BulkAssignmentError):
            self.perm_model.objects.bulk_assign_perm(self.permission, self.group, [self.posts[0], "not-a-model"])
        self.assertEqual(self.perm_count(), 0)


class DirectForeignKeyBulkAssignTests(TestCase):
    """Covers non-generic object permission models (direct FK content_object)."""

    def setUp(self):
        self.user = User.objects.create_user(username="direct-bulk")
        self.projects = [Project.objects.create(name=f"direct-{i}") for i in range(3)]
        self.permission = Permission.objects.get(
            content_type=ContentType.objects.get_for_model(Project), codename="change_project"
        )

    def test_direct_fk_success_skip_and_failure_rollback(self):
        self.assertEqual(ProjectUserObjectPermission.objects.count(), 0)

        result = ProjectUserObjectPermission.objects.bulk_assign_perm(self.permission, self.user, self.projects)
        self.assertEqual(len(result.created), 3)
        self.assertEqual(result.skipped, [])

        again = ProjectUserObjectPermission.objects.bulk_assign_perm(
            self.permission, self.user, self.projects, ignore_existing=True
        )
        self.assertEqual(again.created, [])
        self.assertEqual(len(again.skipped), 3)
        self.assertEqual(ProjectUserObjectPermission.objects.count(), 3)

        post = Post.objects.create(title="alien")
        with self.assertRaises(MixedContentTypeError):
            ProjectUserObjectPermission.objects.bulk_assign_perm(self.permission, self.user, [self.projects[0], post])
        self.assertEqual(ProjectUserObjectPermission.objects.count(), 3)

    def test_direct_fk_duplicate_failure_is_atomic(self):
        before = ProjectUserObjectPermission.objects.count()
        with self.assertRaises(DuplicateBulkAssignmentError):
            ProjectUserObjectPermission.objects.bulk_assign_perm(
                self.permission, self.user, [self.projects[0], self.projects[0]]
            )
        self.assertEqual(ProjectUserObjectPermission.objects.count(), before)

    def test_direct_fk_unpersisted_object_is_rejected(self):
        unsaved = Project(name="unsaved-project")
        with self.assertRaises(ObjectNotPersisted):
            ProjectUserObjectPermission.objects.bulk_assign_perm(
                self.permission, self.user, [self.projects[0], unsaved]
            )
        self.assertEqual(ProjectUserObjectPermission.objects.count(), 0)


class BulkAssignTransactionTests(BulkAssignBaseMixin, TransactionTestCase):
    """Real-commit semantics: verify rollback survives an actual COMMIT boundary."""

    perm_model = UserObjectPermission

    def test_failed_batch_leaves_no_rows_after_commit_boundary(self):
        before = self.perm_count()
        with self.assertRaises(DuplicateBulkAssignmentError):
            self.perm_model.objects.bulk_assign_perm(self.permission, self.user, [self.posts[0], self.posts[0]])
        # Fresh query outside any test-case wrapper transaction.
        self.assertEqual(UserObjectPermission.objects.count(), before)


class CustomContentTypeBulkAssignTests(TestCase):
    """Polymorphic setups rely on GUARDIAN_GET_CONTENT_TYPE returning a base ctype."""

    def setUp(self):
        self.user = User.objects.create_user(username="poly-bulk")
        self.children = [ChildTestModel.objects.create(name=f"child-{i}") for i in range(2)]

    def test_bulk_assign_honours_custom_content_type(self):
        with mock.patch(
            "guardian.conf.settings.GET_CONTENT_TYPE",
            "guardian.testapp.tests.test_managers.get_parent_content_type",
        ):
            parent_ctype = ContentType.objects.get_for_model(ChildTestModel.__mro__[1])
            result = UserObjectPermission.objects.bulk_assign_perm("change_parenttestmodel", self.user, self.children)

        self.assertEqual(len(result.created), 2)
        self.assertEqual(set(UserObjectPermission.objects.values_list("content_type", flat=True)), {parent_ctype.id})
        for row in UserObjectPermission.objects.all():
            self.assertEqual(row.content_type, parent_ctype)

        UserObjectPermission.objects.all().delete()
        with mock.patch(
            "guardian.conf.settings.GET_CONTENT_TYPE",
            "guardian.testapp.tests.test_managers.get_parent_content_type",
        ):
            qs_result = UserObjectPermission.objects.bulk_assign_perm(
                "change_parenttestmodel", self.user, ChildTestModel.objects.all()
            )
        self.assertEqual(len(qs_result.created), 2)
        self.assertEqual(set(UserObjectPermission.objects.values_list("content_type", flat=True)), {parent_ctype.id})


class SingleAssignPermSemanticsTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="single-bulk")
        self.post = Post.objects.create(title="single")
        self.permission = Permission.objects.get(
            content_type=ContentType.objects.get_for_model(Post), codename="change_post"
        )

    def test_single_assign_perm_stays_idempotent_and_never_overwrites(self):
        first = UserObjectPermission.objects.assign_perm(self.permission, self.user, self.post)
        second = UserObjectPermission.objects.assign_perm(self.permission, self.user, self.post)
        self.assertEqual(first.pk, second.pk)
        self.assertEqual(UserObjectPermission.objects.count(), 1)

        # Shortcut stays idempotent as well.
        again = assign_perm("change_post", self.user, self.post)
        self.assertEqual(again.pk, first.pk)
        self.assertEqual(UserObjectPermission.objects.count(), 1)
