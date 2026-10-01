from django.core.exceptions import NON_FIELD_ERRORS
from django.db import connection
from django.test import TestCase, override_settings
from unittest.mock import patch

from .models import (
    BulkUniqueCustomMessageModel,
    BulkUniqueModel,
    BulkUniquePlainModel,
)


class BulkUniqueValidationTests(TestCase):
    def assertErrors(self, result, **expected):
        actual = {
            field: [str(error) for error in errors]
            for field, errors in result.errors.items()
        }
        self.assertEqual(actual, expected)

    def test_database_and_batch_conflicts(self):
        BulkUniquePlainModel.objects.create(
            name="existing", group=1, color="red"
        )
        first = BulkUniquePlainModel(name="batch", group=2, color="blue")
        second = BulkUniquePlainModel(name="batch", group=2, color="blue")
        third = BulkUniquePlainModel(name="existing", group=3, color="green")

        results = BulkUniquePlainModel.validate_unique_list([first, second, third])

        self.assertTrue(results[0].errors[NON_FIELD_ERRORS])
        self.assertTrue(results[1].errors[NON_FIELD_ERRORS])
        self.assertEqual(
            str(results[0].errors["name"][0]),
            str(results[2].errors["name"][0]),
        )
        self.assertFalse(results[0].used_fallback)
        self.assertFalse(results[1].used_fallback)
        self.assertFalse(results[2].used_fallback)

    def test_update_excludes_itself_but_not_other_updates(self):
        first = BulkUniquePlainModel.objects.create(
            name="first", group=1, color="red"
        )
        second = BulkUniquePlainModel.objects.create(
            name="second", group=2, color="blue"
        )

        first_result = BulkUniquePlainModel.validate_unique_list([first])[0]
        self.assertEqual(first_result.errors, {})

        second.name = "changed"
        second.group = 2
        second.color = "blue"
        first.name = "changed"
        first.group = 2
        first.color = "blue"

        results = BulkUniquePlainModel.validate_unique_list([first, second])

        self.assertIn("name", results[0].errors)
        self.assertIn("name", results[1].errors)
        self.assertTrue(results[0].errors[NON_FIELD_ERRORS])
        self.assertTrue(results[1].errors[NON_FIELD_ERRORS])

    def test_database_conflict_and_batch_conflict_are_both_reported(self):
        BulkUniquePlainModel.objects.create(
            name="duplicate", group=1, color="red"
        )
        first = BulkUniquePlainModel(name="duplicate", group=1, color="red")
        second = BulkUniquePlainModel(name="duplicate", group=1, color="red")

        results = BulkUniquePlainModel.validate_unique_list([first, second])

        for result in results:
            self.assertIn("name", result.errors)
            self.assertTrue(result.errors[NON_FIELD_ERRORS])

    def test_exclude_removes_constraint_groups(self):
        existing = BulkUniquePlainModel.objects.create(
            name="existing", group=1, color="red"
        )
        duplicate = BulkUniquePlainModel(name="existing", group=1, color="red")
        duplicate.pk = None

        results = BulkUniquePlainModel.validate_unique_list(
            [duplicate], exclude={"name", "color", "group"}
        )

        self.assertEqual(results[0].errors, {})
        self.assertEqual(existing.name, "existing")

    def test_nulls_use_backend_null_semantics(self):
        first = BulkUniquePlainModel(
            name="first", group=1, color="red", category=None
        )
        second = BulkUniquePlainModel(
            name="second", group=1, color="blue", category=None
        )

        results = BulkUniquePlainModel.validate_unique_list([first, second])

        self.assertEqual(results[0].errors, {})
        self.assertEqual(results[1].errors, {})

    def test_custom_unique_constraint_message_is_preserved(self):
        BulkUniqueCustomMessageModel.objects.create(name="existing")
        instance = BulkUniqueCustomMessageModel(name="existing")

        result = BulkUniqueCustomMessageModel.validate_unique_list([instance])[0]

        self.assertEqual(
            result.errors["name"][0].message,
            "Custom bulk unique message.",
        )

    def test_query_count_scales_with_constraint_groups_and_chunks(self):
        instances = [
            BulkUniquePlainModel(
                name=f"name-{index}",
                group=index,
                color=f"color-{index}",
                category=f"category-{index}",
            )
            for index in range(3)
        ]

        with self.assertNumQueries(3):
            results = BulkUniquePlainModel.validate_unique_list(instances)

        self.assertEqual([result.errors for result in results], [{}, {}, {}])

    def test_query_count_scales_with_chunks(self):
        instances = [
            BulkUniquePlainModel(
                name=f"name-{index}",
                group=index,
                color=f"color-{index}",
            )
            for index in range(4)
        ]

        with (
            patch.object(connection.ops, "bulk_batch_size", return_value=2),
            self.assertNumQueries(4),
        ):
            results = BulkUniquePlainModel.validate_unique_list(instances)

        self.assertEqual([result.errors for result in results], [{}, {}, {}, {}])

    def test_expression_constraints_fallback_to_instance_validation(self):
        BulkUniqueModel.objects.create(
            name="CASE", group=1, color="red", active=False
        )
        instance = BulkUniqueModel(name="case", group=2, color="blue", active=False)

        with self.assertNumQueries(6):
            results = BulkUniqueModel.validate_unique_list([instance])

        self.assertTrue(results[0].used_fallback)
        self.assertTrue(results[0].errors[NON_FIELD_ERRORS])

    def test_conditional_constraints_fallback_to_instance_validation(self):
        BulkUniqueModel.objects.create(
            name="first", group=1, color="red", active=True
        )
        instance = BulkUniqueModel(
            name="second", group=2, color="red", active=True
        )

        with self.assertNumQueries(6):
            results = BulkUniqueModel.validate_unique_list([instance])

        self.assertTrue(results[0].used_fallback)
        self.assertTrue(results[0].errors[NON_FIELD_ERRORS])

    def test_excluded_fallback_constraint_is_not_validated(self):
        BulkUniqueModel.objects.create(
            name="CASE", group=1, color="red", active=True
        )
        instance = BulkUniqueModel(name="case", group=2, color="red", active=True)

        with self.assertNumQueries(1):
            results = BulkUniqueModel.validate_unique_list(
                [instance], exclude={"name", "active"}
            )

        self.assertFalse(results[0].used_fallback)
        self.assertEqual(results[0].errors, {})


class InstanceStateRouter:
    def db_for_write(self, model, **hints):
        instance = hints.get("instance")
        return instance._state.db if instance is not None and instance._state.db else "default"


@override_settings(DATABASE_ROUTERS=[InstanceStateRouter()])
class BulkUniqueDatabaseAliasTests(TestCase):
    databases = {"default", "other"}

    def test_instances_are_grouped_by_database_alias(self):
        existing = BulkUniquePlainModel.objects.using("other").create(
            name="existing", group=1, color="red"
        )
        duplicate_default = BulkUniquePlainModel(
            name="existing", group=2, color="blue"
        )
        duplicate_other = BulkUniquePlainModel(
            name="existing", group=2, color="blue"
        )
        duplicate_other._state.db = "other"

        results = BulkUniquePlainModel.validate_unique_list(
            [duplicate_default, duplicate_other]
        )

        self.assertEqual(results[0].errors, {})
        self.assertEqual(set(results[1].errors), {"name"})
