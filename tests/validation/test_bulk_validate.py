from django.core.exceptions import ValidationError
from django.db import connection, models
from django.test import TestCase, skipUnlessDBFeature
from django.test.utils import CaptureQueriesContext

from .models import (
    BulkValidateFallbackModel,
    BulkValidateModel,
    ChildUniqueConstraintProduct,
    UniqueConstraintProduct,
    UniqueDbDefaultExpressionModel,
    UniqueErrorsModel,
    UniqueFieldsModel,
    UniqueFuncConstraintModel,
    UniqueTogetherModel,
)


def make_unique_fields_model(charfield, integerfield, pk=None):
    return UniqueFieldsModel(
        pk=pk,
        unique_charfield=charfield,
        unique_integerfield=integerfield,
        non_unique_field=0,
    )


class BulkValidateTests(TestCase):
    def test_empty(self):
        result = BulkValidateModel.bulk_validate([])
        self.assertEqual(list(result), [])
        self.assertTrue(result.valid)
        self.assertTrue(result)
        self.assertEqual(result.fallback, [])

    def test_no_conflicts(self):
        instances = [
            BulkValidateModel(name="a", city="X", email="a@example.com"),
            BulkValidateModel(name="b", city="Y", email="b@example.com"),
        ]
        result = BulkValidateModel.bulk_validate(instances)
        self.assertTrue(result.valid)
        self.assertEqual(list(result), [None, None])

    def test_database_conflict_on_unique_field(self):
        UniqueFieldsModel.objects.create(
            unique_charfield="taken", unique_integerfield=1, non_unique_field=0
        )
        conflicting = make_unique_fields_model("taken", 2)
        free = make_unique_fields_model("free", 3)
        instances = [conflicting, free]
        result = UniqueFieldsModel.bulk_validate(instances)
        self.assertIsInstance(result[0], ValidationError)
        self.assertIn("unique_charfield", result[0].message_dict)
        self.assertIsNone(result[1])
        error = result[0].error_dict["unique_charfield"][0]
        self.assertEqual(error.code, "unique")
        self.assertIs(error.params["model"], conflicting)

    def test_batch_internal_conflict_on_unique_field(self):
        instances = [
            make_unique_fields_model("same", 1),
            make_unique_fields_model("same", 2),
        ]
        result = UniqueFieldsModel.bulk_validate(instances)
        self.assertIn("unique_charfield", result[0].message_dict)
        self.assertIn("unique_charfield", result[1].message_dict)

    def test_unique_together_database_conflict(self):
        UniqueTogetherModel.objects.create(
            ifield=1, cfield="a", efield="a@b.co"
        )
        instances = [
            UniqueTogetherModel(ifield=1, cfield="a", efield="c@d.co"),
            UniqueTogetherModel(ifield=2, cfield="a", efield="e@f.co"),
        ]
        result = UniqueTogetherModel.bulk_validate(instances)
        self.assertIn("__all__", result[0].message_dict)
        self.assertIsNone(result[1])

    def test_unique_together_batch_conflict(self):
        instances = [
            UniqueTogetherModel(ifield=1, cfield="a", efield="a@b.co"),
            UniqueTogetherModel(ifield=1, cfield="a", efield="c@d.co"),
        ]
        result = UniqueTogetherModel.bulk_validate(instances)
        self.assertIn("__all__", result[0].message_dict)
        self.assertIn("__all__", result[1].message_dict)

    def test_plain_unique_constraint(self):
        UniqueConstraintProduct.objects.create(name="p", color="red", rank=1)
        instances = [
            UniqueConstraintProduct(name="q", color="red", rank=1),
            UniqueConstraintProduct(name="q", color="blue", rank=2),
        ]
        result = UniqueConstraintProduct.bulk_validate(instances)
        # rank conflicts with the stored row for the first instance.
        self.assertIsNotNone(result[0])
        # The second instance has no conflict.
        self.assertIsNone(result[1])

        # A multi-field UniqueConstraint conflict within the batch.
        instances = [
            UniqueConstraintProduct(name="z", color="green", rank=10),
            UniqueConstraintProduct(name="z", color="green", rank=11),
        ]
        result = UniqueConstraintProduct.bulk_validate(instances)
        self.assertIn("__all__", result[0].message_dict)
        self.assertIn("__all__", result[1].message_dict)

    def test_single_field_constraint_uses_field_key(self):
        UniqueConstraintProduct.objects.create(name="p", color="red", rank=1)
        instances = [
            UniqueConstraintProduct(name="q", color="red", rank=1),
        ]
        result = UniqueConstraintProduct.bulk_validate(instances)
        self.assertIn("rank", result[0].message_dict)

    def test_field_unique_custom_message_is_preserved(self):
        UniqueErrorsModel.objects.create(name="Some Name", no=10)
        instances = [UniqueErrorsModel(name="Some Name", no=11)]
        result = UniqueErrorsModel.bulk_validate(instances)
        self.assertEqual(
            result[0].message_dict,
            {"name": ["Custom unique name message."]},
        )

    def test_child_model_checks_parent_constraints(self):
        ChildUniqueConstraintProduct.objects.create(
            name="p", color="red", rank=1
        )
        instances = [
            ChildUniqueConstraintProduct(name="q", color="red", rank=1),
        ]
        result = ChildUniqueConstraintProduct.bulk_validate(instances)
        self.assertIn("rank", result[0].message_dict)

    def test_editing_child_excludes_itself_on_parent_table(self):
        child = ChildUniqueConstraintProduct.objects.create(
            name="keep", color="red", rank=5
        )
        child.name = "keep"
        result = ChildUniqueConstraintProduct.bulk_validate([child])
        self.assertTrue(result.valid, result.errors)

    def test_null_values_are_distinct_by_default(self):
        instances = [
            BulkValidateModel(name="a", city=None, email="a@example.com"),
            BulkValidateModel(name="b", city=None, email="b@example.com"),
        ]
        result = BulkValidateModel.bulk_validate(instances)
        self.assertTrue(result.valid, result.errors)

    def test_nulls_distinct_false_marks_batch_conflict(self):
        instances = [
            BulkValidateModel(name="a", city=None, email="a@example.com"),
            BulkValidateModel(name="a", city=None, email="b@example.com"),
        ]
        result = BulkValidateModel.bulk_validate(instances)
        # The nulls_distinct=False UniqueConstraint on (name, city) fires.
        self.assertFalse(result.valid)

    def test_nulls_distinct_false_database_conflict(self):
        BulkValidateModel.objects.create(
            name="a", city=None, email="stored@example.com"
        )
        instances = [
            BulkValidateModel(name="a", city=None, email="new@example.com"),
        ]
        result = BulkValidateModel.bulk_validate(instances)
        self.assertIsNotNone(result[0])

    def test_exclude_skips_checks(self):
        UniqueFieldsModel.objects.create(
            unique_charfield="taken", unique_integerfield=1, non_unique_field=0
        )
        instances = [make_unique_fields_model("taken", 1)]
        result = UniqueFieldsModel.bulk_validate(
            instances, exclude={"unique_charfield", "unique_integerfield"}
        )
        self.assertTrue(result.valid)

    def test_exclude_one_field_skips_multi_field_constraint(self):
        UniqueConstraintProduct.objects.create(name="p", color="red", rank=1)
        instances = [
            UniqueConstraintProduct(name="p", color="red", rank=9),
        ]
        result = UniqueConstraintProduct.bulk_validate(
            instances, exclude={"color"}
        )
        # (name, color) is excluded, rank=9 is still unique: no errors.
        self.assertTrue(result.valid, result.errors)

    def test_editing_instance_excludes_itself(self):
        obj = UniqueFieldsModel.objects.create(
            unique_charfield="keep", unique_integerfield=10, non_unique_field=0
        )
        instance = make_unique_fields_model("keep", 10, pk=obj.pk)
        instance._state.adding = False
        result = UniqueFieldsModel.bulk_validate([instance])
        self.assertTrue(result.valid, result.errors)

    def test_editing_instance_does_not_exclude_other_batch_instance(self):
        first = UniqueFieldsModel.objects.create(
            unique_charfield="first", unique_integerfield=1, non_unique_field=0
        )
        second = UniqueFieldsModel.objects.create(
            unique_charfield="second", unique_integerfield=2, non_unique_field=0
        )
        first.unique_charfield = "second"
        second.unique_charfield = "first"
        result = UniqueFieldsModel.bulk_validate([first, second])
        self.assertFalse(result.valid)
        self.assertIsNotNone(result[0])
        self.assertIsNotNone(result[1])

    def test_new_instance_conflicting_with_editing_instance_db_row(self):
        existing = UniqueFieldsModel.objects.create(
            unique_charfield="taken", unique_integerfield=1, non_unique_field=0
        )
        editing = UniqueFieldsModel(
            pk=existing.pk,
            unique_charfield="taken",
            unique_integerfield=1,
            non_unique_field=0,
        )
        editing._state.adding = False
        # Alone, the editing instance only matches itself and is valid.
        result = UniqueFieldsModel.bulk_validate([editing])
        self.assertIsNone(result[0])

    def test_editing_instance_keeps_batch_conflict_with_new_instance(self):
        existing = UniqueFieldsModel.objects.create(
            unique_charfield="taken", unique_integerfield=1, non_unique_field=0
        )
        editing = make_unique_fields_model("taken", 2, pk=existing.pk)
        editing._state.adding = False
        new_instance = make_unique_fields_model("taken", 3)
        result = UniqueFieldsModel.bulk_validate([editing, new_instance])
        # They duplicate each other within the batch: both are flagged even
        # though the editing row excludes itself from the database check.
        self.assertIsNotNone(result[0])
        self.assertIsNotNone(result[1])

    def test_database_and_batch_conflicts_both_retained(self):
        UniqueFieldsModel.objects.create(
            unique_charfield="dup", unique_integerfield=100, non_unique_field=0
        )
        instances = [
            make_unique_fields_model("dup", 1),
            make_unique_fields_model("dup", 2),
        ]
        result = UniqueFieldsModel.bulk_validate(instances)
        self.assertIsNotNone(result[0])
        self.assertIsNotNone(result[1])

    def test_batch_conflict_spanning_chunks(self):
        instances = [
            make_unique_fields_model("cross", 1),
            make_unique_fields_model("other", 2),
            make_unique_fields_model("cross", 3),
        ]
        result = UniqueFieldsModel.bulk_validate(instances, chunk_size=1)
        # Batch conflicts are detected globally, not only within a chunk.
        self.assertIsNotNone(result[0])
        self.assertIsNone(result[1])
        self.assertIsNotNone(result[2])

    def test_query_count_scales_with_chunks_not_rows(self):
        instances = [make_unique_fields_model(f"v{i}", i) for i in range(6)]
        # Two non-pk constraint groups (charfield, integerfield), each checked
        # with one query per chunk: 2 groups * ceil(6 / 2) chunks = 6 queries,
        # rather than one query per instance per check.
        with self.assertNumQueries(6):
            result = UniqueFieldsModel.bulk_validate(instances, chunk_size=2)
        self.assertTrue(result.valid, result.errors)

    def test_result_is_aligned_with_input_order(self):
        instances = [
            make_unique_fields_model("ok1", 1),
            make_unique_fields_model("dup", 2),
            make_unique_fields_model("dup", 3),
            make_unique_fields_model("ok4", 4),
        ]
        result = UniqueFieldsModel.bulk_validate(instances)
        self.assertIsNone(result[0])
        self.assertIsNotNone(result[1])
        self.assertIsNotNone(result[2])
        self.assertIsNone(result[3])

    def test_database_alias_grouping_and_using(self):
        obj = UniqueFieldsModel.objects.create(
            unique_charfield="x", unique_integerfield=1, non_unique_field=0
        )
        instance = make_unique_fields_model("x", 1, pk=obj.pk)
        instance._state.adding = False
        instance._state.db = "default"
        result = UniqueFieldsModel.bulk_validate([instance])
        self.assertTrue(result.valid, result.errors)

    def test_type_error_for_other_model(self):
        msg = "all instances must be instances of"
        with self.assertRaisesMessage(TypeError, msg):
            UniqueFieldsModel.bulk_validate([BulkValidateModel(name="z")])

    def test_invalid_chunk_size(self):
        with self.assertRaisesMessage(ValueError, "chunk_size"):
            BulkValidateModel.bulk_validate([], chunk_size=0)

    def test_fallback_constraint_classification(self):
        conditional = models.UniqueConstraint(
            fields=["name"],
            name="conditional_name_uq",
            condition=models.Q(name="x"),
        )
        expression = models.UniqueConstraint(
            models.F("name"), name="expression_name_uq"
        )
        plain = models.UniqueConstraint(fields=["name"], name="plain_name_uq")
        needs_fallback = BulkValidateModel._constraint_needs_fallback
        self.assertFalse(needs_fallback(BulkValidateModel, plain))
        self.assertTrue(needs_fallback(BulkValidateModel, conditional))
        self.assertTrue(needs_fallback(BulkValidateModel, expression))

    @skipUnlessDBFeature("supports_partial_indexes")
    def test_conditional_constraint_falls_back(self):
        BulkValidateFallbackModel.objects.create(name="n", color="red")
        instances = [
            BulkValidateFallbackModel(name="n", color="red"),
            BulkValidateFallbackModel(name="n", color="blue"),
        ]
        result = BulkValidateFallbackModel.bulk_validate(instances)
        self.assertTrue(result.fallback)
        model_class, constraint = result.fallback[0]
        self.assertIs(model_class, BulkValidateFallbackModel)
        self.assertEqual(constraint.name, "bulk_fallback_condition_uq")
        # The conditional unique only applies when color="red".
        self.assertIsNotNone(result[0])
        self.assertIsNone(result[1])

    def test_expression_constraint_falls_back(self):
        if not connection.features.supports_expression_indexes:
            self.skipTest("Backend does not support expression indexes.")
        UniqueFuncConstraintModel.objects.create(field="ABC")
        instances = [UniqueFuncConstraintModel(field="abc")]
        result = UniqueFuncConstraintModel.bulk_validate(instances)
        self.assertTrue(result.fallback)
        self.assertIsNotNone(result[0])

    def test_fallback_matches_per_instance_validation(self):
        if not connection.features.supports_expression_indexes:
            self.skipTest("Backend does not support expression indexes.")
        UniqueFuncConstraintModel.objects.create(field="ABC")
        instance = UniqueFuncConstraintModel(field="abc")
        with self.assertRaises(ValidationError) as cm:
            instance.validate_constraints()
        result = UniqueFuncConstraintModel.bulk_validate([instance])
        self.assertEqual(
            result[0].messages,
            cm.exception.messages,
        )

    def test_no_database_writes(self):
        instances = [make_unique_fields_model("tmp", 4242)]
        before = UniqueFieldsModel.objects.count()

        with CaptureQueriesContext(connection) as captured:
            UniqueFieldsModel.bulk_validate(instances)
        self.assertTrue(
            all(query["sql"].lstrip().startswith("SELECT") for query in captured)
        )
        self.assertEqual(UniqueFieldsModel.objects.count(), before)

    def test_db_default_constant_is_checked(self):
        # unique_integerfield defaults to 42 via a constant db_default; two
        # new instances relying on that default conflict with each other.
        first = UniqueFieldsModel(unique_charfield="a", non_unique_field=0)
        second = UniqueFieldsModel(unique_charfield="b", non_unique_field=0)
        from django.db.models.expressions import DatabaseDefault

        self.assertIsInstance(first.unique_integerfield, DatabaseDefault)
        result = UniqueFieldsModel.bulk_validate([first, second])
        self.assertIsNotNone(result[0])
        self.assertIsNotNone(result[1])

    def test_db_default_expression_is_skipped(self):
        instances = [
            UniqueDbDefaultExpressionModel(),
            UniqueDbDefaultExpressionModel(),
        ]
        result = UniqueDbDefaultExpressionModel.bulk_validate(instances)
        # The dynamic default cannot be known beforehand; no conflict raised.
        self.assertTrue(result.valid, result.errors)


class BulkValidateMultiDBTests(TestCase):
    databases = {"default", "other"}

    def test_grouping_by_alias(self):
        UniqueFieldsModel.objects.using("default").create(
            unique_charfield="shared", unique_integerfield=1, non_unique_field=0
        )
        on_other = make_unique_fields_model("shared", 2)
        on_other._state.db = "other"
        on_default = make_unique_fields_model("shared", 3)
        result = UniqueFieldsModel.bulk_validate([on_other, on_default])
        self.assertIsNone(result[0])
        self.assertIsNotNone(result[1])

    def test_using_argument_overrides_state_db(self):
        UniqueFieldsModel.objects.using("other").create(
            unique_charfield="shared", unique_integerfield=1, non_unique_field=0
        )
        instance = make_unique_fields_model("shared", 2)
        result = UniqueFieldsModel.bulk_validate([instance], using="other")
        self.assertIsNotNone(result[0])
