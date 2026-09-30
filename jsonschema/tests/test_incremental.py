from __future__ import annotations

from copy import deepcopy
from unittest import TestCase

import referencing

from jsonschema import _incremental, exceptions
from jsonschema.validators import Draft202012Validator
from jsonschema.validators import Draft4Validator


def signatures(errors):
    return sorted(
        (
            error.message,
            error.validator,
            tuple(error.absolute_path),
            tuple(error.absolute_schema_path),
        )
        for error in errors
    )


class TestIncrementalValidation(TestCase):
    def assert_matches_full_validation(self, session, instance, schema,
                                       changes, registry=None,
                                       validator_class=Draft202012Validator):
        candidate = deepcopy(session.instance)
        candidate, _ = _incremental._apply_changes(
            candidate,
            _incremental._normalise_changes(changes),
        )
        expected = list(
            validator_class(
                schema,
                **({"registry": registry} if registry is not None else {}),
            ).iter_errors(candidate),
        )
        actual = session.apply(changes)
        self.assertEqual(signatures(actual), signatures(expected))
        return candidate

    def test_single_property_change_and_skip_observation(self):
        schema = {
            "type": "object",
            "properties": {
                "changed": {"type": "integer"},
                "untouched": {"type": "integer"},
            },
        }
        counter = _incremental.CountingValidator()
        session = _incremental.session(
            {"changed": 1, "untouched": 2},
            schema,
            observer=counter,
        )
        counter.reset()
        self.assert_matches_full_validation(
            session,
            session.instance,
            schema,
            {"/changed": "not an integer"},
        )
        self.assertGreater(counter.skipped, 0)
        self.assertEqual(session.instance["untouched"], 2)

    def test_skipped_work_scales_with_untouched_fields(self):
        schema = {
            "type": "object",
            "required": ["changed"],
            "properties": {
                f"field{index}": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 100,
                }
                for index in range(100)
            },
        }
        schema["properties"]["changed"] = {"type": "integer"}
        initial = {f"field{index}": index for index in range(100)}
        initial["changed"] = 1
        counter = _incremental.CountingValidator()
        session = _incremental.session(
            initial,
            schema,
            observer=counter,
        )
        full_evaluated = counter.evaluated
        counter.reset()
        session.apply({"/changed": "invalid"})
        self.assertGreater(full_evaluated, counter.evaluated * 10)
        self.assertGreater(counter.skipped, 90)

    def test_required_revalidates_object_scope(self):
        schema = {
            "type": "object",
            "required": ["changed", "other"],
            "properties": {
                "changed": {"type": "string"},
                "other": {"type": "string"},
            },
        }
        session = _incremental.session(
            {"changed": "a", "other": "b"},
            schema,
        )
        self.assert_matches_full_validation(
            session,
            session.instance,
            schema,
            {"op": "remove", "path": "/changed"},
        )
        self.assert_matches_full_validation(
            session,
            session.instance,
            schema,
            {"op": "add", "path": "/changed", "value": 3},
        )

    def test_dependent_required_and_schemas(self):
        schema = {
            "type": "object",
            "properties": {
                "trigger": {"const": True},
                "target": {"type": "integer"},
            },
            "dependentRequired": {"trigger": ["target"]},
            "dependentSchemas": {
                "trigger": {
                    "required": ["target"],
                    "properties": {"target": {"minimum": 5}},
                },
            },
        }
        session = _incremental.session({"trigger": False}, schema)
        self.assert_matches_full_validation(
            session,
            session.instance,
            schema,
            {"/trigger": True},
        )
        self.assert_matches_full_validation(
            session,
            session.instance,
            schema,
            {"op": "add", "path": "/target", "value": 10},
        )
        self.assert_matches_full_validation(
            session,
            session.instance,
            schema,
            {"op": "remove", "path": "/target"},
        )

    def test_legacy_dependencies_revalidate_when_trigger_is_removed(self):
        schema = {
            "type": "object",
            "dependencies": {
                "trigger": {"required": ["target"]},
            },
        }
        session = _incremental.session(
            {"trigger": 1},
            schema,
            Draft4Validator,
        )
        self.assertEqual(len(session.errors), 1)
        self.assert_matches_full_validation(
            session,
            session.instance,
            schema,
            {"op": "remove", "path": "/trigger"},
            validator_class=Draft4Validator,
        )
        self.assertEqual(session.errors, [])

    def test_conditional_branch_change(self):
        schema = {
            "type": "object",
            "properties": {"flag": {"type": "boolean"}},
            "if": {"properties": {"flag": {"const": True}}},
            "then": {"required": ["when_true"]},
            "else": {"required": ["when_false"]},
        }
        session = _incremental.session(
            {"flag": True, "when_true": 1},
            schema,
        )
        self.assert_matches_full_validation(
            session,
            session.instance,
            schema,
            {"/flag": False},
        )
        self.assertEqual(session.instance, {"flag": False, "when_true": 1})

    def test_contains_and_unique_items_array_scope(self):
        schema = {
            "type": "array",
            "contains": {"type": "string", "const": "special"},
            "uniqueItems": True,
            "items": {"type": ["string", "integer"]},
        }
        session = _incremental.session(
            ["special", 1, 2, 3, 4, 5, 6, 7, 8],
            schema,
        )
        self.assert_matches_full_validation(
            session,
            session.instance,
            schema,
            {"/0": 2},
        )
        self.assert_matches_full_validation(
            session,
            session.instance,
            schema,
            {"/1": 2},
        )
        self.assert_matches_full_validation(
            session,
            session.instance,
            schema,
            {"op": "add", "path": "/1", "value": "special"},
        )

    def test_array_insertion_invalidates_shifted_items(self):
        schema = {
            "prefixItems": [{"const": "a"}, {"const": "b"}],
            "items": {"const": 1},
        }
        session = _incremental.session(["a", "b", 1, 2], schema)
        self.assert_matches_full_validation(
            session,
            session.instance,
            schema,
            {"op": "add", "path": "/0", "value": "new"},
        )

    def test_unevaluated_properties_revalidates_object_scope(self):
        schema = {
            "type": "object",
            "allOf": [
                {"properties": {"evaluated": {"type": "integer"}}},
            ],
            "unevaluatedProperties": False,
        }
        session = _incremental.session(
            {"evaluated": 1},
            schema,
        )
        self.assert_matches_full_validation(
            session,
            session.instance,
            schema,
            {"/evaluated": "still-allowed"},
        )
        self.assert_matches_full_validation(
            session,
            session.instance,
            schema,
            {"op": "add", "path": "/extra", "value": True},
        )

    def test_reference_registry_remains_fixed(self):
        registry = referencing.Registry().with_resource(
            "https://example.com/item",
            referencing.jsonschema.DRAFT202012.create_resource(
                {"type": "integer"},
            ),
        )
        schema = {
            "type": "object",
            "properties": {
                "item": {"$ref": "https://example.com/item"},
            },
        }
        session = _incremental.session(
            {"item": 1},
            schema,
            registry=registry,
        )
        self.assert_matches_full_validation(
            session,
            session.instance,
            schema,
            {"/item": "not an integer"},
            registry=registry,
        )

    def test_unknown_custom_keyword_falls_back_to_full_validation(self):
        def custom(validator, value, instance, schema):
            if instance.get("remote_field") != value:
                yield exceptions.ValidationError("custom cross-field failure")

        Validator = Draft202012Validator
        original = dict(Validator.VALIDATORS)
        Validator.VALIDATORS["x-cross-field"] = custom
        try:
            schema = {
                "type": "object",
                "properties": {"local": {"type": "string"}},
                "x-cross-field": "expected",
            }
            session = _incremental.session(
                {"local": "x", "remote_field": "expected"},
                schema,
            )
            self.assert_matches_full_validation(
                session,
                session.instance,
                schema,
                {"/local": "y"},
            )
        finally:
            Validator.VALIDATORS.clear()
            Validator.VALIDATORS.update(original)

    def test_declared_local_custom_keyword_is_incremental(self):
        @_incremental.local_keyword
        def local_even(validator, value, instance, schema):
            if validator.is_type(instance, "integer") and instance % 2:
                yield exceptions.ValidationError("must be even")

        Validator = Draft202012Validator
        original = dict(Validator.VALIDATORS)
        Validator.VALIDATORS["x-even"] = local_even
        try:
            schema = {
                "type": "object",
                "properties": {
                    "changed": {"x-even": True, "type": "integer"},
                    "untouched": {"x-even": True, "type": "integer"},
                },
            }
            counter = _incremental.CountingValidator()
            session = _incremental.session(
                {"changed": 2, "untouched": 4},
                schema,
                observer=counter,
            )
            counter.reset()
            self.assert_matches_full_validation(
                session,
                session.instance,
                schema,
                {"/changed": 3},
            )
            self.assertGreater(counter.skipped, 0)
        finally:
            Validator.VALIDATORS.clear()
            Validator.VALIDATORS.update(original)

    def test_failed_update_does_not_pollute_state(self):
        schema = {"type": "object", "additionalProperties": False}
        session = _incremental.session({"existing": 1}, schema)
        before_instance = deepcopy(session.instance)
        before_errors = signatures(session.errors)
        with self.assertRaises(_incremental.IncrementalValidationError):
            session.apply({"/missing/child": 1})
        self.assertEqual(session.instance, before_instance)
        self.assertEqual(signatures(session.errors), before_errors)

    def test_json_pointer_array_append(self):
        schema = {"type": "array", "items": {"type": "integer"}}
        session = _incremental.session([1, 2], schema)
        errors = session.update({
            "op": "add",
            "path": "/-",
            "value": 3,
        })
        self.assertEqual(errors, [])
        self.assertEqual(session.instance, [1, 2, 3])

    def test_validation_error_does_not_pollute_state(self):
        def explode(validator, value, instance, schema):
            if instance.get("safe") != "explode":
                return
            raise RuntimeError("boom")

        Validator = Draft202012Validator
        original = dict(Validator.VALIDATORS)
        Validator.VALIDATORS["x-explode"] = (
            _incremental.full_validation_keyword(explode)
        )
        try:
            schema = {
                "type": "object",
                "properties": {"safe": {"type": "string"}},
                "x-explode": True,
            }
            session = _incremental.session({"safe": "initial"}, schema)
            before_instance = deepcopy(session.instance)
            with self.assertRaises(RuntimeError):
                session.apply({"/safe": "explode"})
            self.assertEqual(session.instance, before_instance)
        finally:
            Validator.VALIDATORS.clear()
            Validator.VALIDATORS.update(original)
