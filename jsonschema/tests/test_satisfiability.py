from __future__ import annotations

from unittest import TestCase

from jsonschema import Draft202012Validator, check_satisfiability, validators
from jsonschema.satisfiability import SatisfiabilityStatus


class SatisfiabilityTests(TestCase):
    def assert_constructible(self, schema, expected=None):
        result = check_satisfiability(schema)
        self.assertEqual(result.status, SatisfiabilityStatus.CONSTRUCTIBLE)
        Draft202012Validator(schema).validate(result.example)
        if expected is not None:
            self.assertEqual(result.example, expected)
        return result

    def assert_contradiction(self, schema, conflicts):
        result = check_satisfiability(schema)
        self.assertEqual(result.status, SatisfiabilityStatus.CONTRADICTION)
        self.assertEqual(result.conflicts, conflicts)

    def assert_unknown(self, schema, unsupported_path=None):
        result = check_satisfiability(schema)
        self.assertEqual(result.status, SatisfiabilityStatus.UNKNOWN)
        if unsupported_path is not None:
            self.assertEqual(result.unsupported[0].path, unsupported_path)

    def test_scalar_types_are_constructible(self):
        for schema, expected in [
            ({"type": "null"}, None),
            ({"type": "boolean"}, True),
            ({"type": "array"}, []),
            ({"type": "string"}, ""),
            ({"type": "integer"}, 0),
        ]:
            with self.subTest(schema):
                self.assert_constructible(schema, expected)

    def test_enum_and_const_are_constructible(self):
        self.assert_constructible({"enum": [1, "two", None]}, None)
        self.assert_constructible(
            {"type": "integer", "enum": [1, 2], "const": 2},
            2,
        )

    def test_type_conflicts_with_enum(self):
        self.assert_contradiction(
            {"type": "string", "enum": [1, 2]},
            ((("enum",), ("type",)),),
        )

    def test_enum_const_intersection_is_contradictory(self):
        self.assert_contradiction(
            {"enum": [1, 2], "const": 3},
            ((("enum",), ("const",)),),
        )

    def test_numeric_and_string_ranges(self):
        self.assert_constructible(
            {"type": "integer", "minimum": 2, "maximum": 5},
            2,
        )
        self.assert_contradiction(
            {"type": "number", "minimum": 2, "maximum": 1},
            ((("minimum",), ("maximum",), ("type",)),),
        )
        self.assert_contradiction(
            {"type": "string", "minLength": 3, "maxLength": 2},
            ((("minLength",), ("maxLength",), ("type",)),),
        )

    def test_draft4_boolean_exclusive_bounds(self):
        self.assert_constructible(
            {
                "$schema": "http://json-schema.org/draft-04/schema#",
                "type": "integer",
                "minimum": 1,
                "maximum": 2,
                "exclusiveMinimum": True,
            },
            2,
        )

    def test_object_properties_and_required(self):
        self.assert_constructible(
            {
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
            },
            {"name": ""},
        )

    def test_required_contradicts_additional_properties_false(self):
        self.assert_contradiction(
            {
                "type": "object",
                "allOf": [
                    {"required": ["name"]},
                    {"additionalProperties": False},
                ],
            },
            (
                (
                    (
                        ("allOf", 0, "required"),
                        ("allOf", 1, "additionalProperties"),
                        ("type",),
                    )
                ),
            ),
        )

    def test_other_all_of_properties_do_not_bypass_ap_false(self):
        self.assert_contradiction(
            {
                "type": "object",
                "allOf": [
                    {"required": ["name"]},
                    {"properties": {"other": {"type": "string"}}},
                    {"additionalProperties": False},
                ],
            },
            (
                (
                    ("allOf", 0, "required"),
                    ("allOf", 2, "additionalProperties"),
                    ("type",),
                ),
            ),
        )

    def test_same_branch_property_bypasses_ap_false(self):
        self.assert_constructible(
            {
                "type": "object",
                "required": ["name"],
                "properties": {"name": {"type": "string"}},
                "additionalProperties": False,
            },
            {"name": ""},
        )

    def test_required_property_uses_additional_properties_schema(self):
        self.assert_constructible(
            {
                "type": "object",
                "required": ["name"],
                "additionalProperties": {"type": "integer"},
            },
            {"name": 0},
        )

    def test_nested_property_contradiction(self):
        self.assert_contradiction(
            {
                "type": "object",
                "required": ["name"],
                "allOf": [
                    {"properties": {"name": {"type": "string"}}},
                    {"properties": {"name": {"type": "integer"}}},
                ],
            },
            (
                (
                    (
                        ("allOf", 0, "properties", "name", "type"),
                        ("allOf", 1, "properties", "name", "type"),
                    )
                ),
            ),
        )

    def test_all_of_and_any_of_combination(self):
        schema = {
            "allOf": [{"type": "integer"}],
            "anyOf": [{"minimum": 2}, {"const": 0}],
        }
        result = self.assert_constructible(schema)
        self.assertGreaterEqual(result.example, 2)

    def test_all_any_of_branches_contradictory(self):
        self.assert_contradiction(
            {
                "anyOf": [
                    {"type": "integer", "const": "x"},
                    {"type": "string", "const": 1},
                ],
            },
            (
                (
                    (
                        ("anyOf", 0, "const"),
                        ("anyOf", 0, "type"),
                        ("anyOf", 1, "const"),
                        ("anyOf", 1, "type"),
                    )
                ),
            ),
        )

    def test_one_constructible_any_of_branch_is_constructible(self):
        self.assert_constructible(
            {
                "anyOf": [
                    {"type": "integer", "minimum": 2, "maximum": 1},
                    {"type": "string"},
                ],
            },
            "",
        )

    def test_boolean_schemas(self):
        self.assert_constructible(True, None)
        self.assert_contradiction(False, (((),),))

    def test_false_any_of_branch_does_not_block_other_branches(self):
        self.assert_constructible(
            {"anyOf": [False, {"type": "null"}]},
            None,
        )

    def test_regex_is_explicitly_unsupported(self):
        self.assert_unknown(
            {"type": "string", "pattern": "x"},
            ("pattern",),
        )

    def test_ignored_unsupported_keyword_is_still_reported(self):
        result = check_satisfiability(
            {
                "type": "integer",
                "minItems": 1,
            },
        )
        self.assertEqual(result.status, SatisfiabilityStatus.CONSTRUCTIBLE)
        self.assertEqual(result.example, 0)
        self.assertEqual(result.unsupported[0].path, ("minItems",))

    def test_custom_keyword_is_explicitly_unsupported(self):
        def validate(validator, value, instance, schema):
            if instance != value:
                from jsonschema.exceptions import ValidationError

                yield ValidationError("custom")

        Validator = validators.extend(
            Draft202012Validator,
            {"x-custom": validate},
        )
        validator = Validator({"type": "integer", "x-custom": 3})
        result = check_satisfiability(validator)
        self.assertEqual(result.status, SatisfiabilityStatus.UNKNOWN)
        self.assertEqual(result.unsupported[0].keyword, "x-custom")

    def test_search_budget_exhaustion_is_unknown(self):
        result = check_satisfiability(
            {
                "anyOf": [
                    {"type": "integer", "minimum": 2, "maximum": 1},
                    {"type": "string", "minLength": 2, "maxLength": 1},
                ],
            },
            search_budget=1,
        )
        self.assertEqual(result.status, SatisfiabilityStatus.UNKNOWN)
        self.assertTrue(result.budget_exhausted)

    def test_small_budget_allows_simple_schema(self):
        result = check_satisfiability(
            {"type": "boolean"},
            search_budget=2,
        )
        self.assertEqual(result.status, SatisfiabilityStatus.CONSTRUCTIBLE)
        self.assertFalse(result.budget_exhausted)
