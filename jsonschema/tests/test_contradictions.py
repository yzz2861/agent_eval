from unittest import TestCase

from jsonschema import (
    CONSTRUCTIBLE,
    CONTRADICTORY,
    UNKNOWN,
    Draft201909Validator,
    Draft202012Validator,
    Draft4Validator,
    Draft7Validator,
)
from jsonschema import validators
from jsonschema._contradictions import Conflict
from jsonschema.exceptions import ValidationError


def paths(conflict):
    return conflict.paths


def reject_all(validator, value, instance, schema):
    yield ValidationError("unsupported custom keyword rejects all")


class ContradictionTests(TestCase):
    def assert_constructible(self, validator):
        result = validator.check_contradiction()
        self.assertEqual(result.status, CONSTRUCTIBLE)
        self.assertTrue(validator.is_valid(result.example))
        return result

    def assert_contradictory(self, validator):
        result = validator.check_contradiction()
        self.assertEqual(result.status, CONTRADICTORY)
        self.assertIsNone(result.example)
        self.assertIsInstance(result.conflict, Conflict)
        return result

    def test_boolean_schemas(self):
        self.assert_constructible(Draft202012Validator(True))
        result = self.assert_contradictory(Draft202012Validator(False))
        self.assertEqual(result.conflict.paths, ((),))

    def test_types_and_enum_and_const(self):
        result = self.assert_contradictory(Draft202012Validator({
            "allOf": [{"type": "string"}, {"type": "integer"}],
        }))
        self.assertEqual(paths(result.conflict), (
            ("allOf", 0, "type"),
            ("allOf", 1, "type"),
        ))

        result = self.assert_contradictory(Draft202012Validator({
            "enum": [1, 2],
            "const": 3,
        }))
        self.assertEqual(set(paths(result.conflict)), {
            ("enum",),
            ("const",),
        })

        result = self.assert_constructible(Draft202012Validator({
            "enum": [1, "two", True],
            "type": "boolean",
        }))
        self.assertEqual(result.example, True)

    def test_numeric_ranges(self):
        result = self.assert_contradictory(Draft202012Validator({
            "type": "integer",
            "minimum": 5,
            "maximum": 3,
        }))
        self.assertEqual(paths(result.conflict), (
            ("type",),
            ("minimum",),
            ("maximum",),
        ))

        result = self.assert_constructible(Draft202012Validator({
            "type": "number",
            "exclusiveMinimum": 0,
            "exclusiveMaximum": 1,
        }))
        self.assertTrue(
            Draft202012Validator({
                "type": "number",
                "exclusiveMinimum": 0,
                "exclusiveMaximum": 1,
            }).is_valid(result.example),
        )

        self.assert_contradictory(Draft202012Validator({
            "type": "integer",
            "exclusiveMinimum": 2,
            "exclusiveMaximum": 3,
        }))

        result = self.assert_contradictory(Draft4Validator({
            "type": "integer",
            "minimum": 2,
            "maximum": 2,
            "exclusiveMinimum": True,
        }))
        self.assertEqual(paths(result.conflict), (
            ("type",),
            ("minimum",),
            ("maximum",),
        ))

    def test_string_length(self):
        result = self.assert_contradictory(Draft202012Validator({
            "type": "string",
            "minLength": 3,
            "maxLength": 1,
        }))
        self.assertEqual(paths(result.conflict), (
            ("type",),
            ("minLength",),
            ("maxLength",),
        ))
        self.assert_constructible(Draft202012Validator({
            "type": "string",
            "minLength": 2,
            "maxLength": 3,
        }))

    def test_object_constraints(self):
        result = self.assert_contradictory(Draft202012Validator({
            "type": "object",
            "required": ["x"],
            "additionalProperties": False,
        }))
        self.assertEqual(paths(result.conflict), (
            ("type",),
            ("additionalProperties",),
            ("required", 0),
        ))

        self.assert_constructible(Draft202012Validator({
            "type": "object",
            "properties": {"x": {"type": "integer", "minimum": 4}},
            "required": ["x"],
            "additionalProperties": False,
        }))

        self.assert_constructible(Draft202012Validator({
            "type": "object",
            "properties": {"x": {"type": "integer"}},
            "required": ["x"],
            "additionalProperties": False,
            "allOf": [{"properties": {"x": {"minimum": 4}}}],
        }))

        result = self.assert_contradictory(Draft202012Validator({
            "const": {},
            "required": ["x"],
        }))
        self.assertEqual(paths(result.conflict), (
            ("const",),
            ("required", 0),
        ))

        result = self.assert_contradictory(Draft202012Validator({
            "type": "object",
            "required": ["x"],
            "additionalProperties": {
                "type": "integer",
                "minimum": 5,
                "maximum": 4,
            },
        }))
        self.assertEqual(paths(result.conflict.alternatives[0]), (
            ("additionalProperties", "type"),
            ("additionalProperties", "minimum"),
            ("additionalProperties", "maximum"),
        ))

    def test_allof_and_anyof_combinations(self):
        result = self.assert_contradictory(Draft202012Validator({
            "type": "null",
            "anyOf": [{"type": "string"}, {"type": "integer"}],
        }))
        self.assertEqual(len(result.conflict.alternatives), 2)

        self.assert_constructible(Draft202012Validator({
            "const": None,
            "anyOf": [{"type": "null"}, {"type": "integer"}],
        }))

        self.assert_constructible(Draft202012Validator({
            "const": None,
            "allOf": [
                {"anyOf": [{"type": "string"}, {"type": "null"}]},
                {"anyOf": [{"type": "integer"}, {"type": "null"}]},
            ],
        }))

        self.assert_contradictory(Draft202012Validator({
            "const": None,
            "allOf": [
                {"anyOf": [{"type": "string"}, {"type": "object"}]},
                {"anyOf": [{"type": "integer"}, {"type": "array"}]},
            ],
        }))

        self.assert_constructible(Draft202012Validator({
            "allOf": [
                {"anyOf": [
                    {"type": "integer", "minimum": 5},
                    {"type": "string", "minLength": 3},
                ]},
                {"anyOf": [
                    {"type": "integer", "maximum": 6},
                    {"type": "string", "maxLength": 4},
                ]},
            ],
        }))

        result = self.assert_contradictory(Draft202012Validator({
            "type": "object",
            "properties": {"x": {
                "anyOf": [
                    {"type": "integer", "minimum": 5, "maximum": 4},
                    {"type": "string", "minLength": 2, "maxLength": 1},
                ],
            }},
            "required": ["x"],
        }))
        nested = result.conflict.alternatives[0]
        self.assertEqual(paths(nested), (
            ("properties", "x", "anyOf", 0, "type"),
            ("properties", "x", "anyOf", 0, "minimum"),
            ("properties", "x", "anyOf", 0, "maximum"),
        ))

        result = self.assert_contradictory(Draft202012Validator({
            "type": "object",
            "allOf": [{"required": ["x"]}],
            "additionalProperties": False,
        }))
        self.assertEqual(paths(result.conflict), (
            ("type",),
            ("additionalProperties",),
            ("allOf", 0, "required", 0),
        ))

    def test_unsupported_keywords_are_unknown_or_witnessed(self):
        result = Draft202012Validator({"pattern": "^x$"}).check_contradiction()
        self.assertEqual(result.status, CONSTRUCTIBLE)
        self.assertTrue(result.unsupported)
        self.assertEqual(result.unsupported[0].keyword, "pattern")
        self.assertTrue(Draft202012Validator({"pattern": "^x$"}).is_valid(
            result.example,
        ))

        result = Draft202012Validator({
            "pattern": "^x$",
            "maxLength": 0,
        }).check_contradiction()
        self.assertEqual(result.status, CONSTRUCTIBLE)
        self.assertTrue(result.unsupported)

    def test_search_budget_can_only_produce_unknown(self):
        schema = {"allOf": [
            {"anyOf": [{"type": "integer"}, {"type": "string"}]},
            {"type": "integer"},
        ]}
        for _ in range(12):
            schema = {"allOf": [schema, {"type": "integer"}]}

        result = Draft202012Validator(schema).check_contradiction(
            search_budget=2,
        )
        self.assertEqual(result.status, UNKNOWN)
        self.assertTrue(result.budget_exhausted)
        self.assertIsNone(result.conflict)

    def test_empty_anyof_and_empty_enum_are_contradictory(self):
        result = self.assert_contradictory(Draft202012Validator({"anyOf": []}))
        self.assertEqual(result.conflict.paths, (("anyOf",),))
        result = self.assert_contradictory(Draft202012Validator({"enum": []}))
        self.assertEqual(result.conflict.paths, (("enum",),))

    def test_validators_with_custom_keywords_remain_conservative(self):
        schema = {"x-custom": True, "type": "integer"}
        result = Draft7Validator(schema).check_contradiction()
        self.assertEqual(result.status, CONSTRUCTIBLE)
        self.assertTrue(any(
            item.keyword == "x-custom" for item in result.unsupported
        ))
        self.assertEqual(result.example, 0)

        RejectingValidator = validators.extend(
            Draft202012Validator,
            {"x-reject-all": reject_all},
        )
        result = RejectingValidator({
            "x-reject-all": True,
            "type": "integer",
        }).check_contradiction()
        self.assertEqual(result.status, UNKNOWN)
        self.assertTrue(any(
            item.keyword == "x-reject-all" for item in result.unsupported
        ))
        self.assertIsNone(result.example)

    def test_201909_enum_const(self):
        result = self.assert_constructible(Draft201909Validator({
            "const": {"x": 1},
            "required": ["x"],
        }))
        self.assertEqual(result.example, {"x": 1})
