"""
Tests for explicit application of the (annotative) ``default`` keyword.
"""
from unittest import TestCase
import warnings

import referencing
from referencing.jsonschema import DRAFT202012

from jsonschema import (
    AppliedDefault,
    Completion,
    DefaultsConflict,
    Draft202012Validator,
    ValidationError,
    apply_defaults,
)


class ApplyDefaultsTests(TestCase):
    def test_validate_does_not_apply_defaults(self):
        schema = {"properties": {"x": {"default": 1}}}
        instance = {}
        Draft202012Validator(schema).validate(instance)
        self.assertEqual(instance, {})

    def test_applies_nested_defaults(self):
        schema = {
            "type": "object",
            "properties": {
                "outer": {
                    "type": "object",
                    "properties": {
                        "inner": {"type": "integer", "default": 7},
                    },
                },
            },
        }
        result = apply_defaults({"outer": {}}, schema)
        self.assertEqual(result.instance, {"outer": {"inner": 7}})

    def test_fills_missing_object_then_its_nested_defaults(self):
        schema = {
            "properties": {
                "point": {
                    "default": {},
                    "properties": {"x": {"default": 0}},
                },
            },
        }
        self.assertEqual(
            apply_defaults({}, schema).instance,
            {"point": {"x": 0}},
        )

    def test_explicit_null_is_not_missing(self):
        schema = {
            "properties": {
                "x": {"type": ["integer", "null"], "default": 1},
            },
        }
        result = apply_defaults({"x": None}, schema)
        self.assertEqual(result.instance, {"x": None})
        self.assertEqual(result.applied, [])

    def test_original_instance_is_never_mutated(self):
        schema = {
            "properties": {
                "point": {
                    "default": {},
                    "properties": {"x": {"default": 0}},
                },
            },
        }
        original = {}
        result = apply_defaults(original, schema)
        self.assertEqual(original, {})
        self.assertIsNot(result.instance, original)

    def test_inserted_defaults_are_independent_copies(self):
        schema = {
            "properties": {
                name: {
                    "default": {},
                    "properties": {"n": {"default": 1}},
                }
                for name in ("a", "b")
            },
        }
        result = apply_defaults({}, schema)
        result.instance["a"]["n"] = 99
        self.assertEqual(result.instance["b"], {"n": 1})
        self.assertIsNot(result.instance["a"], result.instance["b"])

    def test_records_schema_source_of_each_inserted_value(self):
        schema = {"properties": {"x": {"default": 1}}}
        result = apply_defaults({}, schema)
        (applied,) = result.applied
        self.assertIsInstance(applied, AppliedDefault)
        self.assertEqual(applied.path, ("x",))
        self.assertEqual(applied.value, 1)
        self.assertEqual(applied.schema_path, ("properties", "x"))
        self.assertIs(applied.schema, schema["properties"]["x"])
        self.assertIs(result.defaults[("x",)], applied)

    def test_returns_completion_object(self):
        self.assertIsInstance(
            apply_defaults({}, {"properties": {"x": {"default": 1}}}),
            Completion,
        )

    def test_present_values_are_not_overwritten(self):
        schema = {"properties": {"x": {"default": 1}}}
        self.assertEqual(apply_defaults({"x": 5}, schema).instance, {"x": 5})

    def test_nested_defaults_inside_present_values(self):
        schema = {
            "properties": {
                "point": {
                    "properties": {
                        "x": {"default": 0},
                        "y": {"default": 0},
                    },
                },
            },
        }
        result = apply_defaults({"point": {"x": 3}}, schema)
        self.assertEqual(result.instance, {"point": {"x": 3, "y": 0}})

    def test_array_elements_complete_nested_defaults(self):
        schema = {
            "items": {
                "type": "object",
                "properties": {"k": {"default": 0}},
            },
        }
        result = apply_defaults([{}, {"k": 5}], schema)
        self.assertEqual(result.instance, [{"k": 0}, {"k": 5}])

    def test_prefix_items_followed_by_items(self):
        schema = {
            "prefixItems": [{"properties": {"a": {"default": 1}}}],
            "items": {"properties": {"b": {"default": 2}}},
        }
        result = apply_defaults([{}, {}, {}], schema)
        self.assertEqual(
            result.instance,
            [{"a": 1}, {"b": 2}, {"b": 2}],
        )


class AllOfTests(TestCase):
    def test_merges_allof_defaults(self):
        schema = {
            "allOf": [
                {"properties": {"a": {"default": 1}}},
                {"properties": {"b": {"default": 2}}},
            ],
        }
        self.assertEqual(apply_defaults({}, schema).instance, {"a": 1, "b": 2})

    def test_equal_allof_defaults_do_not_conflict(self):
        schema = {
            "allOf": [
                {"properties": {"x": {"default": 1}}},
                {"properties": {"x": {"default": 1}}},
            ],
        }
        result = apply_defaults({}, schema)
        self.assertEqual(result.instance, {"x": 1})
        self.assertEqual(len(result.applied), 1)

    def test_conflicting_allof_defaults_raise(self):
        schema = {
            "allOf": [
                {"properties": {"x": {"default": 1}}},
                {"properties": {"x": {"default": 2}}},
            ],
        }
        with self.assertRaises(DefaultsConflict) as caught:
            apply_defaults({}, schema)
        self.assertEqual(caught.exception.path, ("x",))
        self.assertEqual(caught.exception.values, [1, 2])
        self.assertEqual(
            caught.exception.sources,
            [
                ("allOf", 0, "properties", "x"),
                ("allOf", 1, "properties", "x"),
            ],
        )

    def test_conflict_between_inserted_value_and_then_default(self):
        schema = {
            "properties": {"x": {"default": 1}},
            "if": {"required": ["y"]},
            "then": {"properties": {"x": {"default": 2}}},
        }
        with self.assertRaises(DefaultsConflict) as caught:
            apply_defaults({"y": True}, schema)
        self.assertEqual(caught.exception.path, ("x",))

    def test_explicit_value_preempts_default_conflict(self):
        schema = {
            "allOf": [
                {"properties": {"x": {"default": 1}}},
            ],
        }
        self.assertEqual(
            apply_defaults({"x": 3}, schema).instance, {"x": 3},
        )


class AnyOfOneOfTests(TestCase):
    def test_ambiguous_anyof_applies_nothing(self):
        schema = {
            "anyOf": [
                {"properties": {"a": {"default": "A"}}},
                {"properties": {"b": {"default": "B"}}},
            ],
        }
        result = apply_defaults({}, schema)
        self.assertEqual(result.instance, {})
        self.assertEqual(result.applied, [])

    def test_unique_anyof_match_applies_its_defaults(self):
        schema = {
            "type": "object",
            "properties": {"t": {"type": "string"}},
            "anyOf": [
                {
                    "properties": {
                        "t": {"const": "x"},
                        "x": {"default": 1},
                    },
                },
                {
                    "properties": {
                        "t": {"const": "y"},
                        "y": {"default": 2},
                    },
                },
            ],
        }
        self.assertEqual(
            apply_defaults({"t": "x"}, schema).instance,
            {"t": "x", "x": 1},
        )

    def test_unique_oneof_match_applies_its_defaults(self):
        schema = {
            "oneOf": [
                {
                    "required": ["t"],
                    "properties": {"a": {"default": 1}},
                },
                {"type": "array"},
            ],
        }
        self.assertEqual(
            apply_defaults({"t": "x"}, schema).instance,
            {"t": "x", "a": 1},
        )

    def test_ambiguous_oneof_is_not_guessed(self):
        schema = {
            "oneOf": [
                {"properties": {"a": {"default": 1}}},
                {"properties": {"b": {"default": 2}}},
            ],
        }
        # {} matches both branches, so no branch default may be picked;
        # the instance is genuinely invalid and post-validation fails.
        with self.assertRaises(ValidationError):
            apply_defaults({}, schema)

    def test_no_matching_branch_applies_nothing(self):
        schema = {
            "anyOf": [
                {"type": "string"},
                {"type": "integer"},
            ],
        }
        with self.assertRaises(ValidationError):
            apply_defaults({}, schema)


class ConditionalTests(TestCase):
    def test_then_defaults_applied_when_if_matches(self):
        schema = {
            "properties": {"kind": {"enum": ["a", "b"]}},
            "if": {
                "properties": {"kind": {"const": "a"}},
                "required": ["kind"],
            },
            "then": {"properties": {"av": {"default": 1}}},
            "else": {"properties": {"bv": {"default": 2}}},
        }
        self.assertEqual(
            apply_defaults({"kind": "a"}, schema).instance,
            {"kind": "a", "av": 1},
        )

    def test_else_defaults_applied_when_if_does_not_match(self):
        schema = {
            "properties": {"kind": {"enum": ["a", "b"]}},
            "if": {
                "properties": {"kind": {"const": "a"}},
                "required": ["kind"],
            },
            "then": {"properties": {"av": {"default": 1}}},
            "else": {"properties": {"bv": {"default": 2}}},
        }
        self.assertEqual(
            apply_defaults({"kind": "b"}, schema).instance,
            {"kind": "b", "bv": 2},
        )

    def test_condition_evaluated_after_unconditional_defaults(self):
        schema = {
            "properties": {
                "flag": {"default": True},
                "value": {"default": 1},
            },
            "if": {"properties": {"flag": {"const": True}}},
            "then": {"properties": {"value": {"default": 1}}},
        }
        # Unconditional ``flag`` is inserted; the condition then matches,
        # but the proposed ``value`` defaults agree across schema/then.
        result = apply_defaults({}, schema)
        self.assertEqual(result.instance, {"flag": True, "value": 1})

    def test_branch_default_conflicting_with_inserted_value_is_reported(self):
        schema = {
            "properties": {
                "flag": {"default": True},
                "value": {"default": 0},
            },
            "if": {"properties": {"flag": {"const": True}}},
            "then": {"properties": {"value": {"default": 1}}},
        }
        with self.assertRaises(DefaultsConflict):
            apply_defaults({}, schema)


class ReferenceTests(TestCase):
    def test_local_ref_defaults_are_followed(self):
        schema = {
            "$defs": {
                "point": {
                    "type": "object",
                    "properties": {"q": {"default": 9}},
                },
            },
            "properties": {"r": {"$ref": "#/$defs/point"}},
        }
        result = apply_defaults({"r": {}}, schema)
        self.assertEqual(result.instance, {"r": {"q": 9}})
        self.assertEqual(
            result.applied[0].schema_path,
            ("properties", "r", "$ref", "properties", "q"),
        )

    def test_default_below_ref_object_is_inserted_then_completed(self):
        schema = {
            "$defs": {
                "point": {
                    "properties": {"x": {"default": 1}},
                },
            },
            "properties": {
                "r": {"$ref": "#/$defs/point", "default": {}},
            },
        }
        self.assertEqual(
            apply_defaults({}, schema).instance, {"r": {"x": 1}},
        )

    def test_external_ref_source_uri_is_recorded(self):
        registry = referencing.Registry().with_resource(
            "https://x.test/p.json",
            referencing.Resource.from_contents(
                {"properties": {"z": {"default": 7}}},
                default_specification=DRAFT202012,
            ),
        )
        schema = {
            "$id": "https://x.test/root.json",
            "properties": {"p": {"$ref": "p.json"}},
        }
        validator = Draft202012Validator(schema, registry=registry)
        result = validator.apply_defaults({"p": {}})
        self.assertEqual(result.instance, {"p": {"z": 7}})
        self.assertEqual(
            result.applied[0].schema_uri, "https://x.test/p.json",
        )

    def test_legacy_ref_siblings_are_ignored_in_draft7(self):
        from jsonschema import Draft7Validator

        schema = {
            "definitions": {
                "p": {"properties": {"a": {"default": 1}}},
            },
            "properties": {
                "r": {
                    "$ref": "#/definitions/p",
                    # In drafts <= 7, $ref shadows sibling annotations.
                    "properties": {"sibling": {"default": 2}},
                },
            },
        }
        result = Draft7Validator(schema).apply_defaults({"r": {}})
        self.assertEqual(result.instance, {"r": {"a": 1}})

    def test_ref_siblings_apply_in_2020_12(self):
        schema = {
            "$defs": {"p": {"type": "object"}},
            "properties": {
                "r": {
                    "$ref": "#/$defs/p",
                    "properties": {"a": {"default": 1}},
                },
            },
        }
        result = Draft202012Validator(schema).apply_defaults({"r": {}})
        self.assertEqual(result.instance, {"r": {"a": 1}})

    def test_legacy_ref_resolver_path_works(self):
        from jsonschema import RefResolver

        schema = {"$ref": "/schemas/p.json"}
        resolver = RefResolver.from_schema(
            schema,
            store={
                "/schemas/p.json": {
                    "properties": {"x": {"default": 1}},
                },
            },
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            validator = Draft202012Validator(schema, resolver=resolver)
            result = validator.apply_defaults({})
        self.assertEqual(result.instance, {"x": 1})

    def test_dynamic_ref_cycle_terminates(self):
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$dynamicAnchor": "node",
            "properties": {
                "child": {"$dynamicRef": "#node"},
            },
        }
        result = apply_defaults(
            {"child": {"child": {}}}, schema,
        )
        self.assertEqual(
            result.instance,
            {"child": {"child": {}}},
        )

    def test_2019_09_recursive_ref_is_followed(self):
        from jsonschema import Draft201909Validator

        schema = {
            "$schema": "https://json-schema.org/draft/2019-09/schema",
            "$recursiveAnchor": True,
            "properties": {
                "v": {"default": 1},
                "child": {"$recursiveRef": "#"},
            },
        }
        result = Draft201909Validator(schema).apply_defaults(
            {"child": {}},
        )
        self.assertEqual(
            result.instance, {"v": 1, "child": {"v": 1}},
        )


class RecursiveSchemaTests(TestCase):
    def test_explicit_tree_nodes_are_completed(self):
        schema = {
            "$defs": {
                "node": {
                    "type": "object",
                    "properties": {
                        "value": {"default": 0},
                        "children": {
                            "type": "array",
                            "items": {"$ref": "#/$defs/node"},
                        },
                    },
                },
            },
            "$ref": "#/$defs/node",
        }
        result = apply_defaults(
            {"children": [{"children": []}, {}]}, schema,
        )
        self.assertEqual(
            result.instance,
            {
                "value": 0,
                "children": [
                    {"value": 0, "children": []},
                    {"value": 0},
                ],
            },
        )

    def test_default_object_with_self_ref_terminates(self):
        schema = {
            "$defs": {
                "node": {
                    "type": "object",
                    "properties": {
                        "child": {"$ref": "#/$defs/node"},
                    },
                },
            },
            "properties": {
                "root": {"$ref": "#/$defs/node", "default": {}},
            },
        }
        # Inserting ``root`` must not then infinitely synthesize children.
        result = apply_defaults({}, schema)
        self.assertEqual(result.instance, {"root": {}})

    def test_stable_result_is_idempotent(self):
        schema = {
            "$defs": {
                "node": {
                    "properties": {
                        "value": {"default": 0},
                        "child": {"$ref": "#/$defs/node"},
                    },
                },
            },
            "$ref": "#/$defs/node",
        }
        first = apply_defaults({"child": {}}, schema).instance
        second = apply_defaults(first, schema).instance
        self.assertEqual(first, second)


class PostValidationTests(TestCase):
    def test_invalid_completed_instance_raises_validation_error(self):
        schema = {
            "properties": {"x": {"type": "integer", "default": "oops"}},
        }
        with self.assertRaises(ValidationError):
            apply_defaults({}, schema)

    def test_originally_valid_instance_with_optional_defaults_succeeds(self):
        schema = {
            "properties": {"x": {"type": "integer", "default": 1}},
        }
        self.assertEqual(apply_defaults({}, schema).instance, {"x": 1})

    def test_required_satisfied_by_inserted_default(self):
        schema = {
            "required": ["x"],
            "properties": {"x": {"type": "integer", "default": 1}},
        }
        result = apply_defaults({}, schema)
        self.assertEqual(result.instance, {"x": 1})


class DependentSchemasTests(TestCase):
    def test_dependent_schema_defaults_apply(self):
        schema = {
            "properties": {
                "trigger": {"type": "boolean"},
            },
            "dependentSchemas": {
                "trigger": {"properties": {"extra": {"default": 1}}},
            },
        }
        self.assertEqual(
            apply_defaults({"trigger": True}, schema).instance,
            {"trigger": True, "extra": 1},
        )
        self.assertEqual(
            apply_defaults({}, schema).instance, {},
        )
