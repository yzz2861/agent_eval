"""
Tests for explicitly filling ``default`` annotations.
"""
from unittest import TestCase

from jsonschema import (
    DefaultConflictError,
    DefaultFillLoopError,
    Draft201909Validator,
    Draft202012Validator,
    Draft4Validator,
    Draft7Validator,
    ValidationError,
    fill_defaults,
)


class FillDefaultsTests(TestCase):
    def fill(self, instance, schema, cls=Draft202012Validator):
        return fill_defaults(instance, schema, cls=cls)

    def test_validation_does_not_fill(self):
        schema = {"type": "object", "properties": {"a": {"default": 1}}}
        instance = {}
        Draft202012Validator(schema).validate(instance)
        self.assertEqual(instance, {})

    def test_fills_missing_properties(self):
        schema = {
            "type": "object",
            "properties": {"a": {"default": 1}, "b": {"default": 2}},
        }
        result = self.fill({}, schema)
        self.assertEqual(result.instance, {"a": 1, "b": 2})
        self.assertEqual(
            result.defaults[("a",)].schema_path,
            ("properties", "a", "default"),
        )
        self.assertEqual(result.defaults[("b",)].value, 2)

    def test_present_properties_are_not_touched(self):
        schema = {
            "type": "object",
            "properties": {"a": {"default": 1}},
        }
        result = self.fill({"a": 5}, schema)
        self.assertEqual(result.instance, {"a": 5})
        self.assertEqual(result.defaults, {})

    def test_null_is_not_missing(self):
        schema = {
            "type": "object",
            "properties": {"a": {"default": 1}},
        }
        result = self.fill({"a": None}, schema)
        self.assertEqual(result.instance, {"a": None})
        self.assertEqual(result.defaults, {})

    def test_original_instance_is_not_mutated(self):
        schema = {
            "type": "object",
            "properties": {"a": {"default": {"b": 1}}},
        }
        instance = {}
        result = self.fill(instance, schema)
        self.assertEqual(instance, {})
        self.assertIsNot(result.instance, instance)

    def test_default_values_are_deep_copied(self):
        nested = {"b": 1}
        schema = {
            "type": "object",
            "properties": {
                "x": {"default": nested},
                "y": {"default": nested},
            },
        }
        result = self.fill({}, schema)
        self.assertIsNot(result.instance["x"], result.instance["y"])
        result.instance["x"]["b"] = 99
        self.assertEqual(result.instance["y"], {"b": 1})

    def test_nested_existing_object(self):
        schema = {
            "type": "object",
            "properties": {
                "outer": {
                    "type": "object",
                    "properties": {"inner": {"default": 5}},
                },
            },
        }
        result = self.fill({"outer": {}}, schema)
        self.assertEqual(result.instance, {"outer": {"inner": 5}})
        self.assertEqual(
            result.defaults[("outer", "inner")].schema_path,
            ("properties", "outer", "properties", "inner", "default"),
        )

    def test_nested_default_parent_is_filled_recursively(self):
        schema = {
            "type": "object",
            "properties": {
                "outer": {
                    "type": "object",
                    "default": {},
                    "properties": {"inner": {"default": 5}},
                },
            },
        }
        result = self.fill({}, schema)
        self.assertEqual(result.instance, {"outer": {"inner": 5}})

    def test_array_items(self):
        schema = {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {"x": {"default": 7}},
            },
        }
        result = self.fill([{}, {}], schema)
        self.assertEqual(result.instance, [{"x": 7}, {"x": 7}])

    def test_prefix_items_and_items(self):
        schema = {
            "type": "array",
            "prefixItems": [
                {"type": "object", "properties": {"p": {"default": 0}}},
            ],
            "items": {
                "type": "object", "properties": {"q": {"default": 2}},
            },
        }
        result = self.fill([{}, {}, {}], schema)
        self.assertEqual(
            result.instance,
            [{"p": 0}, {"q": 2}, {"q": 2}],
        )

    def test_all_of_matching_defaults_merge(self):
        schema = {
            "allOf": [
                {"properties": {"a": {"default": 1}}},
                {"properties": {"a": {"default": 1}, "b": {"default": 2}}},
            ],
        }
        result = self.fill({}, schema)
        self.assertEqual(result.instance, {"a": 1, "b": 2})

    def test_all_of_conflicting_defaults(self):
        schema = {
            "allOf": [
                {"properties": {"a": {"default": 1}}},
                {"properties": {"a": {"default": 2}}},
            ],
        }
        with self.assertRaises(DefaultConflictError) as cm:
            self.fill({}, schema)
        self.assertEqual(cm.exception.path, ("a",))
        self.assertEqual(cm.exception.values, (1, 2))

    def test_ref_conflict(self):
        schema = {
            "$defs": {"a": {"properties": {"x": {"default": 1}}}},
            "allOf": [
                {"$ref": "#/$defs/a"},
                {"properties": {"x": {"default": 2}}},
            ],
        }
        with self.assertRaises(DefaultConflictError):
            self.fill({}, schema)

    def test_any_of_unambiguous_branch(self):
        schema = {
            "anyOf": [
                {
                    "required": ["x"],
                    "properties": {"a": {"default": 1}},
                },
                {
                    "required": ["y"],
                    "properties": {"b": {"default": 2}},
                },
            ],
        }
        result = self.fill({"x": True}, schema)
        self.assertEqual(result.instance, {"x": True, "a": 1})

    def test_any_of_ambiguous_branch_is_not_chosen(self):
        schema = {
            "anyOf": [
                {"properties": {"a": {"default": 1}}},
                {"properties": {"b": {"default": 2}}},
            ],
        }
        result = self.fill({}, schema)
        self.assertEqual(result.instance, {})

    def test_one_of_unambiguous_branch(self):
        schema = {
            "oneOf": [
                {
                    "required": ["x"],
                    "properties": {"a": {"default": 1}},
                },
                {
                    "required": ["y"],
                    "properties": {"b": {"default": 2}},
                },
            ],
        }
        result = self.fill({"y": True}, schema)
        self.assertEqual(result.instance, {"y": True, "b": 2})

    def test_if_then(self):
        schema = {
            "if": {"required": ["t"]},
            "then": {"properties": {"a": {"default": 1}}},
            "else": {"properties": {"b": {"default": 2}}},
        }
        self.assertEqual(
            self.fill({"t": True}, schema).instance, {"t": True, "a": 1},
        )
        self.assertEqual(self.fill({}, schema).instance, {"b": 2})

    def test_conditional_reaches_fixpoint(self):
        schema = {
            "properties": {"t": {"default": True}},
            "if": {"required": ["t"]},
            "then": {"properties": {"a": {"default": 1}}},
        }
        result = self.fill({}, schema)
        self.assertEqual(result.instance, {"t": True, "a": 1})

    def test_conditional_default_that_changes_branch_is_pruned(self):
        # With no instance the ``if`` briefly matches (no ``kind`` yet), so
        # the ``then`` default is collected; filling ``kind`` then makes the
        # ``else`` branch apply. The transient ``then`` value must not remain.
        schema = {
            "properties": {"kind": {"default": "B"}},
            "if": {"properties": {"kind": {"enum": ["A"]}}},
            "then": {"properties": {"a": {"default": 1}}},
            "else": {"properties": {"b": {"default": 2}}},
        }
        result = self.fill({}, schema)
        self.assertEqual(result.instance, {"kind": "B", "b": 2})
        self.assertNotIn(("a",), result.defaults)

    def test_ambiguous_branch_transient_default_is_pruned(self):
        schema = {
            "properties": {"x": {"default": True}},
            "anyOf": [
                {
                    "required": ["x"],
                    "properties": {"a": {"default": 1}},
                },
                {"properties": {"b": {"default": 2}}},
            ],
        }
        result = self.fill({}, schema)
        self.assertEqual(result.instance, {"x": True})
        self.assertNotIn(("a",), result.defaults)

    def test_dependent_schemas_reach_fixpoint(self):
        schema = {
            "properties": {"a": {"default": {}}},
            "dependentSchemas": {
                "a": {"properties": {"c": {"default": 3}}},
            },
        }
        result = self.fill({}, schema)
        self.assertEqual(result.instance, {"a": {}, "c": 3})

    def test_reference(self):
        schema = {
            "$defs": {
                "a": {
                    "type": "object",
                    "properties": {"b": {"default": 1}},
                },
            },
            "$ref": "#/$defs/a",
        }
        result = self.fill({}, schema)
        self.assertEqual(result.instance, {"b": 1})

    def test_reference_with_sibling_properties(self):
        schema = {
            "$defs": {
                "b": {"properties": {"from_ref": {"default": 1}}},
            },
            "type": "object",
            "properties": {
                "wrapper": {
                    "$ref": "#/$defs/b",
                    "properties": {
                        "from_sibling": {"default": 2},
                    },
                },
            },
        }
        result = self.fill({"wrapper": {}}, schema)
        self.assertEqual(
            result.instance,
            {"wrapper": {"from_ref": 1, "from_sibling": 2}},
        )

    def test_recursive_user_data_is_filled(self):
        schema = {
            "type": "object",
            "properties": {
                "name": {"default": "n"},
                "child": {"$ref": "#"},
            },
        }
        result = self.fill({"child": {"child": {}}}, schema)
        self.assertEqual(
            result.instance,
            {
                "name": "n",
                "child": {
                    "name": "n",
                    "child": {"name": "n"},
                },
            },
        )

    def test_cyclic_default_is_reported(self):
        schema = {
            "$defs": {
                "node": {
                    "type": "object",
                    "properties": {
                        "name": {"default": "x"},
                        "child": {"default": {}, "$ref": "#/$defs/node"},
                    },
                },
            },
            "$ref": "#/$defs/node",
        }
        with self.assertRaises(DefaultFillLoopError):
            self.fill({}, schema)

    def test_shared_subschema_for_distinct_properties(self):
        schema = {
            "$defs": {
                "node": {
                    "type": "object",
                    "properties": {"v": {"default": 1}},
                },
            },
            "type": "object",
            "properties": {
                "a": {"default": {}, "$ref": "#/$defs/node"},
                "b": {"default": {}, "$ref": "#/$defs/node"},
            },
        }
        result = self.fill({}, schema)
        self.assertEqual(
            result.instance,
            {"a": {"v": 1}, "b": {"v": 1}},
        )

    def test_nested_unambiguous_any_of(self):
        schema = {
            "type": "object",
            "properties": {
                "cfg": {
                    "anyOf": [
                        {
                            "required": ["k"],
                            "properties": {"v": {"default": 1}},
                        },
                        {
                            "required": ["j"],
                            "properties": {"w": {"default": 2}},
                        },
                    ],
                },
            },
        }
        result = self.fill({"cfg": {"k": True}}, schema)
        self.assertEqual(result.instance, {"cfg": {"k": True, "v": 1}})

    def test_nested_ambiguous_any_of_is_skipped(self):
        schema = {
            "type": "object",
            "properties": {
                "cfg": {
                    "anyOf": [
                        {
                            "required": ["k"],
                            "properties": {"v": {"default": 1}},
                        },
                        {"properties": {"w": {"default": 2}}},
                    ],
                },
            },
        }
        result = self.fill({"cfg": {"k": True}}, schema)
        self.assertEqual(result.instance, {"cfg": {"k": True}})

    def test_pattern_properties_nested(self):
        schema = {
            "patternProperties": {
                "^x$": {"properties": {"n": {"default": 1}}},
            },
        }
        result = self.fill({"x": {}}, schema)
        self.assertEqual(result.instance, {"x": {"n": 1}})

    def test_additional_properties_nested(self):
        schema = {
            "properties": {"known": {}},
            "additionalProperties": {
                "properties": {"m": {"default": 7}},
            },
        }
        result = self.fill({"known": {}, "extra": {}}, schema)
        self.assertEqual(result.instance, {"known": {}, "extra": {"m": 7}})

    def test_invalid_filled_instance_raises(self):
        schema = {
            "type": "object",
            "properties": {
                "a": {"default": 1, "type": "string"},
            },
        }
        with self.assertRaises(ValidationError):
            self.fill({}, schema)

    def test_invalid_original_instance_raises(self):
        schema = {
            "type": "object",
            "properties": {"a": {"default": 1}},
        }
        with self.assertRaises(ValidationError):
            self.fill(42, schema)

    def test_validator_method(self):
        validator = Draft202012Validator(
            {"type": "object", "properties": {"a": {"default": 1}}},
        )
        instance, defaults = validator.fill_defaults({})
        self.assertEqual(instance, {"a": 1})
        self.assertEqual(defaults[("a",)].value, 1)

    def test_booleans_and_non_objects_are_ignored(self):
        self.assertEqual(self.fill("hello", True).instance, "hello")
        self.assertEqual(self.fill(3, {}).instance, 3)

    def test_draft7_if_then(self):
        schema = {
            "if": {"required": ["t"]},
            "then": {"properties": {"a": {"default": 1}}},
        }
        result = self.fill({"t": True}, schema, cls=Draft7Validator)
        self.assertEqual(result.instance, {"t": True, "a": 1})

    def test_draft4_all_of(self):
        schema = {
            "allOf": [
                {"properties": {"a": {"default": 1}}},
            ],
        }
        result = self.fill({}, schema, cls=Draft4Validator)
        self.assertEqual(result.instance, {"a": 1})

    def test_draft201909_reference(self):
        schema = {
            "$defs": {"a": {"properties": {"b": {"default": 1}}}},
            "$ref": "#/$defs/a",
        }
        result = self.fill({}, schema, cls=Draft201909Validator)
        self.assertEqual(result.instance, {"b": 1})
