from collections import deque
from unittest import TestCase
import sys

from jsonschema import Draft202012Validator, ValidationError
from jsonschema.explain import explain
from jsonschema.validators import extend


class ExplanationTest(TestCase):
    def test_properties_are_located_with_json_pointers(self):
        schema = {
            "properties": {"foo": {}, "bar": {}},
            "unevaluatedProperties": False,
        }

        result = explain({"foo": 1, "quux": 2}, schema)

        sources = {
            source.instance_pointer: source.schema_pointer
            for source in result.evaluated_properties
        }
        assert sources == {
            "/foo": "/properties/foo",
            "/quux": "/unevaluatedProperties/quux",
        }
        assert not result.valid
        assert result.errors[0].absolute_path == deque()

    def test_array_items_are_located(self):
        schema = {
            "prefixItems": [{"type": "string"}],
            "items": {"type": "string"},
        }

        result = explain([1, 2], schema)

        assert [
            (source.name, source.keyword) for source in result.evaluated_items
        ] == [(0, "prefixItems"), (1, "items")]
        assert result.evaluated_items[0].instance_pointer == "/0"
        assert result.evaluated_items[0].schema_pointer == "/prefixItems/0"

    def test_items_false_records_extra_items(self):
        schema = {"prefixItems": [{"type": "string"}], "items": False}
        result = explain(["x", 1], schema)
        assert [
            (source.name, source.keyword) for source in result.evaluated_items
        ] == [(0, "prefixItems"), (1, "items")]
        assert result.evaluated_items[1].instance_pointer == "/1"

    def test_values_are_not_included_by_default(self):
        result = explain(
            {"secret": 1},
            {"properties": {"secret": {}}},
        )
        summary = result.to_summary()
        assert "value" not in summary["evaluated_properties"][0]

        with_values = explain(
            {"secret": 1},
            {"properties": {"secret": {}}},
            include_values=True,
        )
        assert (
            with_values.to_summary()["evaluated_properties"][0]["value"] == 1
        )

    def test_sources_for_looks_up_instance_pointer(self):
        result = explain(
            {"nested": {"x": 1}},
            {"properties": {"nested": {"properties": {"x": {}}}}},
        )
        sources = result.sources_for("/nested/x")
        assert len(sources) == 1
        assert sources[0].keyword == "properties"
        assert sources[0].schema_pointer == ("/properties/nested/properties/x")


class BranchTest(TestCase):
    def _branches(self, result, keyword):
        return [
            branch for branch in result.branches if branch.keyword == keyword
        ]

    def test_all_of_records_each_branch_and_failure(self):
        schema = {"allOf": [{"type": "string"}]}
        result = explain(3, schema)
        branches = self._branches(result, "allOf")
        assert len(branches) == 1
        assert branches[0].branch_pointer == "0"
        assert branches[0].evaluated is True
        assert branches[0].valid is False

    def test_all_of_failed_branch_still_evaluates_properties(self):
        # Per the JSON Schema spec allOf annotations are produced even when
        # the branch fails.
        schema = {
            "allOf": [{"properties": {"a": {"type": "integer"}}}],
        }
        result = explain({"a": "x"}, schema)
        assert [source.name for source in result.evaluated_properties] == [
            "a",
        ]

    def test_any_of_failed_branch_annotations_are_discarded(self):
        schema = {
            "anyOf": [
                {"required": ["x"], "properties": {"bad": {}}},
                {"properties": {"good": {}}},
            ],
        }
        result = explain({"bad": 1, "good": 2}, schema)
        branches = self._branches(result, "anyOf")
        assert [branch.valid for branch in branches] == [False, True]
        assert [source.name for source in result.evaluated_properties] == [
            "good",
        ]

    def test_any_of_records_skipped_branches(self):
        schema = {"anyOf": [{"type": "integer"}, {"type": "number"}]}
        result = explain(3, schema)
        branches = self._branches(result, "anyOf")
        assert branches[0].valid is True
        assert branches[1].evaluated is False
        assert branches[1].valid is None

    def test_one_of_records_all_branch_outcomes(self):
        schema = {
            "oneOf": [
                {"properties": {"a": {}}},
                {"properties": {"b": {}}},
            ],
        }
        result = explain({"a": 1, "b": 2}, schema)
        branches = sorted(
            self._branches(result, "oneOf"),
            key=lambda branch: branch.branch_pointer,
        )
        assert [branch.valid for branch in branches] == [True, True]

    def test_if_then_else_branches(self):
        schema = {
            "if": {"required": ["a"]},
            "then": {"properties": {"t": {}}},
            "else": {"properties": {"e": {}}},
        }

        taken = explain({"a": 1}, schema)
        by_keyword = {branch.keyword: branch for branch in taken.branches}
        assert by_keyword["if"].valid is True
        assert by_keyword["then"].evaluated is True
        assert by_keyword["else"].evaluated is False

        not_taken = explain({}, schema)
        by_keyword = {branch.keyword: branch for branch in not_taken.branches}
        assert by_keyword["if"].valid is False
        assert by_keyword["then"].evaluated is False
        assert by_keyword["else"].evaluated is True


class ReferenceTest(TestCase):
    def test_ref_records_target_and_evaluated_property(self):
        schema = {
            "$defs": {"p": {"properties": {"x": {}}}},
            "$ref": "#/$defs/p",
        }
        result = explain({"x": 1}, schema)
        refs = [
            branch for branch in result.branches if branch.keyword == "$ref"
        ]
        assert len(refs) == 1
        assert refs[0].ref == "#/$defs/p"
        assert refs[0].valid is True
        source = result.evaluated_properties[0]
        assert source.instance_pointer == "/x"
        assert source.schema_pointer == "/properties/x"
        assert source.via == (("$ref", "#/$defs/p"),)

    def test_dynamic_ref_records_keyword(self):
        schema = {
            "$id": "https://example.com/root",
            "$defs": {
                "node": {
                    "$dynamicAnchor": "node",
                    "type": "string",
                },
            },
            "$ref": "#/$defs/node",
            "$dynamicRef": "#node",
        }
        result = explain(3, schema)
        keywords = {branch.keyword for branch in result.branches}
        assert "$ref" in keywords
        assert "$dynamicRef" in keywords

    def test_recursive_ref_draft2019_is_recorded(self):
        from jsonschema import Draft201909Validator

        schema = {
            "$id": "https://example.com/recursive2019",
            "$recursiveAnchor": True,
            "type": "object",
            "properties": {"child": {"$recursiveRef": "#"}},
        }
        result = Draft201909Validator(schema).explain(
            {"child": {"child": {}}},
        )
        refs = [
            branch
            for branch in result.branches
            if branch.keyword == "$recursiveRef"
        ]
        assert len(refs) == 2
        assert all(ref.valid for ref in refs)

    def test_recursive_reference_report_terminates(self):
        schema = {
            "$id": "https://example.com/recursive",
            "type": "object",
            "properties": {"next": {"$ref": "#"}},
        }
        instance = current = {}
        for _ in range(200):
            current["next"] = {}
            current = current["next"]

        old_limit = sys.getrecursionlimit()
        sys.setrecursionlimit(10000)
        try:
            result = explain(instance, schema, max_depth=30)
        finally:
            sys.setrecursionlimit(old_limit)
        assert result.truncated is True
        assert result.valid is True
        assert len(result.branches) <= 60


class CapTest(TestCase):
    def test_event_cap_marks_report_truncated(self):
        schema = {"properties": {"a": {}, "b": {}, "c": {}}}
        result = explain({"a": 1, "b": 2, "c": 3}, schema, max_events=2)
        assert result.truncated is True

    def test_depth_cap_does_not_raise(self):
        schema = {
            "allOf": [
                {
                    "allOf": [
                        {"allOf": [{"type": "integer"}]},
                    ],
                },
            ],
        }
        result = explain(3, schema, max_depth=2)
        assert result.truncated is True
        assert result.valid is True


class BehaviorPreservationTest(TestCase):
    def test_iter_errors_results_and_order_unchanged(self):
        schema = {
            "properties": {
                "a": {"type": "string"},
                "b": {"type": "string"},
            },
            "required": ["a", "b"],
            "minProperties": 5,
        }
        instance = {"a": 1, "b": 2}
        validator = Draft202012Validator(schema)
        baseline = [error.message for error in validator.iter_errors(instance)]

        explanation = validator.explain(instance)
        explained = [error.message for error in explanation.errors]

        assert baseline == explained
        assert explanation.valid is False

    def test_custom_validators_are_not_run_again(self):
        calls = []

        def custom(validator, value, instance, schema):
            calls.append(instance)
            if instance != 42:
                yield ValidationError("must be 42")

        CustomValidator = extend(
            Draft202012Validator,
            {"x-custom": custom},
        )
        validator = CustomValidator(
            {"properties": {"a": {"x-custom": True}}},
        )

        explanation = validator.explain({"a": 1})

        # Once at the root (which does not apply the keyword to the value)
        # and once for property "a".
        # The keyword runs exactly once: at property a.
        assert calls == [1]
        assert explanation.keyword_evaluations
        source = explanation.evaluated_properties[0]
        assert source.name == "a"
        assert source.schema_pointer == "/properties/a"

    def test_plain_iterations_are_unaffected(self):
        validator = Draft202012Validator({"type": "string"})
        assert validator.is_valid("x")
        assert not validator.is_valid(3)
        assert list(validator.iter_errors(3))
