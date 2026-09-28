"""
Tests for offline schema bundling (jsonschema.bundling).
"""

import json

from referencing import Registry, Resource
from referencing.exceptions import Unresolvable
from referencing.jsonschema import DRAFT7, DRAFT202012
import pytest

from jsonschema.bundling import bundle, load
from jsonschema.exceptions import (
    BundleIntegrityError,
    ConflictingResourceError,
    MissingResourceError,
)
from jsonschema.validators import validator_for


def registry_with(**resources):
    return Registry().with_resources(
        (
            uri,
            Resource.from_contents(
                contents, default_specification=DRAFT202012,
            ),
        )
        for uri, contents in resources.items()
    )


def errors_for(schema, registry, instance):
    cls = validator_for(schema)
    validator = cls(schema, registry=registry)
    return sorted(e.message for e in validator.iter_errors(instance))


class TestBundling:
    def test_single_schema_without_references(self):
        schema = {"type": "integer", "minimum": 3}
        bundled = bundle(schema)

        assert bundled.entry == ""
        assert list(bundled.manifest) == [""]
        assert bundled.digest.startswith("sha256:")
        assert bundled.manifest[""]["digest"].startswith("sha256:")

        loaded = load(bundled)
        assert loaded.schema == schema
        assert loaded.is_valid(4)
        assert not loaded.is_valid(2)

    def test_relative_references_across_documents(self):
        schema = {
            "$id": "https://example.com/schemas/root.json",
            "type": "object",
            "properties": {
                "thing": {"$ref": "dir/thing.json"},
                "other": {"$ref": "dir/other.json"},
            },
        }
        thing = {
            "$id": "https://example.com/schemas/dir/thing.json",
            "type": "object",
            "properties": {"name": {"$ref": "other.json#/$defs/name"}},
        }
        other = {
            "$id": "https://example.com/schemas/dir/other.json",
            "$defs": {"name": {"type": "string", "minLength": 2}},
        }
        registry = registry_with(
            **{
                "https://example.com/schemas/dir/thing.json": thing,
                "https://example.com/schemas/dir/other.json": other,
            },
        )

        bundled = bundle(schema, registry=registry)
        assert set(bundled.manifest) == {
            "https://example.com/schemas/root.json",
            "https://example.com/schemas/dir/thing.json",
            "https://example.com/schemas/dir/other.json",
        }

        loaded = load(bundled.to_json())
        instance = {"thing": {"name": "ab"}, "other": "whatever"}
        invalid = {"thing": {"name": "a"}}
        assert loaded.is_valid(instance)
        assert not loaded.is_valid(invalid)

        # the original registry and the offline one agree
        assert errors_for(schema, registry, invalid) == [
            e.message
            for e in loaded.validator().iter_errors(invalid)
        ]

    def test_anchors_and_dynamic_refs(self):
        # the "recursive tree" example from the JSON Schema docs
        tree = {
            "$id": "https://example.com/tree.json",
            "$dynamicAnchor": "node",
            "type": "object",
            "properties": {
                "data": True,
                "children": {
                    "type": "array",
                    "items": {"$dynamicRef": "#node"},
                },
            },
        }
        strict_tree = {
            "$id": "https://example.com/strict-tree.json",
            "$ref": "tree.json",
            "unevaluatedProperties": False,
        }
        registry = registry_with(
            **{
                "https://example.com/tree.json": tree,
                "https://example.com/strict-tree.json": strict_tree,
            },
        )

        bundled = bundle(tree, registry=registry)
        loaded = load(bundled.to_json())

        instance = {"data": 1, "children": [{"data": 2, "children": []}]}
        invalid = {"data": 1, "extra": True}
        assert loaded.is_valid(instance)
        # extra properties are fine under the plain tree schema ...
        assert loaded.is_valid(invalid)

        strict = bundle(strict_tree, registry=registry)
        strict_loaded = load(strict.to_json())
        assert strict_loaded.is_valid(instance)
        # ... but rejected by strict-tree's unevaluatedProperties
        assert not strict_loaded.is_valid(invalid)

        # equivalence with the original registry
        assert errors_for(strict_tree, registry, invalid) == [
            e.message for e in strict_loaded.validator().iter_errors(invalid)
        ]

    def test_anchor_references(self):
        schema = {
            "$id": "https://example.com/root.json",
            "$defs": {
                "named": {
                    "$anchor": "thing",
                    "type": "string",
                },
            },
            "properties": {"a": {"$ref": "other.json#thing"}},
        }
        other = {
            "$id": "https://example.com/other.json",
            "$defs": {
                "named": {
                    "$anchor": "thing",
                    "type": "integer",
                },
            },
        }
        registry = registry_with(
            **{"https://example.com/other.json": other},
        )
        loaded = load(bundle(schema, registry=registry).to_json())
        assert loaded.is_valid({"a": 3})
        assert not loaded.is_valid({"a": "no"})

    def test_recursive_resources_are_stored_once(self):
        a = {
            "$id": "https://example.com/a.json",
            "type": "object",
            "properties": {"b": {"$ref": "b.json"}},
        }
        b = {
            "$id": "https://example.com/b.json",
            "type": "object",
            "properties": {"a": {"$ref": "a.json"}},
        }
        registry = registry_with(
            **{
                "https://example.com/a.json": a,
                "https://example.com/b.json": b,
            },
        )
        bundled = bundle(a, registry=registry)
        assert set(bundled.manifest) == {
            "https://example.com/a.json",
            "https://example.com/b.json",
        }
        # one manifest entry per URI, and one stored resource per digest
        digests = [info["digest"] for info in bundled.manifest.values()]
        assert len(digests) == len(set(digests)) == 2

        loaded = load(bundled.to_json())
        assert loaded.is_valid({"b": {"a": {"b": {}}}})
        assert not loaded.is_valid({"b": {"a": 3}})

    def test_self_referential_schema(self):
        schema = {
            "$id": "https://example.com/self.json",
            "type": "object",
            "properties": {"child": {"$ref": "#"}},
        }
        bundled = bundle(schema)
        assert list(bundled.manifest) == ["https://example.com/self.json"]
        loaded = load(bundled.to_json())
        assert loaded.is_valid({"child": {"child": {}}})
        assert not loaded.is_valid({"child": 3})

    def test_embedded_subresources_with_ids(self):
        schema = {
            "$id": "https://example.com/root.json",
            "$defs": {
                "child": {
                    "$id": "child.json",
                    "type": "integer",
                },
            },
            "properties": {"n": {"$ref": "child.json"}},
        }
        bundled = bundle(schema)
        assert set(bundled.manifest) == {
            "https://example.com/root.json",
            "https://example.com/child.json",
        }
        loaded = load(bundled.to_json())
        assert loaded.is_valid({"n": 3})
        assert not loaded.is_valid({"n": "no"})

    def test_only_reachable_resources_are_bundled(self):
        schema = {"$id": "https://example.com/root.json", "$ref": "used.json"}
        registry = registry_with(
            **{
                "https://example.com/used.json": {"type": "integer"},
                "https://example.com/unused.json": {"type": "string"},
            },
        )
        bundled = bundle(schema, registry=registry)
        assert set(bundled.manifest) == {
            "https://example.com/root.json",
            "https://example.com/used.json",
        }

    def test_missing_resource_is_rejected(self):
        schema = {
            "$id": "https://example.com/root.json",
            "$ref": "absent.json",
        }
        with pytest.raises(MissingResourceError) as excinfo:
            bundle(schema, registry=Registry())
        assert excinfo.value.uri == "https://example.com/absent.json"

    def test_conflicting_entry_resource_is_rejected(self):
        registry = registry_with(
            **{"https://example.com/root.json": {"type": "string"}},
        )
        with pytest.raises(ConflictingResourceError):
            bundle(
                {"$id": "https://example.com/root.json", "type": "integer"},
                registry=registry,
            )

    def test_conflicting_subresource_is_rejected(self):
        schema = {
            "$id": "https://example.com/root.json",
            "$defs": {
                "child": {"$id": "child.json", "type": "integer"},
            },
        }
        registry = registry_with(
            **{"https://example.com/child.json": {"type": "string"}},
        )
        with pytest.raises(ConflictingResourceError):
            bundle(schema, registry=registry)

    def test_same_content_under_two_uris_is_stored_once(self):
        shared = {"type": "integer"}
        schema = {
            "$id": "https://example.com/root.json",
            "properties": {
                "a": {"$ref": "one.json"},
                "b": {"$ref": "two.json"},
            },
        }
        registry = registry_with(
            **{
                "https://example.com/one.json": shared,
                "https://example.com/two.json": dict(shared),
            },
        )
        bundled = bundle(schema, registry=registry)
        assert len(bundled.manifest) == 3
        assert len(bundled.to_dict()["resources"]) == 2

    def test_dialect_is_preserved(self):
        schema = {
            "$id": "https://example.com/root.json",
            "$ref": "old.json",
        }
        old = Resource(
            {"id": "https://example.com/old.json", "type": "integer"},
            DRAFT7,
        )
        registry = Registry().with_resource(
            "https://example.com/old.json", old,
        )
        loaded = load(bundle(schema, registry=registry).to_json())
        resource = loaded.registry["https://example.com/old.json"]
        assert resource._specification is DRAFT7

    def test_resource_entry(self):
        resource = Resource.from_contents(
            {"$id": "https://example.com/root.json", "type": "integer"},
            default_specification=DRAFT202012,
        )
        bundled = bundle(resource)
        assert bundled.entry == "https://example.com/root.json"
        assert load(bundled.to_json()).is_valid(3)

    def test_base_uri(self):
        bundled = bundle(
            {"type": "integer"},
            base_uri="https://example.com/root.json",
        )
        assert bundled.entry == "https://example.com/root.json"

    def test_non_json_serializable_contents_are_rejected(self):
        from jsonschema.exceptions import BundleError

        with pytest.raises(BundleError):
            bundle({"const": object()})


class TestLoading:
    def test_roundtrip_via_json(self):
        schema = {"type": "array", "items": {"$ref": "#/$defs/pos"}}
        schema["$defs"] = {"pos": {"type": "integer", "minimum": 0}}
        text = bundle(schema).to_json()
        assert isinstance(text, str)
        json.loads(text)  # really JSON

        loaded = load(text)
        assert loaded.is_valid([1, 2])
        assert not loaded.is_valid([-1])

    def test_roundtrip_via_dict(self):
        schema = {"type": "boolean"}
        loaded = load(bundle(schema).to_dict())
        assert loaded.is_valid(True)

    def test_load_accepts_bundle(self):
        loaded = load(bundle({"type": "integer"}))
        assert loaded.is_valid(1)

    def test_tampered_resource_is_rejected(self):
        data = bundle({"type": "integer"}).to_dict()
        key = next(iter(data["resources"]))
        data["resources"][key] = {"type": "string"}
        with pytest.raises(BundleIntegrityError, match="tampered"):
            load(data)

    def test_tampered_manifest_is_rejected(self):
        data = bundle({"type": "integer"}).to_dict()
        data["manifest"][""]["specification"] = "draft-04"
        with pytest.raises(BundleIntegrityError, match="tampered"):
            load(data)

    def test_tampered_entry_is_rejected(self):
        data = bundle({"type": "integer"}).to_dict()
        data["entry"] = "https://example.com/other.json"
        with pytest.raises(BundleIntegrityError):
            load(data)

    def test_missing_resource_is_rejected(self):
        data = bundle({"type": "integer"}).to_dict()
        data["resources"].clear()
        with pytest.raises(BundleIntegrityError, match="missing"):
            load(data)

    def test_missing_entry_is_rejected(self):
        data = bundle({"type": "integer"}).to_dict()
        # a well-formed bundle whose manifest lacks the entry
        other = bundle({"$id": "https://example.com/x.json"}).to_dict()
        other["entry"] = "https://example.com/absent.json"
        other["digest"] = data["digest"]  # replaced below anyway
        import jsonschema.bundling as bundling

        other["digest"] = bundling._digest_of(
            {
                "version": other["version"],
                "entry": other["entry"],
                "manifest": other["manifest"],
            },
            "<bundle>",
        )
        with pytest.raises(BundleIntegrityError, match="entry"):
            load(other)

    def test_malformed_bundles_are_rejected(self):
        with pytest.raises(BundleIntegrityError):
            load("not json")
        with pytest.raises(BundleIntegrityError):
            load("{}")
        with pytest.raises(BundleIntegrityError):
            load({"version": 2})
        with pytest.raises(TypeError):
            load(12)

    def test_loaded_registry_does_not_retrieve(self):
        schema = {"$id": "https://example.com/root.json", "type": "integer"}
        loaded = load(bundle(schema).to_json())
        assert loaded.is_valid(3)

        # a reference to something outside the bundle cannot be resolved
        # (and in particular is not retrieved from the network)
        bad = {"$ref": "https://example.com/absent.json"}
        cls = validator_for(bad)
        validator = cls(bad, registry=loaded.registry)
        with pytest.raises(Unresolvable):
            list(validator.iter_errors(1))


class TestEquivalence:
    SCHEMA = {
        "$id": "https://example.com/root.json",
        "type": "object",
        "properties": {
            "name": {"$ref": "defs/common.json#name"},
            "tags": {
                "type": "array",
                "items": {"$ref": "/abs/tag.json"},
            },
            "sub": {"$dynamicRef": "#node"},
        },
        "$defs": {
            "node": {
                "$dynamicAnchor": "node",
                "type": "object",
                "properties": {"value": {"type": "integer"}},
            },
        },
    }
    COMMON = {
        "$id": "https://example.com/defs/common.json",
        "$defs": {
            "name": {
                "$anchor": "name",
                "type": "string",
                "minLength": 1,
            },
        },
    }
    TAG = {
        "$id": "https://example.com/abs/tag.json",
        "type": "string",
        "pattern": "^[a-z]+$",
    }
    INSTANCES = [
        {"name": "ok", "tags": ["abc"], "sub": {"value": 1}},
        {"name": "", "tags": ["ABC"], "sub": {"value": "no"}},
        {"name": 3},
        {"sub": {"value": 2, "extra": "allowed"}},
        "not an object",
    ]

    @pytest.fixture
    def registry(self):
        return registry_with(
            **{
                "https://example.com/defs/common.json": self.COMMON,
                "https://example.com/abs/tag.json": self.TAG,
            },
        )

    @pytest.mark.parametrize("instance", INSTANCES)
    def test_same_results(self, registry, instance):
        loaded = load(bundle(self.SCHEMA, registry=registry).to_json())

        expected = errors_for(self.SCHEMA, registry, instance)
        actual = [
            e.message for e in loaded.validator().iter_errors(instance)
        ]
        assert actual == expected
        assert loaded.is_valid(instance) == (not expected)
