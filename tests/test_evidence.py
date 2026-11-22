import json
from decimal import Decimal

import pytest

import ijson
from ijson.evidence import (
    IndexSegment,
    KeySegment,
    SelectionNotFound,
    canonical_number,
    format_path,
    numbers_equal,
    parse_path,
    verify_evidence,
)


SOURCE = (
    b"{\"item\": \"object-key\", \"arr\": [10, 20], "
    b"\"dup\": {\"k\": \"first\", \"k\": \"second\"}, "
    b"\"numbers\": {\"a\": 1, \"b\": 1.0, \"c\": 1e0}}"
)


def _extract(source=SOURCE, selections=None, **kwargs):
    if selections is None:
        selections = ["item", "arr[1]", "dup.k#0", "dup.k#1"]
    return ijson.extract_evidence(source, selections, **kwargs)


def test_extract_typed_paths_and_distinct_array_key_types():
    bundle = _extract(selections=["item", "arr[0]"])
    by_path = {observation.path_string: observation for observation in bundle.observations}
    assert by_path["$[\"item\"]"].value == "object-key"
    assert by_path["$[\"item\"]"].position["kind"] == "key"
    assert by_path["$[\"arr\"][0]"].value == 10
    assert by_path["$[\"arr\"][0]"].position["kind"] == "index"
    assert isinstance(by_path["$[\"arr\"][0]"].path[-1], IndexSegment)


def test_duplicate_keys_are_addressed_by_physical_occurrence():
    bundle = _extract(selections=["dup.k#0", "dup.k#1"])
    first, second = bundle.observations
    assert first.value == "first"
    assert second.value == "second"
    assert first.position == {
        "kind": "key",
        "type": "object",
        "key": "k",
        "occurrence": 0,
        "order": 0,
    }
    assert second.position["occurrence"] == 1
    assert second.position["order"] == 1
    assert first.path == (KeySegment("dup"), KeySegment("k", 0))
    assert second.path == (KeySegment("dup"), KeySegment("k", 1))


def test_compact_and_canonical_path_syntax():
    path = parse_path("$[\"dup\"][\"k\"]#1")
    assert path == (KeySegment("dup"), KeySegment("k", 1))
    assert format_path(path) == "$[\"dup\"][\"k\"]#1"
    assert parse_path("arr[1]") == (KeySegment("arr"), IndexSegment(1))
    assert format_path(parse_path("arr[1]")) == "$[\"arr\"][1]"


def test_number_equivalence_is_reproducible():
    assert numbers_equal(1, Decimal("1.0"), "decimal")
    assert not numbers_equal(1, Decimal("1.0"), "exact")
    assert canonical_number(100, "decimal") == canonical_number(Decimal("1e2"), "decimal")

    decimal_bundle = _extract(selections=["numbers.a", "numbers.b"], numbers="decimal")
    exact_bundle = _extract(selections=["numbers.a", "numbers.b"], numbers="exact")
    assert decimal_bundle.observations[0].value_commitment == decimal_bundle.observations[1].value_commitment
    assert exact_bundle.observations[0].value_commitment != exact_bundle.observations[1].value_commitment
    assert decimal_bundle.root != exact_bundle.root


def test_root_ignores_number_lexeme_under_decimal_convention():
    first = b"{\"a\": 1}"
    second = b"{\"a\": 1.0}"
    first_bundle = _extract(first, selections=["a"], numbers="decimal")
    second_bundle = _extract(second, selections=["a"], numbers="decimal")
    assert first_bundle.root == second_bundle.root
    assert first_bundle.observations[0].value_commitment == second_bundle.observations[0].value_commitment

    exact_first = _extract(first, selections=["a"], numbers="exact")
    exact_second = _extract(second, selections=["a"], numbers="exact")
    assert exact_first.root != exact_second.root


def test_verify_uses_trusted_root_and_paths():
    selections = ["item", "arr[1]", "dup.k#0", "dup.k#1"]
    bundle = _extract(selections=selections)
    result = verify_evidence(
        SOURCE,
        bundle,
        root=bundle.root,
        selections=selections,
    )
    assert result.ok
    assert result == True


def test_verify_detects_tampered_path_commitment():
    selections = ["item", "arr[1]"]
    bundle = _extract(selections=selections)
    evidence = bundle.to_jsonable()
    evidence["observations"][1]["path"] = list(evidence["observations"][0]["path"])
    result = verify_evidence(
        SOURCE,
        evidence,
        root=bundle.root,
        selections=selections,
    )
    assert not result.ok
    assert "path_commitment" in result.violated_commitments
    assert "order_commitment" not in result.violated_commitments


def test_verify_detects_swapped_duplicate_positions():
    selections = ["dup.k#0", "dup.k#1"]
    bundle = _extract(selections=selections)
    evidence = bundle.to_jsonable()
    first, second = evidence["observations"]
    for field in ("position", "order_commitment", "sibling_prefix_commitment"):
        first[field], second[field] = second[field], first[field]
    result = verify_evidence(
        SOURCE,
        evidence,
        root=bundle.root,
        selections=selections,
    )
    assert not result.ok
    assert "order_commitment" in result.violated_commitments
    assert "path_commitment" not in result.violated_commitments
    assert "value_commitment" not in result.violated_commitments


def test_verify_detects_changed_source_through_root():
    bundle = _extract(selections=["item"])
    changed = SOURCE.replace(b"object-key", b"changed-key")
    result = verify_evidence(
        changed,
        bundle,
        root=bundle.root,
        selections=["item"],
    )
    assert not result.ok
    assert "root_commitment" in result.violated_commitments


def test_missing_path_can_be_required_or_reported():
    with pytest.raises(SelectionNotFound):
        _extract(selections=["missing"])
    bundle = _extract(selections=["missing"], require_all=False)
    assert not bundle.observations[0].found
    result = verify_evidence(
        SOURCE,
        bundle,
        root=bundle.root,
        selections=["missing"],
    )
    assert not result.ok
    assert "path_commitment" in result.violated_commitments


def test_container_values_and_duplicate_keys_survive_roundtrip():
    source = b"{\"obj\": {\"x\": 1, \"x\": 2}, \"arr\": [1, {\"y\": 3}]}"
    bundle = _extract(
        source,
        selections=["obj", "arr[1]"],
        numbers="decimal",
    )
    obj_wire = bundle.observations[0].wire_value
    assert obj_wire == {
        "type": "object",
        "items": [
            ["x", {"type": "number", "representation": "integer", "value": "1", "canonical": "dec:1E0", "equivalence": "decimal"}],
            ["x", {"type": "number", "representation": "integer", "value": "2", "canonical": "dec:2E0", "equivalence": "decimal"}],
        ],
    }

    reloaded = json.loads(bundle.to_json())
    result = verify_evidence(
        source,
        reloaded,
        root=bundle.root,
        selections=["obj", "arr[1]"],
    )
    assert result.ok


def test_no_json_loads_needed(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("json.loads must not be used to parse the source")

    monkeypatch.setattr(json, "loads", fail)
    bundle = _extract()
    assert bundle.root


def test_large_source_is_read_incrementally():
    class OneReadAtATime:
        def __init__(self, data):
            self.data = data
            self.position = 0
            self.reads = 0

        def read(self, size=-1):
            self.reads += 1
            chunk = self.data[self.position:self.position + size]
            self.position += len(chunk)
            return chunk

    source = OneReadAtATime(b"{\"a\": 1, \"b\": 2, \"c\": 3}")
    bundle = ijson.extract_evidence(source, ["a", "c"], buf_size=4)
    assert [observation.value for observation in bundle.observations] == [1, 3]
    assert source.reads > 1


def test_verify_detects_tampered_displayed_value_even_with_old_commitment():
    selections = ["item"]
    bundle = _extract(selections=selections)
    evidence = bundle.to_jsonable()
    evidence["observations"][0]["wire_value"]["value"] = "changed-key"
    result = verify_evidence(
        SOURCE,
        evidence,
        root=bundle.root,
        selections=selections,
    )
    assert not result.ok
    assert "value_commitment" in result.violated_commitments


def test_verify_requires_value_commitment():
    selections = ["item"]
    bundle = _extract(selections=selections)
    evidence = bundle.to_jsonable()
    del evidence["observations"][0]["value_commitment"]
    result = verify_evidence(
        SOURCE,
        evidence,
        root=bundle.root,
        selections=selections,
    )
    assert not result.ok
    assert "value_commitment" in result.violated_commitments


def test_verify_detects_reordered_observation_list():
    selections = ["dup.k#0", "dup.k#1"]
    bundle = _extract(selections=selections)
    evidence = bundle.to_jsonable()
    evidence["observations"][0], evidence["observations"][1] = (
        evidence["observations"][1],
        evidence["observations"][0],
    )
    result = verify_evidence(
        SOURCE,
        evidence,
        root=bundle.root,
        selections=selections,
    )
    assert not result.ok
    assert "order_commitment" in result.violated_commitments
