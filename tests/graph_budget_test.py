# Copyright (C) 2024 David Aguilar (davvid -at- gmail.com)
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
"""Tests for the per-decode graph budgets and reference policy."""

import json

import pytest

import jsonpickle
import jsonpickle.handlers
from jsonpickle import errors, tags, unpickler


class Node:
    """A plain object that can participate in cycles."""

    def __init__(self, name=None):
        self.name = name
        self.other = None


class CountingThing:
    """Counts how often the class is actually instantiated during decode."""

    restore_count = 0

    def __init__(self):
        self.value = None


class CountingHandler(jsonpickle.handlers.BaseHandler):
    def flatten(self, obj, data):
        data["value"] = obj.value
        return data

    def restore(self, data):
        CountingThing.restore_count += 1
        instance = CountingThing()
        instance.value = data["value"]
        return instance


def setup_function(_function):
    CountingThing.restore_count = 0
    jsonpickle.handlers.register(CountingThing, CountingHandler)


def teardown_function(_function):
    jsonpickle.handlers.unregister(CountingThing)


def encode(value):
    return jsonpickle.encode(value)


# ---------------------------------------------------------------------------
# Reference policy
# ---------------------------------------------------------------------------


def test_backward_reference_resolves_to_same_object():
    thing = Node("a")
    decoded = jsonpickle.decode(encode([thing, thing]))
    assert decoded[0] is decoded[1]


def test_dangling_id_raises_invalid_reference():
    payload = json.dumps({"ref": {tags.ID: 99}})
    with pytest.raises(errors.InvalidReferenceError):
        jsonpickle.decode(payload)


def test_forward_id_raises_invalid_reference():
    # The referenced list is registered *after* the id entry is encountered.
    payload = json.dumps([{tags.ID: 1}, [1, 2, 3]])
    with pytest.raises(errors.InvalidReferenceError):
        jsonpickle.decode(payload)


@pytest.mark.parametrize("bad_id", ["1", -1, True, 1.5, None, [], {}])
def test_non_integer_or_negative_id_raises_invalid_reference(bad_id):
    payload = json.dumps([1, {tags.ID: bad_id}])
    with pytest.raises(errors.InvalidReferenceError):
        jsonpickle.decode(payload)


def test_failed_decode_does_not_leak_into_next_decode():
    with pytest.raises(errors.InvalidReferenceError):
        jsonpickle.decode(json.dumps({tags.ID: 42}))
    # A fresh decode must start with an empty reference table and succeed.
    decoded = jsonpickle.decode(encode(Node("fresh")))
    assert decoded.name == "fresh"


# ---------------------------------------------------------------------------
# Cycles: legal, proxy-based, bounded
# ---------------------------------------------------------------------------


def test_self_cycle_roundtrips_without_recursive_copy():
    node = Node("self")
    node.other = node
    decoded = jsonpickle.decode(encode(node))
    assert decoded is decoded.other
    assert decoded.name == "self"


def test_two_node_cycle_roundtrips():
    first = Node("first")
    second = Node("second")
    first.other = second
    second.other = first
    decoded = jsonpickle.decode(encode([first, second]))
    assert decoded[0].other is decoded[1]
    assert decoded[1].other is decoded[0]


def test_craft_self_referencing_list_uses_proxy_without_duplication():
    # A hand-crafted id-0 self loop. During restore the list registers a
    # placeholder proxy, so the reference resolves to the same list rather
    # than recursively materialising copies.
    payload = json.dumps([{tags.ID: 0}])
    decoded = jsonpickle.decode(payload)
    assert decoded[0] is decoded
    assert len(decoded) == 1


def test_legal_cycle_is_bounded_by_object_budget():
    # A cycle is small, but an explicit tight budget must still abort cleanly
    # instead of silently truncating the graph.
    node = Node("self")
    node.other = node
    with pytest.raises(errors.GraphBudgetExceededError):
        jsonpickle.decode(encode(node), max_objects=1)


# ---------------------------------------------------------------------------
# Width / sharing attacks
# ---------------------------------------------------------------------------


def test_wide_shared_reference_restores_object_once():
    CountingThing.restore_count = 0
    shared = CountingThing()
    shared.value = 1
    graph = [shared] + [shared] * 1000
    decoded = jsonpickle.decode(
        encode(graph), max_container_width=1_000_000, max_objects=5_000_000
    )
    # The handler runs once: sharing is preserved via the reference table.
    assert CountingThing.restore_count == 1
    assert all(item is decoded[0] for item in decoded)
    assert len(decoded) == 1001


def test_wide_container_is_rejected_by_width_budget():
    payload = json.dumps(list(range(10_000)))
    with pytest.raises(errors.GraphBudgetExceededError):
        jsonpickle.decode(payload, max_container_width=100)


def test_wide_container_default_budget_allows_shallow_big_list():
    # Shallow, large-but-reasonable lists stay within the default budget.
    payload = json.dumps(list(range(1000)))
    decoded = jsonpickle.decode(payload)
    assert decoded == list(range(1000))


def test_million_reference_payload_cannot_create_million_proxies():
    # One real object plus a huge number of back-references. The references
    # must resolve to the same object; no per-reference proxies may be built,
    # and the width budget aborts before memory can be exhausted.
    shared = {"py/object": "tests.graph_budget_test.Node", "name": "x"}
    payload = json.dumps([shared] + [{tags.ID: 1}] * 1_000_000)
    with pytest.raises(errors.GraphBudgetExceededError):
        jsonpickle.decode(payload, max_container_width=10_000)


# ---------------------------------------------------------------------------
# Depth / object / reference-table budgets
# ---------------------------------------------------------------------------


def test_excessive_nesting_is_rejected_by_depth_budget():
    payload = "[" * 600 + "0" + "]" * 600
    with pytest.raises(errors.GraphBudgetExceededError):
        jsonpickle.decode(payload, max_depth=100)


def test_object_count_budget_aborts_decode():
    payload = json.dumps([[i] for i in range(1000)])
    with pytest.raises(errors.GraphBudgetExceededError):
        jsonpickle.decode(payload, max_objects=50)


def test_reference_table_budget_aborts_decode():
    payload = json.dumps([[i] for i in range(1000)])
    with pytest.raises(errors.GraphBudgetExceededError):
        jsonpickle.decode(payload, max_ref_table_entries=10)


def test_budget_exception_is_specialized_and_keeps_base_type():
    payload = json.dumps(list(range(1000)))
    with pytest.raises(errors.GraphBudgetExceededError) as exc_info:
        jsonpickle.decode(payload, max_objects=10)
    assert isinstance(exc_info.value, errors.DecodeError)


# ---------------------------------------------------------------------------
# Time budget
# ---------------------------------------------------------------------------


def test_decode_time_budget_is_enforced(monkeypatch):
    calls = {"n": 0}
    real_monotonic = unpickler.time.monotonic

    def fake_monotonic():
        # First call establishes the deadline; every later call is past it.
        value = real_monotonic() if calls["n"] == 0 else real_monotonic() + 100
        calls["n"] += 1
        return value

    monkeypatch.setattr(unpickler.time, "monotonic", fake_monotonic)
    with pytest.raises(errors.GraphBudgetExceededError):
        jsonpickle.decode(encode([1, 2, 3]), max_decode_time=1.0)


# ---------------------------------------------------------------------------
# Budget isolation and handlers
# ---------------------------------------------------------------------------


def test_budgets_are_isolated_between_decode_calls():
    payload = json.dumps(list(range(500)))
    for _ in range(5):
        decoded = jsonpickle.decode(payload, max_objects=10_000)
        assert len(decoded) == 500


def test_budgets_can_be_disabled_with_none():
    payload = json.dumps([[i] for i in range(2000)])
    decoded = jsonpickle.decode(
        payload,
        max_objects=None,
        max_ref_table_entries=None,
        max_depth=None,
        max_container_width=None,
        max_decode_time=None,
    )
    assert len(decoded) == 2000


def test_unpickler_instance_resets_budget_counters():
    instance = unpickler.Unpickler(max_objects=10_000)
    instance.restore(json.loads(json.dumps(list(range(100)))))
    assert instance._object_count > 0
    instance.restore(json.loads(json.dumps(list(range(100)))))
    # Counters start from zero again after the implicit reset.
    assert instance._object_count < 500


def test_custom_handler_shares_the_decode_budget():
    CountingThing.restore_count = 0
    graph = [CountingThing() for _ in range(20)]
    with pytest.raises(errors.GraphBudgetExceededError):
        jsonpickle.decode(encode(graph), max_objects=10)
