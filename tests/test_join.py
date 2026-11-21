"""Tests for ijson.join"""

import io

import pytest

import ijson


OLD = b'''
{
  "meta": {"id": "decoy"},
  "records": [
    {"id": "alpha", "secret": "old-alpha", "approval": "A-1", "meta": {"id": "nested-alpha"}},
    {"id": "beta",  "secret": "old-beta",  "approval": "A-2", "meta": {"id": "nested-beta"}},
    {"id": "gamma", "secret": "old-gamma", "approval": "A-3", "meta": {"id": "nested-gamma"}}
  ]
}
'''

NEW = b'''
{
  "meta": {"id": "decoy"},
  "records": [
    {"id": "gamma", "secret": "new-gamma", "approval": "A-3", "meta": {"id": "nested-gamma"}},
    {"id": "alpha", "secret": "new-alpha", "approval": "A-1", "meta": {"id": "nested-alpha"}},
    {"id": "delta", "secret": "new-delta", "approval": null,   "meta": {"id": "nested-delta"}}
  ]
}
'''


def _joined(backend, **kwargs):
    return list(backend.join(OLD, NEW, "records.item", keys="id", fields="approval", **kwargs))


def _by_key(rows):
    return {row["key"]: row for row in rows}


def test_reordered_records_match_by_business_key(backend):
    rows = _joined(backend)
    by_key = _by_key(rows)

    assert set(by_key) == {"alpha", "beta", "gamma", "delta"}
    assert by_key["alpha"]["status"] == "matched"
    assert by_key["alpha"]["resolved"] is True
    assert by_key["alpha"]["reason"] is None
    assert by_key["gamma"]["status"] == "matched"

    assert by_key["beta"]["status"] == "pending"
    assert by_key["beta"]["reason"] == "unmatched"
    assert by_key["beta"]["left"]["approval"] == "A-2"
    assert by_key["beta"]["right"] is None

    assert by_key["delta"]["status"] == "pending"
    assert by_key["delta"]["reason"] == "unmatched"
    assert by_key["delta"]["left"] is None
    assert by_key["delta"]["right"]["approval"] is None


def test_only_substantive_records_share_approval(backend):
    rows = _joined(backend)
    matched = [row for row in rows if row.matched]
    pending = [row for row in rows if row.pending]

    assert {row["key"] for row in matched} == {"alpha", "gamma"}
    for row in matched:
        assert row["left"]["approval"] == row["right"]["approval"]
    for row in pending:
        assert not (row["left"] and row["right"])


def test_secret_members_and_other_layers_are_not_retained(backend):
    rows = _joined(backend)
    rendered = repr(rows)

    assert "secret" not in rendered
    assert "old-alpha" not in rendered
    assert "new-alpha" not in rendered
    for row in rows:
        for side in ("left", "right"):
            if row[side] is not None:
                assert set(row[side]) <= {"id", "approval"}

    assert all(row["key"] != "decoy" for row in rows)
    assert all(row["key"] != "nested-alpha" for row in rows)


def test_parse_events_can_be_reused(backend):
    left_events = backend.parse(OLD)
    right_events = backend.parse(NEW)
    rows = list(backend.join(
        left_events, right_events, "records.item", keys="id", fields="approval"
    ))
    assert {row["key"] for row in rows if row.matched} == {"alpha", "gamma"}


def test_duplicate_keys_are_pending(backend):
    left = b'{"r": [{"id": "a", "approval": 1}, {"id": "a", "approval": 2}]}'
    right = b'{"r": [{"id": "a", "approval": 3}]}'
    rows = list(backend.join(left, right, "r.item", keys="id", fields="approval"))

    assert rows
    assert all(row["status"] == "pending" for row in rows)
    assert all(row["reason"] == "duplicate_key" for row in rows)
    assert all(row["key"] == "a" for row in rows)
    assert all(not (row["left"] and row["right"]) for row in rows)


def test_incomplete_keys_are_pending(backend):
    left = b'{"r": [{"id": "a"}, {"other": 1}, {"id": null}]}'
    right = b'{"r": [{"id": "a"}]}'
    rows = list(backend.join(left, right, "r.item", keys="id"))

    incomplete = [row for row in rows if row["reason"] == "incomplete_key"]
    assert len(incomplete) == 2
    assert all(row["key"] is None for row in incomplete)
    assert all(row["status"] == "pending" for row in incomplete)
    assert [row["left"] for row in incomplete] == [{}, {"id": None}]

    matched = [row for row in rows if row.matched]
    assert len(matched) == 1
    assert matched[0]["key"] == "a"


def test_composite_keys(backend):
    left = (
        b'{"r": [{"tenant": "t1", "id": 1, "approval": true}, '
        b'{"tenant": "t2", "id": 1, "approval": false}]}'
    )
    right = (
        b'{"r": [{"tenant": "t2", "id": 1, "approval": false}, '
        b'{"tenant": "t1", "id": 1, "approval": true}]}'
    )
    rows = list(backend.join(left, right, "r.item", keys=("tenant", "id"), fields="approval"))

    assert [row["key"] for row in rows] == [("t1", 1), ("t2", 1)]
    assert all(row["status"] == "matched" for row in rows)


def test_nested_declared_key(backend):
    left = b'{"r": [{"id": "outer", "key": {"id": "inner"}, "approval": 1}]}'
    right = b'{"r": [{"id": "decoy", "key": {"id": "inner"}, "approval": 1}]}'
    rows = list(backend.join(left, right, "r.item", keys="key.id", fields="approval"))

    assert len(rows) == 1
    assert rows[0]["status"] == "matched"
    assert rows[0]["left"] == {"key": {"id": "inner"}, "approval": 1}
    assert rows[0]["right"] == {"key": {"id": "inner"}, "approval": 1}


def test_join_requires_key(backend):
    with pytest.raises(ValueError):
        list(backend.join(b'{}', b'{}', "", keys=()))


def test_top_level_join():
    rows = list(ijson.join(
        io.BytesIO(OLD), io.BytesIO(NEW), "records.item", keys="id", fields="approval"
    ))
    assert {row["key"] for row in rows if row.matched} == {"alpha", "gamma"}
