import hashlib
import io
import json
import struct
from pathlib import Path

from Registry import GenerationalDiff as gd
from Registry import Registry

from synthetic_hives import T_NEW
from synthetic_hives import T_OLD
from synthetic_hives import KeySpec
from synthetic_hives import SyntheticHive
from synthetic_hives import dword_value


def hive_bytes(root):
    return SyntheticHive().build(root)


def compare_trees(old_root, new_root):
    return gd.compare_hives(
        io.BytesIO(hive_bytes(old_root)),
        io.BytesIO(hive_bytes(new_root)),
    )


def control_tree(target):
    return KeySpec("Root", children=[
        KeySpec("Control", offset=0x100, children=[target]),
    ])


def target(name="Target", value=0x11111111, ticks=T_OLD, rel=0x200):
    return KeySpec(
        name,
        offset=rel,
        timestamp=ticks,
        values=[dword_value("Counter", value)],
    )


def one_change(diff, path):
    matches = diff.changes_for_path(path)
    assert len(matches) == 1
    return matches[0]


def test_normal_value_update_is_modified_with_raw_byte_evidence():
    old_root = control_tree(target(value=0x11111111))
    new_root = control_tree(target(value=0x22222222, ticks=T_NEW))

    diff = compare_trees(old_root, new_root)
    change = one_change(diff, r"Control\Target")

    assert change.kind == gd.MODIFIED
    assert not change.ambiguous
    assert change.old_key.nk_offset == change.new_key.nk_offset
    assert change.old_key.parent_offset == change.new_key.parent_offset

    data_evidence = [
        item for item in change.evidence if item.kind == "value_data"
    ]
    assert len(data_evidence) == 1
    evidence = data_evidence[0]
    assert evidence.old_bytes == struct.pack("<I", 0x11111111)
    assert evidence.new_bytes == struct.pack("<I", 0x22222222)
    assert evidence.old_offset == evidence.new_offset
    assert evidence.old_offset == change.old_key.values[0].data_offset
    assert evidence.new_offset == change.new_key.values[0].data_offset
    assert evidence.old_hex and evidence.new_hex

    assert len(diff.modified) == 1
    assert diff.rebuild_candidates == []
    assert diff.indeterminate == []
    json.dumps(diff.to_dict())


def test_timestamp_only_change_is_not_identity_replacement_event():
    old_root = control_tree(target(ticks=T_OLD))
    new_root = control_tree(target(ticks=T_NEW))

    diff = compare_trees(old_root, new_root)
    change = one_change(diff, r"Control\Target")

    assert change.kind == gd.TIMESTAMP_ONLY
    assert not change.ambiguous
    assert change.old_key.nk_offset == change.new_key.nk_offset
    timestamp_evidence = [
        item for item in change.evidence if item.kind == "nk_timestamp"
    ]
    assert len(timestamp_evidence) == 1
    assert timestamp_evidence[0].old_bytes == struct.pack("<Q", T_OLD)
    assert timestamp_evidence[0].new_bytes == struct.pack("<Q", T_NEW)
    assert not [
        item for item in change.evidence if item.kind == "value_data"
    ]

    assert diff.modified == []
    assert diff.rebuild_candidates == []
    assert diff.indeterminate == []
    assert len(diff.timestamp_only) == 1


def test_same_path_rebuild_at_new_offset_is_rebuild_candidate():
    old_root = control_tree(target(rel=0x200, ticks=T_OLD))
    new_root = control_tree(target(rel=0x280, ticks=T_NEW))

    diff = compare_trees(old_root, new_root)
    change = one_change(diff, r"Control\Target")

    assert change.kind == gd.REBUILD_CANDIDATE
    assert not change.ambiguous
    assert change.old_key.nk_offset != change.new_key.nk_offset
    candidate = change.candidates[0]
    assert candidate.relation == gd.REBUILD_CANDIDATE
    assert "same_path" in candidate.support
    assert "same_path_different_offset" in candidate.conflicts
    assert any(item.kind == "nk_record" for item in change.evidence)

    assert len(diff.rebuild_candidates) == 1
    assert diff.modified == []
    assert diff.indeterminate == []


def test_same_offset_reuse_with_different_identity_is_indeterminate():
    old_root = control_tree(
        target(name="Alpha", value=0xAAAAAAAA, rel=0x200))
    new_root = control_tree(
        target(name="Beta", value=0xBBBBBBBB, rel=0x200))

    diff = compare_trees(old_root, new_root)
    change = one_change(diff, r"Control\Alpha")

    assert change.kind == gd.INDETERMINATE
    candidate = change.candidates[0]
    assert candidate.old_key.nk_offset == candidate.new_key.nk_offset
    assert candidate.new_path == r"\control\beta"
    assert "same_nk_offset" in candidate.support
    assert "same_offset_different_path" in candidate.conflicts
    assert "same_offset_different_name" in candidate.conflicts

    path_kinds = [item.kind for item in diff.path_changes]
    assert gd.ADDED in path_kinds
    assert gd.REMOVED in path_kinds
    assert diff.modified == []
    assert diff.rebuild_candidates == []
    assert len(diff.indeterminate) == 1


def test_migration_uses_offset_name_and_content_together():
    old_root = KeySpec("Root", children=[
        KeySpec("Control", offset=0x100, children=[target(rel=0x200)]),
    ])
    new_root = KeySpec("Root", children=[
        KeySpec("Control", offset=0x100),
        KeySpec("Destination", offset=0x180, children=[target(rel=0x200)]),
    ])

    diff = compare_trees(old_root, new_root)
    change = one_change(diff, r"Control\Target")

    assert change.kind == gd.MIGRATED
    assert change.old_path == r"\control\target"
    assert change.new_path == r"\destination\target"
    assert change.old_key.nk_offset == change.new_key.nk_offset
    candidate = change.candidates[0]
    assert "same_nk_offset" in candidate.support
    assert "same_name" in candidate.support
    assert "same_content_fingerprint" in candidate.support
    assert len(diff.migrations) == 1
    json.dumps(diff.to_dict())


def test_equal_candidates_are_all_retained_as_ambiguous():
    shared = lambda rel: KeySpec(
        "Shared",
        offset=rel,
        timestamp=T_OLD,
        values=[dword_value("Token", 0x42424242)],
    )
    old_root = KeySpec("Root", children=[
        KeySpec("OldBranch", offset=0x100, children=[shared(0x300)]),
    ])
    new_root = KeySpec("Root", children=[
        KeySpec("BranchA", offset=0x180, children=[shared(0x380)]),
        KeySpec("BranchB", offset=0x200, children=[shared(0x400)]),
    ])

    diff = compare_trees(old_root, new_root)
    change = one_change(diff, r"OldBranch\Shared")

    assert change.kind == gd.INDETERMINATE
    assert change.ambiguous
    assert change.equal_candidates
    assert change.new_key is None
    assert len(change.candidates) == 2
    assert [item.new_path for item in change.candidates] == [
        r"\brancha\shared",
        r"\branchb\shared",
    ]
    scores = {item.score for item in change.candidates}
    assert len(scores) == 1
    assert change.candidates[0].peer_ids == [change.candidates[1].id]
    assert change.candidates[1].peer_ids == [change.candidates[0].id]
    assert any(event.ambiguous for event in diff.ambiguous)
    json.dumps(diff.to_dict())


def test_default_browsing_remains_available_on_synthetic_hive():
    data = hive_bytes(control_tree(target(value=0x12345678)))
    registry = Registry.Registry(io.BytesIO(data))

    key = registry.open(r"Control\Target")
    assert key.name() == "Target"
    assert key.value("Counter").value() == 0x12345678
    assert key.timestamp() is not None


def _sha256_path(path):
    digest = hashlib.sha256()
    with open(str(path), "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def test_file_inputs_are_read_only_and_keep_hashes(tmp_path):
    old_path = tmp_path / "old-synthetic.hive"
    new_path = tmp_path / "new-synthetic.hive"
    old_path.write_bytes(hive_bytes(control_tree(target())))
    new_path.write_bytes(hive_bytes(control_tree(
        target(value=0x22222222, ticks=T_NEW))))

    old_hash_before = _sha256_path(old_path)
    new_hash_before = _sha256_path(new_path)

    result = gd.compare_hives(str(old_path), str(new_path))
    assert result.modified

    assert _sha256_path(old_path) == old_hash_before
    assert _sha256_path(new_path) == new_hash_before

    sample = Path(__file__).resolve().parent / "reg_samples" / "issue22.hive"
    sample_hash_before = _sha256_path(sample)
    gd.compare_hives(str(sample), str(sample))
    assert _sha256_path(sample) == sample_hash_before


def test_timestamp_alone_does_not_create_candidate():
    old_root = control_tree(KeySpec(
        "Alpha", offset=0x200, timestamp=T_OLD,
        values=[dword_value("OldValue", 1)]))
    new_root = control_tree(KeySpec(
        "Beta", offset=0x280, timestamp=T_OLD,
        values=[dword_value("NewValue", 2)]))

    diff = compare_trees(old_root, new_root)
    old_change = one_change(diff, r"Control\Alpha")
    new_change = one_change(diff, r"Control\Beta")

    assert old_change.kind == gd.REMOVED
    assert old_change.candidates == []
    assert new_change.kind == gd.ADDED
    assert new_change.candidates == []
    assert [
        candidate for candidate in diff.candidates
        if candidate.old_path == r"\control\alpha"
    ] == []
    assert [
        candidate for candidate in diff.candidates
        if candidate.new_path == r"\control\beta"
    ] == []


def test_object_facade_and_serializable_candidate_aliases():
    old_root = control_tree(target(value=0x11111111))
    new_root = control_tree(target(value=0x22222222, ticks=T_NEW))
    result = gd.GenerationalDiff.compare(
        io.BytesIO(hive_bytes(old_root)),
        io.BytesIO(hive_bytes(new_root)),
    )

    assert isinstance(result, gd.HiveDiff)
    assert result.correspondences is result.candidates
    assert result.matches is result.candidates
    payload = json.dumps(result.to_dict())
    assert "value_data" in payload
