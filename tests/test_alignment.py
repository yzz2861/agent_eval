from pathlib import Path

from Evtx.Evtx import Evtx
from Evtx.alignment import (
    EvidenceAligner,
    HandoffMarker,
    align_evidence,
    align_evtx,
    align_files,
    ambiguous_local_instants,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_DIR = REPO_ROOT / "examples" / "evidence_alignment"
ISSUE_38 = REPO_ROOT / "tests" / "data" / "issue_38.evtx"


def test_record_numbers_and_file_order_give_single_chain():
    result = align_evidence(
        [
            {"id": "a", "record_number": 10},
            {"id": "b", "record_number": 11},
            {"id": "c", "record_number": 12},
        ]
    )
    assert result.possible_orders == [["a", "b", "c"]]
    assert result.original_order == ["a", "b", "c"]


def test_two_candidate_handoff_positions():
    records = [
        {"id": "a", "record_number": 10, "file_order": 0},
        {"id": "b", "record_number": 11, "file_order": 1},
        {"id": "c", "record_number": 12, "file_order": 2},
        {"id": "d", "record_number": 13, "file_order": 3},
    ]
    handoff = HandoffMarker(
        id="h",
        before_shift="old-shift",
        after_shift="new-shift",
        candidate_anchors=[
            {"name": "early", "after": ["b"], "before": ["c"]},
            {"name": "late", "after": ["c"], "before": ["d"]},
        ],
    )
    result = align_evidence(records, [handoff])
    assert [list(order) for order in result.possible_orders] == [
        ["a", "b", "h", "c", "d"],
        ["a", "b", "c", "h", "d"],
    ]
    assert result.definitely_before_handoff == ["a", "b"]
    assert result.ambiguous_handoff == ["c"]
    assert result.definitely_after_handoff == ["d"]
    assert result.shift_assignments["c"] == {"old-shift", "new-shift"}


def test_signed_marker_keyword_alias():
    result = EvidenceAligner(
        record_numbers={"a": 1, "b": 2},
        file_order=["a", "b"],
        signed_markers=[{"id": "h", "handoff": True, "after": ["b"]}],
    ).align()
    assert result.handoff == "h"
    assert result.possible_orders == [["a", "b", "h"]]
    assert result.definitely_before_handoff == ["a", "b"]


def test_contradictory_record_number_keeps_original_position():
    result = align_evidence(
        [
            {"id": "a", "record_number": 2},
            {"id": "b", "record_number": 1},
        ]
    )
    assert result.original_order == ["a", "b"]
    assert len(result.conflicts) == 1
    assert result.conflicts[0].edge == ("b", "a")
    assert result.possible_orders == [["a", "b"]]
    assert result.classification["a"] == "conflicting-preserved-original-position"
    assert result.classification["b"] == "conflicting-preserved-original-position"


def test_contradicted_handoff_classification_still_preserves_position():
    aligner = EvidenceAligner()
    aligner.add_evidence(
        [
            {"id": "a", "record_number": 1, "file_order": 0},
            {"id": "x", "record_number": 99, "file_order": 1},
            {"id": "b", "record_number": 2, "file_order": 2},
        ]
    )
    aligner.add_signed_shift_marker(
        {
            "id": "h",
            "handoff": True,
            "candidate_anchors": [{"after": ["b"]}],
        }
    )
    result = aligner.align()
    assert result.possible_orders == [["a", "x", "b", "h"]]
    assert result.original_order[:3] == ["a", "x", "b"]
    assert result.conflicts[0].edge == ("b", "x")
    assert "x" in result.preserved_before_handoff
    assert "x" in result.definitely_before_handoff
    assert "x" not in result.uncontested_before_handoff


def test_small_example_files_show_expected_shift_split():
    result = align_files(EXAMPLE_DIR)
    assert len(result.possible_orders) == 2
    assert result.possible_orders[0].label == "fold-0/EDT"
    assert result.possible_orders[1].label == "fold-1/EST"
    assert result.possible_orders[0] == [
        "door-01",
        "backup",
        "printer",
        "door-02",
        "signed-handoff",
        "batch",
        "usb",
        "stop",
    ]
    assert result.possible_orders[1] == [
        "door-01",
        "backup",
        "printer",
        "door-02",
        "batch",
        "usb",
        "signed-handoff",
        "stop",
    ]
    assert result.uncontested_before_handoff == ["door-01", "backup", "door-02"]
    assert result.definitely_before_handoff == ["door-01", "backup", "printer", "door-02"]
    assert result.ambiguous_handoff == ["batch", "usb"]
    assert result.definitely_after_handoff == ["stop"]
    assert result.shift_assignments["batch"] == {"night-shift", "day-shift"}
    assert result.shift_assignments["usb"] == {"night-shift", "day-shift"}
    source_order = result.file_order["night-log.partial.evtx"]
    assert source_order == ["door-01", "backup", "printer", "door-02", "batch", "usb", "stop"]
    assert result.conflicts[0].edge == ("stop", "printer")
    assert result.classification["printer"] == "conflicting-preserved-before-handoff"


def test_align_real_single_record_evtx():
    result = align_evtx(ISSUE_38)
    assert len(result.evidence) == 1
    assert result.evidence[0].record_number == 1
    assert result.possible_orders[0][0].endswith("#1")


def test_evtx_object_has_alignment_method():
    with Evtx(str(ISSUE_38)) as log:
        result = log.align_evidence()
    assert len(result.evidence) == 1
    assert result.evidence[0].record_number == 1


def test_ambiguous_local_instants_offsets():
    instants = ambiguous_local_instants("2026-11-01T01:40:00", utc_offsets=(-4, -5))
    assert [item.hour for item in instants] == [5, 6]


def test_result_dictionary_contains_core_views():
    result = align_evidence({"a": 1, "b": 2}, file_order=["a", "b"])
    payload = result.to_dict()
    assert payload["possible_orders"] == [["a", "b"]]
    assert payload["original_order"] == ["a", "b"]
    assert "classification" in payload
