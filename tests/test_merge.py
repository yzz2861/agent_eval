"""
Tests for the offline, reviewable EVTX merge layer (Evtx.Merge).

The three synthetic collections are rebuilt from tests/data/security.evtx at
test time by tests/make_merge_fixtures.py, so no binary fixtures are tracked.
"""
import os

import pytest

import Evtx.Merge as merge_mod
from make_merge_fixtures import build_fixtures


@pytest.fixture(scope="module")
def fixtures(tmp_path_factory):
    data_dir = os.path.join(os.path.dirname(__file__), "data", "security.evtx")
    out_dir = tmp_path_factory.mktemp("merge_fixtures")
    return build_fixtures(data_dir, str(out_dir))


@pytest.fixture(scope="module")
def merged(fixtures):
    specs = [
        merge_mod.SourceSpec(fixtures["A_full"], "A", "full export"),
        merge_mod.SourceSpec(fixtures["B_overlap"], "B", "earlier overlapping window"),
        merge_mod.SourceSpec(fixtures["C_cleared"], "C", "crossed a log clear, corrupt tail"),
    ]
    return merge_mod.merge_sources(specs)


def test_physical_copies_are_conserved(merged, fixtures):
    # every physical record survives the merge exactly once in occurrences
    total_copies = sum(event.copy_count for event in merged.events)
    expected = 2261 + 1239 + (2261 - 60)
    assert total_copies == expected


def test_overlapping_windows_dedup_by_content_not_count(merged):
    # the 1239 records shared by A and B collapse to one event each
    duplicates = [e for e in merged.events if e.is_duplicate()]
    assert len(duplicates) == 1239
    sample = next(e for e in duplicates if e.record_num == 1 and e.global_era == 0)
    sources = sorted(o.source_id for o in sample.occurrences)
    assert sources == ["A", "B", "C"]
    fingerprints = {o.sha256 for o in sample.occurrences}
    assert len(fingerprints) == 1
    assert sample.duplicate_basis.startswith("identical sha256")
    # provenance keeps the original file, chunk and record offsets
    occ = sample.occurrences[0]
    assert occ.chunk_offset is not None and occ.record_offset is not None
    assert occ.chunk_offset % 0x10000 == 0x1000


def test_log_clear_same_number_records_kept_side_by_side(merged):
    # post-clear records reuse low numbers but must not overwrite pre-clear ones
    assert len(merged.same_number_pairs) == 962
    pair = next(p for p in merged.same_number_pairs if p["record_num"] == 1)
    assert pair["classification"] == merge_mod.REUSE_CLEAR
    assert pair["global_eras"] == [0, 1]
    by_era = {event["global_era"]: event for event in pair["events"]}
    assert by_era[0]["sha256"] != by_era[1]["sha256"]


def test_era_boundary_is_classified_as_clear_not_wraparound(merged):
    assert len(merged.boundaries) == 1
    boundary = merged.boundaries[0]
    assert boundary.source_id == "C"
    assert boundary.reason == merge_mod.BOUNDARY_LOG_CLEAR
    assert boundary.next_record_num == 1
    assert boundary.next_timestamp > boundary.previous_timestamp


def test_corrupt_tail_chunk_keeps_coverage_unknown(fixtures):
    scanned = merge_mod.scan_source(merge_mod.SourceSpec(fixtures["C_cleared"], "C"))
    tail = scanned.chunk_coverage[25]
    assert tail.coverage_known is False
    assert tail.records_read == 0
    assert tail.claimed_log_first == 963
    assert tail.claimed_log_last == 1022
    assert tail.error is not None
    assert all(c.coverage_known for c in scanned.chunk_coverage[:25])
    assert len(scanned.provenance) == 2201


def test_truncated_export_reports_coverage_note_not_parse_error(fixtures):
    scanned = merge_mod.scan_source(merge_mod.SourceSpec(fixtures["B_overlap"], "B"))
    assert scanned.parse_errors == []
    assert len(scanned.truncation_notes) == 1
    assert len(scanned.provenance) == 1239


def test_descending_timestamp_order_tolerates_out_of_order(merged):
    ordered = merge_mod.sort_events(merged.events, order="desc")
    stamps = [e.timestamp for e in ordered if e.timestamp]
    assert stamps == sorted(stamps, reverse=True)
    ascending = merge_mod.sort_events(merged.events, order="asc")
    assert [e.sha256 for e in ascending] != [e.sha256 for e in ordered]


def test_boundary_classification_distinguishes_three_cases():
    reason, _ = merge_mod._classify_boundary(1200, 5, "2016-07-09T00:00:00+00:00", "2016-07-08T00:00:00+00:00")
    assert reason == merge_mod.BOUNDARY_CIRCULAR_WRAP
    reason, _ = merge_mod._classify_boundary(2261, 1, "2016-07-29T00:00:00+00:00", "2016-08-15T00:00:00+00:00")
    assert reason == merge_mod.BOUNDARY_LOG_CLEAR
    reason, _ = merge_mod._classify_boundary(
        merge_mod.UINT64_READ_LIMIT, 1, "2016-07-29T00:00:00+00:00", "2016-07-30T00:00:00+00:00"
    )
    assert reason == merge_mod.BOUNDARY_COUNTER_WRAPAROUND


def test_malformed_real_world_files_do_not_crash(data_path):
    for name in ("dns_log_malformed.evtx", "issue_38.evtx"):
        scanned = merge_mod.scan_source(merge_mod.SourceSpec(os.path.join(data_path, name), name))
        assert len(scanned.provenance) >= 1
        assert len(scanned.file_sha256) == 64


def test_report_and_jsonl_are_written(merged, tmp_path):
    import json
    report = tmp_path / "report.json"
    jsonl = tmp_path / "events.jsonl"
    merge_mod.write_report(merged, str(report))
    merge_mod.write_jsonl(merged, str(jsonl))
    payload = json.loads(report.read_text())
    assert payload["event_count"] == len(merged.events)
    assert payload["same_number_reuse_count"] == 962
    lines = [line for line in jsonl.read_text().splitlines() if line]
    assert len(lines) == len(merged.events)
    first = json.loads(lines[0])
    assert "occurrences" in first and "sha256" in first
