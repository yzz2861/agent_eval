"""Tests for the read-only page-correspondence audit demo package."""

import pytest

from page_audit import auditor
from page_audit.generator import generate


@pytest.fixture(scope="module")
def audit_result(tmp_path_factory):
    fixture_dir = tmp_path_factory.mktemp("fixtures")
    original_path, rearranged_path = generate(fixture_dir)
    original_bytes = original_path.read_bytes()
    rearranged_bytes = rearranged_path.read_bytes()
    original, rearranged, findings = auditor.audit(
        original_path, rearranged_path
    )
    return {
        "original_path": original_path,
        "rearranged_path": rearranged_path,
        "original_bytes": original_bytes,
        "rearranged_bytes": rearranged_bytes,
        "original": original,
        "rearranged": rearranged,
        "findings": findings,
    }


def _by_conclusion(findings, conclusion):
    return [item for item in findings if item.conclusion == conclusion]


def test_fixture_page_counts(audit_result):
    assert len(audit_result["original"]) == 9
    assert len(audit_result["rearranged"]) == 8


def test_all_conclusion_types_present(audit_result):
    findings = audit_result["findings"]
    seen = {item.conclusion for item in findings}
    assert seen == {
        auditor.MOVED_PAGE,
        auditor.MERGED_PAGE,
        auditor.SPLIT_PAGE,
        auditor.SAME_CONTENT_CONFLICT,
        auditor.MISSING_PAGE,
    }


def test_moved_pages(audit_result):
    moved = _by_conclusion(audit_result["findings"], auditor.MOVED_PAGE)
    pairs = {(item.source_indices[0], item.target_index) for item in moved}
    assert pairs == {(3, 0), (0, 1)}  # O4->R1, O1->R2 (zero-based)


def test_merged_page_has_two_sources_and_both_resources(audit_result):
    merged = _by_conclusion(audit_result["findings"], auditor.MERGED_PAGE)
    assert len(merged) == 2
    r3 = next(item for item in merged if item.target_index == 2)
    assert r3.source_indices == (1, 2)  # O2 + O3
    resource_evidence = next(
        item for item in r3.evidence if item.kind == "resource"
    )
    assert "e6bba48634a1" in resource_evidence.detail
    assert "0fa1588da731" in resource_evidence.detail


def test_split_page_pair_shares_one_source_and_is_cropped(audit_result):
    split = _by_conclusion(audit_result["findings"], auditor.SPLIT_PAGE)
    assert len(split) == 2
    assert {item.target_index for item in split} == {3, 4}
    assert {item.source_indices for item in split} == {(4,)}
    structure = {item.target_index: item.evidence[0].detail for item in split}
    assert "220.0" in structure[3]
    assert structure[4].startswith("CropBox [0.0, 0.0, 320.0, 220.0]")


def test_same_content_conflict_duplicates(audit_result):
    conflict = _by_conclusion(
        audit_result["findings"], auditor.SAME_CONTENT_CONFLICT
    )
    assert len(conflict) == 2
    assert {item.target_index for item in conflict} == {6, 7}
    assert {item.source_indices[0] for item in conflict} == {6}


def test_missing_page_is_o9(audit_result):
    missing = _by_conclusion(audit_result["findings"], auditor.MISSING_PAGE)
    assert len(missing) == 1
    assert missing[0].source_indices == (8,)
    assert missing[0].target_index is None
    assert "无对应页" in missing[0].rearranged_ref


def test_every_finding_has_double_sided_references(audit_result):
    for finding in audit_result["findings"]:
        assert "原件 p" in finding.original_ref
        assert "重排" in finding.rearranged_ref
        kinds = {item.kind for item in finding.evidence}
        assert kinds == {"structure", "resource", "content"}


def test_cross_file_match_uses_content_hash_not_object_number(audit_result):
    moved = _by_conclusion(audit_result["findings"], auditor.MOVED_PAGE)[0]
    original = audit_result["original"][moved.source_indices[0]]
    target = audit_result["rearranged"][moved.target_index]
    assert original.content_hash == target.content_hash
    assert original.object_refs["page"] != target.object_refs["page"]


def test_audit_is_read_only(audit_result):
    assert audit_result["original_path"].read_bytes() == audit_result["original_bytes"]
    assert audit_result["rearranged_path"].read_bytes() == audit_result["rearranged_bytes"]
