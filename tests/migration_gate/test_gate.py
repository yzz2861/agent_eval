import pathlib

import pytest
import yaml

from migration_gate import run_gate
from migration_gate.gate import VERDICT_FAIL, VERDICT_PASS, VERDICT_REVIEW

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def read_fixture(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


def findings_of_kind(report, kind):
    return [finding for finding in report.findings if finding.kind == kind]


def test_anchor_rename_only_passes():
    report = run_gate(
        read_fixture("anchor_rename_before.yaml"),
        read_fixture("anchor_rename_after.yaml"),
        ["service"],
    )
    assert report.verdict == VERDICT_PASS
    assert report.findings == []


def test_sharing_change_fails_and_locates_both_paths():
    report = run_gate(
        read_fixture("sharing_change_before.yaml"),
        read_fixture("sharing_change_after.yaml"),
        ["app.database"],
    )
    assert report.verdict == VERDICT_FAIL
    sharing = findings_of_kind(report, "sharing_changed")
    assert len(sharing) == 1
    assert sharing[0].paths == ["app.database.primary", "app.database.replica"]


def test_sharing_change_has_identical_values():
    # The gate must not confuse the sharing-change fixture with a value diff:
    # no value/type findings may be reported for it.
    report = run_gate(
        read_fixture("sharing_change_before.yaml"),
        read_fixture("sharing_change_after.yaml"),
        ["app.database"],
    )
    assert findings_of_kind(report, "value_mismatch") == []
    assert findings_of_kind(report, "type_mismatch") == []


def test_merge_key_inlining_changes_sharing():
    report = run_gate(
        read_fixture("merge_sharing_before.yaml"),
        read_fixture("merge_sharing_after.yaml"),
        ["service"],
    )
    assert report.verdict == VERDICT_FAIL
    sharing = findings_of_kind(report, "sharing_changed")
    changed = {tuple(finding.paths) for finding in sharing}
    assert ("service.defaults.limits", "service.primary.limits") in changed
    assert ("service.defaults.limits", "service.secondary.limits") in changed


def test_merge_key_evidence_is_recorded():
    report = run_gate(
        read_fixture("merge_sharing_before.yaml"),
        read_fixture("merge_sharing_after.yaml"),
        ["service"],
    )
    before_merge = report.evidence["before"].merge_keys
    assert "$.service.primary" in before_merge
    assert "$.service.secondary" in before_merge
    assert report.evidence["after"].merge_keys == []


def test_duplicate_reference_evidence_is_recorded():
    report = run_gate(
        read_fixture("sharing_change_before.yaml"),
        read_fixture("sharing_change_after.yaml"),
        ["app.database"],
    )
    before_groups = report.evidence["before"].shared_groups
    assert ["$.app.database.primary", "$.app.database.replica"] in before_groups
    assert report.evidence["after"].shared_groups == []


def test_cyclic_graph_with_renamed_anchor_passes():
    report = run_gate(
        read_fixture("cyclic_before.yaml"),
        read_fixture("cyclic_after.yaml"),
        ["node"],
    )
    assert report.verdict == VERDICT_PASS
    assert report.evidence["before"].cycles
    assert report.evidence["after"].cycles


def test_cycle_removed_fails():
    acyclic = "node:\n  name: n1\n  peer:\n    name: n2\n    back:\n      name: n2\n"
    report = run_gate(read_fixture("cyclic_before.yaml"), acyclic, ["node"])
    assert report.verdict == VERDICT_FAIL
    assert findings_of_kind(report, "sharing_changed")


def test_value_mismatch_fails():
    report = run_gate("a: 1\n", "a: 2\n", ["a"])
    assert report.verdict == VERDICT_FAIL
    assert findings_of_kind(report, "value_mismatch")


def test_type_mismatch_fails():
    report = run_gate('a: "30"\n', "a: 30\n", ["a"])
    assert report.verdict == VERDICT_FAIL
    assert findings_of_kind(report, "type_mismatch")


def test_bool_is_not_int():
    report = run_gate("a: true\n", "a: 1\n", ["a"])
    assert report.verdict == VERDICT_FAIL
    assert findings_of_kind(report, "type_mismatch")


def test_missing_protected_path_fails():
    report = run_gate("a:\n  b: 1\n", "a: {}\n", ["a.b"])
    assert report.verdict == VERDICT_FAIL
    assert findings_of_kind(report, "path_missing")


def test_sequence_index_in_protected_path():
    report = run_gate(
        "items:\n  - name: x\n  - name: y\n",
        "items:\n  - name: x\n  - name: z\n",
        ["items.1"],
    )
    assert report.verdict == VERDICT_FAIL
    mismatch = findings_of_kind(report, "value_mismatch")
    assert mismatch[0].paths == ["items.1.name"]


def test_unsafe_tag_goes_to_review():
    report = run_gate(read_fixture("unsafe_tag.yaml"), "a: 1\n", ["a"])
    assert report.verdict == VERDICT_REVIEW
    assert any("before" in reason for reason in report.review_reasons)


def test_multi_document_stream_goes_to_review():
    report = run_gate("a: 1\n---\nb: 2\n", "a: 1\n", ["a"])
    assert report.verdict == VERDICT_REVIEW
    assert report.review_reasons


def test_excessive_depth_goes_to_review():
    deep = "a:\n"
    for level in range(150):
        deep += "  " * (level + 1) + "b:\n"
    report = run_gate(deep, "a: 1\n", ["a"])
    assert report.verdict == VERDICT_REVIEW
    assert any("深度" in reason for reason in report.review_reasons)


def test_excessive_node_count_goes_to_review():
    wide = "\n".join("k%d: %d" % (index, index) for index in range(50))
    report = run_gate(wide, wide, ["k0"], max_nodes=10)
    assert report.verdict == VERDICT_REVIEW
    assert any("节点数" in reason for reason in report.review_reasons)


def test_report_is_safe_dumpable():
    report = run_gate(
        read_fixture("sharing_change_before.yaml"),
        read_fixture("sharing_change_after.yaml"),
        ["app.database"],
    )
    dumped = report.to_yaml()
    loaded = yaml.safe_load(dumped)
    assert loaded["verdict"] == VERDICT_FAIL
    assert loaded["findings"][0]["kind"] == "sharing_changed"
