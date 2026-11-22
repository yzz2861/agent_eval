import json

import pytest

from pip_audit._lineage import (
    REASON_MISSING_SCOPE,
    REASON_NAME_CONFLICT,
    REASON_NEW,
    REASON_NO_APPROVAL,
    REASON_NOT_COVERED,
    REASON_SAME_ID_CONFLICT,
    AliasEvent,
    Approval,
    ApprovalEvidence,
    ImpactScope,
    VulnerabilityInstance,
    build_lineage,
    parse_alias_events,
    parse_approvals,
    parse_audit,
    reconcile,
    reconcile_files,
)


def _load(asset, name):
    with asset(name).open() as handle:
        return json.load(handle)


@pytest.fixture
def lineage_inputs(asset):
    return (
        _load(asset, "lineage/audit.old.json"),
        _load(asset, "lineage/audit.new.json"),
        _load(asset, "lineage/alias_events.json"),
        _load(asset, "lineage/approvals.json"),
    )


def _by_id(items):
    return {item.instance.advisory_id: item for item in items}


def test_parse_audit_skips_skipped_dependencies():
    document = {
        "dependencies": [
            {"name": "foo", "version": "1.0.0", "vulns": [{"id": "GHSA-1"}]},
            {"name": "bar", "skip_reason": "not installed"},
        ]
    }

    instances = parse_audit(document)

    assert len(instances) == 1
    assert instances[0].advisory_id == "GHSA-1"
    assert instances[0].identity == {"GHSA-1"}


def test_parse_alias_events_models_merge_split_and_alias():
    document = {
        "events": [
            {"id": "e1", "type": "merge", "sources": ["A", "B"], "into": "M"},
            {"id": "e2", "type": "split", "from": "M", "into": ["D", "E"]},
            {"id": "e3", "type": "alias", "from": "E", "to": "CVE-E"},
        ]
    }

    events = parse_alias_events(document)

    assert events == [
        AliasEvent("e1", {"A": ["M"], "B": ["M"]}),
        AliasEvent("e2", {"M": ["D", "E"]}),
        AliasEvent("e3", {"E": ["CVE-E"]}),
    ]
    assert build_lineage(events) == {
        "A": {"M"},
        "B": {"M"},
        "M": {"D", "E"},
        "E": {"CVE-E"},
    }


def test_parse_alias_events_rejects_unknown_type():
    with pytest.raises(ValueError, match="unknown alias event type"):
        parse_alias_events({"events": [{"id": "e", "type": "bogus"}]})


def test_parse_approvals_marks_scopeless_evidence():
    document = {
        "approvals": [
            {
                "advisory_id": "A",
                "disposition": "accepted_risk",
                "evidence": [
                    {
                        "id": "scoped",
                        "scope": {"name": "foo", "introduced": "1.0.0", "fixed": "2.0.0"},
                    },
                    {
                        "id": "scopeless",
                        "scope": {"name": "bar", "introduced": None, "fixed": None},
                    },
                ],
            }
        ]
    }

    approval = parse_approvals(document)["A"]

    assert approval.evidence[0].has_scope
    assert not approval.evidence[1].has_scope


def test_impact_scope_requires_both_bounds_and_matching_package():
    instance = VulnerabilityInstance("foo", "1.5.0", "GHSA-1", "desc", frozenset())

    complete = ImpactScope("foo", "1.0.0", "2.0.0")
    assert complete.is_complete
    assert complete.covers(instance)

    scopeless = ImpactScope("foo", None, None)
    assert not scopeless.is_complete
    assert not scopeless.covers(instance)

    other_package = ImpactScope("bar", "1.0.0", "2.0.0")
    assert not other_package.covers(instance)

    out_of_range = ImpactScope("foo", "2.0.0", "3.0.0")
    assert not out_of_range.covers(instance)


def test_reconcile_propagates_only_to_covered_split_branch(lineage_inputs):
    report = reconcile(*lineage_inputs)

    todo = _by_id(report.todo)
    resolved = _by_id(report.resolved)

    # The many-to-one merge followed by a one-to-many split is reconstructed.
    covered = resolved["GHSA-SPLIT-D"]
    assert covered.predecessor_ids == ["GHSA-OLD-A", "GHSA-OLD-B"]
    assert covered.propagated_from == ["GHSA-OLD-A"]
    assert covered.reason == "accepted_risk"

    # The old ticket whose evidence lacks an impact scope leaves its successor on
    # the new to-do list, with an explicit reason instead of a silent closure.
    uncovered = todo["GHSA-SPLIT-E"]
    assert uncovered.reason == REASON_MISSING_SCOPE
    assert uncovered.predecessor_ids == ["GHSA-OLD-A", "GHSA-OLD-B"]
    assert uncovered.propagated_from == []


def test_reconcile_flags_same_identifier_name_conflict(lineage_inputs):
    report = reconcile(*lineage_inputs)

    item = _by_id(report.todo)["GHSA-RENAME-1"]
    assert item.reason == REASON_SAME_ID_CONFLICT


def test_reconcile_flags_shared_name_conflict(lineage_inputs):
    report = reconcile(*lineage_inputs)

    todo = _by_id(report.todo)
    assert todo["GHSA-DUP-1"].reason == REASON_NAME_CONFLICT
    assert todo["GHSA-DUP-2"].reason == REASON_NAME_CONFLICT


def test_reconcile_keeps_new_and_unapproved_advisories_on_todo(lineage_inputs):
    report = reconcile(*lineage_inputs)

    todo = _by_id(report.todo)
    assert todo["GHSA-FRESH-1"].reason == REASON_NEW
    assert todo["GHSA-NOAPP-1"].reason == REASON_NO_APPROVAL


def test_reconcile_propagates_stable_identifier_with_coverage(lineage_inputs):
    report = reconcile(*lineage_inputs)

    item = _by_id(report.resolved)["GHSA-KEEP-1"]
    assert item.reason == "accepted_risk"
    assert item.propagated_from == ["GHSA-KEEP-1"]


def test_reconcile_does_not_propagate_when_scope_does_not_cover():
    old_audit = {
        "dependencies": [
            {
                "name": "foo",
                "version": "1.0.0",
                "vulns": [{"id": "GHSA-OLD", "description": "old"}],
            }
        ]
    }
    new_audit = {
        "dependencies": [
            {
                "name": "foo",
                "version": "9.0.0",
                "vulns": [{"id": "GHSA-NEW", "description": "new"}],
            }
        ]
    }
    aliases = {"events": [{"id": "e", "type": "alias", "from": "GHSA-OLD", "to": "GHSA-NEW"}]}
    approvals = {
        "approvals": [
            {
                "advisory_id": "GHSA-OLD",
                "disposition": "accepted_risk",
                "evidence": [
                    {"id": "ev", "scope": {"name": "foo", "introduced": "1.0.0", "fixed": "2.0.0"}}
                ],
            }
        ]
    }

    item = _by_id(reconcile(old_audit, new_audit, aliases, approvals).todo)["GHSA-NEW"]
    assert item.reason == REASON_NOT_COVERED


def test_reconcile_files_matches_in_memory_reconciliation(lineage_inputs, asset):
    report = reconcile_files(
        asset("lineage/audit.old.json"),
        asset("lineage/audit.new.json"),
        asset("lineage/alias_events.json"),
        asset("lineage/approvals.json"),
    )

    expected = reconcile(*lineage_inputs)
    assert report.to_dict() == expected.to_dict()
    serialized = report.to_dict()
    assert set(serialized) == {"todo", "resolved"}
    assert all(item["on_todo"] for item in serialized["todo"])
    assert all(not item["on_todo"] for item in serialized["resolved"])


def test_approval_and_evidence_dataclasses_are_immutable():
    evidence = ApprovalEvidence("ev", ImpactScope("foo", "1.0.0", "2.0.0"))
    approval = Approval("GHSA-1", "accepted_risk", [evidence])

    with pytest.raises(Exception):
        approval.disposition = "other"  # type: ignore[misc]
