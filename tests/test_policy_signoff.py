"""policy_signoff 的离线签收审计测试.

覆盖三类消费方:
1. 依赖的标量值未变, 仅锚点改名       -> 签收有效;
2. 分支经合并继承的安全开关真变了     -> 需要重新审批, 且能定位依赖;
3. 旧签收声明未记录消费来源路径       -> 证据不足.
"""

import pytest

from policy_signoff import (
    INSUFFICIENT_EVIDENCE,
    REAPPROVAL_NEEDED,
    VALID,
    Signoff,
    Snapshot,
    UnsupportedNodeError,
    evaluate_signoff,
    format_report,
)

OLD_SOURCE = """
security:
  session: &session_policy
    timeout: 30
    issuer: iam
  baseline: &sec_baseline
    enforced: true
    audit: true
  consumer_view:
    <<: *session_policy
branches:
  legacy:
    <<: *sec_baseline
  modern:
    <<: *sec_baseline
    enforced: true
"""

NEW_SOURCE = """
security:
  session: &session_policy_v2
    timeout: 30
    issuer: iam
  baseline: &sec_baseline
    enforced: false
    audit: true
  consumer_view:
    <<: *session_policy_v2
branches:
  legacy:
    <<: *sec_baseline
  modern:
    <<: *sec_baseline
    enforced: true
"""

OLD_ID = "policy@2026-11-01"
NEW_ID = "policy@2026-11-26"


@pytest.fixture(scope="module")
def old_snapshot():
    return Snapshot.record(OLD_SOURCE, OLD_ID)


@pytest.fixture(scope="module")
def new_snapshot():
    return Snapshot.record(NEW_SOURCE, NEW_ID)


def test_snapshot_records_scalars_anchors_and_merges(old_snapshot):
    paths = {fact.path for fact in old_snapshot.scalars}
    assert "security.session.timeout" in paths
    assert "security.baseline.enforced" in paths
    timeout = next(f for f in old_snapshot.scalars
                   if f.path == "security.session.timeout")
    assert timeout.tag == "tag:yaml.org,2002:int"
    assert timeout.value == "30"
    assert timeout.line > 0 and timeout.column > 0

    assert old_snapshot.anchors["session_policy"].path == "security.session"
    assert old_snapshot.anchors["sec_baseline"].path == "security.baseline"

    merges = {fact.path: fact for fact in old_snapshot.merges}
    assert merges["security.consumer_view"].anchors == ("session_policy",)
    assert merges["security.consumer_view"].targets == ("security.session",)
    assert merges["branches.legacy"].anchors == ("sec_baseline",)
    assert merges["branches.legacy"].targets == ("security.baseline",)


def test_merge_resolution_provenance(old_snapshot):
    entry = old_snapshot.resolve("branches.legacy.enforced")
    assert entry.value == "true"
    assert entry.origin == "security.baseline.enforced"
    assert entry.via_anchor == "sec_baseline"
    explicit = old_snapshot.resolve("branches.modern.enforced")
    assert explicit.value == "true"
    assert explicit.via_anchor is None


def test_consumer_anchor_rename_only_stays_valid(old_snapshot, new_snapshot):
    signoff = Signoff(consumer="svc-session-timeout",
                      snapshot_id=OLD_ID,
                      sources=("security.consumer_view.timeout",))
    verdict = evaluate_signoff(signoff, old_snapshot, new_snapshot)
    assert verdict.status == VALID
    assert verdict.triggering_dependencies == []
    old_entry = old_snapshot.resolve("security.consumer_view.timeout")
    new_entry = new_snapshot.resolve("security.consumer_view.timeout")
    assert old_entry.via_anchor == "session_policy"
    assert new_entry.via_anchor == "session_policy_v2"
    assert (old_entry.tag, old_entry.value) == (new_entry.tag, new_entry.value)


def test_consumer_inherited_toggle_change_needs_reapproval(old_snapshot,
                                                           new_snapshot):
    signoff = Signoff(consumer="svc-legacy-branch",
                      snapshot_id=OLD_ID,
                      sources=("branches.legacy.enforced",
                               "branches.legacy.audit"))
    verdict = evaluate_signoff(signoff, old_snapshot, new_snapshot)
    assert verdict.status == REAPPROVAL_NEEDED
    assert verdict.triggering_dependencies == ["branches.legacy.enforced"]

    report = format_report([verdict])
    assert "svc-legacy-branch" in report
    assert "branches.legacy.enforced" in report
    assert "security.baseline.enforced" in report
    assert "sec_baseline" in report
    assert "branches.legacy.audit" in report


def test_consumer_without_declared_sources_is_insufficient(old_snapshot,
                                                           new_snapshot):
    signoff = Signoff(consumer="svc-legacy-decl",
                      snapshot_id=OLD_ID,
                      sources=None)
    verdict = evaluate_signoff(signoff, old_snapshot, new_snapshot)
    assert verdict.status == INSUFFICIENT_EVIDENCE
    assert verdict.dependencies == []
    assert any("未记录" in reason for reason in verdict.reasons)
    assert "svc-legacy-decl" in format_report([verdict])


def test_explicit_override_is_not_fooled_by_merge_change(old_snapshot,
                                                         new_snapshot):
    signoff = Signoff(consumer="svc-modern-branch",
                      snapshot_id=OLD_ID,
                      sources=("branches.modern.enforced",))
    verdict = evaluate_signoff(signoff, old_snapshot, new_snapshot)
    assert verdict.status == VALID


def test_removed_dependency_is_located(old_snapshot):
    shrunk = Snapshot.record("security:\n  session:\n    timeout: 30\n", NEW_ID)
    signoff = Signoff(consumer="svc-view",
                      snapshot_id=OLD_ID,
                      sources=("security.consumer_view.timeout",))
    verdict = evaluate_signoff(signoff, old_snapshot, shrunk)
    assert verdict.status == REAPPROVAL_NEEDED
    assert verdict.triggering_dependencies == ["security.consumer_view.timeout"]
    assert "security.consumer_view.timeout" in format_report([verdict])


def test_unknown_old_dependency_is_insufficient(old_snapshot, new_snapshot):
    signoff = Signoff(consumer="svc-typo",
                      snapshot_id=OLD_ID,
                      sources=("security.nonexistent",))
    verdict = evaluate_signoff(signoff, old_snapshot, new_snapshot)
    assert verdict.status == INSUFFICIENT_EVIDENCE


def test_loader_has_no_constructor():
    from yaml.constructor import BaseConstructor
    from policy_signoff import _NodeLoader
    assert not issubclass(_NodeLoader, BaseConstructor)


@pytest.mark.parametrize("source", [
    "a:\n  <<: {inline: true}\n",
    "? [complex]\n: key\n",
    "a: 1\na: 2\n",
    "a: &x\n  b: *x\n",
    "a:\n  <<: *missing\n",
])
def test_outside_documented_subset_is_rejected(source):
    with pytest.raises(UnsupportedNodeError):
        Snapshot.record(source, "subset")
