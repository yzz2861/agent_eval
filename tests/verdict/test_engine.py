"""Core engine tests: states, propagation, dedup, retry, order independence."""

import random

import pytest

from oletools.verdict import (
    Capability,
    ContainerEdge,
    ContainerNode,
    DetectorResult,
    EvidenceReason,
    NodeKind,
    NodeStatus,
    Outcome,
    Policy,
    Severity,
    Verdict,
    VerdictEngine,
)
from oletools.verdict.fixtures import (
    SimulatedScanner,
    build_partial_encryption_tree,
    strict_policy,
)


def _engine(policy=None):
    roots, nodes, edges = build_partial_encryption_tree()
    return VerdictEngine(roots, edges=edges, nodes=nodes,
                         policy=policy or strict_policy())


def _clean_plan():
    # Coverage plan that satisfies every required capability on every node.
    roots, nodes, _ = build_partial_encryption_tree()
    caps = (
        Capability.MACRO, Capability.DDE, Capability.EMBEDDED_OBJECT,
        Capability.EXTERNAL_RELATIONSHIP, Capability.FLASH,
        Capability.OLE_STRUCTURE, Capability.OOXML_STRUCTURE,
    )
    plan = []
    for node in nodes:
        for cap in caps:
            plan.append((node.node_id, cap))
    return plan

def test_fixture_tree_structure():
    roots, nodes, edges = build_partial_encryption_tree()
    ids = {node.node_id for node in nodes}
    assert ids == {"doc", "macro-part", "encrypted-ole", "shared-stream",
                   "dde-part", "mystery-embed", "corrupt-stream"}
    by_id = {node.node_id: node for node in nodes}
    assert by_id["encrypted-ole"].encrypted is True
    assert by_id["mystery-embed"].kind == NodeKind.UNKNOWN
    assert by_id["corrupt-stream"].corrupt is True
    # shared-stream has exactly two incoming edges but is one node
    incoming = [e for e in edges if e.child_id == "shared-stream"]
    assert len(incoming) == 2
    assert len({e.child_id for e in incoming}) == 1


def test_risk_always_blocks_even_when_capability_optional():
    policy = Policy(required_capabilities=[Capability.PARSER])  # macro optional
    roots, nodes, edges = build_partial_encryption_tree()
    engine = VerdictEngine(roots, edges=edges, nodes=nodes, policy=policy)
    engine.submit_result(DetectorResult(
        "macro-part", Capability.MACRO, Outcome.RISK, "olevba",
        severity=Severity.HIGH, detail="macro", signature="vba"))
    report = engine.evaluate()
    assert report.verdict == Verdict.BLOCK_RISK
    reasons = {item.reason for item in report.blocking_evidence}
    assert EvidenceReason.DETECTOR_FINDING in reasons
    assert report.node_states["macro-part"] == NodeStatus.RISK
    # risk propagates to the root
    assert report.node_states["doc"] == NodeStatus.RISK


def test_encrypted_node_is_uncovered_not_clean():
    engine = _engine()
    report = engine.evaluate()
    assert report.node_states["encrypted-ole"] == NodeStatus.UNCOVERED
    reasons = {e.reason for e in report.blocking_evidence}
    assert EvidenceReason.ENCRYPTED in reasons
    assert report.verdict in (Verdict.BLOCK_UNCOVERED,
                              Verdict.BLOCK_UNPARSEABLE)


def test_unknown_embed_is_uncovered():
    engine = _engine()
    report = engine.evaluate()
    assert report.node_states["mystery-embed"] == NodeStatus.UNCOVERED
    assert any(e.reason == EvidenceReason.UNKNOWN_FORMAT
               for e in report.blocking_evidence)


def test_corrupt_node_is_unparseable():
    engine = _engine()
    report = engine.evaluate()
    assert report.node_states["corrupt-stream"] == NodeStatus.UNPARSEABLE
    assert any(e.reason == EvidenceReason.CORRUPT
               for e in report.blocking_evidence)
    assert report.verdict == Verdict.BLOCK_UNPARSEABLE

def test_fully_covered_clean_tree_allows():
    # Build a simple tree without encryption/unknown/corrupt so CLEAN is
    # reachable once every required capability reports clean.
    root = ContainerNode("doc", kind=NodeKind.OOXML)
    child = ContainerNode("part", kind=NodeKind.OOXML_PART)
    edges = [ContainerEdge("doc", "part", label="p")]
    caps = strict_policy().required_for(NodeKind.OOXML)
    engine = VerdictEngine([root], edges=edges, nodes=[child],
                           policy=strict_policy())
    for node_id in ("doc", "part"):
        for cap in caps:
            engine.submit_result(DetectorResult(
                node_id, cap, Outcome.CLEAN, "sim", severity=Severity.INFO))
    report = engine.evaluate()
    assert report.verdict == Verdict.ALLOW
    assert set(report.node_states.values()) == {NodeStatus.CLEAN}
    assert report.blocking_evidence == []


def test_missing_required_capability_is_uncovered():
    root = ContainerNode("doc", kind=NodeKind.OOXML)
    engine = VerdictEngine([root], policy=Policy(
        required_capabilities=[Capability.MACRO, Capability.DDE]))
    engine.submit_result(DetectorResult(
        "doc", Capability.MACRO, Outcome.CLEAN, "olevba"))
    report = engine.evaluate()
    assert report.verdict == Verdict.BLOCK_UNCOVERED
    assert any(e.reason == EvidenceReason.CAPABILITY_GAP and
               e.capability == Capability.DDE.value
               for e in report.blocking_evidence)


def test_optional_capability_gap_does_not_block():
    root = ContainerNode("doc", kind=NodeKind.OOXML)
    engine = VerdictEngine([root], policy=Policy(
        required_capabilities=[Capability.MACRO]))
    engine.submit_result(DetectorResult(
        "doc", Capability.MACRO, Outcome.CLEAN, "olevba"))
    report = engine.evaluate()
    assert report.verdict == Verdict.ALLOW
    assert not any(e.capability == Capability.FLASH.value
                   for e in report.blocking_evidence)


def test_order_independence_shuffled_submission():
    plan = _clean_plan()
    canonical = None
    for seed in range(8):
        engine = _engine()
        scanner = SimulatedScanner()
        shuffled = list(plan)
        random.Random(seed).shuffle(shuffled)
        scanner.scan_all(engine, shuffled)
        report = engine.evaluate()
        payload = report.to_json()
        if canonical is None:
            canonical = payload
        else:
            assert payload == canonical
    # shuffled scan must still detect the two scripted risks
    assert "macro-part" and "dde-part" in canonical

def test_retry_replaces_only_matching_evidence():
    root = ContainerNode("doc", kind=NodeKind.OOXML)
    engine = VerdictEngine([root], policy=Policy(
        required_capabilities=[Capability.MACRO, Capability.DDE]))
    # first macro attempt fails (transient), DDE has a confirmed risk
    engine.submit_result(DetectorResult(
        "doc", Capability.MACRO, Outcome.ERROR, "olevba",
        detail="boom", signature="macro"))
    dde = DetectorResult("doc", Capability.DDE, Outcome.RISK, "msodde",
                         severity=Severity.HIGH, detail="dde",
                         signature="dde")
    engine.submit_result(dde)
    first = engine.evaluate()
    assert first.verdict == Verdict.BLOCK_RISK
    # retry macro: same detector+signature -> replace only this evidence
    engine.submit_result(DetectorResult(
        "doc", Capability.MACRO, Outcome.CLEAN, "olevba",
        detail="ok now", signature="macro"))
    second = engine.evaluate()
    macro_evidence = [e for e in second.evidence
                      if e.capability == Capability.MACRO.value]
    # exactly one macro record remains, carrying the retry count
    assert len(macro_evidence) == 1
    assert macro_evidence[0].attempts == 2
    assert macro_evidence[0].reason == EvidenceReason.DETECTOR_CLEAN
    # the unrelated DDE risk is untouched and still blocks
    dde_evidence = [e for e in second.blocking_evidence
                    if e.capability == Capability.DDE.value]
    assert len(dde_evidence) == 1
    assert second.verdict == Verdict.BLOCK_RISK


def test_shared_node_counted_once_but_all_paths_listed():
    engine = _engine()
    report = engine.evaluate()
    # one node, one state entry, one count even with two incoming edges
    assert sum(report.counts.values()) == len(engine.node_ids)
    paths = report.node_paths["shared-stream"]
    assert ("doc", "shared-stream") in paths
    assert ("doc", "encrypted-ole", "shared-stream") in paths
    # no duplicated evidence for the shared node
    shared_evidence = [e for e in report.evidence
                       if e.node_id == "shared-stream"]
    keys = [e.dedupe_key() for e in shared_evidence]
    assert len(keys) == len(set(keys))


def test_unexamined_edge_does_not_hide_branch():
    root = ContainerNode("doc", kind=NodeKind.OOXML)
    skipped = ContainerNode("part", kind=NodeKind.OOXML_PART)
    edges = [ContainerEdge("doc", "part", label="lazy", examined=False)]
    engine = VerdictEngine([root], edges=edges, nodes=[skipped],
                           policy=Policy(required_capabilities=[
                               Capability.OOXML_STRUCTURE]))
    report = engine.evaluate()
    assert report.verdict == Verdict.BLOCK_UNCOVERED
    assert any(e.reason == EvidenceReason.UNEXAMINED_EDGE
               for e in report.blocking_evidence)
    assert report.node_states["doc"] == NodeStatus.UNCOVERED


def test_unknown_edge_format_is_uncovered():
    root = ContainerNode("doc", kind=NodeKind.OOXML)
    blob = ContainerNode("blob", kind=NodeKind.UNKNOWN)
    edges = [ContainerEdge("doc", "blob", label="x", known_format=False)]
    engine = VerdictEngine([root], edges=edges, nodes=[blob],
                           policy=Policy(required_capabilities=[
                               Capability.UNKNOWN_EMBED]))
    report = engine.evaluate()
    assert any(e.reason == EvidenceReason.UNKNOWN_EDGE
               for e in report.blocking_evidence)

def test_reference_cycle_is_unparseable():
    a = ContainerNode("a", kind=NodeKind.OLE)
    b = ContainerNode("b", kind=NodeKind.OLE_STREAM)
    edges = [ContainerEdge("a", "b", label="down"),
             ContainerEdge("b", "a", label="back")]
    engine = VerdictEngine([a], edges=edges, nodes=[b],
                           policy=Policy(required_capabilities=[
                               Capability.OLE_STRUCTURE]))
    report = engine.evaluate()
    assert report.node_states["a"] == NodeStatus.UNPARSEABLE
    assert any(e.reason == EvidenceReason.CYCLE
               for e in report.blocking_evidence)
    assert report.verdict == Verdict.BLOCK_UNPARSEABLE


def test_multiple_roots_worst_status_wins():
    good = ContainerNode("good", kind=NodeKind.OOXML)
    bad = ContainerNode("bad", kind=NodeKind.OOXML)
    policy = Policy(required_capabilities=[Capability.MACRO])
    engine = VerdictEngine([good, bad], policy=policy)
    engine.submit_result(DetectorResult(
        "good", Capability.MACRO, Outcome.CLEAN, "olevba"))
    engine.submit_result(DetectorResult(
        "bad", Capability.MACRO, Outcome.RISK, "olevba",
        severity=Severity.HIGH, signature="x"))
    report = engine.evaluate()
    assert report.verdict == Verdict.BLOCK_RISK
    assert report.node_states["good"] == NodeStatus.CLEAN
    assert report.node_states["bad"] == NodeStatus.RISK


def test_canonical_json_is_stable():
    engine_a = _engine()
    engine_b = _engine()
    scanner_a = SimulatedScanner()
    scanner_b = SimulatedScanner()
    plan = _clean_plan()
    scanner_a.scan_all(engine_a, plan)
    scanner_b.scan_all(engine_b, list(reversed(plan)))
    assert engine_a.evaluate().to_json() == engine_b.evaluate().to_json()


def test_disabling_detector_cannot_erase_confirmed_risk():
    # A risk reported first cannot be removed by a later policy that drops
    # the capability from the required set: findings stay authoritative.
    root = ContainerNode("doc", kind=NodeKind.OOXML)
    strict = Policy(required_capabilities=[Capability.MACRO])
    engine = VerdictEngine([root], policy=strict)
    engine.submit_result(DetectorResult(
        "doc", Capability.MACRO, Outcome.RISK, "olevba",
        severity=Severity.HIGH, signature="vba"))
    assert engine.evaluate().verdict == Verdict.BLOCK_RISK
    engine.policy = Policy(required_capabilities=[])  # nothing required
    relaxed = engine.evaluate()
    assert relaxed.verdict == Verdict.BLOCK_RISK
    assert any(e.reason == EvidenceReason.DETECTOR_FINDING
               for e in relaxed.blocking_evidence)


def test_duplicate_node_id_rejected():
    first = ContainerNode("same", kind=NodeKind.OOXML)
    second = ContainerNode("same", kind=NodeKind.OOXML)
    with pytest.raises(ValueError):
        VerdictEngine([first], nodes=[second])


def test_edge_with_unknown_endpoint_rejected():
    root = ContainerNode("doc", kind=NodeKind.OOXML)
    bad_edge = ContainerEdge("doc", "ghost", label="g")
    with pytest.raises(KeyError):
        VerdictEngine([root], edges=[bad_edge])
