"""End-to-end tests over the nested partially-encrypted fixture."""

from oletools.verdict import (
    Capability,
    DetectorResult,
    EvidenceReason,
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


def _build():
    roots, nodes, edges = build_partial_encryption_tree()
    engine = VerdictEngine(roots, edges=edges, nodes=nodes,
                           policy=strict_policy())
    return engine, nodes


def test_partial_encryption_fixture_blocks_and_classifies():
    engine, nodes = _build()
    report = engine.evaluate()
    # encryption / unknown / corrupt mean the document is not clean
    assert report.verdict in (Verdict.BLOCK_UNPARSEABLE,
                              Verdict.BLOCK_UNCOVERED, Verdict.BLOCK_RISK)
    states = report.node_states
    assert states["encrypted-ole"] == NodeStatus.UNCOVERED
    assert states["mystery-embed"] == NodeStatus.UNCOVERED
    assert states["corrupt-stream"] == NodeStatus.UNPARSEABLE
    # every node appears exactly once in the counts
    assert sum(report.counts.values()) == len(nodes)


def test_scanner_detects_macro_and_dde_risk():
    engine, _ = _build()
    scanner = SimulatedScanner()
    engine.submit_result(scanner.scan("macro-part", Capability.MACRO))
    engine.submit_result(scanner.scan("dde-part", Capability.DDE))
    report = engine.evaluate()
    assert report.verdict == Verdict.BLOCK_RISK
    blocking_caps = {e.capability for e in report.blocking_evidence
                     if e.reason == EvidenceReason.DETECTOR_FINDING}
    assert Capability.MACRO.value in blocking_caps
    assert Capability.DDE.value in blocking_caps


def test_transient_failure_then_retry_keeps_single_evidence():
    engine, _ = _build()
    scanner = SimulatedScanner(fail_once={("macro-part", "macro"): 1})
    first = scanner.scan("macro-part", Capability.MACRO)
    assert first.outcome == Outcome.ERROR
    engine.submit_result(first)
    failing = engine.evaluate()
    assert any(e.reason == EvidenceReason.DETECTOR_ERROR
               and e.node_id == "macro-part"
               for e in failing.evidence)
    # retry succeeds and replaces only the macro evidence
    retry = scanner.scan("macro-part", Capability.MACRO)
    assert retry.outcome == Outcome.RISK
    engine.submit_result(retry)
    recovered = engine.evaluate()
    macro = [e for e in recovered.evidence
             if e.node_id == "macro-part"
             and e.capability == Capability.MACRO.value]
    assert len(macro) == 1
    assert macro[0].attempts == 2
    assert macro[0].reason == EvidenceReason.DETECTOR_FINDING
    assert recovered.verdict == Verdict.BLOCK_RISK


def test_verdict_does_not_change_with_traversal_order():
    caps = list(strict_policy().required_capabilities)
    engines = []
    for order in (sorted(caps), list(reversed(caps))):
        engine, nodes = _build()
        scanner = SimulatedScanner()
        for node in nodes:
            for cap in order:
                engine.submit_result(scanner.scan(node.node_id, cap))
        engines.append(engine.evaluate().to_dict())
    assert engines[0] == engines[1]
