"""Adapter tests: oleid indicator mapping and node construction."""

from oletools.verdict import (
    Capability,
    DetectorResult,
    EvidenceReason,
    NodeKind,
    Outcome,
    Policy,
    Verdict,
    VerdictEngine,
)
from oletools.verdict.adapters import (
    indicator_to_result,
    node_from_bytes,
    results_from_oleid,
)


class FakeIndicator(object):
    """Minimal stand-in for oletools.oleid.Indicator."""

    def __init__(self, indicator_id, value, risk):
        self.id = indicator_id
        self.value = value
        self.risk = risk
        self.name = indicator_id


class FakeOleID(object):
    def __init__(self, indicators):
        self.indicators = indicators


def test_indicator_risk_maps_to_finding():
    indicator = FakeIndicator("macros", True, "HIGH")
    result = indicator_to_result("n1", indicator)
    assert isinstance(result, DetectorResult)
    assert result.capability == Capability.MACRO
    assert result.outcome == Outcome.RISK
    assert result.signature == "macros"


def test_indicator_none_maps_to_clean():
    indicator = FakeIndicator("flash", 0, "none")
    result = indicator_to_result("n1", indicator)
    assert result.outcome == Outcome.CLEAN
    assert result.capability == Capability.FLASH


def test_indicator_error_maps_to_error():
    indicator = FakeIndicator("encrypted", None, "Error")
    result = indicator_to_result("n1", indicator)
    assert result.outcome == Outcome.ERROR


def test_unmapped_indicator_returns_none():
    indicator = FakeIndicator("author", "someone", "info")
    assert indicator_to_result("n1", indicator) is None


def test_results_from_oleid_skips_metadata_and_kept_order():
    fake = FakeOleID([
        FakeIndicator("author", "x", "info"),
        FakeIndicator("macros", True, "HIGH"),
        FakeIndicator("flash", 0, "none"),
    ])
    results = results_from_oleid("doc", fake)
    assert [r.signature for r in results] == ["macros", "flash"]


def test_adapter_result_drives_engine_verdict():
    root = node_from_bytes("doc", b"PK\\x03\\x04 bytes", kind=NodeKind.OOXML)
    fake = FakeOleID([FakeIndicator("macros", True, "HIGH")])
    results = results_from_oleid("doc", fake)
    engine = VerdictEngine([root], edges=[],
                           policy=Policy(required_capabilities=[
                               Capability.MACRO]))
    engine.submit_results(results)
    report = engine.evaluate()
    assert report.verdict == Verdict.BLOCK_RISK
    assert any(e.reason == EvidenceReason.DETECTOR_FINDING
               for e in report.blocking_evidence)


def test_node_from_bytes_hashes_content():
    node_a = node_from_bytes("a", b"same bytes")
    node_b = node_from_bytes("b", b"same bytes")
    assert node_a.content_key == node_b.content_key
    assert node_a.kind == NodeKind.UNKNOWN
