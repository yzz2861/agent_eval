from __future__ import annotations

from io import BytesIO

import pytest

from dissect.cstruct.discriminator import (
    ByteWindow,
    CandidateStatus,
    DiscriminationOutcome,
    ReadCache,
    TruncatedRead,
    discriminate,
    evaluate_candidate,
)
from tests.discriminator_layouts import (
    HEADER_SIZE,
    ambiguous_record,
    layout_a,
    layout_a_record,
    layout_b,
    layout_b_record,
)


@pytest.fixture
def candidates() -> list:
    return [layout_a(), layout_b()]


def _verdict(result: object, name: str) -> object:
    return next(verdict for verdict in result.verdicts if verdict.schema_name == name)


def test_ambiguous_record_matches_both_layouts(candidates: list) -> None:
    result = discriminate(candidates, ambiguous_record())

    assert result.outcome is DiscriminationOutcome.AMBIGUOUS
    assert {verdict.schema_name for verdict in result.survivors} == {"layout_a", "layout_b"}
    assert all(verdict.status is CandidateStatus.CONFIRMED for verdict in result.verdicts)


def test_ambiguous_plan_is_minimum_single_field_and_intrinsic(candidates: list) -> None:
    result = discriminate(candidates, ambiguous_record())
    plan = result.evidence_plan

    assert plan is not None
    assert len(plan.items) == 1
    item = plan.items[0]
    assert item.key == "field:version"
    assert item.span == (2, 3)
    assert item.fully_readable is True
    assert item.distinguishes == (("layout_a", "layout_b"),)
    assert plan.missing_ranges == ()
    assert plan.intrinsic is True
    assert plan.resolvable is True


def test_unique_match_excludes_other_with_semantic_reason(candidates: list) -> None:
    result = discriminate(candidates, layout_a_record())

    assert result.outcome is DiscriminationOutcome.UNIQUE_MATCH
    assert result.unique.schema_name == "layout_a"
    rejected = _verdict(result, "layout_b")
    assert rejected.status is CandidateStatus.EXCLUDED
    assert any(violation.name == "reserved" for violation in rejected.violations)
    assert all("constraint" in violation.reason for violation in rejected.violations)


def test_layout_b_record_is_unique_to_b(candidates: list) -> None:
    result = discriminate(candidates, layout_b_record())

    assert result.outcome is DiscriminationOutcome.UNIQUE_MATCH
    assert result.unique.schema_name == "layout_b"
    rejected = _verdict(result, "layout_a")
    assert rejected.status is CandidateStatus.EXCLUDED
    assert {violation.name for violation in rejected.violations} >= {"version", "flags"}


def test_all_failed_reports_each_candidate_atomically(candidates: list) -> None:
    broken = bytearray(ambiguous_record())
    broken[0] = 0x00
    result = discriminate(candidates, bytes(broken))

    assert result.outcome is DiscriminationOutcome.ALL_FAILED
    assert result.evidence_plan is None
    assert all(verdict.status is CandidateStatus.EXCLUDED for verdict in result.verdicts)
    for verdict in result.verdicts:
        assert any(violation.name == "magic" for violation in verdict.violations)


def test_parse_success_is_not_semantic_correctness(candidates: list) -> None:
    # layout_a_record decodes without raising under layout B field widths,
    # yet B must be excluded on its declared reserved-word invariant.
    verdict = evaluate_candidate(layout_b(), ByteWindow(layout_a_record()))
    assert verdict.status is CandidateStatus.EXCLUDED
    assert any(violation.name == "reserved" for violation in verdict.violations)


def test_truncated_ambiguous_record_reports_missing_ranges(candidates: list) -> None:
    result = discriminate(candidates, ambiguous_record(), window_size=2)

    assert result.outcome is DiscriminationOutcome.AMBIGUOUS
    assert all(verdict.status is CandidateStatus.PENDING for verdict in result.verdicts)
    plan = result.evidence_plan
    assert plan is not None
    assert plan.intrinsic is False
    assert plan.resolvable is True
    assert len(plan.items) == 1
    item = plan.items[0]
    assert item.span == (2, 3)
    # The distinguishing byte sits past the 2-byte window: report the gap.
    assert item.missing_ranges == ((2, 3),)
    assert item.readable_missing_ranges == ()
    assert item.fetchable is False
    assert plan.missing_ranges == ((2, 3),)
    assert plan.readable_missing_ranges == ()


def test_cache_distinguishes_fetchable_gap_from_out_of_window() -> None:
    window = ByteWindow(bytes([0xA5, 0x02, 0x01]), window_size=3)
    cache = ReadCache(window)

    # A range crossing the readable edge: the request is reported whole, but
    # only the in-window prefix is currently fetchable.
    assert cache.missing(2, 4) == ((2, 6),)
    assert cache.readable(2, 4) is False
    assert cache.readable(2, 1) is True

    assert cache.read(0, 2) == bytes([0xA5, 0x02])
    assert cache.missing(0, 2) == ()
    assert cache.missing(0, 4) == ((2, 4),)


def test_truncated_unique_candidate_stays_pending_with_gap(candidates: list) -> None:
    result = discriminate(candidates, layout_a_record(), window_size=8)

    assert result.outcome is DiscriminationOutcome.AMBIGUOUS
    survivor = _verdict(result, "layout_a")
    assert survivor.status is CandidateStatus.PENDING
    assert _verdict(result, "layout_b").status is CandidateStatus.EXCLUDED
    plan = result.evidence_plan
    assert plan is not None
    assert plan.missing_ranges
    assert all(start >= 8 for start, _end in plan.missing_ranges)


def test_extending_window_resolves_pending_ambiguity(candidates: list) -> None:
    record = layout_a_record()
    truncated = discriminate(candidates, record, window_size=2)
    resolved = discriminate(candidates, record)

    assert truncated.outcome is DiscriminationOutcome.AMBIGUOUS
    assert all(v.status is CandidateStatus.PENDING for v in truncated.verdicts)
    assert resolved.outcome is DiscriminationOutcome.UNIQUE_MATCH
    assert resolved.unique.schema_name == "layout_a"


def test_discrimination_is_order_independent() -> None:
    record = layout_a_record()
    forward = discriminate([layout_a(), layout_b()], record)
    reversed_order = discriminate([layout_b(), layout_a()], record)

    assert forward.outcome == reversed_order.outcome
    assert [v.schema_name for v in forward.verdicts] == [v.schema_name for v in reversed_order.verdicts]
    assert [v.status for v in forward.verdicts] == [v.status for v in reversed_order.verdicts]


def test_shared_prefix_read_once_but_candidate_state_is_isolated(candidates: list) -> None:
    result = discriminate(candidates, ambiguous_record())

    stats = result.cache_stats
    assert stats.source_reads < stats.source_reads + stats.cache_hits
    assert stats.cache_hits > 0
    names = [verdict.schema_name for verdict in result.verdicts]
    assert names == sorted(names)


def test_failed_read_never_poisons_cache(candidates: list) -> None:
    window = ByteWindow(ambiguous_record(), window_size=4)
    cache = ReadCache(window)

    with pytest.raises(TruncatedRead):
        cache.read(HEADER_SIZE - 4, 8)

    assert cache.read(0, 2) == ambiguous_record()[:2]


def test_stream_source_is_supported(candidates: list) -> None:
    result = discriminate(candidates, BytesIO(layout_b_record()))
    assert result.outcome is DiscriminationOutcome.UNIQUE_MATCH
    assert result.unique.schema_name == "layout_b"
