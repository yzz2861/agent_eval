import json

import pytest

from detect_secrets.coverage_receipt import ArchiveManifest
from detect_secrets.coverage_receipt import CoverageReceipt
from detect_secrets.coverage_receipt import StableCommitment
from detect_secrets.coverage_receipt import merge_receipts
from detect_secrets.coverage_receipt import regressed_intervals
from detect_secrets.coverage_receipt import try_merge_receipts


COMMITMENT = 'sha256:' + 'a' * 64
OTHER_COMMITMENT = 'sha256:' + 'b' * 64


def make_manifest(commitment=COMMITMENT):
    return ArchiveManifest({
        'archive/src/config.py': {
            'commitment': commitment,
        },
    })


def test_separates_failed_policy_skipped_and_clean_scanned_ranges():
    receipt = CoverageReceipt(
        commitment=COMMITMENT,
        inclusive=True,
        failed=[(91, 100)],
        skipped=[(41, 50)],
        clean=[(1, 40), (51, 90)],
    )

    assert receipt.failed_intervals == [(91, 100)]
    assert receipt.policy_skipped_intervals == [(41, 50)]
    assert receipt.no_findings_intervals == [(1, 40), (51, 90)]
    assert receipt.successful_intervals == [(1, 40), (51, 90)]


def test_manifest_allows_relocated_receipts_of_same_archived_version():
    first = CoverageReceipt(
        commitment=COMMITMENT,
        path='/review/inbox/team-a/config-copy.py',
        inclusive=True,
        clean=[(1, 60)],
    )
    second = CoverageReceipt(
        commitment=COMMITMENT,
        path='/archive/extracted/renamed-config.py',
        inclusive=True,
        clean=[(55, 120)],
    )

    merged = merge_receipts([first, second], manifest=make_manifest())

    assert merged.commitment == COMMITMENT
    assert merged.successful_intervals == [(1, 120)]


def test_merge_refuses_unknown_or_changed_versions():
    manifest = make_manifest()
    relocated = CoverageReceipt(commitment=COMMITMENT, clean=[(1, 10)])
    changed = CoverageReceipt(commitment=OTHER_COMMITMENT, clean=[(1, 10)])

    with pytest.raises(Exception):
        merge_receipts([relocated, changed], manifest=manifest)
    assert try_merge_receipts([relocated, changed], manifest=manifest) is None
    assert try_merge_receipts([relocated, relocated]) is None


def test_removing_any_success_segment_replays_exact_interval_gap():
    segments = [
        (1, 20, 'no_findings'),
        (21, 40, 'no_findings'),
        (41, 60, 'no_findings'),
    ]
    receipt = CoverageReceipt(
        commitment=COMMITMENT,
        inclusive=True,
        segments=segments,
    )

    for index, expected_gap in enumerate([(1, 20), (21, 40), (41, 60)]):
        candidate = CoverageReceipt.from_dict(json.loads(receipt.to_json()))
        removed = candidate.segments.pop(index)
        gaps = candidate.coverage_gaps()
        assert gaps == [expected_gap]
        assert regressed_intervals(receipt, candidate) == [expected_gap]
        assert removed.is_success


def test_overlapping_segment_removal_only_reports_uncovered_difference():
    first = CoverageReceipt(
        commitment=COMMITMENT,
        inclusive=True,
        clean=[(1, 100)],
    )
    second = CoverageReceipt(
        commitment=COMMITMENT,
        inclusive=True,
        clean=[(1, 30), (71, 100)],
    )
    merged = merge_receipts([first, second], manifest=make_manifest())

    merged.remove_segment(first.segments[0])

    assert merged.coverage_gaps() == [(31, 70)]


def test_generic_intervals_are_half_open():
    receipt = CoverageReceipt(
        commitment=COMMITMENT,
        domain=(0, 100),
        clean=[(0, 40), (60, 100)],
    )

    assert receipt.coverage_gaps() == [(40, 60)]


def test_receipt_serialization_never_contains_file_fragments():
    raw_fragment = 'raw source fragment that must never be serialized'
    receipt = CoverageReceipt(
        commitment=StableCommitment.for_bytes(raw_fragment.encode()),
        inclusive=True,
        clean=[(1, 1)],
        snippet=raw_fragment,
        secret_value=raw_fragment,
        code_snippet=raw_fragment,
    )
    serialized = receipt.to_json()

    assert raw_fragment not in serialized
    payload = json.loads(serialized)
    assert payload['commitment'].startswith('sha256:')


def test_commitment_changes_with_file_version():
    first = StableCommitment.for_bytes(b'version one\n')
    second = StableCommitment.for_bytes(b'version two\n')

    assert first != second
    assert first.matches(str(first))
