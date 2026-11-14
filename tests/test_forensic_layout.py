"""
Forensic layout validation tests.

Each corrupted sample is compared against the same parser under both the
strict forensic and best-effort recovery modes.  The assertions use issue
codes, integer offsets and record numbers only; they never print raw record
bytes, so failure output cannot leak whole binary blobs.
"""

import Evtx.Evtx as evtx


def _chunk(data):
    fh = evtx.FileHeader(data, 0x0)
    return next(fh.chunks())


def _strict_report(data):
    return _chunk(data).validate(mode=evtx.STRICT_FORENSIC, chunk_index=0)


def _recovery_report(data):
    return _chunk(data).validate(mode=evtx.RECOVERY, chunk_index=0)


def test_overlapping_offset_table_is_classified(overlapping_evtx):
    report = _strict_report(overlapping_evtx)
    assert report.trusted is False
    assert evtx.ISSUE_OVERLAPPING_RECORDS in report.issue_codes()
    assert evtx.ISSUE_UNSORTED_OFFSETS in report.issue_codes()
    # strict forensic mode suppresses every record from an untrusted chunk
    assert list(_chunk(overlapping_evtx).records(mode=evtx.STRICT_FORENSIC)) == []

    recovery = _recovery_report(overlapping_evtx)
    assert recovery.trusted is False
    recovered = recovery.records
    assert all(record.trusted is False for record in recovered)
    assert all(record.analysis_mode == evtx.RECOVERY for record in recovered)


def test_out_of_order_table_is_classified(out_of_order_evtx):
    report = _strict_report(out_of_order_evtx)
    assert report.trusted is False
    assert evtx.ISSUE_UNSORTED_OFFSETS in report.issue_codes()
    assert evtx.ISSUE_OVERLAPPING_RECORDS in report.issue_codes()
    assert list(_chunk(out_of_order_evtx).records(mode=evtx.STRICT_FORENSIC)) == []


def test_slack_pseudo_record_is_never_iterated(slack_pseudo_record_evtx):
    chunk = _chunk(slack_pseudo_record_evtx)
    strict = list(chunk.records(mode=evtx.STRICT_FORENSIC))
    recovery = list(chunk.records(mode=evtx.RECOVERY))

    # the legitimate single record is all either mode may surface
    assert [record.record_num() for record in strict] == [1]
    assert [record.record_num() for record in recovery] == [1]
    assert all(record.trusted for record in strict)

    # the planted slack record stays visible to the auditor but never becomes
    # an iterable event
    assert chunk.slack_record_offsets(mode=evtx.STRICT_FORENSIC)
    iterated_offsets = {record.chunk_relative_offset() for record in strict + recovery}
    assert not (set(chunk.slack_record_offsets()) & iterated_offsets)


def test_truncated_chunk_is_classified(truncated_evtx):
    chunk = _chunk(truncated_evtx)
    assert chunk.is_truncated() is True
    report = chunk.validate(mode=evtx.STRICT_FORENSIC, chunk_index=0)
    assert report.trusted is False
    assert evtx.ISSUE_TRUNCATED_CHUNK in report.issue_codes()
    assert list(chunk.records(mode=evtx.STRICT_FORENSIC)) == []
    assert list(chunk.records(mode=evtx.RECOVERY)) == []


def test_zero_length_record_is_classified(zero_length_evtx):
    report = _strict_report(zero_length_evtx)
    assert report.trusted is False
    assert evtx.ISSUE_ZERO_LENGTH_RECORD in report.issue_codes()
    assert list(_chunk(zero_length_evtx).records(mode=evtx.STRICT_FORENSIC)) == []


def test_duplicate_offset_is_classified(duplicate_offset_evtx):
    report = _strict_report(duplicate_offset_evtx)
    assert report.trusted is False
    assert evtx.ISSUE_DUPLICATE_OFFSET in report.issue_codes()
    assert evtx.ISSUE_ZERO_LENGTH_RECORD in report.issue_codes()


def test_cross_chunk_reference_is_classified(cross_chunk_evtx):
    report = _strict_report(cross_chunk_evtx)
    assert report.trusted is False
    assert evtx.ISSUE_OFFSET_OUTSIDE_CHUNK in report.issue_codes()
    assert list(_chunk(cross_chunk_evtx).records(mode=evtx.STRICT_FORENSIC)) == []


def test_reports_never_contain_raw_bytes(overlapping_evtx, truncated_evtx):
    for data in (overlapping_evtx, truncated_evtx):
        report = _strict_report(data)
        rendered = repr(report) + "".join(str(issue) for issue in report.issues)
        # issue rendering only carries codes and integer offsets, never buffers
        assert "ElfChnk" not in rendered
        assert b"\x2a\x2a" not in rendered.encode("utf-8", "ignore")


def test_mode_markers_are_explicit(system):
    fh = evtx.FileHeader(system, 0x0)
    chunk = next(fh.chunks())
    strict = list(chunk.records(mode=evtx.STRICT_FORENSIC))
    recovery = list(chunk.records(mode=evtx.RECOVERY))
    assert strict
    assert len(strict) == len(recovery)
    assert all(record.analysis_mode == evtx.STRICT_FORENSIC for record in strict)
    assert all(record.analysis_mode == evtx.RECOVERY for record in recovery)
    assert all(record.trusted for record in strict)
    assert all(record.trusted for record in recovery)


def test_corrupt_chunk_magic_is_classified(corrupt_chunk_evtx):
    chunk = _chunk(corrupt_chunk_evtx)
    report = chunk.validate(mode=evtx.STRICT_FORENSIC, chunk_index=0)
    assert report.trusted is False
    assert evtx.ISSUE_CORRUPT_CHUNK in report.issue_codes()
    assert list(chunk.records(mode=evtx.STRICT_FORENSIC)) == []


def test_bad_record_magic_is_classified(bad_record_magic_evtx):
    report = _strict_report(bad_record_magic_evtx)
    assert report.trusted is False
    assert evtx.ISSUE_BAD_RECORD_MAGIC in report.issue_codes()


def test_record_number_regression_is_non_fatal(record_number_regression_evtx):
    chunk = _chunk(record_number_regression_evtx)
    report = chunk.validate(mode=evtx.STRICT_FORENSIC)
    assert evtx.ISSUE_RECORD_NUMBER_NOT_INCREASING in report.issue_codes()
    # semantic anomalies are recorded, not treated as fatal layout corruption
    assert report.trusted is True
    records = list(chunk.records(mode=evtx.STRICT_FORENSIC))
    assert [record.record_num() for record in records] == [100, 50]
    assert all(record.trusted for record in records)


def test_timestamp_regression_is_non_fatal(timestamp_regression_evtx):
    chunk = _chunk(timestamp_regression_evtx)
    report = chunk.validate(mode=evtx.STRICT_FORENSIC)
    assert evtx.ISSUE_TIMESTAMP_NOT_INCREASING in report.issue_codes()
    assert report.trusted is True
    assert len(list(chunk.records(mode=evtx.STRICT_FORENSIC))) == 2


def test_record_sets_match_between_modes_for_clean_file(issue_38_bytes):
    chunk = _chunk(issue_38_bytes)
    strict = list(chunk.records(mode=evtx.STRICT_FORENSIC))
    recovery = list(chunk.records(mode=evtx.RECOVERY))
    assert [record.record_num() for record in strict] == [record.record_num() for record in recovery]
    assert [record.chunk_relative_offset() for record in strict] == [
        record.chunk_relative_offset() for record in recovery
    ]


def test_corruption_changes_only_the_untrusted_record_set(overlapping_evtx):
    corrupted = _chunk(overlapping_evtx)

    strict_nums = [record.record_num() for record in corrupted.records(mode=evtx.STRICT_FORENSIC)]
    recovery_nums = [record.record_num() for record in corrupted.records(mode=evtx.RECOVERY)]

    # strict mode removes the untrusted chunk's records; recovery keeps the
    # physically parseable record but flags it, and the hidden forged record
    # (number 999) is excluded from both record sets
    assert strict_nums == []
    assert 999 not in recovery_nums
    assert all(not record.trusted for record in corrupted.records(mode=evtx.RECOVERY))
