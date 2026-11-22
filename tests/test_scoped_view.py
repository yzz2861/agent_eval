import os
import mmap
import contextlib

import pytest

import Evtx.Evtx as evtx
from Evtx.ScopedView import (
    AggregateNotVisible,
    CursorError,
    CursorScopeMismatch,
    ScopedArchive,
    ScopedEventView,
    ScopeMismatch,
)

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
SECURITY = os.path.join(DATA_DIR, "security.evtx")


def test_record_range_and_visible_count():
    view = ScopedEventView(SECURITY, 10, 19, role="investigator")
    assert view.count == 10
    assert view.count() == 10
    assert len(view) == 10

    page = view.records()
    assert [record.record_num for record in page] == list(range(10, 20))
    assert page.total == 10
    assert page[0].ordinal == 1
    assert view.get_record_by_ordinal(1).record_num == 10
    assert view.get_record_by_ordinal(10).record_num == 19
    assert view.get_record_by_ordinal(11) is None
    assert view.get_record(10).record_num == 10
    assert view[0].record_num == 10
    assert view.get_record(9) is None
    assert view.get_by_record_number(20) is None
    assert view.contains_record(10) is True
    assert view.contains_record(9) is False


def test_field_allowlist_and_xml_redaction():
    view = ScopedEventView(
        SECURITY,
        21,
        21,
        role="investigator",
        fields=["System/EventID", 'EventData/Data[@Name="SubjectUserName"]'],
    )
    record = view.get_record_by_ordinal(1)
    assert record.get("System/EventID") == "4672"
    assert record.get('EventData/Data[@Name="SubjectUserName"]') == "LOCAL SERVICE"
    assert record.get("System/Computer") is None
    assert record.field("System/EventID") == "4672"

    xml = str(record.xml)
    assert "4672" in xml
    assert "LOCAL SERVICE" in xml
    assert "37L4247F27-25" not in xml
    assert "EventData" in xml


def test_field_redaction_and_deny():
    redacted = ScopedEventView(
        SECURITY,
        21,
        21,
        role="investigator",
        redact_fields=['EventData/Data[@Name="SubjectUserName"]'],
    )
    record = redacted.get_record_by_ordinal(1)
    assert record.get('EventData/Data[@Name="SubjectUserName"]') == "[REDACTED]"
    xml = str(record.xml)
    assert "[REDACTED]" in xml
    assert "LOCAL SERVICE" not in xml
    with pytest.raises(AggregateNotVisible):
        redacted.count_by('EventData/Data[@Name="SubjectUserName"]')

    denied = ScopedEventView(SECURITY, 21, 21, role="investigator", exclude_fields=["System/Computer"])
    assert denied.get_record_by_ordinal(1).get("System/Computer") is None
    assert "37L4247F27-25" not in str(denied.get_record_by_ordinal(1).xml)


def test_aggregates_use_only_visible_records():
    view = ScopedEventView(SECURITY, 1, 50, role="investigator")
    assert view.aggregate("count") == 50
    groups = view.count_by("System/EventID")
    assert sum(groups.values()) == 50
    assert all(count >= 1 for count in groups.values())

    suppressed = ScopedEventView(SECURITY, 1, 50, role="investigator", min_group_size=2)
    groups = suppressed.count_by("System/EventID")
    assert all(count >= 2 for count in groups.values())
    assert sum(groups.values()) <= 50

    summary = view.summary()
    assert summary["count"] == 50
    assert summary["first_record_num"] == 1
    assert summary["last_record_num"] == 50


def test_aggregate_visibility_is_independent():
    view = ScopedEventView(SECURITY, 1, 10, role="investigator", aggregates=["summary"])
    assert view.summary()["count"] == 10
    with pytest.raises(AggregateNotVisible):
        view.aggregate("count")
    with pytest.raises(AggregateNotVisible):
        view.count_by("System/EventID")

    count_only = ScopedEventView(SECURITY, 1, 10, role="investigator", aggregates=["count"])
    assert count_only.aggregate("count") == 10
    with pytest.raises(AggregateNotVisible):
        count_only.count_by("System/EventID")


def test_cursor_pagination_and_role_isolation():
    operator = ScopedEventView(SECURITY, 1, 20, role="operator")
    lead = ScopedEventView(SECURITY, 1, 20, role="investigator")

    first = operator.records(limit=7)
    assert [record.record_num for record in first] == list(range(1, 8))
    assert first.has_more
    assert first.next_cursor

    second = operator.records(cursor=first.next_cursor, limit=7)
    assert [record.record_num for record in second] == list(range(8, 15))
    assert second.has_more

    with pytest.raises(CursorScopeMismatch):
        lead.records(cursor=first.next_cursor)
    with pytest.raises(CursorError):
        operator.records(cursor=7)


def test_scope_change_verifies_old_output_without_old_cursor():
    broad = ScopedEventView(SECURITY, 1, 20, role="investigator")
    old_page = broad.records(limit=5)
    old_snapshot = broad.snapshot()
    assert old_page.total == 20

    narrow = ScopedEventView(SECURITY, 10, 20, role="investigator")
    assert narrow.verify_output(old_page) is True
    assert narrow.verify_output(old_snapshot) is True
    assert narrow.verify_previous(old_snapshot) is True

    result = narrow.reconcile(old_page)
    assert result.valid is True
    assert result.old_count == 5
    assert result.not_visible == 5
    assert result.matched == 0
    assert result.current_count == 11

    with pytest.raises(CursorScopeMismatch):
        narrow.records(cursor=old_page.next_cursor)
    with pytest.raises(CursorError):
        narrow.records(cursor=old_page.total)

    assert narrow.count == 11
    assert narrow.records(limit=100).total == 11

    overlap_page = broad.records(offset=9, limit=5)
    overlap = narrow.reconcile(overlap_page)
    assert overlap.valid is True
    assert overlap.matched == 5
    assert overlap.changed == 0
    assert overlap.not_visible == 0


def test_overlapping_roles_get_independent_views():
    operator = ScopedEventView(SECURITY, 1, 15, role="operator")
    lead = ScopedEventView(SECURITY, 8, 22, role="investigator")
    assert operator.count == 15
    assert lead.count == 15

    op_page = operator.records(limit=4)
    lead_page = lead.records(limit=4)
    assert [record.record_num for record in op_page] == [1, 2, 3, 4]
    assert [record.record_num for record in lead_page] == [8, 9, 10, 11]

    with pytest.raises(CursorScopeMismatch):
        lead.records(cursor=op_page.next_cursor)
    with pytest.raises(CursorScopeMismatch):
        operator.records(cursor=lead_page.next_cursor)

    op_provenance = operator.provenance()
    lead_provenance = lead.provenance()
    assert "record_start" not in op_provenance
    assert lead_provenance["record_start"] == 8
    assert lead_provenance["record_end"] == 22
    assert operator.get_record_by_ordinal(1).origin is None
    origin = lead.get_record_by_ordinal(1).origin
    assert origin["record_num"] == 8
    assert origin["absolute_offset"] is not None
    assert origin["source_digest"]


def test_signed_scope_is_bound_to_archive_and_role():
    with ScopedArchive(SECURITY) as archive:
        scope = archive.scope(1, 10, role="operator")
        assert archive.verify_scope(scope) is True
        view = archive.browse(scope)
        assert view.count == 10
        with pytest.raises(ScopeMismatch):
            archive.browse(scope, role="investigator")

    with ScopedArchive(SECURITY) as other:
        assert other.verify_scope(scope) is True
        assert other.browse(scope).count == 10


def test_mmap_and_file_header_sources():
    with open(SECURITY, "rb") as handle:
        with contextlib.closing(mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)) as buffer:
            view = ScopedEventView(buffer, 1, 3, role="operator")
            assert view.count == 3
            assert [record.record_num for record in view.records()] == [1, 2, 3]

            header = evtx.FileHeader(buffer, 0x0)
            header_view = ScopedEventView(header, 5, 7, role="investigator")
            assert header_view.count == 3
            assert header_view.get_record(6).record_num == 6


def test_receipt_round_trip_and_leaf_aggregate():
    view = ScopedEventView(
        SECURITY,
        21,
        40,
        role="investigator",
        fields=["System/EventID", 'EventData/Data[@Name="SubjectUserName"]'],
    )
    page = view.records(limit=5)
    receipt = page.to_dict()["receipt"]
    assert view.verify_output(receipt) is True
    assert view.reconcile(page).matched == 5
    assert view.aggregate("count_by", field="EventID")
    assert view.count_by("SubjectUserName")
