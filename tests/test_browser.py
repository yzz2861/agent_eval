import pytest

from Evtx.Browser import EventBrowser, InvalidCursor, RecordRange
from fixtures import system_path


@pytest.fixture
def browser_archive():
    return system_path()


def test_overlapping_scopes_have_independent_counts_and_cursors(browser_archive):
    key = b"shared test key"
    duty = EventBrowser(browser_archive, 12049, 12057, role="duty", page_size=4, signing_key=key)
    lead = EventBrowser(browser_archive, 12054, 12062, role="lead", page_size=4, signing_key=key)

    assert duty.count() == 9
    assert lead.count() == 9

    duty_records = [record.record_number for record in duty.records()]
    lead_records = [record.record_number for record in lead.records()]
    assert duty_records == list(range(12049, 12058))
    assert lead_records == list(range(12054, 12063))

    duty_page = duty.page()
    with pytest.raises(InvalidCursor):
        lead.page(duty_page.next_cursor)


def test_range_change_invalidates_cursor_but_not_old_output(browser_archive):
    browser = EventBrowser(browser_archive, 12049, 12057, page_size=3)
    old_page = browser.page()

    browser.set_range(12100, 12104)

    assert browser.count() == 5
    assert browser.verify(old_page) is True
    assert old_page.verify() is True
    assert browser.verify(browser.range_receipt()) is True
    with pytest.raises(InvalidCursor):
        browser.page(cursor=old_page.next_cursor)


def test_records_fields_and_summaries_are_independently_scoped(browser_archive):
    no_records = EventBrowser(
        browser_archive,
        12049,
        12052,
        record_visibility=False,
        summary_visibility=("total_count",),
    )
    page = no_records.page()
    assert page.records == ()
    assert page.summary.to_dict() == {"total_count": 4}

    only_id = EventBrowser(
        browser_archive,
        12049,
        12052,
        field_visibility=("EventID",),
        summary_visibility=("first_record_number",),
    )
    page = only_id.page()
    assert all(set(record.fields) == {"EventID"} for record in page.records)
    assert page.summary.to_dict() == {"first_record_number": 12049}
    assert page.total_count is None


def test_provenance_maps_page_to_original_record_offsets(browser_archive):
    browser = EventBrowser(browser_archive, 12049, 12057, page_size=2)
    page = browser.page()

    assert page.provenance.page_first_record_number == 12049
    assert page.provenance.page_last_record_number == 12050
    assert page.provenance.record_numbers == (12049, 12050)
    assert page.provenance.first_offset < page.provenance.last_offset
    assert page.provenance.archive_digest == browser.archive_digest
    assert page.provenance.scope_last_record_number == 12057


def test_record_range_supports_named_boundaries():
    assert RecordRange(first_record=2, last_record=4).to_dict() == {
        "first_record": 2,
        "last_record": 4,
    }


def test_receipt_can_be_verified_by_a_fresh_browser(browser_archive):
    key = b"stable receipt key"
    original = EventBrowser(browser_archive, 12049, 12052, signing_key=key)
    page = original.page()

    verifier = EventBrowser(browser_archive, 12100, 12104, signing_key=key)
    assert verifier.verify(page.receipt) is True
    assert verifier.read_receipt(page.receipt)["scope_id"] == original.scope_id


def test_browser_accepts_an_in_memory_archive(system):
    browser = EventBrowser(system, 12049, 12051, page_size=2)
    try:
        assert browser.count() == 3
        assert [record.record_number for record in browser.records()] == [12049, 12050, 12051]
        assert browser.provenance().archive == "<memory>"
    finally:
        browser.close()


def test_zero_based_boundary_selects_archive_ordinals(browser_archive):
    browser = EventBrowser(browser_archive, 0, 2)
    assert [record.record_number for record in browser.records()] == [12049, 12050, 12051]
