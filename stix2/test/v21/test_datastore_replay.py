"""Tests for offline STIX2 data source filter replay."""

import pytest

from stix2 import (
    Filter, MemorySource, MemoryStore, ReplayEntry, SearchRecord,
    record_search, replay_search,
)
from stix2.datastore.replay import (
    REASON_FILTERED_OUT, REASON_MISSING_PRESERVED_OBJECT,
    REASON_OUTSIDE_PRESERVATION_WINDOW, REASON_VERSION_NOT_PRESERVED,
)
from stix2.utils import format_datetime
from stix2.v21 import Indicator


def _indicator(stix_id, modified, name="Malicious site hosting downloader"):
    return Indicator(
        id=stix_id,
        created="2017-01-27T13:49:53.935Z",
        modified=modified,
        name=name,
        indicator_types=["malicious-activity"],
        pattern="[url:value = 'http://example.com']",
        pattern_type="stix",
        valid_from="2017-01-27T13:49:53.935Z",
    )


INDICATOR_1 = "indicator--00000000-0000-4000-8000-000000000001"
INDICATOR_2 = "indicator--00000000-0000-4000-8000-000000000002"
INDICATOR_3 = "indicator--00000000-0000-4000-8000-000000000003"

SEARCH_TIME = "2017-02-01T00:00:00.000Z"


@pytest.fixture
def source():
    return MemoryStore(
        stix_data=[
            _indicator(INDICATOR_1, "2017-01-27T13:49:53.935Z"),
            _indicator(
                INDICATOR_2, "2017-01-28T13:49:53.935Z",
                name="Benign site",
            ),
        ],
    )


def test_record_search_binds_filters_range_and_version(source):
    query = [Filter("type", "=", "indicator"), Filter("name", "=", "Malicious site hosting downloader")]

    record = source.record_search(
        query=query, search_time=SEARCH_TIME, spec_version="2.1",
    )

    assert isinstance(record, SearchRecord)
    assert record.search_time == SEARCH_TIME
    assert record.spec_version == "2.1"
    assert len(record.filters) == 2
    assert set(record.preserved_ids()) == {INDICATOR_1, INDICATOR_2}
    assert record.manifest[INDICATOR_1] == ["2017-01-27T13:49:53.935Z"]


def test_replay_reproduces_original_matches(source):
    query = [Filter("type", "=", "indicator"), Filter("name", "=", "Malicious site hosting downloader")]
    record = source.record_search(query=query, search_time=SEARCH_TIME)

    receipt = source.replay_search(record)

    assert [obj["id"] for obj in receipt.results] == [INDICATOR_1]
    assert receipt.results == source.query(query)
    assert len(receipt.excluded) == 1
    entry = receipt.excluded[0]
    assert entry.id == INDICATOR_2
    assert entry.reason == REASON_FILTERED_OUT
    assert "name" in entry.details
    assert receipt.quarantined == []
    assert receipt.out_of_scope == []


def test_late_ingested_object_is_excluded_and_explained(source):
    query = [Filter("type", "=", "indicator")]
    record = source.record_search(query=query, search_time=SEARCH_TIME)

    # A month later, a new object is ingested into the live store.
    late_indicator = _indicator(INDICATOR_3, "2017-03-01T13:49:53.935Z")
    source.add(late_indicator)

    # The original (frozen) query must still return the same two objects.
    receipt = source.replay_search(record, extra_objects=[late_indicator])

    assert {obj["id"] for obj in receipt.results} == {INDICATOR_1, INDICATOR_2}
    assert len(receipt.out_of_scope) == 1
    entry = receipt.out_of_scope[0]
    assert isinstance(entry, ReplayEntry)
    assert entry.id == INDICATOR_3
    assert entry.reason == REASON_OUTSIDE_PRESERVATION_WINDOW
    assert SEARCH_TIME in entry.details

    explanations = receipt.explain(INDICATOR_3)
    assert len(explanations) == 1
    assert REASON_OUTSIDE_PRESERVATION_WINDOW in explanations[0]


def test_replay_does_not_substitute_current_store_state(source):
    query = [Filter("type", "=", "indicator")]
    record = source.record_search(query=query, search_time=SEARCH_TIME)

    # Simulate replay data going missing after preservation.
    partial_record = SearchRecord(
        filters=record.filters,
        objects=[record.get_object(INDICATOR_1)],
        manifest=record.manifest,
        search_time=record.search_time,
        spec_version=record.spec_version,
    )

    # The source still holds both objects, but replay must not use them.
    receipt = replay_search(partial_record)

    assert [obj["id"] for obj in receipt.results] == [INDICATOR_1]
    assert len(receipt.quarantined) == 1
    missing = receipt.quarantined[0]
    assert missing.id == INDICATOR_2
    assert missing.reason == REASON_MISSING_PRESERVED_OBJECT
    assert receipt.unverifiable is receipt.quarantined
    assert receipt.out_of_scope == []

    explanation = receipt.explain(INDICATOR_2)[0]
    assert REASON_MISSING_PRESERVED_OBJECT in explanation


def test_new_version_after_window_is_not_replayed(source):
    query = [Filter("type", "=", "indicator")]
    record = source.record_search(query=query, search_time=SEARCH_TIME)

    updated = _indicator(INDICATOR_1, "2017-03-05T13:49:53.935Z", name="Updated name")

    receipt = replay_search(record, extra_objects=[updated])

    version_entries = [
        entry for entry in receipt.out_of_scope
        if entry.id == INDICATOR_1
    ]
    assert len(version_entries) == 1
    assert version_entries[0].version == "2017-03-05T13:49:53.935Z"
    assert version_entries[0].reason == REASON_VERSION_NOT_PRESERVED
    assert [
        format_datetime(obj["modified"])
        for obj in receipt.results if obj["id"] == INDICATOR_1
    ] == ["2017-01-27T13:49:53.935Z"]


def test_record_round_trips_through_json(source):
    query = [Filter("name", "=", "Malicious site hosting downloader")]
    record = source.record_search(
        query=query, search_time=SEARCH_TIME, spec_version="2.1",
    )

    restored = SearchRecord.from_json(record.to_json())

    assert restored.search_time == record.search_time
    assert restored.spec_version == record.spec_version
    assert restored.filters == record.filters
    assert restored.manifest == record.manifest

    receipt = replay_search(restored)
    assert [obj["id"] for obj in receipt.results] == [INDICATOR_1]


def test_memory_store_delegates_replay():
    store = MemoryStore(stix_data=[_indicator(INDICATOR_1, "2017-01-27T13:49:53.935Z")])
    record = store.record_search(
        query=[Filter("type", "=", "indicator")], search_time=SEARCH_TIME,
    )

    receipt = store.replay_search(record)

    assert [obj["id"] for obj in receipt.results] == [INDICATOR_1]
