"""Tests for the offline timezone re-verification layer (regipy.timezone_review).

Scenario: a remote Windows host was switched from UTC+9 to UTC+1 at 2023-06-01T00:00:00Z. Plugin output holds
local-time fields that the old script converted with the analyst machine's timezone. The tests below use a few
short event observations to pin down the review layer's behavior.
"""

import datetime as dt

import pytest

from regipy.registry import RegistryHive
from regipy.timezone_review import (
    STATUS_AMBIGUOUS,
    STATUS_INVALID,
    STATUS_RESOLVED,
    STATUS_UNRESOLVED,
    STATUS_UTC_PASSTHROUGH,
    TIME_REVIEW_KEY,
    OffsetSegment,
    TimezoneReviewError,
    review_entries,
    review_local_value,
    review_plugin_results,
    review_utc_value,
    run_plugins_with_time_review,
)

# Confirmed offset evidence for the analyzed host (bounds are UTC).
UTC_PLUS_9 = OffsetSegment(
    offset_minutes=540,
    evidence="SYSTEM timezone_data2: ActiveTimeBias=-540 (ControlSet001)",
    end_utc="2023-06-01T00:00:00+00:00",
)
UTC_PLUS_1 = OffsetSegment(
    offset_minutes=60,
    evidence="SYSTEM timezone_data2: ActiveTimeBias=-60 (ControlSet002, current)",
    start_utc="2023-06-01T00:00:00+00:00",
)
FULL_HISTORY = [UTC_PLUS_9, UTC_PLUS_1]

# The same history, slightly trimmed: both offsets are confirmed, but the transition time is not.
TRIMMED_HISTORY = [
    OffsetSegment(offset_minutes=540, evidence="SYSTEM timezone_data2: ActiveTimeBias=-540 (ControlSet001)"),
    OffsetSegment(offset_minutes=60, evidence="SYSTEM timezone_data2: ActiveTimeBias=-60 (ControlSet002, current)"),
]


class TestLocalValueReview:
    def test_resolved_to_single_candidate_on_correct_day(self):
        # 30 minutes after local midnight: converting with the wrong timezone would move this to another day.
        report = review_local_value("2023-03-15T00:20:00", FULL_HISTORY)

        assert report["status"] == STATUS_RESOLVED
        assert report["raw_value"] == "2023-03-15T00:20:00"
        assert report["candidates"] == [
            {
                "utc": "2023-03-14T15:20:00+00:00",
                "offset_minutes": 540,
                "evidence": [UTC_PLUS_9.evidence],
            }
        ]

    def test_clock_rollback_repeated_window_yields_two_candidates(self):
        # The +9 -> +1 switch made 2023-06-01 01:00-09:00 local happen twice; 05:30 is inside the repeated window.
        report = review_local_value("2023-06-01T05:30:00", FULL_HISTORY)

        assert report["status"] == STATUS_AMBIGUOUS
        assert [c["utc"] for c in report["candidates"]] == [
            "2023-05-31T20:30:00+00:00",
            "2023-06-01T04:30:00+00:00",
        ]
        assert report["candidates"][0]["evidence"] == [UTC_PLUS_9.evidence]
        assert report["candidates"][1]["evidence"] == [UTC_PLUS_1.evidence]

    def test_trimmed_history_turns_exact_time_into_candidate_set(self):
        # With the transition time trimmed away, the previously resolved observation becomes a candidate set,
        # and every candidate still carries the evidence that produced it.
        report = review_local_value("2023-03-15T00:20:00", TRIMMED_HISTORY)

        assert report["status"] == STATUS_AMBIGUOUS
        assert [c["utc"] for c in report["candidates"]] == [
            "2023-03-14T15:20:00+00:00",
            "2023-03-14T23:20:00+00:00",
        ]
        assert all(c["evidence"] for c in report["candidates"])
        assert report["raw_value"] == "2023-03-15T00:20:00"

    def test_partial_history_leaves_uncovered_value_unresolved(self):
        # Only the post-change segment is known: an observation before it cannot be converted at all.
        report = review_local_value("2023-03-15T00:20:00", [UTC_PLUS_1])

        assert report["status"] == STATUS_UNRESOLVED
        assert report["candidates"] == []
        assert report["raw_value"] == "2023-03-15T00:20:00"

    def test_unparseable_value_is_invalid_and_raw_preserved(self):
        report = review_local_value("not-a-timestamp", FULL_HISTORY)

        assert report["status"] == STATUS_INVALID
        assert report["raw_value"] == "not-a-timestamp"
        assert report["candidates"] == []

    def test_aware_value_in_local_field_is_rejected(self):
        report = review_local_value("2023-03-15T00:20:00+00:00", FULL_HISTORY)

        assert report["status"] == STATUS_INVALID
        assert "UTC field" in report["reason"]

    def test_datetime_object_input_is_accepted(self):
        report = review_local_value(dt.datetime(2023, 6, 2, 10, 0, 0), FULL_HISTORY)

        assert report["status"] == STATUS_RESOLVED
        assert report["candidates"][0]["utc"] == "2023-06-02T09:00:00+00:00"
        assert report["raw_value"] == dt.datetime(2023, 6, 2, 10, 0, 0)

    def test_dict_segments_are_accepted(self):
        report = review_local_value(
            "2023-06-02T10:00:00",
            [{"offset_minutes": 60, "evidence": "event log 4624 corroboration", "start_utc": "2023-06-01T00:00:00Z"}],
        )

        assert report["status"] == STATUS_RESOLVED
        assert report["candidates"][0]["evidence"] == ["event log 4624 corroboration"]


class TestUtcValueReview:
    def test_existing_utc_field_passes_through_unconverted(self):
        report = review_utc_value("2023-06-02T10:00:00+00:00")

        assert report["status"] == STATUS_UTC_PASSTHROUGH
        assert report["utc"] == "2023-06-02T10:00:00+00:00"
        assert report["raw_value"] == "2023-06-02T10:00:00+00:00"

    def test_z_suffix_is_normalized(self):
        report = review_utc_value("2023-06-02T10:00:00Z")

        assert report["utc"] == "2023-06-02T10:00:00+00:00"

    def test_naive_value_is_flagged_as_assumed_utc(self):
        report = review_utc_value("2023-06-02T10:00:00")

        assert report["status"] == STATUS_UTC_PASSTHROUGH
        assert report["assumed_utc"] is True


class TestEntryAndPluginResultsReview:
    def test_entry_review_keeps_originals_and_never_mutates_input(self):
        entry = {
            "path": r"\Device\HarddiskVolume1\Windows\Temp\evil.exe",
            "last_mod_date": "2023-06-01T05:30:00",
            "first_seen_utc": "2023-06-01T04:30:00+00:00",
        }

        (reviewed,) = review_entries(
            [entry],
            local_time_fields=["last_mod_date"],
            offset_segments=FULL_HISTORY,
            utc_fields=["first_seen_utc"],
        )

        assert TIME_REVIEW_KEY not in entry  # input untouched
        assert reviewed["last_mod_date"] == "2023-06-01T05:30:00"  # original field intact
        report = reviewed[TIME_REVIEW_KEY]
        assert report["last_mod_date"]["status"] == STATUS_AMBIGUOUS
        assert report["last_mod_date"]["raw_value"] == "2023-06-01T05:30:00"
        assert report["first_seen_utc"]["status"] == STATUS_UTC_PASSTHROUGH

    def test_undeclared_fields_are_not_reviewed(self):
        (reviewed,) = review_entries(
            [{"timestamp": "2023-06-02T10:00:00", "name": "run_key"}],
            local_time_fields=["other_field"],
            offset_segments=FULL_HISTORY,
        )

        assert TIME_REVIEW_KEY not in reviewed
        assert reviewed == {"timestamp": "2023-06-02T10:00:00", "name": "run_key"}

    def test_field_declared_as_both_local_and_utc_raises(self):
        with pytest.raises(TimezoneReviewError):
            review_entries([{"ts": "2023-06-02T10:00:00"}], ["ts"], FULL_HISTORY, utc_fields=["ts"])

    def test_plugin_results_review_passes_dict_shaped_output_through(self):
        plugin_results = {
            "shimcache": [{"last_mod_date": "2023-06-02T10:00:00", "path": "a.exe"}],
            "timezone_data2": {"ControlSet001": {"ActiveTimeBias": -540}},
            "broken_plugin": {"error": "boom"},
        }

        reviewed = review_plugin_results(plugin_results, ["last_mod_date"], FULL_HISTORY)

        assert reviewed["shimcache"][0][TIME_REVIEW_KEY]["last_mod_date"]["status"] == STATUS_RESOLVED
        assert reviewed["timezone_data2"] == plugin_results["timezone_data2"]
        assert reviewed["broken_plugin"] == {"error": "boom"}


class TestPluginEntryPointIntegration:
    def test_run_plugins_with_time_review_on_system_hive(self, system_hive):
        # regipy's shimcache plugin emits tz-aware UTC timestamps, so the field is declared as UTC and must
        # pass through unconverted; the local-time candidate logic is covered by the unit tests above.
        reviewed = run_plugins_with_time_review(
            RegistryHive(system_hive),
            plugins=["shimcache"],
            local_time_fields=[],
            utc_fields=["last_mod_date"],
            offset_segments=FULL_HISTORY,
        )

        entries = reviewed["shimcache"]
        assert entries
        for entry in entries:
            report = entry[TIME_REVIEW_KEY]["last_mod_date"]
            assert report["raw_value"] == entry["last_mod_date"]
            assert report["status"] == STATUS_UTC_PASSTHROUGH
            assert report["utc"] == entry["last_mod_date"]
