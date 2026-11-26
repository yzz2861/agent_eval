"""Tests for the sigma.replay dual-clock replay module."""

from datetime import datetime, timedelta, timezone

import pytest

from sigma.collection import SigmaCollection
from sigma.matching import Event, EventLogSource, SigmaMatcher
from sigma.replay import (
    DualClockReplay,
    MaintenanceSchedule,
    MaintenanceWindow,
    ObservationStatus,
    ReplayEventKind,
)


UTC = timezone.utc


def instant(hour: int, minute: int = 0, second: int = 0) -> datetime:
    return datetime(2026, 11, 27, hour, minute, second, tzinfo=UTC)


def make_event(timestamp: datetime, command_line: str = "benign.exe") -> Event:
    return Event(
        timestamp=timestamp,
        logsource=EventLogSource(category="process_creation", product="windows"),
        data={"CommandLine": command_line},
    )


@pytest.fixture
def rule_collection():
    return SigmaCollection.from_yaml(
        """
title: Mimikatz Rule
name: mimikatz_rule
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: "mimikatz"
    condition: selection
"""
    )


class TestMaintenanceSchedule:
    def test_window_requires_aware_bounds(self):
        with pytest.raises(ValueError):
            MaintenanceWindow(datetime(2026, 11, 27, 1), instant(2))

    def test_window_requires_positive_duration(self):
        with pytest.raises(ValueError):
            MaintenanceWindow(instant(2), instant(2))

    def test_half_open_window_contains(self):
        window = MaintenanceWindow(instant(2), instant(3))
        assert window.contains(instant(2)) is True
        assert window.contains(instant(2, 59, 59)) is True
        assert window.contains(instant(3)) is False

    def test_records_are_preserved_but_overlaps_are_coalesced(self):
        first = MaintenanceWindow(instant(2), instant(3), reason="upgrade")
        second = MaintenanceWindow(instant(2, 30), instant(4), reason="rollback")
        schedule = MaintenanceSchedule([second, first])

        assert schedule.windows == (first, second)
        assert len(schedule.intervals) == 1
        assert schedule.intervals[0].start == instant(2)
        assert schedule.intervals[0].end == instant(4)

    def test_touching_windows_coalesce_for_clock_math(self):
        schedule = MaintenanceSchedule(
            [MaintenanceWindow(instant(2), instant(3)), MaintenanceWindow(instant(3), instant(4))]
        )
        assert len(schedule.windows) == 2
        assert len(schedule.intervals) == 1
        assert schedule.maintenance_between(instant(1), instant(5)) == timedelta(hours=2)

    def test_observed_time_removes_maintenance_before_instant(self):
        schedule = MaintenanceSchedule([MaintenanceWindow(instant(2), instant(3))])
        assert schedule.to_observed_time(instant(1)) == instant(1)
        assert schedule.to_observed_time(instant(2)) == instant(2)
        assert schedule.to_observed_time(instant(2, 30)) == instant(2)
        assert schedule.to_observed_time(instant(3)) == instant(2)
        assert schedule.to_observed_time(instant(4)) == instant(3)
        assert schedule.observed_span(instant(1), instant(4)) == timedelta(hours=2)

    def test_unapproved_window_does_not_pause_the_clock(self):
        schedule = MaintenanceSchedule(
            [MaintenanceWindow(instant(2), instant(3), approved=False)]
        )
        assert schedule.is_maintenance(instant(2, 30)) is False
        assert schedule.to_observed_time(instant(3)) == instant(3)
        assert schedule.observed_span(instant(1), instant(4)) == timedelta(hours=3)

    def test_uncovered_intervals_split_around_maintenance(self):
        schedule = MaintenanceSchedule([MaintenanceWindow(instant(2), instant(3))])
        assert schedule.uncovered_intervals(instant(1), instant(4)) == (
            (instant(1), instant(2)),
            (instant(3), instant(4)),
        )

    def test_replace_returns_independent_schedule(self):
        first = MaintenanceSchedule([MaintenanceWindow(instant(2), instant(3))])
        second = first.replace([MaintenanceWindow(instant(5), instant(6))])
        assert len(first) == 1
        assert first.windows[0].start == instant(2)
        assert second.windows[0].start == instant(5)


class TestBucketsAndBoundaries:
    def test_events_land_by_event_time_not_input_order(self):
        schedule = MaintenanceSchedule([MaintenanceWindow(instant(2), instant(3))])
        replay = DualClockReplay(schedule)
        result = replay.run([make_event(instant(4, 10)), make_event(instant(1, 10))])

        assert [entry.wall_time for entry in result.real_events] == [
            instant(1, 10),
            instant(4, 10),
        ]
        assert [entry.landing_point for entry in result.real_events] == [instant(1), instant(4)]

    def test_bucket_is_half_open_and_boundary_lands_in_next_bucket(self):
        replay = DualClockReplay(MaintenanceSchedule(), bucket_size=timedelta(hours=1))
        assert replay.bucket_bounds(instant(2)) == (instant(2), instant(3))
        assert replay.bucket_bounds(instant(2, 59, 59)) == (instant(2), instant(3))
        assert replay.bucket_bounds(instant(3)) == (instant(3), instant(4))

    def test_synthetic_boundary_markers_report_both_clock_readings(self):
        window = MaintenanceWindow(instant(2), instant(3))
        result = DualClockReplay(MaintenanceSchedule([window])).run(
            [make_event(instant(1)), make_event(instant(4))]
        )

        markers = result.synthetic_events
        assert [marker.kind for marker in markers] == [
            ReplayEventKind.WINDOW_START,
            ReplayEventKind.WINDOW_END,
        ]
        start_marker, end_marker = markers
        assert start_marker.wall_time == instant(2)
        assert start_marker.observed_time == instant(2)
        assert start_marker.landing_point == instant(2)
        assert end_marker.wall_time == instant(3)
        assert end_marker.observed_time == instant(2)
        assert end_marker.landing_point == instant(3)
        assert all(marker.status is ObservationStatus.BOUNDARY for marker in markers)
        assert all(marker.window == window for marker in markers)

    def test_maintenance_only_replay_still_emits_both_boundaries(self):
        schedule = MaintenanceSchedule([MaintenanceWindow(instant(2), instant(3))])
        result = DualClockReplay(schedule).run([])

        assert len(result.synthetic_events) == 2
        assert result.observation_span == timedelta()
        assert result.unobservable_span == timedelta()
        assert result.gaps == ()

    def test_bucket_at_returns_landing_bucket(self):
        result = DualClockReplay(MaintenanceSchedule()).run([make_event(instant(2, 30))])
        bucket = result.bucket_at(instant(2, 45))
        assert bucket is not None
        assert bucket.start == instant(2)
        assert bucket.end == instant(3)
        assert len(bucket.counted_events) == 1
        assert bucket.suppressed_events == ()


class TestDualClockReplay:
    def test_events_are_classified_as_observed_or_suppressed(self, rule_collection):
        schedule = MaintenanceSchedule([MaintenanceWindow(instant(2), instant(3))])
        events = [
            make_event(instant(1)),
            make_event(instant(2, 30), "mimikatz.exe"),
            make_event(instant(4)),
        ]
        with SigmaMatcher(rule_collection) as matcher:
            result = DualClockReplay(schedule, matcher).run(events)

        assert [entry.wall_time for entry in result.observed_events] == [instant(1), instant(4)]
        assert [entry.wall_time for entry in result.suppressed_events] == [instant(2, 30)]
        assert result.suppressed_events[0].status is ObservationStatus.SUPPRESSED_MAINTENANCE
        assert result.suppressed_events[0].window == schedule.windows[0]
        assert result.matches == ()

    def test_maintenance_event_carries_data_but_never_matches(self, rule_collection):
        schedule = MaintenanceSchedule([MaintenanceWindow(instant(2), instant(3))])
        replay = DualClockReplay(schedule, SigmaMatcher(rule_collection))
        matches = replay.feed(make_event(instant(2, 30), "mimikatz.exe"))
        result = replay.finish()

        assert matches == []
        entry = result.suppressed_events[0]
        assert entry.event is not None
        assert "mimikatz" in entry.event.data["CommandLine"]
        assert entry.observed_time == instant(2)

    def test_window_start_is_suppressed_and_window_end_is_countable(self):
        schedule = MaintenanceSchedule([MaintenanceWindow(instant(2), instant(3))])
        result = DualClockReplay(schedule).run(
            [make_event(instant(2)), make_event(instant(3))]
        )
        assert result.suppressed_events[0].wall_time == instant(2)
        assert result.observed_events[0].wall_time == instant(3)

    def test_observed_event_matches_and_is_explained(self, rule_collection):
        schedule = MaintenanceSchedule([MaintenanceWindow(instant(2), instant(3))])
        with SigmaMatcher(rule_collection) as matcher:
            result = DualClockReplay(schedule, matcher).run(
                [make_event(instant(4), "mimikatz.exe")]
            )
        assert len(result.matches) == 1
        assert result.matches[0].rule.name == "mimikatz_rule"

        explanation = result.explain_rule("mimikatz_rule")
        assert len(explanation.matches) == 1
        assert [entry.wall_time for entry in explanation.contributing_events] == [instant(4)]
        assert explanation.buckets[0].start == instant(4)

    def test_window_report_distinguishes_data_present_from_silence(self):
        with_data = MaintenanceWindow(instant(2), instant(3))
        silent = MaintenanceWindow(instant(5), instant(6))
        schedule = MaintenanceSchedule([with_data, silent])
        result = DualClockReplay(schedule).run(
            [
                make_event(instant(1)),
                make_event(instant(2, 30)),
                make_event(instant(4)),
                make_event(instant(7)),
            ]
        )
        reports = {report.window: report for report in result.window_reports()}
        assert reports[with_data].has_data is True
        assert len(reports[with_data].suppressed_events) == 1
        assert reports[silent].has_data is False

    def test_gap_excludes_maintenance_and_reports_actual_missing_part(self):
        schedule = MaintenanceSchedule([MaintenanceWindow(instant(2), instant(3))])
        result = DualClockReplay(schedule).run(
            [make_event(instant(1)), make_event(instant(2, 30)), make_event(instant(5))]
        )

        assert [(gap.start, gap.end) for gap in result.gaps] == [
            (instant(1), instant(2)),
            (instant(3), instant(5)),
        ]
        second_gap = result.gaps[1]
        assert second_gap.duration == timedelta(hours=2)
        assert second_gap.maintenance_duration == timedelta(minutes=30)
        assert second_gap.silent_start == instant(2, 30)
        assert second_gap.observed_start == instant(2)
        assert second_gap.observed_end == instant(4)
        assert all(gap.status is ObservationStatus.UNOBSERVABLE for gap in result.gaps)

    def test_observation_span_excludes_maintenance_but_not_gaps(self):
        schedule = MaintenanceSchedule([MaintenanceWindow(instant(2), instant(3))])
        result = DualClockReplay(schedule).run(
            [make_event(instant(1)), make_event(instant(2, 30)), make_event(instant(5))]
        )
        assert result.wall_span == timedelta(hours=4)
        assert result.maintenance_span == timedelta(hours=1)
        assert result.observation_span == timedelta(hours=3)
        assert result.observed_span == timedelta(hours=3)
        assert result.unobservable_span == timedelta(hours=3)
        assert result.data_span == timedelta()

    def test_buckets_classify_counted_suppressed_missing_and_boundary(self):
        schedule = MaintenanceSchedule([MaintenanceWindow(instant(2), instant(3))])
        result = DualClockReplay(schedule).run(
            [make_event(instant(1)), make_event(instant(2, 30)), make_event(instant(5))]
        )
        buckets = {bucket.start: bucket for bucket in result.buckets}

        assert buckets[instant(1)].status is ObservationStatus.PARTIAL
        assert buckets[instant(2)].status is ObservationStatus.SUPPRESSED_MAINTENANCE
        assert buckets[instant(3)].status is ObservationStatus.UNOBSERVABLE
        assert buckets[instant(4)].status is ObservationStatus.UNOBSERVABLE
        assert buckets[instant(5)].status is ObservationStatus.OBSERVABLE

    def test_replay_without_matcher_still_builds_dual_clock_entries(self):
        schedule = MaintenanceSchedule([MaintenanceWindow(instant(2), instant(3))])
        result = DualClockReplay(schedule).run([make_event(instant(1)), make_event(instant(2, 30))])
        assert len(result.real_events) == 2
        assert result.matches == ()

    def test_explicit_window_bounds_add_leading_and_trailing_gaps(self):
        schedule = MaintenanceSchedule()
        replay = DualClockReplay(
            schedule, window_start=instant(0), window_end=instant(6), bucket_size=timedelta(hours=1)
        )
        result = replay.run([make_event(instant(2)), make_event(instant(4))])
        assert [(gap.start, gap.end) for gap in result.gaps] == [
            (instant(0), instant(2)),
            (instant(2), instant(4)),
            (instant(4), instant(6)),
        ]


class TestSnapshotsAndReplacement:
    def test_snapshot_keeps_old_record_explainable_after_schedule_replacement(
        self, rule_collection
    ):
        maintenance_window = MaintenanceWindow(instant(2), instant(3), reason="patch")
        schedule = MaintenanceSchedule([maintenance_window])
        replay = DualClockReplay(schedule, SigmaMatcher(rule_collection))
        replay.feed(make_event(instant(1), "mimikatz.exe"))
        replay.feed(make_event(instant(2, 30), "mimikatz.exe"))
        snapshot = replay.snapshot(label="original-record")

        previous = replay.replace_schedule(MaintenanceSchedule(), label="replacement")

        assert previous is not None
        assert previous.label == "replacement"
        assert replay.history == (previous,)
        assert len(snapshot.matches) == 1

        explanation = snapshot.explain_rule("mimikatz_rule")
        assert len(explanation.matches) == 1
        assert [entry.wall_time for entry in explanation.contributing_events] == [instant(1)]
        assert [entry.wall_time for entry in explanation.suppressed_events] == [instant(2, 30)]
        assert explanation.maintenance_windows == (maintenance_window,)
        assert snapshot.schedule.windows == (maintenance_window,)
        assert replay.schedule.windows == ()
        assert len(replay.explain_rule("mimikatz_rule", snapshot=snapshot).matches) == 1
        assert replay.explain_rule("mimikatz_rule").matches == ()

    def test_rerun_with_replaced_schedule_reclassifies_the_same_event(self, rule_collection):
        original = MaintenanceSchedule([MaintenanceWindow(instant(2), instant(3))])
        event = make_event(instant(2, 30), "mimikatz.exe")

        with SigmaMatcher(rule_collection) as matcher:
            replay = DualClockReplay(original, matcher)
            first = replay.run([event])
            assert len(first.suppressed_events) == 1
            assert first.matches == ()

            replay.replace_schedule(MaintenanceSchedule())
            second = replay.run([event])
            assert len(second.observed_events) == 1
            assert len(second.matches) == 1
        assert first.matches == ()

    def test_replacing_an_empty_replay_returns_no_snapshot(self):
        replay = DualClockReplay(MaintenanceSchedule())
        assert replay.replace_schedule(MaintenanceSchedule()) is None


class TestValidation:
    def test_naive_event_timestamp_is_rejected(self):
        replay = DualClockReplay(MaintenanceSchedule())
        with pytest.raises(ValueError):
            replay.feed(make_event(datetime(2026, 11, 27, 1)))

    def test_naive_explicit_window_is_rejected(self):
        with pytest.raises(ValueError):
            DualClockReplay(MaintenanceSchedule(), window_start=datetime(2026, 11, 27, 1))

    def test_non_positive_bucket_size_is_rejected(self):
        with pytest.raises(ValueError):
            DualClockReplay(MaintenanceSchedule(), bucket_size=timedelta())

    def test_conflicting_window_aliases_are_rejected(self):
        with pytest.raises(ValueError):
            DualClockReplay(
                MaintenanceSchedule(),
                window=timedelta(hours=1),
                bucket_size=timedelta(hours=2),
            )
