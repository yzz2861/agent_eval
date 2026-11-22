"""Tests for offline exception-quota reconciliation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sigma.quota import (
    CORRECTION_SPLIT,
    KIND_ACTIONABLE,
    KIND_CORRECTION,
    KIND_DEDUCTION,
    KIND_DUPLICATE,
    KIND_LATE_REJECTED,
    KIND_WINDOW_CLOSED,
    CallerHints,
    Correction,
    Observation,
    QuotaReconciler,
    SlidingWindow,
    TumblingWindow,
    observations_from_dicts,
    render_report,
    render_summary,
    render_timeline,
    render_window_stats,
)

UTC = timezone.utc
T0 = datetime(2026, 11, 23, 10, 0, tzinfo=UTC)


def at(seconds: int) -> datetime:
    return T0 + timedelta(seconds=seconds)


def make_observation(
    event_id: str,
    event_seconds: int,
    *,
    group: str = "host-a",
    ingest_seconds: int | None = None,
    exempt: bool = True,
    source: str = "collector-1",
) -> Observation:
    return Observation(
        event_id=event_id,
        group_key=group,
        event_time=at(event_seconds),
        ingest_time=at(ingest_seconds if ingest_seconds is not None else event_seconds),
        exempt=exempt,
        source=source,
    )


def ledger_for(result, group: str = "host-a", index: int = 0):
    matching = [
        ledger
        for ledger in result.ledgers.values()
        if ledger.group_key == group
    ]
    return sorted(matching, key=lambda ledger: ledger.window_start)[index]


class TestTumblingWindow:
    def test_windows_are_half_open_and_aligned(self):
        window = TumblingWindow(timedelta(minutes=10))
        assert window.windows_for(at(0)) == [(at(0), at(600))]
        assert window.windows_for(at(599)) == [(at(0), at(600))]
        assert window.windows_for(at(600)) == [(at(600), at(1200))]

    def test_all_windows_between_covers_range(self):
        window = TumblingWindow(timedelta(minutes=10))
        windows = window.all_windows_between(at(30), at(1250))
        assert windows == [
            (at(0), at(600)),
            (at(600), at(1200)),
            (at(1200), at(1800)),
        ]

    def test_rejects_non_positive_size(self):
        with pytest.raises(ValueError):
            TumblingWindow(timedelta(0))


class TestSlidingWindow:
    def test_event_falls_into_overlapping_windows(self):
        window = SlidingWindow(timedelta(minutes=10), timedelta(minutes=5))
        windows = window.windows_for(at(330))
        assert windows == [(at(0), at(600)), (at(300), at(900))]

    def test_overlapping_windows_keep_independent_quotas(self):
        window = SlidingWindow(timedelta(minutes=10), timedelta(minutes=5))
        reconciler = QuotaReconciler(
            window, quota=1, allowed_lateness=timedelta(minutes=2)
        )
        reconciler.observe(make_observation("e1", 330))
        result = reconciler.finish()
        host_ledgers = [l for l in result.ledgers.values() if l.group_key == "host-a"]
        assert len(host_ledgers) == 2
        for ledger in host_ledgers:
            assert [item.event_id for item in ledger.deductions()] == ["e1"]


class TestDeduplicationAndQuota:
    def _reconciler(self, quota: int = 2):
        return QuotaReconciler(
            TumblingWindow(timedelta(minutes=10)),
            quota=quota,
            allowed_lateness=timedelta(minutes=2),
        )

    def test_duplicate_copy_deducts_quota_only_once(self):
        reconciler = self._reconciler()
        first = reconciler.observe(
            make_observation("evt-1", 30, source="collector-1")
        )
        duplicate = reconciler.observe(
            make_observation("evt-1", 30, ingest_seconds=35, source="collector-2")
        )
        assert [entry.kind for entry in first] == [KIND_DEDUCTION]
        assert [entry.kind for entry in duplicate] == [KIND_DUPLICATE]
        result = reconciler.finish()
        ledger = ledger_for(result)
        assert [item.event_id for item in ledger.deductions()] == ["evt-1"]
        assert ledger.duplicate_count() == 1
        assert ledger.copies_by_event["evt-1"] == 2

    def test_quota_stops_after_distinct_exempt_events(self):
        reconciler = self._reconciler(quota=2)
        entries = []
        for event_id, seconds in [("e1", 10), ("e2", 20), ("e3", 30)]:
            entries.extend(
                entry.kind
                for entry in reconciler.observe(make_observation(event_id, seconds))
            )
        assert entries == [
            KIND_DEDUCTION,
            KIND_DEDUCTION,
            KIND_ACTIONABLE,
        ]
        result = reconciler.finish()
        ledger = ledger_for(result)
        assert [item.event_id for item in ledger.deductions()] == ["e1", "e2"]
        assert [item.event_id for item in ledger.actionable()] == ["e3"]

    def test_nonexempt_event_never_consumes_quota(self):
        reconciler = self._reconciler(quota=1)
        entries = reconciler.observe(
            make_observation("ops-1", 20, exempt=False)
        )
        assert entries[0].kind == KIND_ACTIONABLE
        exempt_entries = reconciler.observe(
            make_observation("known-1", 40, exempt=True)
        )
        assert exempt_entries[0].kind == KIND_DEDUCTION
        result = reconciler.finish()
        ledger = ledger_for(result)
        assert ledger.remaining_quota() == 0
        assert [item.event_id for item in ledger.actionable()] == ["ops-1"]

    def test_groups_keep_separate_ledgers_and_quotas(self):
        reconciler = self._reconciler(quota=1)
        reconciler.observe(make_observation("e1", 10, group="host-a"))
        reconciler.observe(make_observation("e1", 10, group="host-b"))
        result = reconciler.finish()
        assert len(result.ledgers) == 2
        for ledger in result.ledgers.values():
            assert [item.event_id for item in ledger.deductions()] == ["e1"]

    def test_deduction_order_uses_event_time_then_ingest_time(self):
        reconciler = self._reconciler(quota=1)
        reconciler.observe(make_observation("later", 30, ingest_seconds=30))
        reconciler.observe(make_observation("earlier", 10, ingest_seconds=40))
        result = reconciler.finish()
        ledger = ledger_for(result)
        assert [item.event_id for item in ledger.deductions()] == ["earlier"]
        assert [item.event_id for item in ledger.actionable()] == ["later"]


class TestBoundedLateness:
    def _reconciler(self):
        return QuotaReconciler(
            TumblingWindow(timedelta(minutes=10)),
            quota=2,
            allowed_lateness=timedelta(minutes=2),
        )

    def test_window_closes_when_watermark_passes_end(self):
        reconciler = self._reconciler()
        reconciler.observe(make_observation("e1", 30))
        reconciler.observe(make_observation("marker", 700, ingest_seconds=750, exempt=False))
        assert reconciler.watermark == at(630)
        result = reconciler.finish()
        close_entries = [
            entry
            for entry in result.timeline
            if entry.kind == KIND_WINDOW_CLOSED and entry.window_end == at(600)
        ]
        assert len(close_entries) == 1

    def test_record_within_lateness_is_reconciled_after_close(self):
        reconciler = self._reconciler()
        reconciler.observe(make_observation("e1", 30))
        reconciler.observe(make_observation("marker", 700, ingest_seconds=750, exempt=False))
        entries = reconciler.observe(
            make_observation("late-ok", 45, ingest_seconds=720)
        )
        assert entries[0].kind == KIND_DEDUCTION
        result = reconciler.finish()
        ledger = ledger_for(result)
        assert [item.event_id for item in ledger.deductions()] == ["e1", "late-ok"]

    def test_record_beyond_lateness_is_rejected_and_listed(self):
        reconciler = self._reconciler()
        reconciler.observe(make_observation("e1", 30))
        reconciler.observe(make_observation("marker", 700, ingest_seconds=750, exempt=False))
        entries = reconciler.observe(
            make_observation("too-late", 45, ingest_seconds=760)
        )
        assert entries[0].kind == KIND_LATE_REJECTED
        result = reconciler.finish()
        assert len(result.late_rejected) == 1
        first_window = ledger_for(result, index=0)
        assert [item.event_id for item in first_window.distinct_events()] == ["e1"]


class TestCorrections:
    def _reconciler(self):
        return QuotaReconciler(
            TumblingWindow(timedelta(minutes=10)),
            quota=1,
            allowed_lateness=timedelta(minutes=2),
        )

    def test_split_identity_recomputes_window_and_moves_action(self):
        reconciler = self._reconciler()
        reconciler.observe(make_observation("e1", 30, exempt=True))
        reconciler.observe(make_observation("e2", 90, exempt=True))
        correction = Correction(
            original_event_id="e2",
            new_event_id="e2-real",
            group_key="host-a",
            event_time=at(90),
            received_time=at(400),
            new_exempt=False,
            correction_type=CORRECTION_SPLIT,
        )
        entries = reconciler.correct(correction)
        assert entries[0].kind == KIND_CORRECTION
        assert entries[0].before and entries[0].after
        result = reconciler.finish()
        ledger = ledger_for(result)
        assert [item.event_id for item in ledger.deductions()] == ["e1"]
        assert [item.event_id for item in ledger.actionable()] == ["e2-real"]

    def test_correction_can_reassign_the_quota_slot(self):
        reconciler = self._reconciler()
        reconciler.observe(make_observation("n1", 30, exempt=False))
        reconciler.observe(make_observation("x1", 60, exempt=True))
        reconciler.correct(
            Correction(
                original_event_id="n1",
                new_event_id="n1-fixed",
                group_key="host-a",
                event_time=at(30),
                received_time=at(500),
                new_exempt=True,
            )
        )
        result = reconciler.finish()
        ledger = ledger_for(result)
        assert [item.event_id for item in ledger.deductions()] == ["n1-fixed"]
        assert [item.event_id for item in ledger.actionable()] == ["x1"]

    def test_unknown_correction_is_recorded_without_state_change(self):
        reconciler = self._reconciler()
        entries = reconciler.correct(
            Correction(
                original_event_id="ghost",
                new_event_id="ghost-2",
                group_key="host-a",
                event_time=at(30),
                received_time=at(400),
                new_exempt=True,
            )
        )
        assert entries[0].kind == KIND_CORRECTION
        assert "未知事件" in entries[0].detail
        assert reconciler.finish().ledgers == {}


class TestPySigmaAdapter:
    def test_observations_from_dicts_apply_caller_hints(self):
        records = [
            {
                "EventID": "evt-9",
                "Computer": "host-a",
                "KnownOperation": True,
                "EventTime": "2026-11-23T10:00:30+00:00",
                "IngestedAt": "2026-11-23T10:00:31+00:00",
            },
            {
                "EventID": "evt-9",
                "Computer": "host-a",
                "KnownOperation": True,
                "EventTime": "2026-11-23T10:00:30+00:00",
                "IngestedAt": "2026-11-23T10:00:32+00:00",
            },
        ]
        hints = CallerHints(
            identity_field="EventID",
            group_field="Computer",
            exempt_scope="KnownOperation",
            timestamp_field="EventTime",
        )
        observations = observations_from_dicts(records, hints, ingest_field="IngestedAt")
        assert len(observations) == 2
        assert {obs.event_id for obs in observations} == {"evt-9"}
        assert all(obs.group_key == "host-a" for obs in observations)
        assert all(obs.exempt is True for obs in observations)
        assert observations[0].ingest_time < observations[1].ingest_time

    def test_observation_from_sigma_event(self):
        from sigma.matching.event import Event, EventLogSource

        from sigma.quota import observation_from_event

        event = Event(
            timestamp=at(30),
            logsource=EventLogSource(category="process_creation", product="windows"),
            data={
                "EventID": "evt-1",
                "Computer": "host-a",
                "KnownOperation": False,
            },
        )
        hints = CallerHints(
            identity_field="EventID",
            group_field="Computer",
            exempt_scope="KnownOperation",
            timestamp_field=None,
        )
        observation = observation_from_event(
            event, hints, ingest_time=at(31), rule_name="count_rule"
        )
        assert observation.event_id == "evt-1"
        assert observation.group_key == "host-a"
        assert observation.exempt is False
        assert observation.event_time == at(30)
        assert observation.rule_name == "count_rule"


class TestRendering:
    def _result(self):
        reconciler = QuotaReconciler(
            TumblingWindow(timedelta(minutes=10)),
            quota=1,
            allowed_lateness=timedelta(minutes=2),
        )
        reconciler.observe(make_observation("e1", 30, source="c1"))
        reconciler.observe(
            make_observation("e1", 30, ingest_seconds=35, source="c2")
        )
        reconciler.observe(make_observation("e2", 60, exempt=False))
        return reconciler.finish()

    def test_summary_lists_deductions_actionables_and_duplicates(self):
        summary = render_summary(self._result())
        assert "例外扣减总次数: 1" in summary
        assert "仍须处理操作数: 1" in summary
        assert "被去重的副本数: 1" in summary

    def test_window_stats_show_every_deduction_and_open_operation(self):
        result = self._result()
        ledger = ledger_for(result)
        text = render_window_stats(ledger)
        assert "e1" in text and "只扣一次" in text
        assert "e2" in text and "不属例外范围" in text

    def test_timeline_contains_each_processing_step(self):
        text = render_timeline(self._result())
        assert "扣减" in text
        assert "重复" in text
        assert "待处理" in text
        assert "关窗" in text

    def test_full_report_renders_without_error(self):
        report = render_report(self._result())
        assert "统计汇总" in report
        assert "时间线" in report


class TestReplayRegression:
    def test_correction_keeps_duplicate_copy_count(self):
        reconciler = QuotaReconciler(
            TumblingWindow(timedelta(minutes=10)),
            quota=2,
            allowed_lateness=timedelta(minutes=2),
        )
        reconciler.observe(make_observation("dup", 20, source="c1"))
        reconciler.observe(
            make_observation("dup", 20, ingest_seconds=25, source="c2")
        )
        reconciler.observe(make_observation("target", 60, exempt=True))
        reconciler.correct(
            Correction(
                original_event_id="target",
                new_event_id="target-split",
                group_key="host-a",
                event_time=at(60),
                received_time=at(400),
                new_exempt=False,
            )
        )
        result = reconciler.finish()
        ledger = ledger_for(result)
        assert ledger.copies_by_event["dup"] == 2
        assert ledger.duplicate_count() == 1

    def test_late_rejected_observation_never_enters_ledger_state(self):
        reconciler = QuotaReconciler(
            TumblingWindow(timedelta(minutes=10)),
            quota=2,
            allowed_lateness=timedelta(minutes=2),
        )
        reconciler.observe(make_observation("e1", 30))
        reconciler.observe(
            make_observation("marker", 700, ingest_seconds=750, exempt=False)
        )
        reconciler.observe(
            make_observation("too-late", 45, ingest_seconds=760)
        )
        assert ("host-a", "too-late") not in reconciler._observations
        result = reconciler.finish()
        first = ledger_for(result, index=0)
        assert "too-late" not in first.copies_by_event
        assert all(item.event_id != "too-late" for item in first.actionable())

    def test_replay_is_deterministic(self):
        reconciler = QuotaReconciler(
            TumblingWindow(timedelta(minutes=10)),
            quota=1,
            allowed_lateness=timedelta(minutes=2),
        )
        records = [
            make_observation("a", 30),
            make_observation("b", 40),
            make_observation("c", 50, exempt=False),
        ]
        for observation in records:
            reconciler.observe(observation)
        first = reconciler.finish()
        second = QuotaReconciler(
            TumblingWindow(timedelta(minutes=10)),
            quota=1,
            allowed_lateness=timedelta(minutes=2),
        )
        for observation in records:
            second.observe(observation)
        second_result = second.finish()
        assert [
            (entry.kind, entry.event_id) for entry in first.timeline
        ] == [
            (entry.kind, entry.event_id) for entry in second_result.timeline
        ]


class TestSlidingWindowLateness:
    def test_each_overlapping_window_judges_lateness_independently(self):
        window = SlidingWindow(timedelta(minutes=10), timedelta(minutes=5))
        reconciler = QuotaReconciler(
            window, quota=2, allowed_lateness=timedelta(minutes=2)
        )
        reconciler.observe(make_observation("seed", 330))
        reconciler.observe(
            make_observation("advance", 900, ingest_seconds=900, exempt=False)
        )
        late = make_observation("late", 330, ingest_seconds=960)
        entries = reconciler.observe(late)
        kinds = {entry.kind for entry in entries}
        assert KIND_LATE_REJECTED in kinds
        result = reconciler.finish()
        rejected_ids = {entry.event_id for entry in result.late_rejected}
        assert "late" in rejected_ids


    def test_correction_leaves_unaffected_windows_untouched(self):
        reconciler = QuotaReconciler(
            TumblingWindow(timedelta(minutes=10)),
            quota=1,
            allowed_lateness=timedelta(minutes=2),
        )
        reconciler.observe(make_observation("w1", 100, exempt=True))
        reconciler.observe(make_observation("w2", 700, exempt=True))
        unaffected_before = reconciler._snapshot(
            (at(600), at(1200), "host-a")
        )
        reconciler.correct(
            Correction(
                original_event_id="w1",
                new_event_id="w1-split",
                group_key="host-a",
                event_time=at(100),
                received_time=at(900),
                new_exempt=False,
            )
        )
        unaffected_after = reconciler._ledgers[(at(600), at(1200), "host-a")]
        assert [item.event_id for item in unaffected_after.deductions()] == [
            item.event_id for item in unaffected_before.deductions()
        ]
