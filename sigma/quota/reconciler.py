"""Offline quota reconciliation over pySigma match results."""

from __future__ import annotations

from datetime import datetime, timedelta

from sigma.quota.ledger import WindowLedger
from sigma.quota.types import (
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
    ReconciliationResult,
    TimelineEntry,
)
from sigma.quota.windows import WindowSpec


class QuotaReconciler:
    """Replays observations and rebuilds per-window exception ledgers.

    The reconciler is deterministic and offline: feeding the same records in
    the same order always yields the same ledgers and timeline. Records may
    arrive out of order within the bounded lateness allowance; a watermark of
    ``max(ingest_time) - lateness`` decides when a window becomes final.
    """

    def __init__(
        self,
        window_spec: WindowSpec,
        quota: int,
        allowed_lateness: timedelta,
        hints: CallerHints | None = None,
    ) -> None:
        if quota < 0:
            raise ValueError("quota must be non-negative")
        if allowed_lateness < timedelta(0):
            raise ValueError("allowed lateness must be non-negative")
        self._window_spec = window_spec
        self._quota = quota
        self._lateness = allowed_lateness
        self._hints = hints
        self._observations: dict[tuple[str, str], Observation] = {}
        self._copy_counts: dict[tuple[str, str], int] = {}
        self._corrections: list[Correction] = []
        self._ledgers: dict[tuple, WindowLedger] = {}
        self._closed: set[tuple] = set()
        self._watermark: datetime | None = None
        self._timeline: list[TimelineEntry] = []

    @property
    def watermark(self) -> datetime | None:
        return self._watermark

    def observe(self, observation: Observation) -> list[TimelineEntry]:
        """Ingest one matched event and emit the resulting timeline entries."""
        entries = self._ingest_observation(observation)
        self._timeline.extend(entries)
        self._advance_watermark(observation.ingest_time)
        return entries

    def observe_many(self, observations) -> ReconciliationResult:
        for observation in observations:
            self.observe(observation)
        return self.finish()

    def _ingest_observation(self, observation: Observation) -> list[TimelineEntry]:
        window_ranges = self._window_spec.windows_for(observation.event_time)
        entries: list[TimelineEntry] = []
        accepted = False
        for start, end in window_ranges:
            key = (start, end, observation.group_key)
            if key in self._closed:
                if not self._within_lateness(observation, end):
                    entries.append(self._late_entry(observation, start, end))
                    continue
            ledger = self._get_ledger(key, start, end)
            is_new = ledger.add(observation)
            accepted = True
            if not is_new:
                entries.append(
                    TimelineEntry(
                        kind=KIND_DUPLICATE,
                        timestamp=observation.ingest_time,
                        group_key=observation.group_key,
                        event_id=observation.event_id,
                        window_start=start,
                        window_end=end,
                        detail=(
                            f"重复副本已抑制；该事件共收到 "
                            f"{ledger.copies_by_event[observation.event_id]} 份副本"
                        ),
                    )
                )
                continue
            entries.extend(self._classify_entries(observation, ledger, start, end))
        if accepted:
            identity = (observation.group_key, observation.event_id)
            self._observations[identity] = observation
            self._copy_counts[identity] = self._copy_counts.get(identity, 0) + 1
        return entries

    def _within_lateness(self, observation: Observation, window_end: datetime) -> bool:
        return observation.ingest_time - window_end <= self._lateness

    def _classify_entries(
        self,
        observation: Observation,
        ledger: WindowLedger,
        start: datetime,
        end: datetime,
    ) -> list[TimelineEntry]:
        if not observation.exempt:
            return [
                TimelineEntry(
                    kind=KIND_ACTIONABLE,
                    timestamp=observation.ingest_time,
                    group_key=observation.group_key,
                    event_id=observation.event_id,
                    window_start=start,
                    window_end=end,
                    detail="不在例外范围，额度不变",
                )
            ]
        deductions = ledger.deductions()
        if observation in deductions:
            position = deductions.index(observation) + 1
            return [
                TimelineEntry(
                    kind=KIND_DEDUCTION,
                    timestamp=observation.ingest_time,
                    group_key=observation.group_key,
                    event_id=observation.event_id,
                    window_start=start,
                    window_end=end,
                    detail=f"例外扣减 {position}/{self._quota}",
                )
            ]
        return [
            TimelineEntry(
                kind=KIND_ACTIONABLE,
                timestamp=observation.ingest_time,
                group_key=observation.group_key,
                event_id=observation.event_id,
                window_start=start,
                window_end=end,
                detail="例外额度已用尽，该操作仍须处理",
            )
        ]

    def _late_entry(
        self, observation: Observation, start: datetime, end: datetime
    ) -> TimelineEntry:
        return TimelineEntry(
            kind=KIND_LATE_REJECTED,
            timestamp=observation.ingest_time,
            group_key=observation.group_key,
            event_id=observation.event_id,
            window_start=start,
            window_end=end,
            detail=(
                f"超过关窗后的迟到宽限（{self._lateness}），未计入台账"
            ),
        )

    def _advance_watermark(self, ingest_time: datetime) -> None:
        candidate = ingest_time - self._lateness
        if self._watermark is None or candidate > self._watermark:
            self._watermark = candidate
        for key in list(self._ledgers.keys()):
            start, end, _group = key
            if key not in self._closed and end <= self._watermark:
                self._close_window(key)

    def _close_window(self, key: tuple) -> None:
        start, end, group = key
        ledger = self._ledgers[key]
        self._closed.add(key)
        self._timeline.append(
            TimelineEntry(
                kind=KIND_WINDOW_CLOSED,
                timestamp=end,
                group_key=group,
                event_id=None,
                window_start=start,
                window_end=end,
                detail=(
                    f"水位线触发关窗快照：扣减 {len(ledger.deductions())} 次，"
                    f"仍须处理 {len(ledger.actionable())} 次，"
                    f"去重副本 {ledger.duplicate_count()} 份"
                ),
            )
        )

    def _get_ledger(
        self, key: tuple, start: datetime, end: datetime
    ) -> WindowLedger:
        ledger = self._ledgers.get(key)
        if ledger is None:
            ledger = WindowLedger(
                window_start=start,
                window_end=end,
                group_key=key[2],
                quota=self._quota,
            )
            self._ledgers[key] = ledger
        return ledger

    def _affected_windows(self, previous: Observation) -> set[tuple]:
        affected: set[tuple] = set()
        ranges = self._window_spec.windows_for(previous.event_time)
        for start, end in ranges:
            affected.add((start, end, previous.group_key))
        return affected

    def _replay_into(self, ledger: WindowLedger) -> None:
        group = ledger.group_key
        candidates = [
            item
            for item in self._observations.values()
            if item.group_key == group
            and ledger.window_start <= item.event_time < ledger.window_end
        ]
        ledger.observations = []
        ledger.copies_by_event = {}
        for item in sorted(
            candidates, key=lambda obs: (obs.event_time, obs.ingest_time, obs.event_id)
        ):
            ledger.add(item)
            identity = (item.group_key, item.event_id)
            ledger.copies_by_event[item.event_id] = self._copy_counts.get(identity, 1)

    def _snapshot(self, key: tuple) -> WindowLedger:
        ledger = self._ledgers[key]
        return WindowLedger(
            window_start=ledger.window_start,
            window_end=ledger.window_end,
            group_key=ledger.group_key,
            quota=ledger.quota,
            observations=list(ledger.observations),
            copies_by_event=dict(ledger.copies_by_event),
        )

    def _freeze(self, ledger: WindowLedger) -> WindowLedger:
        return self._snapshot(
            (ledger.window_start, ledger.window_end, ledger.group_key)
        )

    def correct(self, correction: Correction) -> list[TimelineEntry]:
        """Apply a retroactive identity change and recompute affected windows."""
        if correction.correction_type != CORRECTION_SPLIT:
            raise ValueError("only identity split corrections are supported offline")
        self._corrections.append(correction)
        previous = self._observations.get(
            (correction.group_key, correction.original_event_id)
        )
        if previous is None:
            entry = TimelineEntry(
                kind=KIND_CORRECTION,
                timestamp=correction.received_time,
                group_key=correction.group_key,
                event_id=correction.original_event_id,
                detail="修正指向未知事件，无台账可回算",
                correction=correction,
            )
            self._timeline.append(entry)
            return [entry]
        affected = self._affected_windows(previous)
        before = {key: self._snapshot(key) for key in affected if key in self._ledgers}
        previous_identity = (previous.group_key, previous.event_id)
        previous_copies = self._copy_counts.pop(previous_identity, 1)
        del self._observations[previous_identity]
        for key in affected:
            ledger = self._ledgers.get(key)
            if ledger is None:
                continue
            ledger.copies_by_event.pop(previous.event_id, None)
            ledger.observations = [
                item
                for item in ledger.observations
                if item.event_id != previous.event_id
            ]
        replacement = Observation(
            event_id=correction.new_event_id,
            group_key=correction.group_key,
            event_time=correction.event_time,
            ingest_time=previous.ingest_time,
            exempt=correction.new_exempt,
            rule_name=previous.rule_name,
            source=previous.source,
            raw=previous.raw,
        )
        replacement_identity = (replacement.group_key, replacement.event_id)
        self._observations[replacement_identity] = replacement
        self._copy_counts[replacement_identity] = previous_copies
        for key in affected:
            if key in self._ledgers:
                self._replay_into(self._ledgers[key])
        after = {key: self._snapshot(key) for key in affected if key in self._ledgers}
        entry = TimelineEntry(
            kind=KIND_CORRECTION,
            timestamp=correction.received_time,
            group_key=correction.group_key,
            event_id=correction.original_event_id,
            detail=(
                f"身份拆分：{correction.original_event_id} -> "
                f"{correction.new_event_id}；已回算 {len(after)} 个窗口"
            ),
            correction=correction,
            before=before,
            after=after,
        )
        self._timeline.append(entry)
        return [entry]

    def finish(self) -> ReconciliationResult:
        """Close every still-open window and return the final reconciliation."""
        for key in list(self._ledgers.keys()):
            if key not in self._closed:
                self._close_window(key)
        late = [
            entry for entry in self._timeline if entry.kind == KIND_LATE_REJECTED
        ]
        return ReconciliationResult(
            timeline=list(self._timeline),
            ledgers={
                key: self._freeze(ledger) for key, ledger in self._ledgers.items()
            },
            closed_windows=set(self._closed),
            late_rejected=list(late),
            corrections=list(self._corrections),
            watermark=self._watermark,
        )
