"""Offline evidence review for Sigma alerts.

Incident response often has to work with an event export that only retained a
small subset of the original fields.  This module answers two questions for
each rule:

* Can the alert be recomputed from the retained export alone?
* If not, which original fields must be recovered, and for which time window?

The reviewer combines the parsed rules, the field mappings applied by a
processing pipeline (before/after conversion), and a caller-provided
retention policy.  Missing evidence is classified so that "the source never
had a value" is not confused with "a retention process removed the field".
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionItem,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.correlations import (
    SigmaCorrelationCondition,
    SigmaCorrelationRule,
    SigmaExtendedCorrelationCondition,
)
from sigma.matching.event import Event, EventLogSource
from sigma.matching.match import SigmaMatch
from sigma.matching.matcher import SigmaMatcher
from sigma.rule.rule import SigmaRule

if TYPE_CHECKING:
    from sigma.processing.pipeline import ProcessingPipeline


RAW_FIELD = "<raw>"
"""Synthetic requirement name used for keyword detections needing raw log text."""


def _utc(value: datetime | None) -> datetime | None:
    """Normalize a datetime to UTC, treating naive values as UTC."""
    if value is None:
        return None
    if not isinstance(value, datetime):
        raise TypeError(f"Expected datetime, got {type(value).__name__}")
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _parse_datetime(value: Any) -> datetime:
    """Parse a JSON timestamp or accept an existing datetime."""
    if isinstance(value, datetime):
        parsed = _utc(value)
        assert parsed is not None
        return parsed
    if isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
            normalized = _utc(parsed)
            assert normalized is not None
            return normalized
        except ValueError:
            pass
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
            try:
                return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    raise ValueError(f"Invalid timestamp value: {value!r}")


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _normalize_fields(value):
    if value is None:
        return None
    if isinstance(value, str):
        return frozenset((value,))
    return frozenset(value)


def _normalize_window(value):
    if value is None:
        return None
    if isinstance(value, TimeWindow):
        return value
    if isinstance(value, datetime):
        return TimeWindow(end=value)
    if isinstance(value, (tuple, list)) and len(value) == 2:
        return TimeWindow(value[0], value[1])
    raise TypeError("Retention windows must be TimeWindow, datetime, or a 2-tuple")


def _normalize_retention_map(value):
    if value is None:
        return {}
    if isinstance(value, str):
        return {value: None}
    if isinstance(value, Mapping):
        return {field: _normalize_window(window) for field, window in value.items()}
    return {field: None for field in value}


@dataclass(frozen=True)
class TimeWindow:
    """Inclusive time window used for evidence and retention decisions."""

    start: datetime | None = None
    end: datetime | None = None

    def __post_init__(self) -> None:
        start = _utc(self.start)
        end = _utc(self.end)
        if start is not None and end is not None and start > end:
            raise ValueError("TimeWindow start must not be after end")
        object.__setattr__(self, "start", start)
        object.__setattr__(self, "end", end)

    @classmethod
    def around(cls, values: Iterable[datetime]) -> TimeWindow | None:
        """Build a window spanning all supplied timestamps."""
        timestamps = [_utc(value) for value in values if value is not None]
        if not timestamps:
            return None
        return cls(min(timestamps), max(timestamps))  # type: ignore[arg-type]

    @property
    def is_empty(self) -> bool:
        return (
            self.start is not None
            and self.end is not None
            and self.start > self.end
        )

    def contains(self, value: datetime) -> bool:
        value = _utc(value)
        assert value is not None
        if self.start is not None and value < self.start:
            return False
        if self.end is not None and value > self.end:
            return False
        return True

    def intersection(self, other: TimeWindow | None) -> TimeWindow | None:
        """Return the overlapping part of two windows, or ``None`` if disjoint."""
        if other is None:
            return self
        start_candidates = [value for value in (self.start, other.start) if value is not None]
        end_candidates = [value for value in (self.end, other.end) if value is not None]
        start = max(start_candidates) if start_candidates else None
        end = min(end_candidates) if end_candidates else None
        if start is not None and end is not None and start > end:
            return None
        return TimeWindow(start, end)

    def to_dict(self) -> dict[str, str | None]:
        return {"start": _iso(self.start), "end": _iso(self.end)}


class MissingFieldReason(str, Enum):
    """Why a field required by a rule is not available for review."""

    NEVER_CAPTURED = "never_captured"
    """The source never recorded this field; there is genuinely no value."""

    SOURCE_ABSENT = "source_absent"
    """The export retained the field, but no relevant event carried a value."""

    NOT_RETAINED = "not_retained"
    """The export omitted the field; it may still be obtainable from collection."""

    RETENTION_PURGED = "retention_purged"
    """A retention/rollover process removed the field from the export."""

    ARCHIVED = "archived"
    """The field is known to exist in an archive and can be restored."""


class ReviewStatus(str, Enum):
    """Outcome of reviewing one alert against one export."""

    REVIEWABLE = "reviewable"
    """All required fields survived; the alert was re-evaluated."""

    NEEDS_BACKFILL = "needs_backfill"
    """At least one missing field can be recovered; ask collection for it."""

    UNRECOVERABLE = "unrecoverable"
    """Required evidence never existed or cannot be recovered."""

    NOT_APPLICABLE = "not_applicable"
    """The export contains no events matching the rule log source."""


@dataclass(frozen=True)
class FieldRetention:
    """Retention disposition for one field.

    ``window`` describes when the field was retained/changed in the export;
    ``restore_window`` describes when an archive copy is available.
    """

    field: str
    reason: MissingFieldReason = MissingFieldReason.NOT_RETAINED
    recoverable: bool = True
    window: TimeWindow | None = None
    restore_window: TimeWindow | None = None
    note: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.reason, str):
            object.__setattr__(self, "reason", MissingFieldReason(self.reason))

    def to_dict(self) -> dict[str, Any]:
        return {
            "field": self.field,
            "reason": self.reason.value,
            "recoverable": self.recoverable,
            "window": self.window.to_dict() if self.window is not None else None,
            "restore_window": (
                self.restore_window.to_dict() if self.restore_window is not None else None
            ),
            "note": self.note,
        }


@dataclass(frozen=True)
class RetentionPolicy:
    """Caller-declared retention policy for the event export.

    The policy is deliberately explicit: pySigma cannot infer whether a
    missing field was never collected or was deleted by a retention process.
    Fields not covered by any special rule are classified as
    :attr:`MissingFieldReason.NOT_RETAINED` and considered recoverable by the
    collection team.
    """

    retained_fields: frozenset[str] | None = None
    never_captured_fields: frozenset[str] = frozenset()
    archived_fields: Mapping[str, TimeWindow] = field(default_factory=dict)
    purged_fields: Mapping[str, TimeWindow] = field(default_factory=dict)
    field_policies: Mapping[str, FieldRetention] = field(default_factory=dict)
    purge_before: datetime | None = None
    notes: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "retained_fields", _normalize_fields(self.retained_fields))
        object.__setattr__(
            self,
            "never_captured_fields",
            _normalize_fields(self.never_captured_fields) or frozenset(),
        )
        object.__setattr__(self, "archived_fields", _normalize_retention_map(self.archived_fields))
        object.__setattr__(self, "purged_fields", _normalize_retention_map(self.purged_fields))
        policies = {}
        for field, policy in dict(self.field_policies).items():
            if isinstance(policy, str):
                policy = MissingFieldReason(policy)
            if isinstance(policy, MissingFieldReason):
                policy = FieldRetention(
                    field=field,
                    reason=policy,
                    recoverable=policy
                    not in {
                        MissingFieldReason.NEVER_CAPTURED,
                        MissingFieldReason.SOURCE_ABSENT,
                    },
                )
            policies[field] = policy
        object.__setattr__(self, "field_policies", policies)
        object.__setattr__(self, "notes", dict(self.notes))
        object.__setattr__(self, "purge_before", _utc(self.purge_before))

    def classify(
        self,
        candidates: Sequence[str],
        event_window: TimeWindow | None = None,
    ) -> FieldRetention:
        """Classify a missing field.

        ``candidates`` contains the post-conversion field names first, followed
        by the original rule field.  This lets a policy be written in either
        schema while still reporting the original field for backfill.
        """
        for candidate in candidates:
            if candidate in self.field_policies:
                policy = self.field_policies[candidate]
                if policy.note is None and candidate in self.notes:
                    return FieldRetention(
                        field=candidate,
                        reason=policy.reason,
                        recoverable=policy.recoverable,
                        window=policy.window,
                        restore_window=policy.restore_window,
                        note=self.notes[candidate],
                    )
                return policy

        if any(candidate in self.never_captured_fields for candidate in candidates):
            field = next(
                candidate for candidate in candidates if candidate in self.never_captured_fields
            )
            return FieldRetention(
                field=field,
                reason=MissingFieldReason.NEVER_CAPTURED,
                recoverable=False,
                note=self.notes.get(field),
            )

        for candidate in candidates:
            if candidate in self.purged_fields:
                return FieldRetention(
                    field=candidate,
                    reason=MissingFieldReason.RETENTION_PURGED,
                    recoverable=True,
                    window=self.purged_fields[candidate],
                    note=self.notes.get(candidate),
                )

        for candidate in candidates:
            if candidate in self.archived_fields:
                return FieldRetention(
                    field=candidate,
                    reason=MissingFieldReason.ARCHIVED,
                    recoverable=True,
                    restore_window=self.archived_fields[candidate],
                    note=self.notes.get(candidate),
                )

        if (
            self.purge_before is not None
            and event_window is not None
            and event_window.start is not None
            and event_window.start < self.purge_before
        ):
            end = event_window.end
            if end is None or end > self.purge_before:
                end = self.purge_before
            return FieldRetention(
                field=candidates[0],
                reason=MissingFieldReason.RETENTION_PURGED,
                recoverable=True,
                window=TimeWindow(event_window.start, end),
                note=self.notes.get(candidates[0]),
            )

        field = candidates[0]
        return FieldRetention(
            field=field,
            reason=MissingFieldReason.NOT_RETAINED,
            recoverable=True,
            window=event_window,
            note=self.notes.get(field),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "retained_fields": (
                sorted(self.retained_fields) if self.retained_fields is not None else None
            ),
            "never_captured_fields": sorted(self.never_captured_fields),
            "archived_fields": {
                key: value.to_dict() if value is not None else None
                for key, value in self.archived_fields.items()
            },
            "purged_fields": {
                key: value.to_dict() if value is not None else None
                for key, value in self.purged_fields.items()
            },
            "field_policies": {
                key: value.to_dict() for key, value in self.field_policies.items()
            },
            "purge_before": _iso(self.purge_before),
            "notes": dict(self.notes),
        }


@dataclass
class EventExport:
    """A small Sigma event export with an optional retention schema.

    ``retained_fields`` is the export's field schema.  When omitted, the
    reviewer falls back to the policy's ``retained_fields`` and finally to the
    keys observed in the exported events.
    """

    events: list[Event] = field(default_factory=list)
    retained_fields: frozenset[str] | None = None
    exported_at: datetime | None = None
    source: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.events, list):
            object.__setattr__(self, "events", list(self.events))
        if isinstance(self.retained_fields, str):
            object.__setattr__(self, "retained_fields", frozenset((self.retained_fields,)))
        elif self.retained_fields is not None:
            object.__setattr__(self, "retained_fields", frozenset(self.retained_fields))
        object.__setattr__(self, "exported_at", _utc(self.exported_at))

    @property
    def observed_fields(self) -> frozenset[str]:
        return frozenset(key for event in self.events for key in event.data)

    @property
    def window(self) -> TimeWindow | None:
        return TimeWindow.around(event.timestamp for event in self.events)

    def available_fields(self, policy: RetentionPolicy | None = None) -> frozenset[str]:
        """Fields that can be used for matching.

        Values actually observed in events count even when the declared schema
        is incomplete.  The schema is additionally used to distinguish "not
        retained" from "retained but no value in these events".
        """
        available = set(self.observed_fields)
        declared = self.retained_fields
        if declared is None and policy is not None:
            declared = policy.retained_fields
        if declared is not None:
            available.update(declared)
        return frozenset(available)

    @classmethod
    def from_events(
        cls,
        events: Iterable[Event],
        *,
        retained_fields: Iterable[str] | None = None,
        exported_at: datetime | None = None,
        source: str | None = None,
    ) -> EventExport:
        return cls(
            events=list(events),
            retained_fields=_normalize_fields(retained_fields),
            exported_at=exported_at,
            source=source,
        )

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any] | Sequence[Mapping[str, Any]],
        *,
        reference_time: datetime | None = None,
        source: str | None = None,
    ) -> EventExport:
        """Load an export from a JSON-like structure.

        Supported top-level shapes:

        * ``{"events": [...], "retained_fields": [...], "exported_at": "..."}``
        * a bare list of event records
        """
        retained_fields: Iterable[str] | None = None
        exported_at: datetime | None = None
        if isinstance(data, Mapping):
            if any(key in data for key in ("events", "records")):
                raw_events = data.get("events", data.get("records", []))
            elif any(key in data for key in ("data", "timestamp", "@timestamp", "time", "ts")):
                raw_events = [data]
            else:
                raw_events = []
            retained_fields = data.get("retained_fields", data.get("fields"))
            exported_at_value = data.get("exported_at")
            if exported_at_value is not None:
                exported_at = _parse_datetime(exported_at_value)
            source = data.get("source", source)
        else:
            raw_events = data
        events = [
            _parse_event(record, reference_time=reference_time)
            if not isinstance(record, Event)
            else record
            for record in raw_events
        ]
        return cls(
            events=events,
            retained_fields=_normalize_fields(retained_fields),
            exported_at=exported_at,
            source=source,
        )

    @classmethod
    def from_json(
        cls,
        text: str | bytes,
        *,
        reference_time: datetime | None = None,
        source: str | None = None,
    ) -> EventExport:
        return cls.from_dict(json.loads(text), reference_time=reference_time, source=source)

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        *,
        reference_time: datetime | None = None,
    ) -> EventExport:
        path = Path(path)
        with path.open(encoding="utf-8") as handle:
            return cls.from_json(handle.read(), reference_time=reference_time, source=str(path))

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "exported_at": _iso(self.exported_at),
            "retained_fields": (
                sorted(self.retained_fields) if self.retained_fields is not None else None
            ),
            "event_count": len(self.events),
            "window": self.window.to_dict() if self.window is not None else None,
            "events": [
                {
                    "timestamp": _iso(event.timestamp),
                    "logsource": {
                        "category": event.logsource.category,
                        "product": event.logsource.product,
                        "service": event.logsource.service,
                    },
                    "data": event.data,
                    "raw": event.raw,
                }
                for event in self.events
            ],
        }


def _parse_event(record: Mapping[str, Any], reference_time: datetime | None = None) -> Event:
    """Convert one JSON event record into an :class:`Event`."""
    timestamp_value: Any = None
    for key in ("timestamp", "@timestamp", "time", "ts"):
        if key in record:
            timestamp_value = record[key]
            break
    if timestamp_value is None:
        if reference_time is None:
            raise ValueError("Event record has no timestamp and no reference_time was supplied")
        timestamp = _utc(reference_time)
    else:
        timestamp = _parse_datetime(timestamp_value)
    assert timestamp is not None

    raw_logsource = record.get("logsource", {})
    if isinstance(raw_logsource, EventLogSource):
        logsource = raw_logsource
    elif isinstance(raw_logsource, Mapping):
        logsource = EventLogSource(
            category=raw_logsource.get("category"),
            product=raw_logsource.get("product"),
            service=raw_logsource.get("service"),
        )
    else:
        logsource = EventLogSource()

    if "data" in record:
        data = dict(record["data"])
    else:
        metadata = {
            "timestamp",
            "@timestamp",
            "time",
            "ts",
            "logsource",
            "raw",
        }
        data = {key: value for key, value in record.items() if key not in metadata}

    return Event(
        timestamp=timestamp,
        logsource=logsource,
        data=data,
        raw=record.get("raw"),
    )


@dataclass(frozen=True)
class MissingField:
    """One missing field finding for a rule."""

    field: str
    """Original field name from the rule, or ``<raw>`` for raw log text."""

    mapped_fields: tuple[str, ...]
    """Post-conversion field names that could satisfy the requirement."""

    reason: MissingFieldReason
    recoverable: bool
    blocking: bool = True
    applicable_from: datetime | None = None
    applicable_to: datetime | None = None
    restore_from: datetime | None = None
    restore_to: datetime | None = None
    note: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.reason, str):
            object.__setattr__(self, "reason", MissingFieldReason(self.reason))
        for name in ("applicable_from", "applicable_to", "restore_from", "restore_to"):
            object.__setattr__(self, name, _utc(getattr(self, name)))

    @property
    def applicable_window(self) -> TimeWindow | None:
        if self.applicable_from is None and self.applicable_to is None:
            return None
        return TimeWindow(self.applicable_from, self.applicable_to)

    @property
    def restore_window(self) -> TimeWindow | None:
        if self.restore_from is None and self.restore_to is None:
            return None
        return TimeWindow(self.restore_from, self.restore_to)

    def to_dict(self) -> dict[str, Any]:
        return {
            "field": self.field,
            "mapped_fields": list(self.mapped_fields),
            "reason": self.reason.value,
            "recoverable": self.recoverable,
            "blocking": self.blocking,
            "applicable_from": _iso(self.applicable_from),
            "applicable_to": _iso(self.applicable_to),
            "restore_from": _iso(self.restore_from),
            "restore_to": _iso(self.restore_to),
            "note": self.note,
        }


@dataclass
class RuleReview:
    """Review result for one rule."""

    rule: SigmaRule | SigmaCorrelationRule
    status: ReviewStatus
    required_fields: tuple[str, ...] = ()
    mapped_fields: tuple[str, ...] = ()
    missing_fields: tuple[MissingField, ...] = ()
    matches: tuple[SigmaMatch, ...] = ()
    evidence_window: TimeWindow | None = None
    field_mappings: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    reason: str | None = None

    @property
    def name(self) -> str | None:
        return self.rule.name

    @property
    def title(self) -> str:
        return self.rule.title

    @property
    def reviewable(self) -> bool:
        return self.status == ReviewStatus.REVIEWABLE

    @property
    def reproduced(self) -> bool:
        return bool(self.matches)

    @property
    def needs_backfill(self) -> bool:
        return self.status == ReviewStatus.NEEDS_BACKFILL

    @property
    def has_unrecoverable_fields(self) -> bool:
        return bool(self.unrecoverable_fields)

    @property
    def backfill_fields(self) -> tuple[MissingField, ...]:
        """Blocking findings whose data can still be recovered."""
        return tuple(field for field in self.missing_fields if field.blocking and field.recoverable)

    @property
    def unrecoverable_fields(self) -> tuple[MissingField, ...]:
        """Blocking findings whose data can no longer be recovered."""
        return tuple(
            field for field in self.missing_fields if field.blocking and not field.recoverable
        )

    @property
    def source_absent_fields(self) -> tuple[MissingField, ...]:
        """Retained fields for which the relevant events genuinely had no value."""
        return tuple(
            field
            for field in self.missing_fields
            if field.reason == MissingFieldReason.SOURCE_ABSENT
        )

    @property
    def fields_to_backfill(self) -> tuple[str, ...]:
        """Minimum original fields the collection team must supply."""
        return tuple(field.field for field in self.backfill_fields)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "status": self.status.value,
            "reviewable": self.reviewable,
            "reproduced": self.reproduced,
            "match_count": len(self.matches),
            "reason": self.reason,
            "required_fields": list(self.required_fields),
            "mapped_fields": list(self.mapped_fields),
            "fields_to_backfill": list(self.fields_to_backfill),
            "field_mappings": {
                source: list(targets) for source, targets in self.field_mappings.items()
            },
            "missing_fields": [finding.to_dict() for finding in self.missing_fields],
            "evidence_window": (
                self.evidence_window.to_dict() if self.evidence_window is not None else None
            ),
        }


@dataclass
class ReviewReport:
    """Review outcome for all rules against one export."""

    results: list[RuleReview]
    export: EventExport
    policy: RetentionPolicy
    reference_time: datetime | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "reference_time", _utc(self.reference_time))

    def __iter__(self):
        return iter(self.results)

    def __len__(self) -> int:
        return len(self.results)

    def __getitem__(self, index: int | str) -> RuleReview:
        if isinstance(index, int):
            return self.results[index]
        for result in self.results:
            if result.name == index or result.title == index:
                return result
        raise KeyError(f"Rule '{index}' not found in review report")

    @property
    def reviewable_rules(self) -> tuple[RuleReview, ...]:
        return tuple(result for result in self.results if result.reviewable)

    @property
    def rules_needing_backfill(self) -> tuple[RuleReview, ...]:
        return tuple(
            result for result in self.results if result.status == ReviewStatus.NEEDS_BACKFILL
        )

    @property
    def needs_backfill_rules(self) -> tuple[RuleReview, ...]:
        """Alias for :attr:`rules_needing_backfill`."""
        return self.rules_needing_backfill

    def for_rule(self, rule_or_name: str | SigmaRule | SigmaCorrelationRule) -> RuleReview:
        """Return the review result for a rule object, name, or title."""
        if isinstance(rule_or_name, (SigmaRule, SigmaCorrelationRule)):
            for result in self.results:
                if result.rule is rule_or_name:
                    return result
            raise KeyError("Rule object is not part of this report")
        return self[rule_or_name]

    @property
    def unrecoverable_rules(self) -> tuple[RuleReview, ...]:
        return tuple(
            result for result in self.results if result.status == ReviewStatus.UNRECOVERABLE
        )

    @property
    def reproduced_rules(self) -> tuple[RuleReview, ...]:
        return tuple(result for result in self.results if result.reproduced)

    def summary(self) -> dict[str, int]:
        return {
            "rules": len(self.results),
            "reviewable": len(self.reviewable_rules),
            "needs_backfill": len(self.rules_needing_backfill),
            "unrecoverable": len(self.unrecoverable_rules),
            "reproduced": len(self.reproduced_rules),
            "backfill_fields": sum(len(result.backfill_fields) for result in self.results),
            "unrecoverable_fields": sum(
                len(result.unrecoverable_fields) for result in self.results
            ),
            "source_absent_fields": sum(
                len(result.source_absent_fields) for result in self.results
            ),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "reference_time": _iso(self.reference_time),
            "export": self.export.to_dict(),
            "policy": self.policy.to_dict(),
            "rules": [result.to_dict() for result in self.results],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(
            self.to_dict(), indent=indent, ensure_ascii=False, default=str
        )


def _logsource_matches(rule: SigmaRule | SigmaCorrelationRule, event: Event) -> bool:
    """Mirror SigmaLogSource containment without constructing empty log sources."""
    logsource = getattr(rule, "logsource", None)
    if logsource is None:
        # Correlation rules do not have their own logsource. Their referenced
        # base rules do the routing, so consider every exported event.
        return True
    return all(
        getattr(logsource, attribute) is None
        or getattr(logsource, attribute) == getattr(event.logsource, attribute)
        for attribute in ("category", "product", "service")
    )


def _collect_condition_fields(
    node: ConditionItem | ConditionFieldEqualsValueExpression | ConditionValueExpression | None,
) -> tuple[set[str], bool]:
    """Return referenced fields and whether a keyword/raw condition is present."""
    if node is None:
        return set(), False
    if isinstance(node, (ConditionAND, ConditionOR)):
        fields: set[str] = set()
        keyword = False
        for argument in node.args:
            argument_fields, argument_keyword = _collect_condition_fields(argument)
            fields.update(argument_fields)
            keyword = keyword or argument_keyword
        return fields, keyword
    if isinstance(node, ConditionNOT):
        return _collect_condition_fields(node.args[0])
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return {node.field}, False
    if isinstance(node, ConditionValueExpression):
        return set(), True
    if isinstance(node, ConditionItem):
        fields = set()
        keyword = False
        for argument in node.args:
            if isinstance(
                argument,
                (ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression),
            ):
                argument_fields, argument_keyword = _collect_condition_fields(argument)
                fields.update(argument_fields)
                keyword = keyword or argument_keyword
        return fields, keyword
    return set(), False


def _rule_condition_fields(
    rule: SigmaRule | SigmaCorrelationRule,
) -> tuple[set[str], bool]:
    """Extract fields referenced by the rule's actual condition, not all detections."""
    fields: set[str] = set()
    keyword = False
    if isinstance(rule, SigmaRule):
        for condition in rule.detection.parsed_condition:
            condition_fields, condition_keyword = _collect_condition_fields(condition.parsed)
            fields.update(condition_fields)
            keyword = keyword or condition_keyword
    else:
        if rule.group_by:
            fields.update(rule.group_by)
        condition = rule.condition
        if isinstance(condition, SigmaCorrelationCondition) and condition.fieldref is not None:
            if isinstance(condition.fieldref, list):
                fields.update(condition.fieldref)
            else:
                fields.add(condition.fieldref)
    return fields, keyword


@dataclass(frozen=True)
class _Requirement:
    field: str
    mapped_fields: tuple[str, ...]


class OfflineReviewer:
    """Offline review entry point.

    The rules are processed once with the supplied pipeline so that
    before/after field mappings can be captured.  The reviewer then evaluates
    the export and reports, per rule, whether the retained evidence is enough
    and which original fields need to be recovered.

    :param rules: ``SigmaCollection``, a single rule, or an iterable of rules.
    :param retention: Caller-declared retention policy.
    :param pipeline: Optional processing pipeline used for field conversion.
    :param reference_time: Fallback timestamp for exports without timestamps.
    """

    def __init__(
        self,
        rules: SigmaCollection
        | SigmaRule
        | SigmaCorrelationRule
        | Iterable[SigmaRule]
        | str
        | Path,
        retention: RetentionPolicy,
        *,
        pipeline: ProcessingPipeline | None = None,
        reference_time: datetime | None = None,
    ) -> None:
        self.policy = retention
        self.pipeline = pipeline
        self.reference_time = _utc(reference_time)
        self.collection = _coerce_rules(rules)
        self._original_fields: dict[int, set[str]] = {}
        self._keyword_rules: dict[int, bool] = {}
        self._field_mappings: dict[int, dict[str, tuple[str, ...]]] = {}
        self._prepare_rules()

    def _prepare_rules(self) -> None:
        for rule in self.collection.rules:
            original_fields, original_keyword = _rule_condition_fields(rule)
            self._original_fields[id(rule)] = original_fields
            self._keyword_rules[id(rule)] = original_keyword
            if self.pipeline is not None:
                self.pipeline.apply(rule)
                mapping = {
                    source: tuple(sorted(targets))
                    for source, targets in self.pipeline.field_mappings.items()
                }
                self._field_mappings[id(rule)] = mapping
            else:
                self._field_mappings[id(rule)] = {}

    def _requirements(
        self,
        rule: SigmaRule | SigmaCorrelationRule,
        _visited: set[int] | None = None,
    ) -> list[_Requirement]:
        if _visited is None:
            _visited = set()
        if id(rule) in _visited:
            return []
        _visited.add(id(rule))

        original_fields = self._original_fields[id(rule)]
        mapped_fields, _ = _rule_condition_fields(rule)
        mapping = self._field_mappings[id(rule)]

        requirements: dict[str, set[str]] = {}
        for original in original_fields:
            mapped = set(mapping.get(original, (original,)))
            if not mapped:
                # A drop transformation removed the field entirely.
                continue
            relevant = mapped & mapped_fields
            if not relevant and mapped_fields:
                # The field no longer occurs in the condition after processing.
                continue
            requirements.setdefault(original, set()).update(relevant or mapped)

        # Fields added by the pipeline do not have an original name; report the
        # post-conversion name directly.
        covered = {field for targets in requirements.values() for field in targets}
        for mapped_field in sorted(mapped_fields - covered):
            requirements.setdefault(mapped_field, set()).add(mapped_field)

        if self._keyword_rules[id(rule)]:
            requirements.setdefault(RAW_FIELD, set()).add(RAW_FIELD)

        if isinstance(rule, SigmaCorrelationRule):
            referenced: list[SigmaRule | SigmaCorrelationRule] = []
            if rule.rules:
                referenced = [
                    reference.rule for reference in rule.rules if hasattr(reference, "rule")
                ]
            elif isinstance(rule.condition, SigmaExtendedCorrelationCondition):
                referenced = [
                    self.collection[name]
                    for name in rule.condition.get_referenced_rules()
                    if name in self.collection.names_to_rules
                ]
            for base_rule in referenced:
                if isinstance(base_rule, (SigmaRule, SigmaCorrelationRule)):
                    for base_requirement in self._requirements(base_rule, _visited):
                        requirements.setdefault(base_requirement.field, set()).update(
                            base_requirement.mapped_fields
                        )

        return [
            _Requirement(field=original, mapped_fields=tuple(sorted(mapped)))
            for original, mapped in sorted(requirements.items())
        ]

    def review(
        self,
        export: EventExport | Iterable[Event] | Mapping[str, Any] | str | Path,
    ) -> ReviewReport:
        """Review the export.

        ``export`` may be an :class:`EventExport`, an iterable of
        :class:`~sigma.matching.Event` objects, a JSON-like mapping, a JSON
        string, or a path to a JSON export.
        """
        export = _coerce_export(export, self.reference_time)
        results = [self._review_rule(rule, export) for rule in self.collection.rules]

        if any(result.status == ReviewStatus.REVIEWABLE for result in results):
            matches = SigmaMatcher(self.collection).bulk_match(export.events)
            for result in results:
                if result.status == ReviewStatus.REVIEWABLE:
                    result.matches = tuple(
                        match for match in matches if match.rule is result.rule
                    )
                    if not result.matches:
                        result.reason = (
                            "all required evidence is retained, but the alert did not "
                            "reproduce from the exported events"
                        )
        return ReviewReport(
            results=results,
            export=export,
            policy=self.policy,
            reference_time=self.reference_time,
        )

    def review_export(
        self,
        export: EventExport | Iterable[Event] | Mapping[str, Any] | str | Path,
    ) -> ReviewReport:
        """Alias for :meth:`review`."""
        return self.review(export)

    def _review_rule(
        self,
        rule: SigmaRule | SigmaCorrelationRule,
        export: EventExport,
    ) -> RuleReview:
        requirements = self._requirements(rule)
        requirement_by_field = {requirement.field: requirement for requirement in requirements}
        reverse: dict[str, set[str]] = {}
        for requirement in requirements:
            for mapped_field in requirement.mapped_fields:
                reverse.setdefault(mapped_field, set()).add(requirement.field)

        relevant_events = [
            event for event in export.events if _logsource_matches(rule, event)
        ]
        evidence_window = TimeWindow.around(event.timestamp for event in relevant_events)
        available_fields = export.available_fields(self.policy)
        observed_fields = frozenset(key for event in relevant_events for key in event.data)
        has_raw = any(event.raw is not None for event in relevant_events)

        def original_for(mapped_field: str) -> str:
            candidates = reverse.get(mapped_field)
            if not candidates:
                return mapped_field
            return sorted(candidates)[0]

        def field_cost(mapped_field: str, original: str) -> tuple[int, int]:
            if mapped_field == RAW_FIELD:
                if has_raw:
                    return 0, 0
            elif mapped_field in available_fields:
                return 0, 0
            retention = self.policy.classify((mapped_field, original), evidence_window)
            return (0, 1) if retention.recoverable else (1, 0)

        def plan_key(plan: dict[str, str]) -> tuple[Any, ...]:
            unrecoverable = 0
            backfill = 0
            for mapped_field, original in plan.items():
                field_unrecoverable, field_backfill = field_cost(mapped_field, original)
                unrecoverable += field_unrecoverable
                backfill += field_backfill
            return (unrecoverable, backfill, len(plan), tuple(sorted(plan.items())))

        def choose(plans: list[dict[str, str]]) -> dict[str, str]:
            return min(plans, key=plan_key) if plans else {}

        def merge(plans: list[dict[str, str]]) -> dict[str, str]:
            merged: dict[str, str] = {}
            for plan in plans:
                merged.update(plan)
            return merged

        def walk(node) -> tuple[dict[str, str], dict[str, str]]:
            if node is None:
                return {}, {}
            if isinstance(node, ConditionNOT):
                true_plan, false_plan = walk(node.args[0])
                return false_plan, true_plan
            if isinstance(node, ConditionAND):
                children = [walk(argument) for argument in node.args]
                return (
                    merge([true_plan for true_plan, _ in children]),
                    choose([false_plan for _, false_plan in children]),
                )
            if isinstance(node, ConditionOR):
                children = [walk(argument) for argument in node.args]
                return (
                    choose([true_plan for true_plan, _ in children]),
                    merge([false_plan for _, false_plan in children]),
                )
            if isinstance(node, ConditionFieldEqualsValueExpression):
                plan = {node.field: original_for(node.field)}
                return dict(plan), dict(plan)
            if isinstance(node, ConditionValueExpression):
                plan = {RAW_FIELD: RAW_FIELD}
                return dict(plan), dict(plan)
            if isinstance(node, ConditionItem):
                children = [
                    walk(argument)
                    for argument in node.args
                    if isinstance(
                        argument,
                        (
                            ConditionItem,
                            ConditionFieldEqualsValueExpression,
                            ConditionValueExpression,
                        ),
                    )
                ]
                if not children:
                    return {}, {}
                return (
                    choose([true_plan for true_plan, _ in children]),
                    merge([false_plan for _, false_plan in children]),
                )
            return {}, {}

        if isinstance(rule, SigmaRule):
            plan = choose(
                [walk(condition.parsed)[0] for condition in rule.detection.parsed_condition]
            )
        else:
            plan = {
                mapped_field: requirement.field
                for requirement in requirements
                for mapped_field in requirement.mapped_fields
            }

        required_fields = tuple(sorted({original for original in plan.values()}))
        mapped_fields = tuple(
            sorted(mapped_field for mapped_field in plan if mapped_field != RAW_FIELD)
        )
        field_mappings = {
            field: (
                requirement_by_field[field].mapped_fields
                if field in requirement_by_field
                else (field,)
            )
            for field in required_fields
        }

        if not relevant_events:
            return RuleReview(
                rule=rule,
                status=ReviewStatus.NOT_APPLICABLE,
                required_fields=required_fields,
                mapped_fields=mapped_fields,
                evidence_window=None,
                field_mappings=field_mappings,
                reason="no exported events match the rule log source",
            )

        findings: list[MissingField] = []
        grouped: dict[str, list[str]] = {}
        for mapped_field, original in plan.items():
            grouped.setdefault(original, []).append(mapped_field)

        for original, mapped_choices in sorted(grouped.items()):
            requirement = requirement_by_field.get(
                original,
                _Requirement(field=original, mapped_fields=tuple(sorted(mapped_choices))),
            )
            if original == RAW_FIELD:
                if not has_raw:
                    findings.append(
                        self._missing_field(
                            requirement,
                            evidence_window,
                            note="keyword detection needs the original raw log text",
                        )
                    )
                continue

            matching_fields = [
                mapped_field for mapped_field in mapped_choices if mapped_field in available_fields
            ]
            if matching_fields:
                if not (set(matching_fields) & observed_fields):
                    findings.append(self._source_absent_field(requirement, evidence_window))
                continue

            findings.append(self._missing_field(requirement, evidence_window))

        blocking = [finding for finding in findings if finding.blocking]
        if not blocking:
            status = ReviewStatus.REVIEWABLE
            reason = "all required evidence survived in the export"
            if any(finding.reason == MissingFieldReason.SOURCE_ABSENT for finding in findings):
                reason = (
                    "all required evidence survived; some retained fields had no value "
                    "in the relevant events"
                )
        elif any(finding.recoverable for finding in blocking):
            status = ReviewStatus.NEEDS_BACKFILL
            if any(not finding.recoverable for finding in blocking):
                reason = (
                    "some missing evidence can be recovered from the collection team, "
                    "but other required fields are unrecoverable"
                )
            else:
                reason = "missing evidence can be recovered from the collection team"
        else:
            status = ReviewStatus.UNRECOVERABLE
            reason = "required evidence was never captured or cannot be recovered"

        return RuleReview(
            rule=rule,
            status=status,
            required_fields=required_fields,
            mapped_fields=mapped_fields,
            missing_fields=tuple(findings),
            evidence_window=evidence_window,
            field_mappings=field_mappings,
            reason=reason,
        )

    def _missing_field(
        self,
        requirement: _Requirement,
        evidence_window: TimeWindow | None,
        *,
        note: str | None = None,
    ) -> MissingField:
        candidates = (*requirement.mapped_fields, requirement.field)
        retention = self.policy.classify(candidates, evidence_window)
        applicable = evidence_window
        if retention.window is not None:
            applicable = (
                evidence_window.intersection(retention.window)
                if evidence_window is not None
                else retention.window
            )
        restore = retention.restore_window
        if (
            restore is not None
            and evidence_window is not None
            and applicable is None
            and restore.intersection(evidence_window) is None
        ):
            applicable = None
        if note is not None:
            retention_note = note
        else:
            retention_note = retention.note
        return MissingField(
            field=requirement.field,
            mapped_fields=requirement.mapped_fields,
            reason=retention.reason,
            recoverable=retention.recoverable,
            blocking=retention.reason != MissingFieldReason.SOURCE_ABSENT,
            applicable_from=applicable.start if applicable is not None else None,
            applicable_to=applicable.end if applicable is not None else None,
            restore_from=restore.start if restore is not None else None,
            restore_to=restore.end if restore is not None else None,
            note=retention_note,
        )

    @staticmethod
    def _source_absent_field(
        requirement: _Requirement,
        evidence_window: TimeWindow | None,
    ) -> MissingField:
        return MissingField(
            field=requirement.field,
            mapped_fields=requirement.mapped_fields,
            reason=MissingFieldReason.SOURCE_ABSENT,
            recoverable=False,
            blocking=False,
            applicable_from=evidence_window.start if evidence_window is not None else None,
            applicable_to=evidence_window.end if evidence_window is not None else None,
            note=(
                "the export retained this field, but no relevant event had a value; "
                "absence is real event data, not a retention loss"
            ),
        )


def _coerce_rules(
    rules: SigmaCollection
    | SigmaRule
    | SigmaCorrelationRule
    | Iterable[SigmaRule]
    | str
    | Path,
) -> SigmaCollection:
    if isinstance(rules, SigmaCollection):
        return rules
    if isinstance(rules, (SigmaRule, SigmaCorrelationRule)):
        return SigmaCollection([rules])
    if isinstance(rules, Path):
        return SigmaCollection.load_ruleset([rules])
    if isinstance(rules, str):
        return SigmaCollection.from_yaml(rules)
    return SigmaCollection(list(rules))


def _coerce_export(
    export: EventExport | Iterable[Event] | Mapping[str, Any] | str | Path,
    reference_time: datetime | None = None,
) -> EventExport:
    if isinstance(export, EventExport):
        return export
    if isinstance(export, (str, Path)):
        text = export if isinstance(export, str) else None
        if text is not None and text.lstrip().startswith(("{", "[")):
            return EventExport.from_json(text, reference_time=reference_time)
        return EventExport.from_file(export, reference_time=reference_time)
    if isinstance(export, Event):
        return EventExport.from_events([export])
    if isinstance(export, Mapping):
        return EventExport.from_dict(export, reference_time=reference_time)
    items = list(export)
    if all(isinstance(item, Event) for item in items):
        return EventExport.from_events(items)
    return EventExport.from_dict(items, reference_time=reference_time)


def review_offline(
    rules: SigmaCollection | SigmaRule | SigmaCorrelationRule | Iterable[SigmaRule] | str | Path,
    export: EventExport | Iterable[Event] | Mapping[str, Any] | str | Path,
    retention: RetentionPolicy,
    *,
    pipeline: ProcessingPipeline | None = None,
    reference_time: datetime | None = None,
) -> ReviewReport:
    """Convenience wrapper around :class:`OfflineReviewer`.

    Example::

        report = review_offline(
            rules,
            export=EventExport.from_file("export.json"),
            retention=RetentionPolicy(
                never_captured_fields={"process.parent.name"},
                purged_fields={"process.executable": TimeWindow(...)},
            ),
            pipeline=ecs_pipeline,
        )
    """
    return OfflineReviewer(
        rules,
        retention,
        pipeline=pipeline,
        reference_time=reference_time,
    ).review(export)


OfflineReview = OfflineReviewer
SigmaOfflineReviewer = OfflineReviewer
review_alerts = review_offline
review_export = review_offline

__all__ = [
    "RAW_FIELD",
    "EventExport",
    "FieldRetention",
    "MissingField",
    "MissingFieldReason",
    "OfflineReview",
    "OfflineReviewer",
    "RetentionPolicy",
    "ReviewReport",
    "ReviewStatus",
    "RuleReview",
    "SigmaOfflineReviewer",
    "TimeWindow",
    "review_alerts",
    "review_export",
    "review_offline",
]
