"""Data types for offline exception-quota reconciliation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Union

KIND_DEDUCTION = "deduction"
KIND_DUPLICATE = "duplicate"
KIND_ACTIONABLE = "actionable"
KIND_LATE_REJECTED = "late_rejected"
KIND_CORRECTION = "correction"
KIND_WINDOW_CLOSED = "window_closed"

CORRECTION_SPLIT = "identity_split"
CORRECTION_MERGE = "identity_merge"


@dataclass(frozen=True)
class Observation:
    """One matched event record forwarded by a collector.

    Observations sharing ``(group_key, event_id)`` describe the same real-world
    event; multiple copies are kept so double deduction can be demonstrated.
    """

    event_id: str
    group_key: str
    event_time: datetime
    ingest_time: datetime
    exempt: bool
    rule_name: str = "sigma_rule"
    source: str = "pysigma"
    raw: str | None = None


@dataclass(frozen=True)
class CallerHints:
    """Caller-supplied identity, exception scope and timestamp instructions."""

    identity_field: Union[str, Callable[[dict[str, Any]], str]]
    group_field: Union[str, Callable[[dict[str, Any]], str]]
    exempt_scope: Union[str, Callable[[dict[str, Any]], bool]]
    timestamp_field: Union[str, Callable[[dict[str, Any]], datetime], None] = None


@dataclass(frozen=True)
class Correction:
    """Retroactive confirmation that two records were not the same event.

    The original identity is split into ``new_event_id`` and the exception
    membership is re-evaluated as ``new_exempt``.
    """

    original_event_id: str
    new_event_id: str
    group_key: str
    event_time: datetime
    received_time: datetime
    new_exempt: bool
    correction_type: str = CORRECTION_SPLIT
    reason: str = ""


@dataclass
class TimelineEntry:
    """One line of the short processing timeline."""

    kind: str
    timestamp: datetime
    group_key: str
    event_id: str | None
    detail: str = ""
    window_start: datetime | None = None
    window_end: datetime | None = None
    correction: Correction | None = None
    before: dict[Any, Any] = field(default_factory=dict)
    after: dict[Any, Any] = field(default_factory=dict)


@dataclass
class ReconciliationResult:
    """Everything produced by one offline reconciliation run."""

    timeline: list[TimelineEntry]
    ledgers: dict[Any, Any]
    closed_windows: set[Any]
    late_rejected: list[TimelineEntry]
    corrections: list[Correction]
    watermark: datetime | None
