"""
Evidence-aware partial ordering for python-registry snapshots.

The module intentionally never consults the system clock and never calls a
Windows API.  LastWrite values are retained as evidence, but timestamp order is
never treated as a causal constraint.
"""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict, deque
from collections.abc import Mapping as MappingABC
from collections.abc import Sequence as SequenceABC
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

__all__ = [
    "Interval",
    "Source",
    "Event",
    "Constraint",
    "Conflict",
    "Relation",
    "OrderingReport",
    "Snapshot",
    "KeyState",
    "ValueState",
    "PartialOrderGraph",
    "PartialOrderConflictError",
    "RelationType",
    "build_report",
    "build_partial_order",
    "build_event_partial_order",
    "analyze_snapshots",
    "snapshot_from_registry",
    "key_state_from_registry",
    "normalize_path",
]


class RelationType:
    BEFORE = "before"
    AFTER = "after"
    POSSIBLY_CONCURRENT = "possibly_concurrent"
    INCOMPARABLE = "incomparable"
    SAME = "same"
    CONFLICTING = "conflicting"

    HAPPENS_BEFORE = BEFORE
    PRECEDES = BEFORE
    DEFINITELY_BEFORE = BEFORE
    DEFINITELY_AFTER = AFTER
    CONCURRENT = POSSIBLY_CONCURRENT
    POSSIBLE_CONCURRENT = POSSIBLY_CONCURRENT


BEFORE = RelationType.BEFORE
AFTER = RelationType.AFTER
POSSIBLY_CONCURRENT = RelationType.POSSIBLY_CONCURRENT
INCOMPARABLE = RelationType.INCOMPARABLE
SAME = RelationType.SAME
CONFLICTING = RelationType.CONFLICTING
HAPPENS_BEFORE = BEFORE
CONCURRENT = POSSIBLY_CONCURRENT


class PartialOrderConflictError(ValueError):
    def __init__(self, report: "OrderingReport"):
        self.report = report
        conflict = report.conflicts[0] if report.conflicts else None
        if conflict is None:
            message = "partial order constraints are inconsistent"
        else:
            message = "minimal conflict: " + " -> ".join(conflict.cycle)
        super().__init__(message)


ConflictError = PartialOrderConflictError
PartialOrderConflict = PartialOrderConflictError


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        return {"__datetime__": value.isoformat()}
    if isinstance(value, bytes):
        return "sha256:" + hashlib.sha256(value).hexdigest()
    if hasattr(value, "to_dict"):
        try:
            return _jsonable(value.to_dict())
        except Exception:
            pass
    if isinstance(value, MappingABC):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (set, frozenset, list, tuple)):
        return [_jsonable(v) for v in value]
    return repr(value)


def stable_digest(prefix: str, payload: Any) -> str:
    raw = json.dumps(
        _jsonable(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()[:16]
    return digest if not prefix else prefix + ":" + digest


def _lt(left: Any, right: Any) -> bool:
    try:
        return left < right
    except TypeError:
        return str(_jsonable(left)) < str(_jsonable(right))


def _equal(left: Any, right: Any) -> bool:
    try:
        return bool(left == right)
    except TypeError:
        return stable_digest("v", left) == stable_digest("v", right)


def normalize_path(path: Optional[str]) -> str:
    if path is None:
        return ""
    normalized = str(path).replace("/", "\\")
    while "\\\\" in normalized:
        normalized = normalized.replace("\\\\", "\\")
    return normalized.strip("\\").rstrip()


def path_identity(path: Optional[str]) -> str:
    return normalize_path(path).casefold()


def parent_path_identity(identity: str) -> Optional[str]:
    if "\\" not in identity:
        return None
    parent, _separator, _name = identity.rpartition("\\")
    return parent or None


@dataclass(frozen=True)
class Interval:
    start: Any = None
    end: Any = None

    def __post_init__(self) -> None:
        if self.start is not None and self.end is not None and _lt(self.end, self.start):
            raise ValueError("interval end precedes start: %r > %r" % (self.start, self.end))

    def before(self, other: "Interval") -> bool:
        return self.end is not None and other.start is not None and _lt(self.end, other.start)

    def overlaps(self, other: "Interval") -> bool:
        if self.end is None or self.start is None or other.end is None or other.start is None:
            return False
        return not (_lt(self.end, other.start) or _lt(other.end, self.start))

    def to_dict(self) -> Dict[str, Any]:
        return {"start": _jsonable(self.start), "end": _jsonable(self.end)}


def _first_key(data: Any, names: Tuple[str, ...]) -> Any:
    if isinstance(data, MappingABC):
        for name in names:
            if name in data:
                return data[name]
        return None
    for name in names:
        if hasattr(data, name):
            return getattr(data, name)
    return None


def coerce_interval(value: Any) -> Optional[Interval]:
    if value is None or isinstance(value, Interval):
        return value
    if isinstance(value, MappingABC):
        start = _first_key(value, ("start", "earliest", "not_before", "collected_after", "begin"))
        end = _first_key(value, ("end", "latest", "not_after", "collected_before", "finish"))
        if start is None and end is None:
            start = value.get("0")
            end = value.get("1")
        return Interval(start, end)
    if isinstance(value, (list, tuple)) and len(value) == 2:
        return Interval(value[0], value[1])
    return Interval(value, value)


def _freeze_evidence(value: Any) -> Any:
    if isinstance(value, MappingABC):
        return tuple(sorted((str(k), _freeze_evidence(v)) for k, v in value.items()))
    if isinstance(value, (list, set, frozenset)):
        return tuple(sorted((_freeze_evidence(v) for v in value), key=lambda x: stable_digest("", x)))
    return value


@dataclass(frozen=True)
class Source:
    kind: str
    detail: str = ""
    snapshot_id: Optional[str] = None
    other_snapshot_id: Optional[str] = None
    subject: Optional[str] = None
    rule: Optional[str] = None
    evidence: Tuple[Tuple[str, Any], ...] = ()

    def __post_init__(self) -> None:
        if isinstance(self.evidence, MappingABC):
            object.__setattr__(
                self,
                "evidence",
                tuple(sorted((str(k), _freeze_evidence(v)) for k, v in self.evidence.items())),
            )
        elif isinstance(self.evidence, list):
            object.__setattr__(self, "evidence", tuple(_freeze_evidence(self.evidence)))

    def key(self) -> str:
        return stable_digest("source", self.to_dict())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "detail": self.detail,
            "snapshot_id": self.snapshot_id,
            "other_snapshot_id": self.other_snapshot_id,
            "subject": self.subject,
            "rule": self.rule,
            "evidence": _jsonable(self.evidence),
        }


def coerce_sources(value: Any) -> Tuple[Source, ...]:
    if value is None:
        return ()
    if isinstance(value, Source):
        return (value,)
    if isinstance(value, MappingABC):
        return (Source(**{k: v for k, v in value.items() if k in Source.__dataclass_fields__}),)
    if isinstance(value, (list, tuple, set, frozenset)):
        result: List[Source] = []
        for item in value:
            result.extend(coerce_sources(item))
        return tuple(result)
    return (Source(kind=str(value)),)


@dataclass
class Event:
    event_id: str
    kind: str = "event"
    subject: Optional[str] = None
    timestamp: Any = None
    time_bounds: Optional[Interval] = None
    collection_interval: Optional[Interval] = None
    snapshot_ids: Tuple[str, ...] = ()
    sources: Tuple[Source, ...] = ()
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "kind": self.kind,
            "subject": self.subject,
            "timestamp": _jsonable(self.timestamp),
            "time_bounds": None if self.time_bounds is None else self.time_bounds.to_dict(),
            "collection_interval": None
            if self.collection_interval is None
            else self.collection_interval.to_dict(),
            "snapshot_ids": list(self.snapshot_ids),
            "sources": [s.to_dict() for s in self.sources],
            "attributes": _jsonable(self.attributes),
        }


def event_from_mapping(data: MappingABC) -> Event:
    data = dict(data)
    event_id = data.pop("event_id", None) or data.pop("id", None) or data.pop("name", None)
    if event_id is None:
        event_id = stable_digest("event", data)
    interval = coerce_interval(data.pop("time_bounds", None) or data.pop("bounds", None))
    collection_interval = coerce_interval(
        data.pop("collection_interval", None) or data.pop("collected_interval", None)
    )
    snapshot_ids = data.pop("snapshot_ids", ()) or ()
    snapshot_id = data.pop("snapshot_id", None)
    if snapshot_id is not None:
        snapshot_ids = tuple(snapshot_ids) + (snapshot_id,)
    return Event(
        event_id=str(event_id),
        kind=str(data.pop("kind", data.pop("type", "event"))),
        subject=data.pop("subject", data.pop("path", None)),
        timestamp=data.pop("timestamp", data.pop("last_write", data.pop("LastWrite", None))),
        time_bounds=interval,
        collection_interval=collection_interval,
        snapshot_ids=tuple(sorted(set(str(x) for x in snapshot_ids))),
        sources=coerce_sources(data.pop("sources", data.pop("source", None))),
        attributes=dict(data.pop("attributes", {}) or {}, **data),
    )


@dataclass(frozen=True)
class Constraint:
    before: str
    after: str
    constraint_id: str = ""
    kind: str = "explicit"
    reason: str = ""
    sources: Tuple[Source, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "constraint_id": self.constraint_id,
            "before": self.before,
            "after": self.after,
            "kind": self.kind,
            "reason": self.reason,
            "sources": [s.to_dict() for s in self.sources],
        }


@dataclass(frozen=True)
class Conflict:
    cycle: Tuple[str, ...]
    event_ids: Tuple[str, ...]
    constraint_ids: Tuple[str, ...]
    constraints: Tuple[Constraint, ...]
    sources: Tuple[Source, ...]
    message: str

    @property
    def minimal_subset(self) -> Tuple[Constraint, ...]:
        return self.constraints

    @property
    def minimal_conflict_subset(self) -> Tuple[Constraint, ...]:
        return self.constraints

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cycle": list(self.cycle),
            "event_ids": list(self.event_ids),
            "constraint_ids": list(self.constraint_ids),
            "minimal_conflict_subset": [c.to_dict() for c in self.constraints],
            "sources": [s.to_dict() for s in self.sources],
            "message": self.message,
        }


@dataclass(frozen=True)
class Relation:
    left: str
    right: str
    relation: str
    definite: bool
    reason: str = ""
    constraint_ids: Tuple[str, ...] = ()
    sources: Tuple[Source, ...] = ()
    interval_overlap: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "left": self.left,
            "right": self.right,
            "relation": self.relation,
            "definite": self.definite,
            "reason": self.reason,
            "constraint_ids": list(self.constraint_ids),
            "sources": [s.to_dict() for s in self.sources],
            "interval_overlap": self.interval_overlap,
        }


@dataclass(frozen=True)
class ValueState:
    name: str
    value_type: Any = None
    signature: Any = None
    timestamp: Any = None
    data: Any = None


@dataclass(frozen=True)
class KeyState:
    path: str
    timestamp: Any = None
    values: Tuple[ValueState, ...] = ()
    subkeys: Tuple[str, ...] = ()

    @property
    def identity(self) -> str:
        return path_identity(self.path)


@dataclass
class Snapshot:
    snapshot_id: Optional[str]
    interval: Optional[Interval] = None
    keys: Dict[str, KeyState] = field(default_factory=dict)
    events: Tuple[Any, ...] = ()
    missing: bool = False


def key_state_from_registry(key: Any) -> KeyState:
    path = None
    timestamp = None
    try:
        path = key.path()
    except Exception:
        path = _first_key(key, ("path_value", "name")) or "<unknown>"
    try:
        timestamp = key.timestamp()
    except Exception:
        timestamp = None

    values: List[ValueState] = []
    try:
        raw_values = key.values()
    except Exception:
        raw_values = []
    for value in raw_values:
        name = "(default)"
        value_type = None
        signature = None
        value_timestamp = None
        try:
            name = value.name()
        except Exception:
            pass
        try:
            value_type = value.value_type()
        except Exception:
            value_type = None
        try:
            raw = value.raw_data()
            signature = "sha256:" + hashlib.sha256(bytes(raw)).hexdigest()
        except Exception:
            try:
                signature = stable_digest(
                    "value", {"type": value_type, "value": value.value()}
                )
            except Exception:
                signature = "unavailable"
        try:
            value_timestamp = value.timestamp()
        except Exception:
            value_timestamp = None
        values.append(
            ValueState(
                name=name,
                value_type=value_type,
                signature=signature,
                timestamp=value_timestamp,
            )
        )

    subkeys: List[str] = []
    try:
        for child in key.subkeys():
            try:
                subkeys.append(child.name())
            except Exception:
                continue
    except Exception:
        subkeys = []

    return KeyState(
        path=path,
        timestamp=timestamp,
        values=tuple(values),
        subkeys=tuple(subkeys),
    )


def snapshot_from_registry(
    snapshot_id: str,
    registry: Any,
    interval: Any = None,
) -> Snapshot:
    root = registry.root() if hasattr(registry, "root") and callable(registry.root) else registry
    states: Dict[str, KeyState] = {}
    stack = [root]
    while stack:
        key = stack.pop()
        state = key_state_from_registry(key)
        states[state.identity] = state
        try:
            stack.extend(key.subkeys())
        except Exception:
            continue
    return Snapshot(
        snapshot_id=str(snapshot_id),
        interval=coerce_interval(interval),
        keys=states,
    )


def _coerce_value_state(name: str, data: Any) -> ValueState:
    if isinstance(data, ValueState):
        return data
    if not isinstance(data, MappingABC):
        signature = stable_digest("value", data)
        return ValueState(name=name, signature=signature, data=_jsonable(data))
    value = _first_key(data, ("value", "data", "content"))
    raw = _first_key(data, ("raw_data", "raw", "bytes", "signature", "digest"))
    if raw is not None and not isinstance(raw, (str, int)):
        signature = "sha256:" + hashlib.sha256(bytes(raw)).hexdigest()
    else:
        signature = _first_key(data, ("signature", "digest", "hash"))
        if signature is None and value is not None:
            signature = stable_digest("value", value)
    return ValueState(
        name=str(_first_key(data, ("name",)) or name),
        value_type=_first_key(data, ("value_type", "type", "data_type")),
        signature=signature,
        timestamp=_first_key(data, ("timestamp", "last_write", "LastWrite")),
        data=_jsonable(value),
    )


def _coerce_key_state(path: str, data: Any) -> KeyState:
    if isinstance(data, KeyState):
        return data
    if hasattr(data, "path") and hasattr(data, "values") and callable(data.values):
        return key_state_from_registry(data)
    if not isinstance(data, MappingABC):
        return KeyState(path=path, timestamp=data)

    timestamp = _first_key(data, ("timestamp", "last_write", "LastWrite", "last_write_time"))
    raw_values = _first_key(data, ("values", "value_map", "vals")) or {}
    values: List[ValueState] = []
    if isinstance(raw_values, MappingABC):
        for name, value_data in raw_values.items():
            values.append(_coerce_value_state(str(name), value_data))
    elif isinstance(raw_values, (list, tuple)):
        for item in raw_values:
            if isinstance(item, ValueState):
                values.append(item)
            elif isinstance(item, MappingABC):
                name = str(_first_key(item, ("name", "id")) or "(default)")
                values.append(_coerce_value_state(name, item))

    raw_subkeys = _first_key(data, ("subkeys", "children", "sub_key_names")) or ()
    subkeys: List[str] = []
    for item in raw_subkeys:
        if isinstance(item, str):
            subkeys.append(item)
        else:
            name = _first_key(item, ("name", "path"))
            if name is not None:
                subkeys.append(str(name))

    return KeyState(
        path=str(_first_key(data, ("path", "name", "key")) or path),
        timestamp=timestamp,
        values=tuple(values),
        subkeys=tuple(str(s) for s in subkeys),
    )


def _coerce_snapshot(raw: Any, index: int) -> Snapshot:
    if isinstance(raw, Snapshot):
        return raw

    if not isinstance(raw, MappingABC):
        if hasattr(raw, "root") and callable(raw.root) or hasattr(raw, "subkeys"):
            snapshot = snapshot_from_registry("__pending__", raw)
            snapshot.snapshot_id = None
            return snapshot
        raise TypeError("unsupported snapshot: %r" % (raw,))

    snapshot_id = _first_key(raw, ("snapshot_id", "id", "name", "label"))
    interval = coerce_interval(
        _first_key(
            raw,
            (
                "interval",
                "time_interval",
                "collection_interval",
                "collected_interval",
                "acquisition_interval",
                "collection_time_range",
            ),
        )
    )
    if interval is None:
        interval = coerce_interval(
            {
                "start": _first_key(raw, ("collection_start", "collected_after", "start")),
                "end": _first_key(raw, ("collection_end", "collected_before", "end")),
            }
        )
    missing = bool(_first_key(raw, ("missing", "is_missing", "unavailable")) or False)

    registry = _first_key(raw, ("registry", "hive", "reg", "parsed_registry", "Registry"))
    keys: Dict[str, KeyState] = {}
    if registry is not None:
        parsed = snapshot_from_registry("__pending__", registry)
        keys.update(parsed.keys)

    raw_root = _first_key(raw, ("root", "key"))
    if raw_root is not None and hasattr(raw_root, "subkeys"):
        parsed = snapshot_from_registry("__pending__", raw_root)
        keys.update(parsed.keys)

    raw_keys = _first_key(raw, ("keys", "key_states", "states", "records", "items"))
    if isinstance(raw_keys, MappingABC):
        for path, key_data in raw_keys.items():
            state = _coerce_key_state(str(path), key_data)
            keys[state.identity] = state
    elif isinstance(raw_keys, (list, tuple)):
        for item in raw_keys:
            state = _coerce_key_state("", item) if not isinstance(item, KeyState) else item
            if not state.path:
                state = _coerce_key_state(str(_first_key(item, ("path", "name", "id"))), item)
            keys[state.identity] = state

    raw_events = _first_key(raw, ("events", "event_records", "writes")) or ()
    if not isinstance(raw_events, (list, tuple)):
        raw_events = (raw_events,)

    snapshot = Snapshot(
        snapshot_id=None if snapshot_id is None else str(snapshot_id),
        interval=interval,
        keys=keys,
        events=tuple(raw_events),
        missing=missing,
    )
    if snapshot.snapshot_id is None:
        snapshot.snapshot_id = stable_digest(
            "snapshot",
            {
                "interval": interval.to_dict() if interval else None,
                "keys": sorted((k, _jsonable(v)) for k, v in keys.items()),
                "events": [_jsonable(e) for e in raw_events],
                "missing": missing,
            },
        )
    return snapshot


def structure_data(state: KeyState) -> Dict[str, Any]:
    values = sorted(
        state.values,
        key=lambda v: (v.name.casefold(), v.value_type or "", stable_digest("", v.signature)),
    )
    return {
        "values": [
            (
                v.name.casefold(),
                _jsonable(v.value_type),
                _jsonable(v.signature),
                _jsonable(v.timestamp),
            )
            for v in values
        ],
        "subkeys": sorted(s.casefold() for s in state.subkeys),
    }


def structure_signature(state: KeyState) -> str:
    return stable_digest("struct", structure_data(state))


class PartialOrderGraph:
    def __init__(self, events: Optional[List[Any]] = None, constraints: Optional[List[Any]] = None):
        self.events: Dict[str, Event] = {}
        self.constraints: Dict[str, Constraint] = {}
        for event in events or ():
            self.add_event(event)
        for constraint in constraints or ():
            self.add_constraint(constraint)

    def add_event(self, event: Any = None, **kwargs: Any) -> Event:
        if isinstance(event, str):
            kwargs["event_id"] = event
            event = None
        if event is not None:
            if isinstance(event, Event):
                new_event = event
            elif isinstance(event, MappingABC):
                new_event = event_from_mapping(event)
            else:
                raise TypeError("unsupported event: %r" % (event,))
        else:
            event_id = kwargs.pop("event_id", None) or kwargs.pop("id", None)
            if event_id is None:
                event_id = stable_digest("event", kwargs)
            if "time_bounds" in kwargs:
                kwargs["time_bounds"] = coerce_interval(kwargs["time_bounds"])
            if "collection_interval" in kwargs:
                kwargs["collection_interval"] = coerce_interval(kwargs["collection_interval"])
            if "sources" in kwargs or "source" in kwargs:
                kwargs["sources"] = coerce_sources(
                    kwargs.pop("sources", None) or kwargs.pop("source", None)
                )
            if "snapshot_ids" in kwargs:
                kwargs["snapshot_ids"] = tuple(sorted(set(kwargs["snapshot_ids"])))
            new_event = Event(event_id=str(event_id), **kwargs)

        existing = self.events.get(new_event.event_id)
        if existing is None:
            self.events[new_event.event_id] = new_event
            return new_event

        if existing.timestamp is None:
            existing.timestamp = new_event.timestamp
        elif new_event.timestamp is not None and not _equal(existing.timestamp, new_event.timestamp):
            observations = existing.attributes.setdefault("timestamp_observations", [])
            observations.append(_jsonable(new_event.timestamp))
        if existing.time_bounds is None:
            existing.time_bounds = new_event.time_bounds
        if existing.collection_interval is None:
            existing.collection_interval = new_event.collection_interval
        existing.snapshot_ids = tuple(
            sorted(set(existing.snapshot_ids) | set(new_event.snapshot_ids))
        )
        source_map = {s.key(): s for s in existing.sources + new_event.sources}
        existing.sources = tuple(sorted(source_map.values(), key=lambda s: s.key()))
        merged_attributes = dict(new_event.attributes)
        merged_attributes.update(existing.attributes)
        existing.attributes = merged_attributes
        if existing.kind == "event" and new_event.kind != "event":
            existing.kind = new_event.kind
        return existing

    def add_constraint(self, before: Any = None, after: Any = None, **kwargs: Any) -> Constraint:
        if isinstance(before, Constraint):
            constraint = before
            before = constraint.before
            after = constraint.after
            kwargs.setdefault("constraint_id", constraint.constraint_id)
            kwargs.setdefault("kind", constraint.kind)
            kwargs.setdefault("reason", constraint.reason)
            kwargs.setdefault("sources", constraint.sources)
        elif isinstance(before, MappingABC):
            data = dict(before)
            before = data.pop("before", None) or data.pop("left", None)
            after = data.pop("after", None) or data.pop("right", None)
            kwargs.update(data)
        elif isinstance(before, (list, tuple)) and after is None:
            if len(before) == 2:
                before, after = before
            elif len(before) == 3:
                before, after, extra = before
                kwargs.update(extra if isinstance(extra, MappingABC) else {"reason": extra})

        if after is None:
            after = kwargs.pop("after_id", None) or kwargs.pop("right", None) or kwargs.pop("after", None)
        if before is None:
            before = kwargs.pop("before_id", None) or kwargs.pop("left", None) or kwargs.pop("before", None)
        if before is None or after is None:
            raise ValueError("constraint requires before and after event ids")

        sources = coerce_sources(kwargs.pop("sources", None) or kwargs.pop("source", None))
        kind = str(kwargs.pop("kind", "explicit"))
        reason = str(kwargs.pop("reason", kwargs.pop("message", "")) or "")
        constraint_id = kwargs.pop("constraint_id", None) or kwargs.pop("cid", None)

        payload = {
            "before": str(before),
            "after": str(after),
            "kind": kind,
            "reason": reason,
            "sources": [s.to_dict() for s in sorted(sources, key=lambda s: s.key())],
            "extra": kwargs,
        }
        if constraint_id is None:
            constraint_id = stable_digest("constraint", payload)

        constraint = Constraint(
            before=str(before),
            after=str(after),
            constraint_id=str(constraint_id),
            kind=kind,
            reason=reason,
            sources=tuple(sorted(sources, key=lambda s: s.key())),
        )
        existing = self.constraints.get(constraint.constraint_id)
        if existing is not None:
            source_map = {s.key(): s for s in existing.sources + constraint.sources}
            constraint = replace(
                existing,
                sources=tuple(sorted(source_map.values(), key=lambda s: s.key())),
            )
        self.constraints[constraint.constraint_id] = constraint
        self.add_event(constraint.before)
        self.add_event(constraint.after)
        return constraint

    def materialize_time_constraints(self) -> None:
        ids = sorted(self.events)
        for index, left_id in enumerate(ids):
            left = self.events[left_id]
            if left.time_bounds is None:
                continue
            for right_id in ids[index + 1 :]:
                right = self.events[right_id]
                if right.time_bounds is None:
                    continue
                source = Source(
                    kind="explicit_time_bounds",
                    rule="disjoint_occurrence_intervals",
                    evidence={
                        "left": left.time_bounds.to_dict(),
                        "right": right.time_bounds.to_dict(),
                    },
                )
                if left.time_bounds.before(right.time_bounds):
                    self.add_constraint(
                        left_id,
                        right_id,
                        kind="time_bounds",
                        reason="left event interval ends before right interval starts",
                        source=source,
                    )
                elif right.time_bounds.before(left.time_bounds):
                    self.add_constraint(
                        right_id,
                        left_id,
                        kind="time_bounds",
                        reason="right event interval ends before left interval starts",
                        source=source,
                    )

    def adjacency(self) -> Dict[str, List[str]]:
        adjacency: Dict[str, set] = {event_id: set() for event_id in self.events}
        for constraint in self.constraints.values():
            adjacency.setdefault(constraint.before, set()).add(constraint.after)
            adjacency.setdefault(constraint.after, set())
        return {key: sorted(value) for key, value in sorted(adjacency.items())}

    def canonical_graph(self) -> Dict[str, Any]:
        edges = sorted(
            {(c.before, c.after) for c in self.constraints.values()},
            key=lambda edge: (edge[0], edge[1]),
        )
        return {
            "nodes": sorted(self.events),
            "edges": [[left, right] for left, right in edges],
        }

    def signature(self) -> str:
        return stable_digest("partial-order-graph", self.canonical_graph())

    def find_conflict(self) -> Optional[Conflict]:
        self.materialize_time_constraints()
        nodes = sorted(set(self.events) | {c.before for c in self.constraints.values()} | {c.after for c in self.constraints.values()})
        edge_cids: Dict[Tuple[str, str], List[str]] = defaultdict(list)
        for cid, constraint in self.constraints.items():
            edge_cids[(constraint.before, constraint.after)].append(cid)

        best_key: Optional[Tuple[int, Tuple[str, ...]]] = None
        best_cids: Tuple[str, ...] = ()

        for (left, right), cids in sorted(edge_cids.items()):
            chosen = sorted(cids)[0]
            if left == right:
                candidate = (chosen,)
                key = (1, candidate)
                if best_key is None or key < best_key:
                    best_key = key
                    best_cids = candidate

        adjacency: Dict[str, set] = {node: set() for node in nodes}
        for (left, right) in edge_cids:
            if left != right:
                adjacency.setdefault(left, set()).add(right)
                adjacency.setdefault(right, set())

        for start in nodes:
            for first_after in sorted(adjacency.get(start, ())):
                if start == first_after:
                    continue
                first_cid = sorted(edge_cids[(start, first_after)])[0]
                parent: Dict[str, Optional[Tuple[str, str]]] = {first_after: None}
                queue = deque([first_after])
                while queue and start not in parent:
                    current = queue.popleft()
                    for nxt in sorted(adjacency.get(current, ())):
                        if nxt in parent:
                            continue
                        cid = sorted(edge_cids[(current, nxt)])[0]
                        parent[nxt] = (current, cid)
                        if nxt == start:
                            break
                        queue.append(nxt)
                    if start in parent:
                        break

                if start not in parent or parent[start] is None:
                    continue

                reverse_edges: List[Tuple[str, str, str]] = []
                current = start
                while current != first_after:
                    predecessor = parent[current]
                    if predecessor is None:
                        break
                    previous_node, cid = predecessor
                    reverse_edges.append((previous_node, current, cid))
                    current = previous_node
                forward_edges = list(reversed(reverse_edges))
                cid_cycle = (first_cid,) + tuple(cid for _u, _v, cid in forward_edges)
                key = (len(cid_cycle), cid_cycle)
                if best_key is None or key < best_key:
                    best_key = key
                    best_cids = cid_cycle

        if not best_cids:
            return None

        constraints = tuple(self.constraints[cid] for cid in best_cids)
        edge_path = [(c.before, c.after) for c in constraints]
        cycle = [constraints[0].before]
        for constraint in constraints:
            cycle.append(constraint.after)
        event_ids: List[str] = []
        for node in cycle:
            if not event_ids or event_ids[-1] != node:
                event_ids.append(node)
        if len(event_ids) > 1 and event_ids[0] == event_ids[-1]:
            event_ids = event_ids[:-1]
        sources: Dict[str, Source] = {}
        for constraint in constraints:
            for source in constraint.sources:
                sources[source.key()] = source
        source_tuple = tuple(sorted(sources.values(), key=lambda s: s.key()))
        message = "contradictory ordering constraints form a minimal cycle: " + " -> ".join(cycle)
        return Conflict(
            cycle=tuple(cycle),
            event_ids=tuple(event_ids),
            constraint_ids=best_cids,
            constraints=constraints,
            sources=source_tuple,
            message=message,
        )

    def topological_orders(
        self, max_orders: Optional[int] = 128
    ) -> Tuple[Tuple[Tuple[str, ...], ...], bool]:
        adjacency = self.adjacency()
        indegree = {node: 0 for node in adjacency}
        for left, rights in adjacency.items():
            for right in rights:
                indegree[right] = indegree.get(right, 0) + 1
                adjacency.setdefault(right, [])
        orders: List[Tuple[str, ...]] = []
        truncated = False

        def visit(order: List[str], current_indegree: Dict[str, int]) -> None:
            nonlocal truncated
            if max_orders is not None and len(orders) >= max_orders:
                truncated = True
                return
            if len(order) == len(indegree):
                orders.append(tuple(order))
                return
            zeros = sorted(node for node, degree in current_indegree.items() if degree == 0 and node not in order)
            for node in zeros:
                next_indegree = dict(current_indegree)
                next_indegree[node] = -1
                for nxt in adjacency.get(node, ()):
                    next_indegree[nxt] -= 1
                order.append(node)
                visit(order, next_indegree)
                order.pop()

        visit([], indegree)
        return tuple(orders), truncated

    def shortest_constraint_path(
        self, source: str, target: str
    ) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
        adjacency: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
        for cid, constraint in self.constraints.items():
            adjacency[constraint.before].append((constraint.after, cid))
        parent: Dict[str, Optional[Tuple[str, str, str]]] = {source: None}
        queue = deque([source])
        while queue and target not in parent:
            current = queue.popleft()
            for nxt, cid in sorted(adjacency.get(current, ()), key=lambda item: (item[0], item[1])):
                if nxt in parent:
                    continue
                parent[nxt] = (current, cid, nxt)
                if nxt == target:
                    break
                queue.append(nxt)
        if target not in parent:
            return (), ()
        node_path = [target]
        cids: List[str] = []
        current = target
        while current != source:
            entry = parent[current]
            if entry is None:
                break
            previous, cid, _node = entry
            cids.append(cid)
            node_path.append(previous)
            current = previous
        node_path.reverse()
        cids.reverse()
        return tuple(node_path), tuple(cids)


@dataclass
class OrderingReport:
    ok: bool
    events: Tuple[Event, ...]
    constraints: Tuple[Constraint, ...]
    facts: Tuple[Dict[str, Any], ...]
    inferences: Tuple[Dict[str, Any], ...]
    conflicts: Tuple[Conflict, ...]
    relations: Dict[Tuple[str, str], Relation]
    legal_orders: Tuple[Tuple[str, ...], ...]
    graph: Dict[str, Any]
    signature: str
    truncated: bool = False

    @property
    def consistent(self) -> bool:
        return self.ok

    @property
    def minimal_conflict(self) -> Optional[Conflict]:
        return self.conflicts[0] if self.conflicts else None

    def relation(self, left: str, right: str) -> Relation:
        return self.relations[(left, right)]

    def is_before(self, left: str, right: str) -> bool:
        relation = self.relations.get((left, right))
        return relation is not None and relation.relation == RelationType.BEFORE

    def to_dict(self) -> Dict[str, Any]:
        relation_items = []
        for (left, right), relation in sorted(self.relations.items()):
            item = relation.to_dict()
            item["key"] = left + "\u0000" + right
            relation_items.append(item)
        return {
            "ok": self.ok,
            "consistent": self.ok,
            "signature": self.signature,
            "graph": _jsonable(self.graph),
            "events": [e.to_dict() for e in self.events],
            "constraints": [c.to_dict() for c in self.constraints],
            "facts": _jsonable(self.facts),
            "inferences": _jsonable(self.inferences),
            "conflicts": [c.to_dict() for c in self.conflicts],
            "relations": relation_items,
            "legal_orders": [list(order) for order in self.legal_orders],
            "truncated": self.truncated,
        }


def _snapshot_interval_before(left: Snapshot, right: Snapshot) -> bool:
    if left.snapshot_id == right.snapshot_id:
        return True
    return left.interval is not None and right.interval is not None and left.interval.before(right.interval)


def _cover_pairs(snapshots: List[Snapshot]) -> List[Tuple[Snapshot, Snapshot]]:
    covers: List[Tuple[Snapshot, Snapshot]] = []
    for left in snapshots:
        for right in snapshots:
            if left.snapshot_id == right.snapshot_id:
                continue
            if not _snapshot_interval_before(left, right):
                continue
            intermediate_exists = False
            for middle in snapshots:
                if (
                    middle.snapshot_id not in (left.snapshot_id, right.snapshot_id)
                    and _snapshot_interval_before(left, middle)
                    and _snapshot_interval_before(middle, right)
                ):
                    intermediate_exists = True
                    break
            if not intermediate_exists:
                covers.append((left, right))
    return covers


def _interval_overlap_evidence(left: Event, right: Event) -> Tuple[bool, str]:
    if left.time_bounds is not None and right.time_bounds is not None:
        if left.time_bounds.overlaps(right.time_bounds):
            return True, "occurrence intervals overlap"
    if left.collection_interval is not None and right.collection_interval is not None:
        if left.collection_interval.overlaps(right.collection_interval):
            return True, "explicit collection intervals overlap"
    if left.timestamp is not None and right.timestamp is not None and _equal(
        left.timestamp, right.timestamp
    ):
        return True, "equal LastWrite reading; this permits but does not prove concurrency"
    return False, "no causal path or overlapping explicit interval"


def _build_relations(graph: PartialOrderGraph) -> Dict[Tuple[str, str], Relation]:
    nodes = sorted(graph.events)
    reachable: Dict[str, set] = {}
    simple_adjacency = graph.adjacency()
    for source in nodes:
        seen = set()
        queue = deque(simple_adjacency.get(source, ()))
        while queue:
            node = queue.popleft()
            if node in seen:
                continue
            seen.add(node)
            queue.extend(simple_adjacency.get(node, ()))
        reachable[source] = seen

    relations: Dict[Tuple[str, str], Relation] = {}
    for node in nodes:
        relations[(node, node)] = Relation(node, node, RelationType.SAME, True, "same event")

    for index, left in enumerate(nodes):
        for right in nodes[index + 1 :]:
            if right in reachable[left]:
                path, cids = graph.shortest_constraint_path(left, right)
                sources: Dict[str, Source] = {}
                for cid in cids:
                    for source in graph.constraints[cid].sources:
                        sources[source.key()] = source
                relation = Relation(
                    left,
                    right,
                    RelationType.BEFORE,
                    True,
                    "constraint path: " + " -> ".join(path),
                    cids,
                    tuple(sorted(sources.values(), key=lambda s: s.key())),
                )
                reverse = Relation(
                    right, left, RelationType.AFTER, True, "inverse of definite order", cids
                )
            elif left in reachable[right]:
                path, cids = graph.shortest_constraint_path(right, left)
                sources = {}
                for cid in cids:
                    for source in graph.constraints[cid].sources:
                        sources[source.key()] = source
                relation = Relation(
                    left,
                    right,
                    RelationType.AFTER,
                    True,
                    "constraint path: " + " -> ".join(path),
                    cids,
                    tuple(sorted(sources.values(), key=lambda s: s.key())),
                )
                reverse = Relation(
                    right, left, RelationType.BEFORE, True, "inverse relation", cids
                )
            else:
                overlap, reason = _interval_overlap_evidence(graph.events[left], graph.events[right])
                label = RelationType.POSSIBLY_CONCURRENT if overlap else RelationType.INCOMPARABLE
                relation = Relation(left, right, label, False, reason, interval_overlap=overlap)
                reverse = Relation(right, left, label, False, reason, interval_overlap=overlap)
            relations[(left, right)] = relation
            relations[(right, left)] = reverse
    return relations


def build_report(
    snapshots: Optional[List[Any]] = None,
    events: Optional[List[Any]] = None,
    constraints: Optional[List[Any]] = None,
    graph: Optional[PartialOrderGraph] = None,
    intervals: Any = None,
    collection_intervals: Any = None,
    collection_windows: Any = None,
    missing_snapshots: Optional[List[Any]] = None,
    max_orders: Optional[int] = 128,
    strict: bool = False,
    **_ignored: Any,
) -> OrderingReport:
    order_graph = graph or PartialOrderGraph()

    raw_snapshots = list(snapshots or ())
    parsed_snapshots = [_coerce_snapshot(raw, index) for index, raw in enumerate(raw_snapshots)]

    interval_overrides = collection_intervals
    if interval_overrides is None:
        interval_overrides = collection_windows
    if interval_overrides is None:
        interval_overrides = intervals

    if interval_overrides is not None:
        if isinstance(interval_overrides, MappingABC):
            for snapshot in parsed_snapshots:
                value = None
                if snapshot.snapshot_id in interval_overrides:
                    value = interval_overrides[snapshot.snapshot_id]
                elif str(snapshot.snapshot_id) in interval_overrides:
                    value = interval_overrides[str(snapshot.snapshot_id)]
                if value is not None:
                    snapshot.interval = coerce_interval(value)
        elif (
            isinstance(interval_overrides, (list, tuple))
            and len(interval_overrides) == len(parsed_snapshots)
            and not (len(interval_overrides) == 2 and parsed_snapshots and isinstance(interval_overrides[0], (str, datetime, int, float)) and not isinstance(interval_overrides[0], (list, tuple, MappingABC)))
        ):
            for snapshot, value in zip(parsed_snapshots, interval_overrides):
                snapshot.interval = coerce_interval(value)
        else:
            common_interval = coerce_interval(interval_overrides)
            for snapshot in parsed_snapshots:
                snapshot.interval = common_interval

    missing: List[Snapshot] = []
    available: List[Snapshot] = []
    for snapshot in parsed_snapshots:
        (missing if snapshot.missing else available).append(snapshot)
    for raw_missing in missing_snapshots or ():
        if isinstance(raw_missing, str):
            missing.append(Snapshot(snapshot_id=raw_missing, missing=True))
        else:
            marker = _coerce_snapshot(raw_missing, len(parsed_snapshots))
            marker.missing = True
            missing.append(marker)

    for snapshot in available:
        for event_data in snapshot.events:
            event = order_graph.add_event(event_data)
            if not event.snapshot_ids and snapshot.snapshot_id is not None:
                event.snapshot_ids = (snapshot.snapshot_id,)
            if event.collection_interval is None and snapshot.interval is not None:
                event.collection_interval = snapshot.interval

    for event_data in events or ():
        order_graph.add_event(event_data)
    for constraint_data in constraints or ():
        order_graph.add_constraint(constraint_data)

    facts: List[Dict[str, Any]] = []
    for snapshot in sorted(missing, key=lambda s: str(s.snapshot_id)):
        facts.append(
            {
                "kind": "missing_snapshot",
                "snapshot_id": snapshot.snapshot_id,
                "message": "No parsed state is available; no intermediate event is inferred.",
            }
        )

    for snapshot in sorted(available, key=lambda s: str(s.snapshot_id)):
        facts.append(
            {
                "kind": "collection_interval",
                "snapshot_id": snapshot.snapshot_id,
                "interval": snapshot.interval.to_dict() if snapshot.interval else None,
                "explicit": snapshot.interval is not None,
            }
        )
        for state in sorted(snapshot.keys.values(), key=lambda item: item.identity):
            facts.append(
                {
                        "kind": "key_timestamp",
                    "snapshot_id": snapshot.snapshot_id,
                    "subject": state.path,
                    "timestamp": _jsonable(state.timestamp),
                    "scope": "this key only; parent LastWrite is not inherited",
                }
            )
            for value in sorted(state.values, key=lambda item: item.name.casefold()):
                if value.timestamp is not None:
                    facts.append(
                        {
                            "kind": "value_timestamp_observation",
                            "snapshot_id": snapshot.snapshot_id,
                            "subject": state.path + "!" + value.name,
                            "timestamp": _jsonable(value.timestamp),
                            "scope": "value record only",
                        }
                    )

    inferences: List[Dict[str, Any]] = []
    metas: List[Dict[str, str]] = []
    snapshots_by_id = {s.snapshot_id: s for s in available}

    for old_snapshot, new_snapshot in sorted(
        _cover_pairs(available),
        key=lambda pair: (str(pair[0].snapshot_id), str(pair[1].snapshot_id)),
    ):
        source = Source(
            kind="structural_snapshot_diff",
            snapshot_id=old_snapshot.snapshot_id,
            other_snapshot_id=new_snapshot.snapshot_id,
            rule="compared parsed key/value structure",
            evidence={
                "old_interval": old_snapshot.interval.to_dict() if old_snapshot.interval else None,
                "new_interval": new_snapshot.interval.to_dict() if new_snapshot.interval else None,
            },
        )
        identities = sorted(set(old_snapshot.keys) | set(new_snapshot.keys))
        for identity in identities:
            old_state = old_snapshot.keys.get(identity)
            new_state = new_snapshot.keys.get(identity)
            display_state = new_state or old_state
            if display_state is None:
                continue
            subject = display_state.path

            if old_state is None or new_state is None:
                kind = "key_created" if old_state is None else "key_deleted"
                timestamp = new_state.timestamp if new_state is not None else old_state.timestamp
                changes = {"presence": [None if old_state is None else old_state.path,
                                        None if new_state is None else new_state.path]}
            else:
                old_signature = structure_signature(old_state)
                new_signature = structure_signature(new_state)
                structure_changed = old_signature != new_signature
                timestamp_changed = not _equal(old_state.timestamp, new_state.timestamp)
                if not structure_changed and not timestamp_changed:
                    continue

                old_values = {v.name.casefold(): v for v in old_state.values}
                new_values = {v.name.casefold(): v for v in new_state.values}
                added_values = sorted(
                    new_values[k].name for k in set(new_values) - set(old_values)
                )
                removed_values = sorted(
                    old_values[k].name for k in set(old_values) - set(new_values)
                )
                changed_values = sorted(
                    new_values[k].name
                    for k in set(old_values) & set(new_values)
                    if structure_signature(
                        KeyState(path=subject, values=(old_values[k],))
                    )
                    != structure_signature(KeyState(path=subject, values=(new_values[k],)))
                )
                old_subkeys = {s.casefold() for s in old_state.subkeys}
                new_subkeys = {s.casefold() for s in new_state.subkeys}
                kind = "key_modified" if structure_changed else "key_last_write_changed"
                timestamp = new_state.timestamp
                changes = {
                    "added_values": added_values,
                    "removed_values": removed_values,
                    "changed_values": changed_values,
                    "added_subkeys": sorted(new_subkeys - old_subkeys),
                    "removed_subkeys": sorted(old_subkeys - new_subkeys),
                    "old_timestamp": _jsonable(old_state.timestamp),
                    "new_timestamp": _jsonable(new_state.timestamp),
                    "timestamp_changed": timestamp_changed,
                }

            event_id = "%s:%s:%s..%s" % (
                kind,
                subject,
                old_snapshot.snapshot_id,
                new_snapshot.snapshot_id,
            )
            bounds = None
            if old_snapshot.interval is not None and new_snapshot.interval is not None:
                bounds = Interval(old_snapshot.interval.start, new_snapshot.interval.end)
            event = Event(
                event_id=event_id,
                kind=kind,
                subject=subject,
                timestamp=timestamp,
                time_bounds=bounds,
                snapshot_ids=tuple(
                    sorted(
                        {
                            str(old_snapshot.snapshot_id),
                            str(new_snapshot.snapshot_id),
                        }
                    )
                ),
                sources=(
                    replace(
                        source,
                        subject=subject,
                        evidence=tuple(
                            source.evidence
                            + (
                                ("change", _freeze_evidence(changes)),
                            )
                        ),
                    ),
                ),
                    attributes=dict(
                        {"changes": _jsonable(changes), "net_transition": True},
                        **_jsonable(changes),
                    ),
            )
            order_graph.add_event(event)
            metas.append(
                {
                    "event_id": event_id,
                    "path_key": identity,
                    "start": str(old_snapshot.snapshot_id),
                    "end": str(new_snapshot.snapshot_id),
                    "kind": kind,
                }
            )
            inferences.append(
                {
                    "kind": "supported_structural_transition",
                    "event_id": event_id,
                    "subject": subject,
                    "snapshots": [old_snapshot.snapshot_id, new_snapshot.snapshot_id],
                    "changes": _jsonable(changes),
                    "fact_separation": "Difference is derived from parsed snapshots; it is not a timestamp sort.",
                }
            )

    ending = defaultdict(list)
    starting = defaultdict(list)
    for meta in metas:
        ending[(meta["end"], meta["path_key"])].append(meta["event_id"])
        starting[(meta["start"], meta["path_key"])].append(meta["event_id"])

    for snapshot_id, identity in sorted(set(ending) & set(starting)):
        for before_id in sorted(ending[(snapshot_id, identity)]):
            for after_id in sorted(starting[(snapshot_id, identity)]):
                if before_id == after_id:
                    continue
                source = Source(
                    kind="intermediate_snapshot_observation",
                    snapshot_id=snapshot_id,
                    subject=identity,
                    rule="same subject state is the endpoint of one transition and start of the next",
                )
                order_graph.add_constraint(
                    before_id,
                    after_id,
                    kind="state_sequence",
                    reason="an intervening parsed state separates these changes",
                    source=source,
                )

    created = [meta for meta in metas if meta["kind"] == "key_created"]
    created_by_path = defaultdict(list)
    for meta in created:
        created_by_path[meta["path_key"]].append(meta)

    for child in sorted(created, key=lambda meta: meta["event_id"]):
        ancestor_identity = parent_path_identity(child["path_key"])
        while ancestor_identity:
            candidates = created_by_path.get(ancestor_identity, [])
            for parent_meta in sorted(candidates, key=lambda meta: meta["event_id"]):
                same_end = parent_meta["end"] == child["end"]
                parent_end = snapshots_by_id.get(parent_meta["end"])
                child_start = snapshots_by_id.get(child["start"])
                sequence_supported = (
                    parent_end is not None
                    and child_start is not None
                    and _snapshot_interval_before(parent_end, child_start)
                )
                if not (same_end or sequence_supported):
                    continue
                source = Source(
                    kind="structural_existence_dependency",
                    subject=ancestor_identity,
                    other_snapshot_id=child["path_key"],
                    rule="a created descendant requires its ancestor key to exist",
                    evidence={
                        "parent_event": parent_meta["event_id"],
                        "child_event": child["event_id"],
                        "same_cover_snapshot": same_end,
                    },
                )
                order_graph.add_constraint(
                    parent_meta["event_id"],
                    child["event_id"],
                    kind="structural_dependency",
                    reason="created registry key ancestor must exist before descendant",
                    source=source,
                )
            ancestor_identity = parent_path_identity(ancestor_identity)

    order_graph.materialize_time_constraints()
    conflict = order_graph.find_conflict()
    conflicts = (conflict,) if conflict is not None else ()

    for constraint in sorted(order_graph.constraints.values(), key=lambda c: c.constraint_id):
        if constraint.kind == "explicit":
            facts.append(
                {
                    "kind": "explicit_constraint",
                    "constraint_id": constraint.constraint_id,
                    "before": constraint.before,
                    "after": constraint.after,
                    "sources": [s.to_dict() for s in constraint.sources],
                }
            )
        else:
            inferences.append(
                {
                    "kind": "ordering_constraint",
                    "constraint_id": constraint.constraint_id,
                    "before": constraint.before,
                    "after": constraint.after,
                    "basis": constraint.kind,
                    "reason": constraint.reason,
                    "sources": [s.to_dict() for s in constraint.sources],
                }
            )

    facts = tuple(sorted(facts, key=lambda item: stable_digest("", item)))
    inferences = tuple(sorted(inferences, key=lambda item: stable_digest("", item)))
    events = tuple(order_graph.events[eid] for eid in sorted(order_graph.events))
    constraint_tuple = tuple(
        order_graph.constraints[cid] for cid in sorted(order_graph.constraints)
    )
    graph_data = order_graph.canonical_graph()
    signature = order_graph.signature()

    if conflict is not None:
        report = OrderingReport(
            ok=False,
            events=events,
            constraints=constraint_tuple,
            facts=facts,
            inferences=inferences,
            conflicts=conflicts,
            relations={},
            legal_orders=(),
            graph=graph_data,
            signature=signature,
        )
        if strict:
            raise PartialOrderConflictError(report)
        return report

    legal_orders, truncated = order_graph.topological_orders(max_orders)
    relations = _build_relations(order_graph)
    relation_inferences = []
    for relation in sorted(relations.values(), key=lambda r: (r.left, r.right)):
        if relation.left == relation.right:
            continue
        relation_inferences.append(
            {
                "kind": "pair_relation",
                "left": relation.left,
                "right": relation.right,
                "relation": relation.relation,
                "definite": relation.definite,
                "reason": relation.reason,
            }
        )
    inferences = tuple(sorted(list(inferences) + relation_inferences, key=lambda item: stable_digest("", item)))

    return OrderingReport(
        ok=True,
        events=events,
        constraints=constraint_tuple,
        facts=facts,
        inferences=inferences,
        conflicts=(),
        relations=relations,
        legal_orders=legal_orders,
        graph=graph_data,
        signature=signature,
        truncated=truncated,
    )


build_partial_order = build_report
build_event_partial_order = build_report
analyze_snapshots = build_report
build_ordering_report = build_report
create_partial_order = PartialOrderGraph
PartialOrderBackend = PartialOrderGraph
RelationGraph = PartialOrderGraph
EventOrderingGraph = PartialOrderGraph

EventNode = Event
ConstraintEdge = Constraint
Edge = Constraint
Provenance = Source
Evidence = Source
ConflictSet = Conflict
PartialOrder = PartialOrderGraph
PartialOrderBuilder = PartialOrderGraph
OrderingGraph = PartialOrderGraph
PartialOrderConflict = PartialOrderConflictError
OrderingConflictError = PartialOrderConflictError


def minimal_conflict_set(events=None, constraints=None, **kwargs):
    report = build_report(events=events, constraints=constraints, **kwargs)
    return report.conflicts[0] if report.conflicts else None


def find_minimal_conflict(events=None, constraints=None, **kwargs):
    return minimal_conflict_set(events=events, constraints=constraints, **kwargs)


OrderingReport.consistent = property(lambda self: self.ok)
OrderingReport.is_valid = property(lambda self: self.ok)
OrderingReport.valid_orders = property(lambda self: self.legal_orders)
OrderingReport.possible_orders = property(lambda self: self.legal_orders)
OrderingReport.minimal_conflict = property(lambda self: self.conflicts[0] if self.conflicts else None)
OrderingReport.conflict = OrderingReport.minimal_conflict
Conflict.minimal_subset = property(lambda self: self.constraints)
Conflict.minimal_conflict_subset = property(lambda self: self.constraints)
PartialOrderGraph.add_node = PartialOrderGraph.add_event
PartialOrderGraph.add_edge = PartialOrderGraph.add_constraint
