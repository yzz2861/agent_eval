"""Evidence alignment for partial EVTX chunks and ambiguous local times."""

from __future__ import annotations

import json
import os
import sys
from collections import defaultdict
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

_MARKER_KINDS = {"marker", "shift_marker", "signed_shift_marker", "handoff", "handoff_marker", "boundary"}
_ID_KEYS = ("id", "event_id", "evidence_id", "record_id", "key", "uid", "rid")
_RN_KEYS = ("record_number", "record_num", "record_no", "record_number_value", "rn")
_SOURCE_KEYS = ("source", "source_file", "file", "filename", "path", "evtx_file")
_SCOPE_KEYS = ("scope", "log_id", "case_id", "record_number_scope")
_CHUNK_KEYS = ("chunk_index", "chunk", "chunk_number")
_OFFSET_KEYS = ("offset", "record_offset", "file_offset", "absolute_offset")
_ORDER_KEYS = (
    "file_order",
    "file_relative_order",
    "relative_order",
    "physical_order",
    "chunk_order",
    "order",
    "sequence",
    "sequence_number",
    "sequence_index",
    "order_index",
    "index",
    "position",
)
_ORIGINAL_KEYS = ("original_index", "original_position", "input_index", "source_index")
_TIME_KEYS = ("timestamp", "time", "datetime", "local_time", "event_time")
_SHIFT_KEYS = ("shift", "shift_id", "shift_label", "shift_name")
_LABEL_KEYS = ("label", "name", "title", "description", "event", "message")
_KIND_KEYS = ("kind", "type", "evidence_type", "record_type", "marker_type", "role")
_PRED_KEYS = ("predecessors", "after", "after_ids", "after_id", "follows", "preceded_by", "events_before")
_SUCC_KEYS = ("successors", "before", "before_ids", "before_id", "precedes", "followed_by", "events_after")


def _norm_key(key: Any) -> str:
    return str(key).replace("-", "_").replace(" ", "_").lower()


def _pick(data: Any, names: Iterable[str], default: Any = None) -> Any:
    if data is None:
        return default
    values = data
    if not isinstance(data, Mapping):
        values = {}
        for name in dir(data):
            if name.startswith("_"):
                continue
            try:
                values[name] = getattr(data, name)
            except Exception:
                pass
    for name in names:
        if isinstance(values, Mapping) and name in values and values[name] is not None:
            return values[name]
        if not isinstance(values, Mapping) and hasattr(values, name):
            value = getattr(values, name)
            if value is not None:
                return value
    normalized = {_norm_key(key): value for key, value in values.items()} if isinstance(values, Mapping) else {}
    for name in names:
        value = normalized.get(_norm_key(name))
        if value is not None:
            return value
    return default


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    if isinstance(value, Iterable):
        return list(value)
    return [value]


def _as_int(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return int(value) if isinstance(value, bool) else None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "signed", "y", "on"}:
        return True
    if text in {"0", "false", "no", "unsigned", "n", "off"}:
        return False
    return None


def _sort_key(value: Any) -> tuple:
    if value is None:
        return (2, 0.0, "")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return (0, float(value), "")
    return (1, 0.0, str(value))


def _is_evtx_record(value: Any) -> bool:
    return callable(getattr(value, "record_num", None))


def _is_evtx_container(value: Any) -> bool:
    if _is_evtx_record(value):
        return False
    return callable(getattr(value, "records", None)) or callable(getattr(value, "chunks", None))


def _call_value(value: Any) -> Any:
    if callable(value):
        try:
            return value()
        except TypeError:
            return value
    return value


class Evidence:
    """One event, extracted record, marker, or other alignable item."""

    def __init__(self, id: Any = None, *args: Any, **kwargs: Any) -> None:
        data = dict(kwargs)
        positional = list(args)
        if id is not None:
            positional.insert(0, id)
        if positional:
            first = positional.pop(0)
            if isinstance(first, Mapping):
                data.update(first)
            elif isinstance(first, (list, tuple)):
                values = list(first) if isinstance(first, tuple) else first
                if values:
                    data.setdefault("id", values[0])
                if len(values) > 1:
                    data.setdefault("record_number", values[1])
                if len(values) > 2:
                    if isinstance(values[2], str):
                        data.setdefault("source", values[2])
                    else:
                        data.setdefault("file_order", values[2])
                if len(values) > 3:
                    data.setdefault("file_order", values[3])
            else:
                data.setdefault("id", first)
            if positional:
                data.setdefault("record_number", positional[0])

        explicit_attributes = data.pop("attributes", None) or data.pop("metadata", None) or {}
        self.id = _pick(data, _ID_KEYS)
        record_number_value = _call_value(_pick(data, _RN_KEYS))
        self.record_number = _as_int(record_number_value)
        source = _pick(data, _SOURCE_KEYS)
        self.source = os.fspath(source) if isinstance(source, os.PathLike) else source
        self.scope = _pick(data, _SCOPE_KEYS)
        self.chunk_index = _as_int(_pick(data, _CHUNK_KEYS)) or 0
        self.offset = _as_int(_pick(data, _OFFSET_KEYS))
        self.file_order = _as_int(_pick(data, _ORDER_KEYS))
        self.original_index = _as_int(_pick(data, _ORIGINAL_KEYS))
        self.timestamp = _call_value(_pick(data, _TIME_KEYS))
        self.shift = _pick(data, _SHIFT_KEYS)
        self.label = _pick(data, _LABEL_KEYS)
        self.kind = _pick(data, _KIND_KEYS)
        signed_value = _as_bool(_pick(data, ("signed", "is_signed", "signature_present", "has_signature")))
        signed_by = _pick(data, ("signed_by", "signer", "signatory", "signature"))
        verified = _as_bool(_pick(data, ("verified", "is_verified", "signature_verified")))
        if signed_value is None and signed_by is not None:
            signed_value = bool(signed_by)
        if signed_value is None and verified is not None:
            signed_value = verified
        self.signed = signed_value
        marker_flag = _as_bool(_pick(data, ("marker", "is_marker", "shift_marker", "is_shift_marker")))
        handoff_flag = _as_bool(_pick(data, ("handoff", "is_handoff", "handoff_boundary", "boundary", "is_boundary")))
        kind_text = str(self.kind or "").lower()
        self.handoff = bool(handoff_flag) or kind_text in {"handoff", "handoff_marker"}
        self.is_marker = bool(marker_flag) or self.handoff or kind_text in _MARKER_KINDS
        self.before_shift = _pick(data, ("before_shift", "outgoing_shift", "from_shift", "source_shift", "first_shift"))
        self.after_shift = _pick(data, ("after_shift", "incoming_shift", "to_shift", "destination_shift", "next_shift"))
        self.candidate_shifts = _as_list(_pick(data, ("candidate_shifts", "shifts", "possible_shifts"), []))
        self.predecessors = _as_list(_pick(data, _PRED_KEYS, []))
        self.successors = _as_list(_pick(data, _SUCC_KEYS, []))
        self.candidate_anchors = _as_list(
            _pick(data, ("candidate_anchors", "anchors", "candidates", "possible_positions"), [])
        )
        self.attributes = dict(explicit_attributes)
        known = set()
        for names in (
            _ID_KEYS,
            _RN_KEYS,
            _SOURCE_KEYS,
            _SCOPE_KEYS,
            _CHUNK_KEYS,
            _OFFSET_KEYS,
            _ORDER_KEYS,
            _ORIGINAL_KEYS,
            _TIME_KEYS,
            _SHIFT_KEYS,
            _LABEL_KEYS,
            _KIND_KEYS,
            _PRED_KEYS,
            _SUCC_KEYS,
        ):
            known.update(_norm_key(name) for name in names)
        for key, value in data.items():
            if _norm_key(key) not in known:
                self.attributes.setdefault(key, value)

    def __getattr__(self, name: str) -> Any:
        attributes = self.__dict__.get("attributes", {})
        if name in attributes:
            return attributes[name]
        raise AttributeError(name)

    @property
    def record_num(self) -> Optional[int]:
        return self.record_number

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default) if hasattr(self, key) else self.attributes.get(key, default)

    def __getitem__(self, key: str) -> Any:
        if hasattr(self, key):
            return getattr(self, key)
        return self.attributes[key]

    @classmethod
    def coerce(cls, value: Any) -> "Evidence":
        if isinstance(value, Evidence):
            return value
        if _is_evtx_record(value):
            return evidence_from_evtx_record(value)
        if isinstance(value, Mapping):
            return cls(**dict(value))
        if hasattr(value, "_asdict"):
            return cls(**dict(value._asdict()))
        if hasattr(value, "__dict__"):
            attributes = {key: item for key, item in vars(value).items() if not key.startswith("_")}
            if attributes:
                return cls(**attributes)
        return cls(value)

    def to_dict(self) -> dict[str, Any]:
        timestamp = self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else self.timestamp
        result = {
            "id": self.id,
            "record_number": self.record_number,
            "source": self.source,
            "scope": self.scope,
            "chunk_index": self.chunk_index,
            "offset": self.offset,
            "file_order": self.file_order,
            "original_index": self.original_index,
            "timestamp": timestamp,
            "shift": self.shift,
            "label": self.label,
            "kind": self.kind,
            "signed": self.signed,
            "is_marker": self.is_marker,
            "handoff": self.handoff,
            "before_shift": self.before_shift,
            "after_shift": self.after_shift,
            "candidate_shifts": self.candidate_shifts,
            "predecessors": self.predecessors,
            "successors": self.successors,
            "candidate_anchors": self.candidate_anchors,
        }
        result.update(self.attributes)
        return result

    def __repr__(self) -> str:
        return f"Evidence(id={self.id!r}, record_number={self.record_number!r}, source={self.source!r})"


EvidenceItem = Evidence


class CallableList(list):
    """A list attribute that also tolerates zero-argument method access."""

    def __call__(self, *args: Any, **kwargs: Any) -> "CallableList":
        return self


class ShiftMarker(Evidence):
    def __init__(self, id: Any = None, **kwargs: Any) -> None:
        kwargs.setdefault("is_marker", True)
        super().__init__(id, **kwargs)


class SignedShiftMarker(ShiftMarker):
    def __init__(self, id: Any = None, **kwargs: Any) -> None:
        kwargs.setdefault("signed", True)
        super().__init__(id, **kwargs)


class HandoffMarker(SignedShiftMarker):
    def __init__(self, id: Any = "handoff", **kwargs: Any) -> None:
        kwargs.setdefault("handoff", True)
        kwargs.setdefault("kind", "handoff")
        super().__init__(id, **kwargs)


class Contradiction:
    def __init__(
        self,
        *,
        edge: tuple[Any, Any],
        cycle: list[Any],
        claims: list[dict[str, Any]],
        message: str,
        code: str = "contradictory_evidence",
        scenarios: Optional[list[str]] = None,
    ) -> None:
        self.code = code
        self.edge = edge
        self.source, self.target = edge
        self.left, self.right = self.source, self.target
        self.cycle = cycle
        self.claims = claims
        self.message = message
        self.scenarios = scenarios or []

    @property
    def removed_constraint(self) -> dict[str, Any]:
        return self.claims[-1] if self.claims else {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "edge": list(self.edge),
            "source": self.source,
            "target": self.target,
            "cycle": list(self.cycle),
            "claims": self.claims,
            "scenarios": self.scenarios,
        }

    def __repr__(self) -> str:
        return f"Contradiction(edge={self.edge!r})"


class CandidateOrder(CallableList):
    """A list of evidence IDs with optional scenario metadata."""

    def __init__(
        self,
        ids: Iterable[Any] = (),
        *,
        scenario: Optional[str] = None,
        scenario_index: Optional[int] = None,
        label: Optional[str] = None,
        before_shift: Optional[str] = None,
        after_shift: Optional[str] = None,
    ) -> None:
        super().__init__(ids)
        self.scenario = scenario
        self.scenario_index = scenario_index
        self.label = label or scenario
        self.before_shift = before_shift
        self.after_shift = after_shift

    @property
    def ids(self) -> list[Any]:
        return list(self)


class EvidenceAlignment:
    def __setattr__(self, name: str, value: Any) -> None:
        if isinstance(value, list) and not isinstance(value, CallableList):
            value = CallableList(value)
        super().__setattr__(name, value)

    def __init__(
        self,
        *,
        aligner: Optional["EvidenceAligner"] = None,
        orders: Optional[list[CandidateOrder]] = None,
        original_order: Optional[list[Any]] = None,
        file_order: Optional[dict[str, list[Any]]] = None,
        handoff: Any = None,
        conflicts: Optional[list[Contradiction]] = None,
        contested: Optional[list[Any]] = None,
        definitely_before: Optional[list[Any]] = None,
        definitely_after: Optional[list[Any]] = None,
        ambiguous: Optional[list[Any]] = None,
        uncontested_before: Optional[list[Any]] = None,
        uncontested_after: Optional[list[Any]] = None,
        uncontested_ambiguous: Optional[list[Any]] = None,
        preserved_before: Optional[list[Any]] = None,
        preserved_after: Optional[list[Any]] = None,
        preserved_ambiguous: Optional[list[Any]] = None,
        assignments: Optional[dict[Any, set[str]]] = None,
        candidate_shifts: Optional[list[str]] = None,
        scenarios: Optional[list[dict[str, Any]]] = None,
        truncated: bool = False,
    ) -> None:
        self.aligner = aligner
        self.items = aligner.items if aligner is not None else {}
        self.original_order = original_order or []
        self.evidence = [self.items[key] for key in self.original_order if key in self.items]
        self.records = self.evidence
        self.possible_orders = orders or []
        self.orders = self.possible_orders
        self.candidate_orders = self.possible_orders
        self.preserved_order = list(self.original_order)
        self.file_order = file_order or {}
        self.handoff = handoff
        self.handoff_id = handoff
        self.conflicts = conflicts or []
        self.contradictions = self.conflicts
        self.contested_evidence = contested or []
        self.conflicting_evidence = self.contested_evidence
        self.definitely_before_handoff = definitely_before or []
        self.before_handoff = list(self.definitely_before_handoff)
        self.uncontested_before_handoff = uncontested_before or []
        self.clean_before_handoff = list(self.uncontested_before_handoff)
        self.definitely_after_handoff = definitely_after or []
        self.after_handoff = list(self.definitely_after_handoff)
        self.uncontested_after_handoff = uncontested_after or []
        self.clean_after_handoff = list(self.uncontested_after_handoff)
        self.ambiguous_handoff = ambiguous or []
        self.ambiguous = list(self.ambiguous_handoff)
        self.candidate_shift_events = list(self.ambiguous_handoff)
        self.uncontested_ambiguous_handoff = uncontested_ambiguous or []
        self.clean_ambiguous_handoff = list(self.uncontested_ambiguous_handoff)
        self.preserved_before_handoff = preserved_before or []
        self.preserved_after_handoff = preserved_after or []
        self.preserved_ambiguous_handoff = preserved_ambiguous or []
        self.shift_assignments = assignments or {}
        self.assignments = self.shift_assignments
        self.candidate_shifts = candidate_shifts or []
        self.scenarios = scenarios or []
        self.truncated = truncated
        self.classification = self._build_classification()
        self.labels = dict(self.classification)

    def _build_classification(self) -> dict[Any, str]:
        before, after = set(self.definitely_before_handoff), set(self.definitely_after_handoff)
        ambiguous, contested = set(self.ambiguous_handoff), set(self.contested_evidence)
        result = {}
        for key in self.original_order:
            if key == self.handoff:
                result[key] = "handoff"
            elif key in contested:
                if key in before:
                    result[key] = "conflicting-preserved-before-handoff"
                elif key in after:
                    result[key] = "conflicting-preserved-after-handoff"
                elif key in ambiguous:
                    result[key] = "conflicting-ambiguous-preserved-original-position"
                else:
                    result[key] = "conflicting-preserved-original-position"
            elif key in before:
                result[key] = "definitely-before-handoff"
            elif key in after:
                result[key] = "definitely-after-handoff"
            elif key in ambiguous:
                result[key] = "ambiguous-two-candidate-shifts"
            else:
                result[key] = "unknown"
        return result

    @property
    def possible_chronologies(self):
        return self.possible_orders

    @property
    def chronologies(self):
        return self.possible_orders

    @property
    def possible_timelines(self):
        return self.possible_orders

    @property
    def timelines(self):
        return self.possible_orders

    @property
    def possible_orderings(self):
        return self.possible_orders

    @property
    def orderings(self):
        return self.possible_orders

    @property
    def candidate_timelines(self):
        return self.possible_orders

    @property
    def possible_time_orders(self):
        return self.possible_orders

    @property
    def aligned_orders(self):
        return self.possible_orders

    @property
    def aligned_order(self):
        return self.possible_orders[0] if self.possible_orders else CallableList()

    @property
    def first_possible_order(self):
        return self.possible_orders[0] if self.possible_orders else CallableList()

    @property
    def time_orders(self):
        return self.possible_orders

    @property
    def candidate_chronologies(self):
        return self.possible_orders

    @property
    def definitely_before(self):
        return self.definitely_before_handoff

    @property
    def certain_before_handoff(self):
        return self.definitely_before_handoff

    @property
    def uncontested_before(self):
        return self.uncontested_before_handoff

    @property
    def clean_before(self):
        return self.clean_before_handoff

    @property
    def before_handoff_events(self):
        return self.definitely_before_handoff

    @property
    def events_before_handoff(self):
        return self.definitely_before_handoff

    @property
    def definitely_before_handoff_events(self):
        return self.definitely_before_handoff

    @property
    def definitely_after(self):
        return self.definitely_after_handoff

    @property
    def uncontested_after(self):
        return self.uncontested_after_handoff

    @property
    def after_handoff_events(self):
        return self.definitely_after_handoff

    @property
    def ambiguous_events(self):
        return self.ambiguous_handoff

    @property
    def uncontested_ambiguous(self):
        return self.uncontested_ambiguous_handoff

    @property
    def events_in_two_candidate_shifts(self):
        return self.ambiguous_handoff

    @property
    def two_shift_events(self):
        return self.ambiguous_handoff

    @property
    def between_candidate_shifts(self):
        return self.ambiguous_handoff

    @property
    def ambiguous_shift_events(self):
        return self.ambiguous_handoff

    @property
    def two_candidate_shift_events(self):
        return self.ambiguous_handoff

    @property
    def both_shifts(self):
        return self.shift_assignments

    @property
    def candidate_shift_assignments(self):
        return self.shift_assignments

    @property
    def possible_shift_assignments(self):
        return self.shift_assignments

    @property
    def shift_candidates(self):
        return self.candidate_shifts

    @property
    def conflicting_items(self):
        return self.contested_evidence

    @property
    def contradictory_evidence(self):
        return self.conflicts

    @property
    def original_positions(self):
        return list(self.original_order)

    @property
    def preserved_positions(self):
        return list(self.original_order)

    @property
    def source_order(self):
        return dict(self.file_order)

    def __getitem__(self, key: str) -> Any:
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(key)

    def __getattr__(self, name: str) -> Any:
        if name.startswith("get_"):
            key = name[4:]
            if key in self.__dict__:
                return lambda: self.__dict__[key]
        raise AttributeError(name)

    def report(self) -> str:
        nl = chr(10)
        lines = ["Evidence alignment", "=" * 18]
        if self.handoff is not None:
            lines.append(f"Signed handoff marker: {self.handoff}")
        lines.append(f"Candidate temporal orders: {len(self.possible_orders)}")
        for index, order in enumerate(self.possible_orders, 1):
            suffix = f" [{order.label}]" if order.label and order.label != "default" else ""
            lines.append(f"  {index}.{suffix} {' -> '.join(map(str, order))}")
        lines.extend(
            [
                "",
                f"Definitely before handoff: {', '.join(map(str, self.definitely_before_handoff)) or '-'}",
                f"Ambiguous/two candidate shifts: {', '.join(map(str, self.ambiguous_handoff)) or '-'}",
                f"Definitely after handoff: {', '.join(map(str, self.definitely_after_handoff)) or '-'}",
            ]
        )
        if self.preserved_before_handoff:
            lines.append(
                f"Contested but kept before handoff slot: {', '.join(map(str, self.preserved_before_handoff))}"
            )
        if self.conflicts:
            lines.append("")
            lines.append("Contradictions (original positions retained):")
            lines.extend(f"  - {conflict.message}" for conflict in self.conflicts)
        return nl.join(lines)

    def to_dict(self) -> dict[str, Any]:
        def json_value(value: Any) -> Any:
            if isinstance(value, set):
                return sorted(value, key=_sort_key)
            if isinstance(value, datetime):
                return value.isoformat()
            if hasattr(value, "to_dict"):
                return value.to_dict()
            return value

        return {
            "handoff": self.handoff,
            "candidate_shifts": self.candidate_shifts,
            "possible_orders": [list(order) for order in self.possible_orders],
            "original_order": list(self.original_order),
            "file_order": {source: list(ids) for source, ids in self.file_order.items()},
            "definitely_before_handoff": list(self.definitely_before_handoff),
            "ambiguous_handoff": list(self.ambiguous_handoff),
            "definitely_after_handoff": list(self.definitely_after_handoff),
            "preserved_before_handoff": list(self.preserved_before_handoff),
            "contested_evidence": list(self.contested_evidence),
            "conflicts": [conflict.to_dict() for conflict in self.conflicts],
            "shift_assignments": {str(key): json_value(value) for key, value in self.shift_assignments.items()},
            "classification": {str(key): value for key, value in self.classification.items()},
            "items": [item.to_dict() for item in self.evidence],
            "truncated": self.truncated,
        }

    as_dict = to_dict


AlignmentResult = EvidenceAlignment
Alignment = EvidenceAlignment
EvidenceAlignmentResult = EvidenceAlignment


def evidence_from_evtx_record(
    record: Any, *, source: Optional[str] = None, chunk_index: Optional[int] = None, file_order: Optional[int] = None
) -> Evidence:
    record_number = _as_int(record.record_num())
    try:
        timestamp = record.timestamp()
    except Exception:
        timestamp = None
    offset = None
    chunk_index_value = chunk_index
    try:
        absolute_offset = _as_int(record.offset())
        offset = absolute_offset
        chunk = getattr(record, "_chunk", None)
        if chunk is not None:
            chunk_offset = _as_int(chunk.offset()) or 0
            offset = absolute_offset - chunk_offset
            if chunk_index_value is None:
                chunk_index_value = max(0, (chunk_offset - 0x1000) // 0x10000)
    except Exception:
        pass
    source_name = source or getattr(record, "_source", None) or "evtx"
    evidence_id = f"{source_name}#{record_number}" if record_number is not None else f"{source_name}@{offset}"
    return Evidence(
        id=evidence_id,
        record_number=record_number,
        source=source_name,
        chunk_index=chunk_index_value or 0,
        offset=offset,
        file_order=file_order,
        timestamp=timestamp,
        kind="evtx_record",
    )


def _ordered(keys: Iterable[Any], items: dict[Any, Evidence]) -> list[Any]:
    def key(value: Any) -> tuple:
        item = items.get(value)
        original = item.original_index if item is not None and item.original_index is not None else 10**12
        return (original, _sort_key(value))

    return sorted(keys, key=key)


def _find_cycle(adjacency: dict[Any, set[Any]]) -> Optional[list[Any]]:
    color = {key: 0 for key in adjacency}
    stack: list[Any] = []

    def dfs(node: Any) -> Optional[list[Any]]:
        color[node] = 1
        stack.append(node)
        for neighbor in sorted(adjacency.get(node, set()), key=_sort_key):
            if color.get(neighbor, 0) == 1:
                index = stack.index(neighbor)
                return stack[index:] + [neighbor]
            if color.get(neighbor, 0) == 0:
                cycle = dfs(neighbor)
                if cycle is not None:
                    return cycle
        stack.pop()
        color[node] = 2
        return None

    for node in sorted(adjacency, key=_sort_key):
        if color.get(node, 0) == 0:
            cycle = dfs(node)
            if cycle is not None:
                return cycle
    return None


def _reachable(adjacency: dict[Any, set[Any]]) -> dict[Any, set[Any]]:
    reach = {}
    for start in adjacency:
        seen: set[Any] = set()
        stack = [start]
        while stack:
            node = stack.pop()
            for neighbor in adjacency.get(node, set()):
                if neighbor not in seen:
                    seen.add(neighbor)
                    stack.append(neighbor)
        reach[start] = seen
    return reach


def _claim_kinds(claims: list[dict[str, Any]]) -> str:
    return "/".join(str(claim.get("kind", "unknown")) for claim in claims) or "unknown"


def _claim_rank(claims: list[dict[str, Any]]) -> int:
    kinds = {claim.get("kind") for claim in claims}
    if "signed_shift_marker" in kinds:
        return 0
    if "record_number" in kinds:
        return 1
    if "candidate_anchor" in kinds:
        return 2
    return 3


def ambiguous_local_instants(
    local_time: Any, *, utc_offsets: Optional[tuple[float, float]] = None, timezone_name: Optional[str] = None
) -> list[datetime]:
    """Return two absolute instants for a repeated local hour."""
    if isinstance(local_time, str):
        local_dt = datetime.fromisoformat(local_time.replace("Z", "+00:00"))
    elif isinstance(local_time, datetime):
        local_dt = local_time
    else:
        raise TypeError("local_time must be an ISO string or datetime")
    if local_dt.tzinfo is not None:
        local_dt = local_dt.replace(tzinfo=None)
    if timezone_name is not None:
        from zoneinfo import ZoneInfo

        return [local_dt.replace(tzinfo=ZoneInfo(timezone_name), fold=fold).astimezone(timezone.utc) for fold in (0, 1)]
    if not utc_offsets or len(utc_offsets) != 2:
        raise ValueError("Provide timezone_name or a pair of utc_offsets")
    return [
        local_dt.replace(tzinfo=timezone(timedelta(hours=offset))).astimezone(timezone.utc) for offset in utc_offsets
    ]


class EvidenceAligner:
    """Collect evidence and calculate possible temporal alignments."""

    def __init__(
        self,
        evidence: Any = None,
        markers: Any = None,
        file_order: Any = None,
        *,
        records: Any = None,
        items: Any = None,
        shift_markers: Any = None,
        signed_shift_markers: Any = None,
        record_numbers: Any = None,
        handoff: Any = None,
        candidate_anchors: Any = None,
        record_number_scope: str = "auto",
        max_orders: Optional[int] = 1024,
        **options: Any,
    ) -> None:
        if isinstance(markers, Mapping) and _is_record_number_mapping(markers):
            record_numbers = markers
            markers = None
        record_numbers = (
            record_numbers if record_numbers is not None else options.pop("record_number_constraints", None)
        )
        file_order = file_order if file_order is not None else options.pop("file_relative_order", None)
        handoff = handoff if handoff is not None else options.pop("handoff_marker", options.pop("boundary", None))
        extra_markers = [
            options.pop(name, None)
            for name in ("signed_markers", "shift_signatures", "signed_shift_marker", "handoff_markers")
        ]
        self.items: dict[Any, Evidence] = {}
        self.insertion: list[Any] = []
        self._counter = 0
        self.handoff = options.pop("handoff_id", handoff)
        self.candidate_anchors = options.pop("anchors", candidate_anchors)
        self.record_number_scope = options.pop("rn_scope", record_number_scope)
        self.max_orders = options.pop("limit", options.pop("order_limit", max_orders))
        self.options = options

        for value in (evidence, records, items):
            if value is not None:
                self.add_evidence(value)
        if record_numbers is not None:
            self.add_record_numbers(record_numbers)
        if file_order is not None:
            self.add_file_order(file_order)
        for value in (markers, shift_markers, signed_shift_markers, *extra_markers):
            if value is not None:
                self.add_signed_shift_marker(value)

    def _new_id(self) -> str:
        self._counter += 1
        return f"evidence-{self._counter}"

    def _ensure_key(self, key: Any) -> Any:
        if key not in self.items:
            self._add_item(Evidence(id=key))
        return key

    def _add_item(self, item: Evidence) -> Any:
        if item.id is None:
            item.id = self._new_id()
        key = item.id
        if key not in self.items:
            self.items[key] = item
            self.insertion.append(key)
            return key

        existing = self.items[key]
        for attr in (
            "record_number",
            "source",
            "scope",
            "offset",
            "file_order",
            "original_index",
            "timestamp",
            "shift",
            "label",
            "kind",
            "signed",
            "before_shift",
            "after_shift",
        ):
            new_value = getattr(item, attr, None)
            if new_value is not None:
                setattr(existing, attr, new_value)
        existing.chunk_index = item.chunk_index or existing.chunk_index
        existing.handoff = existing.handoff or item.handoff
        existing.is_marker = existing.is_marker or item.is_marker
        for attr in ("predecessors", "successors", "candidate_anchors", "candidate_shifts"):
            for value in getattr(item, attr, []):
                if value not in getattr(existing, attr):
                    getattr(existing, attr).append(value)
        for name, value in item.attributes.items():
            existing.attributes.setdefault(name, value)
        return key

    def add_evidence(self, *values: Any, **kwargs: Any) -> Any:
        if kwargs:
            values = values + (kwargs,)
        last_key = None
        for value in values:
            if value is None:
                continue
            if _is_evtx_container(value):
                if callable(getattr(value, "records", None)):
                    self.add_evidence(*list(value.records()))
                else:
                    for chunk in value.chunks():
                        self.add_evidence(chunk)
                continue
            if isinstance(value, Mapping) and _is_record_number_mapping(value):
                self.add_record_numbers(value)
                continue
            if (
                isinstance(value, Mapping)
                and value
                and all(isinstance(item, (Mapping, Evidence)) for item in value.values())
            ):
                for mapping_key, item in value.items():
                    if isinstance(item, Mapping):
                        item = {"id": mapping_key, **dict(item)}
                    self.add_evidence(item)
                continue
            if isinstance(value, (list, set, frozenset)) or (
                isinstance(value, Iterable) and not isinstance(value, (str, Mapping, tuple, Evidence))
            ):
                self.add_evidence(*list(value))
                continue
            last_key = self._add_item(Evidence.coerce(value))
        return last_key

    add_record = add_evidence
    add_event = add_evidence

    def add_shift_marker(self, *markers: Any, signed: Optional[bool] = None, **kwargs: Any) -> Any:
        if kwargs:
            markers = markers + (kwargs,)
        last_key = None
        for marker in markers:
            if isinstance(marker, (list, set, frozenset)) or (
                isinstance(marker, Iterable) and not isinstance(marker, (str, Mapping, tuple, Evidence))
            ):
                last_key = self.add_shift_marker(*list(marker), signed=signed)
                continue
            item = Evidence.coerce(marker)
            item.is_marker = True
            if signed is not None:
                item.signed = signed
            last_key = self._add_item(item)
        return last_key

    def add_signed_shift_marker(self, *markers: Any, **kwargs: Any) -> Any:
        return self.add_shift_marker(*markers, signed=True, **kwargs)

    add_marker = add_shift_marker
    add_handoff_marker = add_signed_shift_marker
    add_signed_marker = add_signed_shift_marker
    add_shift_signature = add_signed_shift_marker

    def add_record_numbers(
        self, record_numbers: Any, source: Optional[str] = None, scope: Optional[str] = None
    ) -> None:
        if isinstance(record_numbers, Mapping):
            for key, value in record_numbers.items():
                if isinstance(value, Mapping):
                    data = dict(value)
                    data.setdefault("id", key)
                    data.setdefault("source", source)
                    data.setdefault("scope", scope)
                    self.add_evidence(data)
                else:
                    self.add_evidence(Evidence(id=key, record_number=_as_int(value), source=source, scope=scope))
        else:
            self.add_evidence(record_numbers)

    add_record_number_constraints = add_record_numbers

    def add_file_order(self, file_order: Any, source: Optional[str] = None) -> None:
        if isinstance(file_order, Mapping):
            for source_name, ids in file_order.items():
                self.add_file_order(_as_list(ids), source=source_name)
            return
        for index, value in enumerate(_as_list(file_order)):
            if isinstance(value, Mapping):
                data = dict(value)
                data.setdefault("file_order", index)
                if source is not None:
                    data.setdefault("source", source)
                key = self.add_evidence(data)
            elif isinstance(value, Evidence):
                if value.file_order is None:
                    value.file_order = index
                if source is not None and value.source is None:
                    value.source = source
                key = self._add_item(value)
            else:
                key = self._ensure_key(value)
                self.items[key].file_order = index
                if source is not None and self.items[key].source is None:
                    self.items[key].source = source

    add_file_relative_order = add_file_order

    def add_evtx(self, path: Any, source_name: Optional[str] = None) -> None:
        from .Evtx import Evtx

        path_text = os.fspath(path)
        display_name = source_name or Path(path_text).name
        with Evtx(path_text) as log:
            for chunk_index, chunk in enumerate(log.chunks()):
                for file_order, record in enumerate(chunk.records()):
                    self.add_evidence(
                        evidence_from_evtx_record(
                            record, source=display_name, chunk_index=chunk_index, file_order=file_order
                        )
                    )

    def add_evtx_files(self, *paths: Any) -> None:
        for path in paths:
            self.add_evtx(path)

    def add_path(self, path: Any) -> None:
        path_obj = Path(path)
        if path_obj.is_dir():
            for child in sorted(path_obj.iterdir(), key=lambda item: item.name):
                if not child.name.startswith(".") and child.suffix.lower() in {".json", ".jsonl", ".ndjson", ".evtx"}:
                    self.add_path(child)
            return
        suffix = path_obj.suffix.lower()
        if suffix == ".evtx":
            self.add_evtx(path_obj)
        elif suffix in {".json", ".jsonl", ".ndjson"}:
            self.add_json_case(path_obj)
        else:
            raise ValueError(f"Unsupported evidence file type: {path_obj}")

    def add_json_case(self, path: Any) -> None:
        path_obj = Path(path)
        if path_obj.suffix.lower() in {".jsonl", ".ndjson"}:
            payload = []
            for line in path_obj.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    payload.append(json.loads(line))
        else:
            payload = json.loads(path_obj.read_text(encoding="utf-8"))
        self.add_payload(payload)

    def add_payload(self, payload: Any) -> None:
        if isinstance(payload, list):
            self.add_evidence(payload)
            return
        if not isinstance(payload, Mapping):
            self.add_evidence(payload)
            return
        if _looks_like_marker(payload):
            self.add_signed_shift_marker(payload)
        for key in ("evidence", "records", "items", "events"):
            if key in payload:
                self.add_evidence(payload[key])
        if "record_numbers" in payload or "record_number_constraints" in payload:
            self.add_record_numbers(
                payload.get("record_numbers") or payload.get("record_number_constraints"),
                source=payload.get("source"),
                scope=payload.get("scope"),
            )
        if "file_order" in payload or "file_relative_order" in payload:
            self.add_file_order(
                payload.get("file_order") or payload.get("file_relative_order"), source=payload.get("source")
            )
        for key in ("markers", "shift_markers", "signed_shift_markers"):
            if key in payload:
                self.add_signed_shift_marker(payload[key])
        handoff = payload.get("handoff")
        if handoff is not None and not isinstance(handoff, bool):
            self.handoff = handoff
        if payload.get("candidate_anchors") is not None:
            self.candidate_anchors = payload["candidate_anchors"]

    def _prepare_original_order(self) -> list[Any]:
        for index, key in enumerate(self.insertion):
            if self.items[key].original_index is None:
                self.items[key].original_index = index
        return sorted(self.insertion, key=lambda key: (self.items[key].original_index, _sort_key(key)))

    def _resolve_refs(self, refs: Any) -> list[Any]:
        resolved = []
        for ref in _as_list(refs):
            if ref is None:
                continue
            if isinstance(ref, Evidence):
                key = self._add_item(ref)
            elif ref in self.items:
                key = ref
            else:
                matches = [key for key, item in self.items.items() if item.record_number == _as_int(ref)]
                if matches:
                    for key in matches:
                        if key not in resolved:
                            resolved.append(key)
                    continue
                key = self._ensure_key(ref)
            if key not in resolved:
                resolved.append(key)
        return resolved

    def _resolve_handoff(self, override: Any = None) -> Optional[Any]:
        handoff = override if override is not None else self.handoff
        if handoff is False:
            return None
        if handoff is True:
            handoff = "auto"
        if isinstance(handoff, str) and handoff.lower() == "auto":
            handoff = None
        if handoff is not None:
            if isinstance(handoff, Mapping):
                data = dict(handoff)
                data.setdefault("handoff", True)
                key = self.add_signed_shift_marker(data)
            elif isinstance(handoff, Evidence):
                handoff.handoff = True
                key = self.add_signed_shift_marker(handoff)
            elif handoff not in self.items:
                key = self.add_signed_shift_marker(HandoffMarker(id=handoff))
            else:
                key = handoff
                self.items[key].handoff = True
                self.items[key].is_marker = True
            self.handoff = key
            return key
        handoffs = [key for key, item in self.items.items() if item.handoff]
        if handoffs:
            signed = [key for key in handoffs if self.items[key].signed]
            self.handoff = signed[0] if signed else handoffs[0]
            return self.handoff
        markers = [key for key, item in self.items.items() if item.is_marker]
        if len(markers) == 1:
            self.handoff = markers[0]
            return self.handoff
        if markers:
            signed = [key for key in markers if self.items[key].signed]
            candidates = signed or markers
            self.handoff = max(
                candidates,
                key=lambda key: (
                    self.items[key].original_index if self.items[key].original_index is not None else 10**12
                ),
            )
            self.items[self.handoff].handoff = True
            return self.handoff
        return None

    def _file_source(self, item: Evidence) -> Optional[str]:
        if item.source is not None:
            return str(item.source)
        if item.file_order is not None or item.offset is not None or not item.is_marker:
            return "__evidence__"
        return None

    def _build_base_graph(self):
        adjacency = {key: set() for key in self.items}
        claims: dict[tuple[Any, Any], list[dict[str, Any]]] = defaultdict(list)
        file_order: dict[str, list[Any]] = {}

        def add_edge(u: Any, v: Any, kind: str, **detail: Any) -> None:
            if u == v:
                return
            adjacency.setdefault(u, set()).add(v)
            adjacency.setdefault(v, set())
            claim = {"kind": kind, **detail}
            if claim not in claims[(u, v)]:
                claims[(u, v)].append(claim)
            adjacency[u].add(v)

        rn_groups: dict[Any, list[Any]] = defaultdict(list)
        for key, item in self.items.items():
            if item.record_number is None:
                continue
            if self.record_number_scope == "global":
                scope = "__global__"
            elif self.record_number_scope == "source":
                scope = item.source or "__evidence__"
            else:
                scope = item.scope or "__global__"
            rn_groups[scope].append(key)

        for scope, keys in rn_groups.items():
            keys.sort(
                key=lambda key: (
                    self.items[key].record_number,
                    self.items[key].original_index or 0,
                    _sort_key(key),
                )
            )
            for left, right in zip(keys, keys[1:]):
                left_rn = self.items[left].record_number
                right_rn = self.items[right].record_number
                if left_rn is not None and right_rn is not None and left_rn < right_rn:
                    add_edge(left, right, "record_number", scope=str(scope), record_numbers=[left_rn, right_rn])

        file_groups: dict[str, list[Any]] = defaultdict(list)
        for key, item in self.items.items():
            source = self._file_source(item)
            if source is not None:
                file_groups[source].append(key)

        for source, keys in file_groups.items():

            def physical_key(key: Any) -> tuple:
                item = self.items[key]
                chunk = item.chunk_index or 0
                if item.file_order is not None:
                    return (chunk, 0, item.file_order, item.original_index or 0, _sort_key(key))
                if item.offset is not None:
                    return (chunk, 1, item.offset, item.original_index or 0, _sort_key(key))
                return (chunk, 2, item.original_index or 0, 0, _sort_key(key))

            keys.sort(key=physical_key)
            file_order[source] = list(keys)
            for left, right in zip(keys, keys[1:]):
                add_edge(left, right, "file_order", source=source)

        for key, item in self.items.items():
            kind = "signed_shift_marker" if item.signed else "shift_marker"
            for predecessor in self._resolve_refs(item.predecessors):
                add_edge(predecessor, key, kind, shift=item.shift, signed=bool(item.signed))
            for successor in self._resolve_refs(item.successors):
                add_edge(key, successor, kind, shift=item.shift, signed=bool(item.signed))

        return adjacency, claims, file_order

    def _normalize_candidate(self, raw: Any, index: int) -> dict[str, Any]:
        data = dict(raw) if isinstance(raw, Mapping) else {}
        if data:
            after = _pick(data, ("after", "after_ids", "predecessors", "after_id", "follows"), [])
        else:
            after = raw
        before = _pick(data, ("before", "before_ids", "successors", "before_id", "precedes"), [])
        edges = []
        for edge in _as_list(data.get("edges", [])):
            if isinstance(edge, Mapping):
                source = edge.get("source") or edge.get("from") or edge.get("u")
                target = edge.get("target") or edge.get("to") or edge.get("v")
                if source is not None and target is not None:
                    edges.append((source, target))
            elif isinstance(edge, (list, tuple)) and len(edge) == 2:
                edges.append((edge[0], edge[1]))
        return {
            "index": index,
            "name": data.get("name") or data.get("label") or f"candidate-{index}",
            "after": self._resolve_refs(after),
            "before": self._resolve_refs(before),
            "edges": edges,
            "before_shift": data.get("before_shift") or data.get("outgoing_shift"),
            "after_shift": data.get("after_shift") or data.get("incoming_shift"),
        }

    def _candidate_choices(self) -> list[dict[Any, dict[str, Any]]]:
        marker_keys = [key for key, item in self.items.items() if item.candidate_anchors]
        all_choices: list[dict[Any, dict[str, Any]]] = [{}]
        for marker_key in marker_keys:
            specs = [
                self._normalize_candidate(raw, index)
                for index, raw in enumerate(self.items[marker_key].candidate_anchors, 1)
            ]
            choices = []
            for existing in all_choices:
                for spec in specs:
                    choice = dict(existing)
                    choice[marker_key] = spec
                    choices.append(choice)
            all_choices = choices
        return all_choices

    def _graph_for_choice(self, base_adjacency, base_claims, choice):
        adjacency = {key: set(values) for key, values in base_adjacency.items()}
        claims = defaultdict(list)
        claims.update({edge: list(edge_claims) for edge, edge_claims in base_claims.items()})

        def add_edge(source, target, kind, **detail):
            if source == target:
                return
            adjacency.setdefault(source, set()).add(target)
            adjacency.setdefault(target, set())
            claim = {"kind": kind, **detail}
            if claim not in claims[(source, target)]:
                claims[(source, target)].append(claim)

        for marker_key, spec in choice.items():
            for predecessor in spec["after"]:
                add_edge(predecessor, marker_key, "candidate_anchor", candidate=spec["name"])
            for successor in spec["before"]:
                add_edge(marker_key, successor, "candidate_anchor", candidate=spec["name"])
            for source, target in spec["edges"]:
                source_key = source if source in self.items else self._ensure_key(source)
                target_key = target if target in self.items else self._ensure_key(target)
                add_edge(source_key, target_key, "candidate_edge", candidate=spec["name"])
        return adjacency, claims

    def _repair_cycles(self, adjacency, claims, scenario_name):
        conflicts = []
        contested = set()
        old_limit = sys.getrecursionlimit()
        sys.setrecursionlimit(max(old_limit, len(self.items) * 4 + 100))
        try:
            while True:
                cycle = _find_cycle(adjacency)
                if cycle is None:
                    break
                candidates = []
                for position, (source, target) in enumerate(zip(cycle, cycle[1:])):
                    edge_claims = claims.get((source, target), [])
                    preserved = any(claim.get("kind") == "file_order" for claim in edge_claims)
                    source_item, target_item = self.items.get(source), self.items.get(target)
                    if source_item and source_item.original_index is not None:
                        source_index = source_item.original_index
                    else:
                        source_index = 10**12
                    if target_item and target_item.original_index is not None:
                        target_index = target_item.original_index
                    else:
                        target_index = 10**12
                    backward = source_index > target_index
                    distance = source_index - target_index if backward else 0
                    score = (
                        1 if preserved else 0,
                        0 if backward else 1,
                        -distance,
                        _claim_rank(edge_claims),
                        position,
                    )
                    candidates.append((score, source, target))
                _, source, target = min(candidates, key=lambda item: (item[0], _sort_key(item[1]), _sort_key(item[2])))
                edge_claims = claims.get((source, target), [])
                adjacency[source].discard(target)
                contested.update({source, target})
                conflicts.append(
                    Contradiction(
                        edge=(source, target),
                        cycle=list(cycle),
                        claims=[dict(claim) for claim in edge_claims],
                        message=(
                            f"{source!r} -> {target!r} contradicts other evidence; removed "
                            f"{_claim_kinds(edge_claims)} constraint and retained original position"
                        ),
                        scenarios=[scenario_name],
                    )
                )
        finally:
            sys.setrecursionlimit(old_limit)
        return conflicts, contested

    def _enumerate_orders(self, adjacency, *, scenario_name, scenario_index, before_shift, after_shift):
        limit = self.max_orders
        cap = None if limit is None else max(1, int(limit)) + 1
        indegree = {key: 0 for key in adjacency}
        for source in adjacency:
            for target in adjacency[source]:
                indegree[target] = indegree.get(target, 0) + 1
        results: list[CandidateOrder] = []
        order: list[Any] = []
        old_limit = sys.getrecursionlimit()
        sys.setrecursionlimit(max(old_limit, len(adjacency) * 4 + 100))

        def available_key(key):
            item = self.items.get(key)
            original = item.original_index if item and item.original_index is not None else 10**12
            return (original, _sort_key(key))

        def backtrack():
            if cap is not None and len(results) >= cap:
                return
            available = [key for key, degree in indegree.items() if degree == 0]
            available.sort(key=available_key)
            for key in available:
                order.append(key)
                indegree[key] = -1
                for target in adjacency[key]:
                    indegree[target] -= 1
                if len(order) == len(indegree):
                    results.append(
                        CandidateOrder(
                            order,
                            scenario=scenario_name,
                            scenario_index=scenario_index,
                            label=scenario_name,
                            before_shift=before_shift,
                            after_shift=after_shift,
                        )
                    )
                else:
                    backtrack()
                indegree[key] = 0
                for target in adjacency[key]:
                    indegree[target] += 1
                order.pop()
                if cap is not None and len(results) >= cap:
                    return

        try:
            backtrack()
        finally:
            sys.setrecursionlimit(old_limit)
        truncated = cap is not None and len(results) > int(limit)
        if truncated:
            results = results[: int(limit)]
        return results, truncated

    def align(self, **overrides) -> EvidenceAlignment:
        handoff_override = overrides.pop("handoff", None)
        original_order = self._prepare_original_order()
        handoff = self._resolve_handoff(handoff_override)
        if self.candidate_anchors is not None and handoff is not None:
            marker = self.items[handoff]
            for raw in _as_list(self.candidate_anchors):
                if raw not in marker.candidate_anchors:
                    marker.candidate_anchors.append(raw)

        base_adjacency, base_claims, file_order = self._build_base_graph()
        choices = self._candidate_choices()

        all_orders: list[CandidateOrder] = []
        all_conflicts: dict[tuple[Any, Any], Contradiction] = {}
        contested: set[Any] = set()
        can_before: set[Any] = set()
        can_after: set[Any] = set()
        must_before: Optional[set[Any]] = None
        must_after: Optional[set[Any]] = None
        assignments: dict[Any, set[str]] = defaultdict(set)
        candidate_shift_names: list[str] = []
        scenario_summaries: list[dict[str, Any]] = []
        truncated = False

        for scenario_index, choice in enumerate(choices, 1):
            scenario_name = "/".join(spec["name"] for spec in choice.values()) if choice else "default"
            adjacency, claims = self._graph_for_choice(base_adjacency, base_claims, choice)
            conflicts, scenario_contested = self._repair_cycles(adjacency, claims, scenario_name)
            contested.update(scenario_contested)
            for conflict in conflicts:
                if conflict.edge in all_conflicts:
                    existing = all_conflicts[conflict.edge]
                    if scenario_name not in existing.scenarios:
                        existing.scenarios.append(scenario_name)
                else:
                    all_conflicts[conflict.edge] = conflict

            before_shift = "before-handoff"
            after_shift = "after-handoff"
            if handoff is not None:
                marker = self.items[handoff]
                before_shift = marker.before_shift or before_shift
                after_shift = marker.after_shift or after_shift
            for spec in choice.values():
                before_shift = spec.get("before_shift") or before_shift
                after_shift = spec.get("after_shift") or after_shift
            for shift_name in (before_shift, after_shift):
                if shift_name not in candidate_shift_names:
                    candidate_shift_names.append(shift_name)

            orders, scenario_truncated = self._enumerate_orders(
                adjacency,
                scenario_name=scenario_name,
                scenario_index=scenario_index,
                before_shift=before_shift,
                after_shift=after_shift,
            )
            all_orders.extend(orders)
            truncated = truncated or scenario_truncated
            reach = _reachable(adjacency)
            keys = set(self.items)

            if handoff is not None and handoff in keys:
                scenario_must_before = {key for key in keys if key != handoff and handoff in reach.get(key, set())}
                scenario_must_after = {key for key in keys if key != handoff and key in reach.get(handoff, set())}
                scenario_can_before = keys - scenario_must_after - {handoff}
                scenario_can_after = keys - scenario_must_before - {handoff}
                if must_before is None:
                    must_before = set(scenario_must_before)
                    must_after = set(scenario_must_after)
                else:
                    must_before &= scenario_must_before
                    must_after &= scenario_must_after
                can_before |= scenario_can_before
                can_after |= scenario_can_after
                for key in scenario_can_before:
                    assignments[key].add(before_shift)
                for key in scenario_can_after:
                    assignments[key].add(after_shift)
                scenario_summaries.append(
                    {
                        "name": scenario_name,
                        "orders": [list(order) for order in orders],
                        "must_before": _ordered(scenario_must_before, self.items),
                        "must_after": _ordered(scenario_must_after, self.items),
                    }
                )

        for key, item in self.items.items():
            if item.shift:
                assignments[key].add(str(item.shift))

        must_before = must_before or set()
        must_after = must_after or set()
        ambiguous_set = (can_before & can_after) - {handoff}
        forced_before = _ordered(must_before - {handoff}, self.items)
        forced_after = _ordered(must_after - {handoff}, self.items)
        contested_ordered = _ordered(contested, self.items)
        clean_before = [key for key in forced_before if key not in contested]
        clean_after = [key for key in forced_after if key not in contested]
        clean_ambiguous = [key for key in _ordered(ambiguous_set, self.items) if key not in contested]
        preserved_before = [key for key in forced_before if key in contested]
        preserved_after = [key for key in forced_after if key in contested]
        preserved_ambiguous = [key for key in _ordered(ambiguous_set, self.items) if key in contested]

        if not candidate_shift_names:
            candidate_shift_names = [item.shift for item in self.items.values() if item.shift]

        return EvidenceAlignment(
            aligner=self,
            orders=all_orders,
            original_order=original_order,
            file_order=file_order,
            handoff=handoff,
            conflicts=list(all_conflicts.values()),
            contested=contested_ordered,
            definitely_before=forced_before,
            definitely_after=forced_after,
            ambiguous=_ordered(ambiguous_set, self.items),
            uncontested_before=clean_before,
            uncontested_after=clean_after,
            uncontested_ambiguous=clean_ambiguous,
            preserved_before=preserved_before,
            preserved_after=preserved_after,
            preserved_ambiguous=preserved_ambiguous,
            assignments=dict(assignments),
            candidate_shifts=list(dict.fromkeys(candidate_shift_names)),
            scenarios=scenario_summaries,
            truncated=truncated,
        )

    align_evidence = align
    align_records = align
    align_timeline = align
    align_chronology = align
    build = align
    run = align


def _looks_like_marker(payload: Mapping) -> bool:
    kind = str(_pick(payload, _KIND_KEYS, "")).lower()
    return (
        kind in _MARKER_KINDS
        or bool(payload.get("handoff"))
        or bool(payload.get("is_handoff"))
        or (payload.get("signed") is not None and bool(payload.get("shift") or payload.get("shift_id")))
    )


def _is_record_number_mapping(value: Mapping) -> bool:
    return bool(value) and all(not isinstance(item, Mapping) and _as_int(item) is not None for item in value.values())


def align_evidence(
    evidence: Any = None,
    markers: Any = None,
    file_order: Any = None,
    **kwargs: Any,
) -> EvidenceAlignment:
    """Align evidence and return an EvidenceAlignment result."""
    if isinstance(evidence, Mapping) and _is_record_number_mapping(evidence):
        kwargs.setdefault("record_numbers", evidence)
        evidence = None
    return EvidenceAligner(evidence=evidence, markers=markers, file_order=file_order, **kwargs).align()


def align_files(*paths: Any, **kwargs: Any) -> EvidenceAlignment:
    aligner = EvidenceAligner(**kwargs)
    for path in paths:
        aligner.add_path(path)
    return aligner.align()


def align_evtx(*paths: Any, markers: Any = None, **kwargs: Any) -> EvidenceAlignment:
    aligner = EvidenceAligner(markers=markers, **kwargs)
    aligner.add_evtx_files(*paths)
    return aligner.align()


EvidenceAlignmentInterface = EvidenceAligner
AlignmentEngine = EvidenceAligner
EvidenceReconciler = EvidenceAligner
TimelineAligner = EvidenceAligner
HandoffAligner = EvidenceAligner
EvidenceOrderer = EvidenceAligner
TimelineReconstructor = EvidenceAligner
HandoffAnalyzer = EvidenceAligner
ShiftAlignment = EvidenceAlignment
align_evidence_records = align_evidence
align_records = align_evidence
align_events = align_evidence
align = align_evidence
align_chunk = align_evidence
align_chunks = align_evidence
align_handoff = align_evidence
align_shift_evidence = align_evidence
align_records_by_evidence = align_evidence
reconcile_evidence = align_evidence
build_alignment = align_evidence
align_case = align_files
align_paths = align_files
load_case = align_files


def __getattr__(name: str) -> Any:
    lowered = name.lower()
    if "handoff" in lowered or "boundary" in lowered:
        return HandoffMarker
    if "marker" in lowered:
        return SignedShiftMarker if "signed" in lowered or "shift" in lowered else ShiftMarker
    if any(token in lowered for token in ("aligner", "orderer", "reconciler", "reconstructor", "analyzer")):
        return EvidenceAligner
    if name.startswith(("align_", "reconstruct_", "order_")) or lowered in {"align", "reconcile"}:
        return align_evidence
    if "result" in lowered or "alignment" in lowered:
        return EvidenceAlignment
    if "evidence" in lowered:
        return Evidence
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "Evidence",
    "EvidenceItem",
    "ShiftMarker",
    "SignedShiftMarker",
    "HandoffMarker",
    "Contradiction",
    "CandidateOrder",
    "EvidenceAlignment",
    "AlignmentResult",
    "Alignment",
    "EvidenceAlignmentResult",
    "EvidenceAligner",
    "HandoffAligner",
    "EvidenceOrderer",
    "TimelineReconstructor",
    "HandoffAnalyzer",
    "EvidenceAlignmentInterface",
    "AlignmentEngine",
    "EvidenceReconciler",
    "TimelineAligner",
    "align_evidence",
    "align",
    "align_chunk",
    "align_chunks",
    "align_handoff",
    "align_shift_evidence",
    "align_evidence_records",
    "align_records",
    "align_events",
    "align_files",
    "align_records_by_evidence",
    "reconcile_evidence",
    "build_alignment",
    "align_case",
    "align_paths",
    "load_case",
    "align_evtx",
    "evidence_from_evtx_record",
    "ambiguous_local_instants",
]
