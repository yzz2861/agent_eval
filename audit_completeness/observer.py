"""Event-level completeness observer.

The observer consumes the public ``(prefix, event, value)`` tuples produced
by ijson parse/parse_coro entry points and never materialises the document.
A *slot* is one concrete value position whose container path is on a rule.
Closed slots deliver negative findings; an interrupted stream keeps its open
slots separate as truncation findings.
"""

from dataclasses import dataclass, field

import ijson

from .rules import compile_rules

@dataclass
class Finding:
    rule_id: str
    rule_path: str
    expected_types: tuple
    actual_type: object
    position: dict
    value: object = None

    @property
    def status(self):
        if self.actual_type is None:
            return "missing"
        if self.actual_type not in self.expected_types:
            return "type_mismatch"
        return "complete"

@dataclass
class Truncation:
    rule_id: str
    rule_path: str
    position: dict
    reason: str

@dataclass
class CompletenessResult:
    complete: list = field(default_factory=list)
    type_mismatched: list = field(default_factory=list)
    missing: list = field(default_factory=list)
    truncated: list = field(default_factory=list)
    open_slots: list = field(default_factory=list)
    stream_truncated: bool = False
    truncation_error: object = None

    @property
    def intact(self):
        return not self.stream_truncated

    def completed_fields(self):
        return list(self.complete) + list(self.type_mismatched)

class _Slot:
    """One map value position or one array element position."""

    __slots__ = ("path", "container", "index", "key", "rule_ids", "closed")

    def __init__(self, path, container, index, key, rule_ids):
        self.path = path
        self.container = container
        self.index = index
        self.key = key
        self.rule_ids = rule_ids
        self.closed = False

    def describe(self):
        position = {"array_indexes": list(self.path)}
        if self.container == "array":
            position["index"] = self.index
        else:
            position["key"] = self.key
        return position

class _Frame:
    """Open container bookkeeping: kind, ijson prefix, path, key/index cursor."""

    __slots__ = ("kind", "prefix", "path", "pending_key", "next_index", "seen_keys")

    def __init__(self, kind, prefix, path):
        self.kind = kind
        self.prefix = prefix
        self.path = path
        self.pending_key = None
        self.next_index = 0
        self.seen_keys = []

    def child_path(self, key, index):
        child = list(self.path)
        if self.kind == "array":
            child.append((self.prefix, index))
        return child

class CompletenessObserver:
    """Consume ijson events and keep negative/truncated findings apart."""

    def __init__(self, rules):
        self._compiled = compile_rules(rules)
        self.result = CompletenessResult()
        self._frame_stack = [_Frame(kind="root", prefix="", path=[])]
        self._slot_stack = []

    @property
    def rules(self):
        return tuple(self._compiled)

    @property
    def _frame(self):
        return self._frame_stack[-1]

    def coroutine(self):
        observer = self

        @ijson.utils.coroutine
        def sink():
            while True:
                prefix, event, value = (yield)
                observer.feed(prefix, event, value)

        return sink()

    def feed(self, prefix, event, value):
        handler = getattr(self, "_on_" + event)
        handler(prefix, value)

    def _on_map_key(self, prefix, value):
        self._frame.pending_key = value
        self._frame.seen_keys.append(value)

    def _on_start_map(self, prefix, value):
        self._open_container(prefix, "map")

    def _on_end_map(self, prefix, value):
        self._close_container(prefix, "map")

    def _on_start_array(self, prefix, value):
        self._open_container(prefix, "array")

    def _on_end_array(self, prefix, value):
        self._close_container(prefix, "array")

    def _on_null(self, prefix, value):
        self._record_scalar(prefix, "null", None)

    def _on_boolean(self, prefix, value):
        self._record_scalar(prefix, "boolean", value)

    def _on_number(self, prefix, value):
        self._record_scalar(prefix, "number", value)

    def _on_string(self, prefix, value):
        self._record_scalar(prefix, "string", value)

    def _open_container(self, prefix, kind):
        parent = self._frame
        key = parent.pending_key if parent.kind == "map" else None
        index = parent.next_index if parent.kind == "array" else None
        path = parent.child_path(key, index)
        slot = self._build_container_slot(prefix, kind, path, key, index)
        self._slot_stack.append(slot)
        if slot is not None and kind in ("map", "array"):
            for rule in self._rules_for(slot):
                if rule.path == prefix and kind in rule.expected_types:
                    self._emit(rule, slot, kind, None)
        self._frame_stack.append(_Frame(kind=kind, prefix=prefix, path=path))
        if parent.kind == "array":
            parent.next_index += 1
        if parent.kind == "map":
            parent.pending_key = None

    def _close_container(self, prefix, kind):
        frame = self._frame_stack.pop()
        slot = self._slot_stack.pop()
        if kind == "map" and slot is not None:
            slot.closed = True
            self._finalize_record_map(slot, frame)
        elif kind == "array":
            self._finalize_array_closure(prefix, frame, slot)

    def _finalize_array_closure(self, prefix, frame, slot):
        if frame.next_index > 0:
            return
        for rule in self._compiled:
            if rule.container_prefix != prefix:
                continue
            placeholder = _Slot(
                path=list(frame.path),
                container="array",
                index=0,
                key=None,
                rule_ids=(rule.rule_id,),
            )
            self._emit_missing(rule, placeholder)

    def _record_scalar(self, prefix, actual_type, value):
        parent = self._frame
        key = parent.pending_key if parent.kind == "map" else None
        index = parent.next_index if parent.kind == "array" else None
        path = parent.child_path(key, index)
        slot = self._build_scalar_slot(prefix, path, key, index)
        if slot is not None:
            slot.closed = True
            self._finalize_value(slot, actual_type, value, prefix)
        if parent.kind == "array":
            parent.next_index += 1
        if parent.kind == "map":
            parent.pending_key = None

    def _build_container_slot(self, prefix, kind, path, key, index):
        rule_ids = tuple(
            rule.rule_id
            for rule in self._compiled
            if rule.container_prefix == prefix or rule.path == prefix
        )
        if not rule_ids:
            return None
        return _Slot(path, kind, index, key, rule_ids)

    def _build_scalar_slot(self, prefix, path, key, index):
        rule_ids = tuple(
            rule.rule_id
            for rule in self._compiled
            if rule.path == prefix
            and rule.expected_types[0] in ("null", "boolean", "number", "string")
        )
        if not rule_ids:
            return None
        container_kind = "array" if self._frame.kind == "array" else "map"
        return _Slot(path, container_kind, index, key, rule_ids)

    def _rules_for(self, slot):
        return [rule for rule in self._compiled if rule.rule_id in slot.rule_ids]

    def _finalize_record_map(self, slot, frame):
        present = set(frame.seen_keys)
        for rule in self._rules_for(slot):
            if rule.container_prefix != frame.prefix:
                continue
            if rule.expected_types[0] in ("map", "array"):
                continue
            if rule.key in present:
                continue
            self._emit_missing(rule, slot)

    def _finalize_value(self, slot, actual_type, value, prefix):
        for rule in self._rules_for(slot):
            if rule.path != prefix:
                continue
            self._emit(rule, slot, actual_type, value)

    def _emit(self, rule, slot, actual_type, value):
        finding = Finding(
            rule_id=rule.rule_id,
            rule_path=rule.path,
            expected_types=rule.expected_types,
            actual_type=actual_type,
            position=slot.describe(),
            value=value,
        )
        if actual_type not in rule.expected_types:
            self.result.type_mismatched.append(finding)
        else:
            self.result.complete.append(finding)

    def _emit_missing(self, rule, slot):
        position = slot.describe()
        position["missing_key"] = rule.key
        finding = Finding(
            rule_id=rule.rule_id,
            rule_path=rule.path,
            expected_types=rule.expected_types,
            actual_type=None,
            position=position,
        )
        self.result.missing.append(finding)

    def mark_truncated(self, error):
        """Record an interrupted stream; open slots never become missing."""
        self.result.stream_truncated = True
        self.result.truncation_error = repr(error)
        seen_positions = set()
        for slot in self._slot_stack:
            if slot is None:
                continue
            position = slot.describe()
            position["unclosed_container"] = slot.container
            pending = tuple(rule.rule_id for rule in self._rules_for(slot))
            position["pending_rules"] = pending
            signature = repr(position)
            if signature in seen_positions:
                continue
            seen_positions.add(signature)
            self.result.truncated.append(
                Truncation(
                    rule_id=None,
                    rule_path=None,
                    position=position,
                    reason="stream ended before this container closed; "
                    "presence of its rules cannot be decided",
                )
            )
            self.result.open_slots.append(position)
        return self.result
