"""Optional call evidence for restricted scripts."""

from __future__ import annotations

import ast
import contextvars
import functools
import hashlib
import sys
import threading
import time
import uuid
from collections.abc import Callable
from collections.abc import Iterable
from collections.abc import Mapping
from collections.abc import Sequence
from dataclasses import dataclass
from dataclasses import field
from typing import Any

from RestrictedPython.Guards import safe_builtins
from RestrictedPython.compile import compile_restricted_eval
from RestrictedPython.compile import compile_restricted_exec
from RestrictedPython.transformer import RestrictingNodeTransformer


CALL_STARTED = "call_started"
ATTEMPT_STARTED = "attempt_started"
ATTEMPT_SUCCEEDED = "attempt_succeeded"
ATTEMPT_FAILED = "attempt_failed"
RETRY_SCHEDULED = "retry_scheduled"
CALL_SUCCEEDED = "call_succeeded"
CALL_FAILED = "call_failed"

_CURRENT_SCOPE: contextvars.ContextVar[CallScope | None] = (
    contextvars.ContextVar("restricted_python_evidence_scope", default=None)
)


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _alias_value(
    mapping: Mapping[str, str], key: str, default: Any = None
) -> Any:
    for candidate in (key, *_ALIASES.get(key, ())):
        if candidate in mapping:
            return mapping[candidate]
    return default


_ALIASES: dict[str, tuple[str, ...]] = {}


class DictAccess:
    """Small mapping adapter so receipts work in attribute and dict style."""

    _aliases: Mapping[str, str] = {}

    def __getitem__(self, key: str) -> Any:
        target = self._aliases.get(key, key)
        if hasattr(self, target):
            return getattr(self, target)
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default


@dataclass(frozen=True)
class SourceLocation(DictAccess):
    script_id: str | None = None
    filename: str = "<string>"
    trace_filename: str | None = None
    lineno: int | None = None
    end_lineno: int | None = None
    col_offset: int | None = None
    end_col_offset: int | None = None
    statement: str | None = None
    source_line: str | None = None
    available: bool = True
    reason: str | None = None

    _aliases = {
        "line": "lineno",
        "line_number": "lineno",
        "source_statement": "statement",
        "text": "statement",
        "source": "statement",
    }

    @property
    def line_number(self) -> int | None:
        return self.lineno

    @property
    def source_statement(self) -> str | None:
        return self.statement

    def to_dict(self) -> dict[str, Any]:
        return {
            "script_id": self.script_id,
            "filename": self.filename,
            "lineno": self.lineno,
            "end_lineno": self.end_lineno,
            "col_offset": self.col_offset,
            "end_col_offset": self.end_col_offset,
            "statement": self.statement,
            "source_line": self.source_line,
            "available": self.available,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ScriptIdentity(DictAccess):
    script_id: str
    source_sha256: str
    filename: str = "<string>"
    caller: str | None = None
    team: str | None = None
    labels: Mapping[str, str] = field(default_factory=dict)

    _aliases = {
        "id": "script_id",
        "name": "script_id",
        "owner": "caller",
        "digest": "source_sha256",
        "sha256": "source_sha256",
    }

    def to_dict(self) -> dict[str, Any]:
        return {
            "script_id": self.script_id,
            "source_sha256": self.source_sha256,
            "filename": self.filename,
            "caller": self.caller,
            "team": self.team,
            "labels": dict(self.labels),
        }


@dataclass(frozen=True)
class EvidenceRecord(DictAccess):
    sequence: int
    record_id: str
    kind: str
    timestamp: float
    call_id: str | None = None
    receipt_id: str | None = None
    root_call_id: str | None = None
    parent_call_id: str | None = None
    script_id: str | None = None
    function_name: str | None = None
    registered_name: str | None = None
    adapter_id: str | None = None
    caller: str | None = None
    attempt: int | None = None
    next_attempt: int | None = None
    status: str | None = None
    error_type: str | None = None
    safe_code: str | None = None
    source: SourceLocation | None = None
    adapter_ref: Any = field(default=None, repr=False, compare=False)

    _aliases = {
        "event": "kind",
        "event_type": "kind",
        "name": "function_name",
        "owner": "caller",
        "line_number": "source",
        "source_statement": "source",
    }

    @property
    def source_statement(self) -> str | None:
        return None if self.source is None else self.source.statement

    @property
    def line_number(self) -> int | None:
        return None if self.source is None else self.source.lineno

    def to_dict(self) -> dict[str, Any]:
        data = {
            "sequence": self.sequence,
            "record_id": self.record_id,
            "kind": self.kind,
            "timestamp": self.timestamp,
            "call_id": self.call_id,
            "receipt_id": self.receipt_id or self.call_id,
            "root_call_id": self.root_call_id,
            "parent_call_id": self.parent_call_id,
            "script_id": self.script_id,
            "function_name": self.function_name,
            "registered_name": self.registered_name,
            "adapter_id": self.adapter_id,
            "caller": self.caller,
            "attempt": self.attempt,
            "next_attempt": self.next_attempt,
            "status": self.status,
            "error_type": self.error_type,
            "safe_code": self.safe_code,
        }
        data["source"] = None if self.source is None else self.source.to_dict()
        return data


@dataclass(frozen=True)
class ScriptHandle:
    identity: ScriptIdentity
    source: str
    trace_filename: str
    tree: ast.AST | None
    lines: tuple[str, ...]


class SourceCatalog:
    """Map unique compile filenames back to script identity and source."""

    def __init__(self) -> None:
        self._handles: dict[str, ScriptHandle] = {}
        self._lock = threading.RLock()
        self._counter = 0

    def register(
        self,
        source: str,
        *,
        script_id: str | None = None,
        filename: str = "<string>",
        caller: str | None = None,
        team: str | None = None,
        labels: Mapping[str, str] | None = None,
    ) -> ScriptHandle:
        if not isinstance(source, str):
            raise TypeError("evidence source must be text")
        with self._lock:
            self._counter += 1
            generated_id = script_id or f"script-{self._counter:04d}"
            digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
            trace_filename = (
                f"<restricted-evidence:{generated_id}:{uuid.uuid4().hex}>"
            )
            try:
                tree = ast.parse(source, filename=filename, mode="exec")
            except SyntaxError:
                tree = None
            identity = ScriptIdentity(
                script_id=generated_id,
                source_sha256=digest,
                filename=filename,
                caller=caller,
                team=team,
                labels=dict(labels or {}),
            )
            handle = ScriptHandle(
                identity=identity,
                source=source,
                trace_filename=trace_filename,
                tree=tree,
                lines=tuple(source.splitlines()),
            )
            self._handles[trace_filename] = handle
            return handle

    def locate_frame(self, frame: Any) -> SourceLocation | None:
        current = frame
        while current is not None:
            handle = self._handles.get(current.f_code.co_filename)
            if handle is not None:
                return self.locate_position(handle, current.f_lineno)
            current = current.f_back
        return None

    def locate_position(
        self, handle: ScriptHandle, lineno: int | None
    ) -> SourceLocation:
        identity = handle.identity
        if lineno is None or lineno <= 0 or lineno > len(handle.lines):
            return SourceLocation(
                script_id=identity.script_id,
                filename=identity.filename,
                trace_filename=handle.trace_filename,
                available=False,
                reason="line_not_found",
            )

        source_line = handle.lines[lineno - 1].strip()
        node = self._find_statement(handle.tree, lineno)
        if node is None:
            statement: str | None = source_line
            end_lineno = lineno
            col_offset = None
            end_col_offset = None
        else:
            statement = self._statement_text(handle.source, node, source_line)
            end_lineno = getattr(node, "end_lineno", lineno)
            col_offset = getattr(node, "col_offset", None)
            end_col_offset = getattr(node, "end_col_offset", None)

        return SourceLocation(
            script_id=identity.script_id,
            filename=identity.filename,
            trace_filename=handle.trace_filename,
            lineno=lineno,
            end_lineno=end_lineno,
            col_offset=col_offset,
            end_col_offset=end_col_offset,
            statement=statement,
            source_line=source_line,
        )

    @staticmethod
    def _find_statement(tree: ast.AST | None, lineno: int) -> ast.stmt | None:
        if tree is None:
            return None
        best: ast.stmt | None = None
        best_span: tuple[int, int] | None = None
        for node in ast.walk(tree):
            if not isinstance(node, ast.stmt):
                continue
            start = getattr(node, "lineno", None)
            end = getattr(node, "end_lineno", start)
            if start is None or end is None or not (start <= lineno <= end):
                continue
            span = (
                end - start,
                (
                    (getattr(node, "end_col_offset", 0) or 0)
                    - (getattr(node, "col_offset", 0) or 0)
                ),
            )
            if best is None or span < best_span:  # type: ignore[operator]
                best = node
                best_span = span
        return best

    @staticmethod
    def _statement_text(
        source: str, node: ast.stmt, source_line: str
    ) -> str | None:
        body = getattr(node, "body", None)
        first_statement = body[0] if isinstance(body, list) and body else None
        if (
            first_statement is not None
            and getattr(first_statement, "lineno", None) != node.lineno
        ):
            lines = source.splitlines()
            header = "\n".join(
                lines[node.lineno - 1 : first_statement.lineno - 1]
            ).strip()
            if header:
                return header
        try:
            segment = ast.get_source_segment(source, node)
        except (IndexError, ValueError):
            segment = None
        return segment.strip() if segment else source_line


@dataclass
class CallScope:
    hub: EvidenceHub
    call_id: str
    root_call_id: str
    parent_call_id: str | None = None
    attempt: int = 0
    script_id: str | None = None


class FunctionAdapter:
    """Trusted caller-side adapter with optional audited retry behavior."""

    def __init__(
        self,
        func: Callable[..., Any] | None = None,
        *,
        name: str | None = None,
        adapter_id: str | None = None,
        caller: str | None = None,
        owner: str | None = None,
        max_attempts: int = 1,
        retry_on: type[BaseException] | tuple[type[BaseException], ...] = (
            Exception,
        ),
        backoff: float = 0.0,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        self.func = func
        self.name = name or getattr(func, "__name__", None)
        self.adapter_id = adapter_id or getattr(func, "adapter_id", None)
        self.caller = caller or owner or getattr(func, "caller", None)
        self.max_attempts = max_attempts
        self.retry_on = retry_on
        self.backoff = backoff
        self.sleeper = sleeper

    def host_call(self, *args: Any, **kwargs: Any) -> Any:
        if self.func is None:
            raise NotImplementedError("adapter has no host function")
        return self.func(*args, **kwargs)

    def sleep(self, delay: float) -> None:
        if delay <= 0:
            return
        if self.sleeper is not None:
            self.sleeper(delay)
        else:
            time.sleep(delay)

    def invoke(self, *args: Any, **kwargs: Any) -> Any:
        last_error: BaseException | None = None
        for attempt in range(1, self.max_attempts + 1):
            record_adapter_event(ATTEMPT_STARTED, attempt=attempt)
            try:
                result = self.host_call(*args, **kwargs)
            except self.retry_on as error:
                last_error = error
                record_adapter_event(
                    ATTEMPT_FAILED,
                    attempt=attempt,
                    error=error,
                )
                if attempt >= self.max_attempts:
                    raise
                record_adapter_event(
                    RETRY_SCHEDULED,
                    attempt=attempt,
                    next_attempt=attempt + 1,
                    error=error,
                )
                self.sleep(self.backoff * attempt)
            else:
                record_adapter_event(ATTEMPT_SUCCEEDED, attempt=attempt)
                return result
        if last_error is not None:  # pragma: no cover
            raise last_error

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self.invoke(*args, **kwargs)


class RetryingFunctionAdapter(FunctionAdapter):
    """Convenience subclass used to make retry intent explicit."""


def current_scope() -> CallScope | None:
    return _CURRENT_SCOPE.get()


def current_call_id() -> str | None:
    scope = current_scope()
    return None if scope is None else scope.call_id


def record_adapter_event(
    kind: str,
    *,
    attempt: int | None = None,
    next_attempt: int | None = None,
    error: BaseException | None = None,
    error_type: str | None = None,
    safe_code: str | None = None,
) -> EvidenceRecord | None:
    scope = current_scope()
    if scope is None:
        return None
    if attempt is not None:
        scope.attempt = attempt
    status = kind.removeprefix("attempt_").removeprefix("call_")
    return scope.hub._emit(
        kind=kind,
        call_id=scope.call_id,
        root_call_id=scope.root_call_id,
        parent_call_id=scope.parent_call_id,
        attempt=attempt,
        next_attempt=next_attempt,
        script_id=scope.script_id,
        status=status,
        error_type=error_type
        or (type(error).__name__ if error is not None else None),
        safe_code=safe_code,
    )


def record_failure(
    error: BaseException | None = None,
    *,
    error_type: str | None = None,
    safe_code: str | None = None,
    attempt: int | None = None,
) -> EvidenceRecord | None:
    return record_adapter_event(
        ATTEMPT_FAILED,
        error=error,
        error_type=error_type,
        safe_code=safe_code,
        attempt=attempt,
    )


def record_retry(
    error: BaseException | None = None,
    *,
    attempt: int | None = None,
    safe_code: str | None = None,
) -> EvidenceRecord | None:
    return record_adapter_event(
        RETRY_SCHEDULED,
        error=error,
        attempt=attempt,
        safe_code=safe_code,
    )


@dataclass(frozen=True)
class EvidenceReceipt(DictAccess):
    receipt_id: str
    call_id: str
    sequence: int | None = None
    root_call_id: str | None = None
    parent_call_id: str | None = None
    script_id: str | None = None
    function_name: str | None = None
    registered_name: str | None = None
    adapter_id: str | None = None
    caller: str | None = None
    status: str = "unknown"
    attempt_count: int = 0
    error_type: str | None = None
    safe_code: str | None = None
    source: SourceLocation | None = None
    missing_start: bool = False
    missing_terminal: bool = False
    adapter_ref: Any = None

    _aliases = {
        "id": "receipt_id",
        "parent_receipt_id": "parent_call_id",
        "root_receipt_id": "root_call_id",
        "name": "function_name",
        "owner": "caller",
        "line": "line_number",
        "line_number": "line_number",
        "source_statement": "source_statement",
        "function_adapter": "function_adapter",
    }

    @property
    def parent_receipt_id(self) -> str | None:
        return self.parent_call_id

    @property
    def line_number(self) -> int | None:
        return None if self.source is None else self.source.lineno

    @property
    def source_statement(self) -> str | None:
        return None if self.source is None else self.source.statement

    @property
    def adapter(self) -> Any:
        return (
            self.adapter_ref
            if self.adapter_ref is not None
            else self.adapter_id
        )

    @property
    def function_adapter(self) -> Any:
        return self.adapter

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "call_id": self.call_id,
            "sequence": self.sequence,
            "root_call_id": self.root_call_id,
            "parent_call_id": self.parent_call_id,
            "parent_receipt_id": self.parent_call_id,
            "script_id": self.script_id,
            "function_name": self.function_name,
            "registered_name": self.registered_name,
            "adapter_id": self.adapter_id,
            "caller": self.caller,
            "status": self.status,
            "attempt_count": self.attempt_count,
            "error_type": self.error_type,
            "safe_code": self.safe_code,
            "source": None if self.source is None else self.source.to_dict(),
            "source_statement": self.source_statement,
            "lineno": self.line_number,
            "missing_start": self.missing_start,
            "missing_terminal": self.missing_terminal,
        }


@dataclass(frozen=True)
class AuditIssue(DictAccess):
    code: str
    message: str
    call_id: str | None = None
    sequence: int | None = None
    parent_call_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "call_id": self.call_id,
            "sequence": self.sequence,
            "parent_call_id": self.parent_call_id,
        }


@dataclass(frozen=True)
class AuditReport:
    ok: bool
    issues: tuple[AuditIssue, ...] = ()
    sequence_gaps: tuple[tuple[int, int], ...] = ()
    missing_sequences: tuple[int, ...] = ()
    incomplete_call_ids: tuple[str, ...] = ()
    orphan_call_ids: tuple[str, ...] = ()

    @property
    def gaps(self) -> tuple[tuple[int, int], ...]:
        return self.sequence_gaps

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "issues": [issue.to_dict() for issue in self.issues],
            "sequence_gaps": [list(gap) for gap in self.sequence_gaps],
            "missing_sequences": list(self.missing_sequences),
            "incomplete_call_ids": list(self.incomplete_call_ids),
            "orphan_call_ids": list(self.orphan_call_ids),
        }


@dataclass(frozen=True)
class EvidenceReport:
    receipts: tuple[EvidenceReceipt, ...]
    records: tuple[EvidenceRecord, ...]
    audit: AuditReport
    generated_at: float = field(default_factory=time.time)
    script_ids: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.audit.ok

    @property
    def issues(self) -> tuple[AuditIssue, ...]:
        return self.audit.issues

    @property
    def gaps(self) -> tuple[tuple[int, int], ...]:
        return self.audit.sequence_gaps

    def receipt_for(self, receipt_id: str) -> EvidenceReceipt | None:
        for receipt in self.receipts:
            if receipt.receipt_id == receipt_id:
                return receipt
        return None

    def receipts_for_script(
        self, script_id: str
    ) -> tuple[EvidenceReceipt, ...]:
        return tuple(r for r in self.receipts if r.script_id == script_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "ok": self.ok,
            "script_ids": list(self.script_ids),
            "receipts": [item.to_dict() for item in self.receipts],
            "records": [item.to_dict() for item in self.records],
            "audit": self.audit.to_dict(),
        }

    def to_json(self, **kwargs: Any) -> str:
        import json

        kwargs.setdefault("ensure_ascii", False)
        kwargs.setdefault("indent", 2)
        return json.dumps(self.to_dict(), **kwargs)


class EvidenceLedger:
    """Append-only evidence stream with receipt aggregation and auditing."""

    def __init__(
        self,
        records: Iterable[EvidenceRecord] | None = None,
        sinks: Iterable[Callable[..., Any] | Any] | None = None,
        *,
        sink: Callable[..., Any] | Any | None = None,
        on_record: Callable[[EvidenceRecord], None] | None = None,
    ) -> None:
        self._lock = threading.RLock()
        initial_records: Iterable[EvidenceRecord] = ()
        initial_sinks: list[Any] = []
        if records is not None:
            if callable(records) or hasattr(records, "emit"):
                initial_sinks.append(records)
            elif isinstance(records, EvidenceRecord):
                initial_records = (records,)
            elif isinstance(records, (list, tuple, set)) and records and all(
                callable(item) or hasattr(item, "emit") for item in records
            ):
                initial_sinks.extend(records)
            else:
                initial_records = records
        self._records: list[EvidenceRecord] = list(initial_records)
        self._sinks: list[Callable[[EvidenceRecord], None]] = []
        self.sink_errors: list[dict[str, str | None]] = []
        for item in initial_sinks:
            self.add_sink(item)
        for item in sinks or ():
            self.add_sink(item)
        if sink is not None:
            self.add_sink(sink)
        if on_record is not None:
            self.add_sink(on_record)

    @property
    def records(self) -> tuple[EvidenceRecord, ...]:
        with self._lock:
            return tuple(self._records)

    def add_sink(self, sink: Callable[..., Any] | Any) -> None:
        if hasattr(sink, "emit") and callable(sink.emit):
            self._sinks.append(sink.emit)
        elif callable(sink):
            self._sinks.append(sink)
        else:
            raise TypeError("evidence sink must be callable or provide emit()")

    def emit(self, **fields: Any) -> EvidenceRecord:
        with self._lock:
            sequences = [record.sequence for record in self._records]
            fields.setdefault(
                "sequence", (max(sequences) + 1) if sequences else 1
            )
            fields.setdefault("record_id", _new_id("evt"))
            fields.setdefault("timestamp", time.time())
            record = EvidenceRecord(**fields)
            self._records.append(record)
            for sink in tuple(self._sinks):
                try:
                    sink(record)
                except Exception as error:  # noqa: BLE001 - outlet isolation
                    self.sink_errors.append(
                        {
                            "sink": getattr(
                                sink, "__name__", sink.__class__.__name__
                            ),
                            "error_type": type(error).__name__,
                        }
                    )
            return record

    def _aggregate(
        self, records: Iterable[EvidenceRecord]
    ) -> list[EvidenceReceipt]:
        grouped: dict[str, dict[str, Any]] = {}
        for record in records:
            call_id = record.call_id
            if call_id is None:
                continue
            bucket = grouped.setdefault(call_id, {"records": []})
            bucket["records"].append(record)

        receipts: list[EvidenceReceipt] = []
        for call_id, bucket in grouped.items():
            items: list[EvidenceRecord] = bucket["records"]
            starts = [item for item in items if item.kind == CALL_STARTED]
            terminals = [
                item
                for item in items
                if item.kind in (CALL_SUCCEEDED, CALL_FAILED)
            ]
            start = starts[0] if starts else None
            terminal = terminals[-1] if terminals else None
            source = start.source if start is not None else None
            if source is None:
                sourced = [
                    item.source for item in items if item.source is not None
                ]
                source = sourced[0] if sourced else None
            ordered = sorted(items, key=lambda item: item.sequence)
            first = ordered[0]
            attempts = [
                item.attempt for item in items if item.attempt is not None
            ]
            status = (
                terminal.status
                if terminal is not None and terminal.status is not None
                else ("incomplete" if start is not None else "partial")
            )
            receipts.append(
                EvidenceReceipt(
                    receipt_id=call_id,
                    call_id=call_id,
                    sequence=(
                        start.sequence if start is not None else first.sequence
                    ),
                    root_call_id=first.root_call_id,
                    parent_call_id=first.parent_call_id,
                    script_id=first.script_id,
                    function_name=first.function_name,
                    registered_name=first.registered_name,
                    adapter_id=first.adapter_id,
                    caller=first.caller,
                    status=status or "unknown",
                    attempt_count=max(attempts, default=0),
                    error_type=terminal.error_type if terminal else None,
                    safe_code=terminal.safe_code if terminal else None,
                    source=source,
                    adapter_ref=first.adapter_ref,
                    missing_start=start is None,
                    missing_terminal=terminal is None,
                )
            )
        receipts.sort(
            key=lambda item: (
                item.sequence if item.sequence is not None else 10**12
            )
        )
        return receipts

    def receipts(
        self, script_id: str | None = None
    ) -> tuple[EvidenceReceipt, ...]:
        receipts = self._aggregate(self._records)
        if script_id is not None:
            receipts = [
                item for item in receipts if item.script_id == script_id
            ]
        return tuple(receipts)

    def receipt(self, receipt_id: str) -> EvidenceReceipt | None:
        for item in self.receipts():
            if item.receipt_id == receipt_id:
                return item
        return None

    def audit(
        self, records: Iterable[EvidenceRecord] | None = None
    ) -> AuditReport:
        items = tuple(records if records is not None else self._records)
        issues: list[AuditIssue] = []
        call_ids = {item.call_id for item in items if item.call_id}
        grouped: dict[str, list[EvidenceRecord]] = {}
        for item in items:
            if item.call_id:
                grouped.setdefault(item.call_id, []).append(item)

        incomplete: list[str] = []
        orphans: list[str] = []
        for call_id, call_records in grouped.items():
            has_start = any(item.kind == CALL_STARTED for item in call_records)
            has_terminal = any(
                item.kind in (CALL_SUCCEEDED, CALL_FAILED)
                for item in call_records
            )
            first = min(call_records, key=lambda item: item.sequence)
            if not has_start:
                issues.append(
                    AuditIssue(
                        code="missing_call_start",
                        message=(
                            "Call evidence has events without a "
                            "start record."
                        ),
                        call_id=call_id,
                        sequence=first.sequence,
                    )
                )
            if not has_terminal:
                incomplete.append(call_id)
                issues.append(
                    AuditIssue(
                        code="incomplete_call",
                        message="Call evidence has no terminal record.",
                        call_id=call_id,
                        sequence=first.sequence,
                    )
                )
            parent = first.parent_call_id
            if parent and parent not in call_ids:
                orphans.append(call_id)
                issues.append(
                    AuditIssue(
                        code="missing_parent_record",
                        message="Parent call evidence is absent.",
                        call_id=call_id,
                        sequence=first.sequence,
                        parent_call_id=parent,
                    )
                )

        sequences = sorted({item.sequence for item in items})
        missing_sequences: list[int] = []
        gaps: list[tuple[int, int]] = []
        for previous, current in zip(sequences, sequences[1:]):
            if current != previous + 1:
                gaps.append((previous, current))
                missing_sequences.extend(range(previous + 1, current))
        ok = not issues and not missing_sequences
        return AuditReport(
            ok=ok,
            issues=tuple(issues),
            sequence_gaps=tuple(gaps),
            missing_sequences=tuple(missing_sequences),
            incomplete_call_ids=tuple(incomplete),
            orphan_call_ids=tuple(orphans),
        )

    def report(self, script_id: str | None = None) -> EvidenceReport:
        with self._lock:
            records = tuple(self._records)
        if script_id is not None:
            records = tuple(
                item for item in records if item.script_id == script_id
            )
        receipts = self._aggregate(records)
        script_ids = tuple(
            dict.fromkeys(item.script_id for item in records if item.script_id)
        )
        return EvidenceReport(
            receipts=tuple(receipts),
            records=records,
            audit=self.audit(records),
            script_ids=script_ids,
        )


def audit_records(records: Iterable[EvidenceRecord]) -> AuditReport:
    """Audit an externally retained or partial evidence sequence."""
    return EvidenceLedger().audit(records)


class RestrictedEvidenceError(RuntimeError):
    """Raised when an evidence-backed restricted script cannot compile."""

    def __init__(self, errors: Sequence[str]) -> None:
        self.errors = tuple(errors)
        super().__init__("; ".join(self.errors))


@dataclass(frozen=True)
class RegisteredAdapter:
    name: str
    adapter_id: str
    caller: str | None
    adapter: Any
    target: Callable[..., Any]

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self.target(*args, **kwargs)


@dataclass
class ScriptRun:
    identity: ScriptIdentity
    handle: ScriptHandle
    namespace: dict[str, Any]
    ledger: EvidenceLedger
    compile_result: Any = None
    value: Any = None
    error: BaseException | None = None
    mode: str = "exec"

    @property
    def script(self) -> ScriptIdentity:
        return self.identity

    @property
    def receipts(self) -> tuple[EvidenceReceipt, ...]:
        return self.ledger.receipts(self.identity.script_id)

    @property
    def report(self) -> EvidenceReport:
        return self.ledger.report(self.identity.script_id)

    @property
    def ok(self) -> bool:
        return self.error is None and self.report.ok


class EvidenceHub:
    """Registry, source catalog and evidence-backed restricted runner."""

    def __init__(
        self,
        sink: Callable[[EvidenceRecord], None] | Any | None = None,
        *,
        ledger: EvidenceLedger | None = None,
        sinks: Iterable[Callable[[EvidenceRecord], None] | Any] | None = None,
        catalog: SourceCatalog | None = None,
        on_record: Callable[[EvidenceRecord], None] | None = None,
    ) -> None:
        if isinstance(sink, EvidenceLedger) and ledger is None:
            ledger = sink
            sink = None
        elif isinstance(sink, (list, tuple)):
            if sink and all(
                isinstance(item, EvidenceRecord) for item in sink
            ):
                ledger = EvidenceLedger(sink)  # type: ignore[arg-type]
            else:
                sinks = tuple(sink) + tuple(sinks or ())
            sink = None
        self.ledger = ledger or EvidenceLedger()
        if sink is not None:
            self.ledger.add_sink(sink)
        if on_record is not None:
            self.ledger.add_sink(on_record)
        for item in sinks or ():
            self.ledger.add_sink(item)
        self.catalog = catalog or SourceCatalog()
        self._adapters: dict[tuple[str | None, str], RegisteredAdapter] = {}
        self._lock = threading.RLock()

    def register_function(
        self,
        name: str | Callable[..., Any] | None = None,
        func: Callable[..., Any] | None = None,
        *,
        adapter: Any | None = None,
        caller: str | None = None,
        owner: str | None = None,
        team: str | None = None,
        adapter_id: str | None = None,
        max_attempts: int = 1,
        retry_on: type[BaseException] | tuple[type[BaseException], ...] = (
            Exception,
        ),
        replace: bool = True,
    ) -> RegisteredAdapter | Callable[..., RegisteredAdapter]:
        if callable(name) and func is None and adapter is None:
            func = name
            name = None
        elif (
            name is not None and not isinstance(name, str) and adapter is None
        ):
            adapter = name
            name = None

        caller = caller or owner or team
        original = adapter if adapter is not None else func
        if original is None and isinstance(name, str):

            def decorator(item: Callable[..., Any]) -> RegisteredAdapter:
                return self.register_function(
                    name,
                    item,
                    caller=caller,
                    adapter_id=adapter_id,
                    max_attempts=max_attempts,
                    retry_on=retry_on,
                    replace=replace,
                )

            return decorator

        if original is None:
            raise TypeError("a function or adapter is required")

        caller = caller or getattr(original, "caller", None)
        actual_name = (
            name
            or getattr(original, "name", None)
            or getattr(original, "__name__", None)
            or original.__class__.__name__
        )
        if not isinstance(actual_name, str):
            raise TypeError("registered function name must be a string")

        target = self._adapter_target(original)
        if max_attempts > 1 and not isinstance(target, FunctionAdapter):
            target = RetryingFunctionAdapter(
                target,
                name=actual_name,
                adapter_id=adapter_id,
                caller=caller,
                max_attempts=max_attempts,
                retry_on=retry_on,
            )

        actual_adapter_id = (
            adapter_id
            or getattr(original, "adapter_id", None)
            or getattr(target, "adapter_id", None)
            or f"{caller or 'caller'}:{actual_name}"
        )
        key = (caller, actual_name)
        if key in self._adapters and not replace:
            raise ValueError(
                f"adapter already registered: {caller!r}/{actual_name}"
            )
        registration = RegisteredAdapter(
            name=actual_name,
            adapter_id=str(actual_adapter_id),
            caller=caller,
            adapter=original,
            target=target,
        )
        with self._lock:
            self._adapters[key] = registration
        return registration

    @staticmethod
    def _adapter_target(original: Any) -> Callable[..., Any]:
        if isinstance(original, FunctionAdapter):
            return original
        if callable(original):
            return original
        for method_name in ("adapt", "execute", "run", "handle"):
            method = getattr(original, method_name, None)
            if callable(method):
                return method
        raise TypeError(
            "adapter must be callable or provide adapt/execute/run/handle"
        )

    def register_adapter(
        self,
        name: str | Any | None = None,
        adapter: Any | None = None,
        **kwargs: Any,
    ) -> RegisteredAdapter | Callable[..., Any]:
        if adapter is None and name is not None and not isinstance(name, str):
            adapter = name
            name = kwargs.pop("registered_name", None)
        return self.register_function(name, adapter=adapter, **kwargs)

    def adapter(self, name: str, **kwargs: Any) -> Callable[..., Any]:
        return self.register_function(name, **kwargs)

    def _resolve(self, name: str, caller: str | None) -> RegisteredAdapter:
        registration = self._adapters.get((caller, name))
        if registration is not None:
            return registration
        if caller is not None:
            registration = self._adapters.get((None, name))
            if registration is not None:
                return registration
        matches = [
            item
            for (item_caller, item_name), item in self._adapters.items()
            if item_name == name and (caller is None or item_caller == caller)
        ]
        if len(matches) == 1:
            return matches[0]
        if not matches:
            raise KeyError(f"no evidence adapter registered for {name!r}")
        raise KeyError(
            f"multiple evidence adapters registered for {name!r}; pass caller"
        )

    def wrapper_for(
        self, name: str, caller: str | None = None
    ) -> Callable[..., Any]:
        registration = self._resolve(name, caller)

        def evidence_wrapper(*args: Any, **kwargs: Any) -> Any:
            source = self.catalog.locate_frame(sys._getframe(0))
            return self._invoke(registration, source, args, kwargs)

        try:
            functools.update_wrapper(
                evidence_wrapper, registration.target, updated=()
            )
        except Exception:
            pass
        setattr(evidence_wrapper, "__wrapped__", registration.target)
        setattr(
            evidence_wrapper,
            "__evidence_adapter_id__",
            registration.adapter_id,
        )
        return evidence_wrapper

    def wrappers(
        self, caller: str | None = None
    ) -> dict[str, Callable[..., Any]]:
        result: dict[str, Callable[..., Any]] = {}
        for registration in self._adapters.values():
            if registration.caller is None:
                result[registration.name] = self.wrapper_for(
                    registration.name, None
                )
        if caller is not None:
            for registration in self._adapters.values():
                if registration.caller == caller:
                    result[registration.name] = self.wrapper_for(
                        registration.name, caller
                    )
        return result

    def _emit(self, **fields: Any) -> EvidenceRecord:
        return self.ledger.emit(**fields)

    def _invoke(
        self,
        registration: RegisteredAdapter,
        source: SourceLocation | None,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> Any:
        call_id = _new_id("call")
        parent = current_scope()
        parent_call_id = parent.call_id if parent is not None else None
        root_call_id = parent.root_call_id if parent is not None else call_id
        script_id = source.script_id if source is not None else None
        common = {
            "receipt_id": call_id,
            "call_id": call_id,
            "root_call_id": root_call_id,
            "parent_call_id": parent_call_id,
            "script_id": script_id,
            "function_name": registration.name,
            "registered_name": registration.name,
            "adapter_id": registration.adapter_id,
            "caller": registration.caller,
            "adapter_ref": registration.adapter,
            "source": source,
        }
        self.ledger.emit(
            kind=CALL_STARTED,
            status="started",
            **common,
        )
        scope = CallScope(
            hub=self,
            call_id=call_id,
            root_call_id=root_call_id,
            parent_call_id=parent_call_id,
            script_id=script_id,
        )
        token = _CURRENT_SCOPE.set(scope)
        try:
            result = registration.target(*args, **kwargs)
        except BaseException as error:
            self.ledger.emit(
                kind=CALL_FAILED,
                status="failed",
                attempt=scope.attempt or 1,
                error_type=type(error).__name__,
                **common,
            )
            raise
        else:
            self.ledger.emit(
                kind=CALL_SUCCEEDED,
                status="succeeded",
                attempt=scope.attempt or 1,
                **common,
            )
            return result
        finally:
            _CURRENT_SCOPE.reset(token)

    def run_script(
        self,
        source: str | None = None,
        *,
        script: Any | None = None,
        script_id: str | None = None,
        name: str | None = None,
        caller: str | None = None,
        owner: str | None = None,
        team: str | None = None,
        filename: str = "<string>",
        namespace: dict[str, Any] | None = None,
        glb: dict[str, Any] | None = None,
        globals: dict[str, Any] | None = None,
        environment: dict[str, Any] | None = None,
        functions: Mapping[str, Any] | Iterable[str] | None = None,
        mode: str = "exec",
        flags: int = 0,
        policy: type[Any] | None = RestrictingNodeTransformer,
        capture_errors: bool = False,
        labels: Mapping[str, str] | None = None,
    ) -> ScriptRun:
        if source is None and isinstance(script, str):
            source = script
        elif source is None and isinstance(script, ScriptHandle):
            source = script.source
        if source is None:
            raise TypeError("run_script requires source text")

        caller = caller or owner or team
        handle = self.catalog.register(
            source,
            script_id=script_id or name,
            filename=filename,
            caller=caller,
            team=team,
            labels=labels,
        )

        runtime: dict[str, Any] = {}
        for candidate in (namespace, glb, globals, environment):
            if candidate:
                runtime.update(candidate)
        runtime.setdefault("__builtins__", safe_builtins.copy())

        evidence_functions = self._prepare_functions(functions, caller)
        runtime.update(evidence_functions)

        compile_policy = (
            RestrictingNodeTransformer if policy is None else policy
        )
        if mode == "exec":
            result = compile_restricted_exec(
                source,
                filename=handle.trace_filename,
                flags=flags,
                policy=compile_policy,
            )
        elif mode == "eval":
            result = compile_restricted_eval(
                source,
                filename=handle.trace_filename,
                flags=flags,
                policy=compile_policy,
            )
        else:
            raise ValueError("evidence runner supports exec and eval modes")
        if result.errors:
            raise RestrictedEvidenceError(result.errors)
        assert result.code is not None

        error: BaseException | None = None
        value: Any = None
        try:
            if mode == "eval":
                value = eval(result.code, runtime)  # noqa: S307
            else:
                exec(result.code, runtime)  # noqa: S102
        except Exception as exc:
            error = exc
            if not capture_errors:
                raise

        return ScriptRun(
            identity=handle.identity,
            handle=handle,
            namespace=runtime,
            ledger=self.ledger,
            compile_result=result,
            value=value,
            error=error,
            mode=mode,
        )

    def _prepare_functions(
        self,
        functions: Mapping[str, Any] | Iterable[str] | None,
        caller: str | None,
    ) -> dict[str, Callable[..., Any]]:
        if functions is None:
            return self.wrappers(caller)

        if isinstance(functions, Mapping):
            prepared: dict[str, Callable[..., Any]] = {}
            for name, value in functions.items():
                if isinstance(value, RegisteredAdapter):
                    registration = value
                elif callable(value):
                    registration = self.register_function(
                        str(name), value, caller=caller
                    )
                else:
                    raise TypeError(f"function {name!r} is not callable")
                prepared[str(name)] = self._invoke_bound(registration)
            return prepared

        return {name: self.wrapper_for(name, caller) for name in functions}

    def _invoke_bound(
        self, registration: RegisteredAdapter
    ) -> Callable[..., Any]:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            source = self.catalog.locate_frame(sys._getframe(0))
            return self._invoke(registration, source, args, kwargs)

        return wrapper

    def receipt(self, receipt_id: str) -> EvidenceReceipt | None:
        return self.ledger.receipt(receipt_id)

    def receipts(
        self, script_id: str | None = None
    ) -> tuple[EvidenceReceipt, ...]:
        return self.ledger.receipts(script_id)

    def report(self, script_id: str | None = None) -> EvidenceReport:
        return self.ledger.report(script_id)


def create_evidence_outlet(**kwargs: Any) -> EvidenceHub:
    return EvidenceHub(**kwargs)


def create_evidence_recorder(**kwargs: Any) -> EvidenceHub:
    return EvidenceHub(**kwargs)


def run_restricted(
    source: str | None = None,
    *,
    evidence: EvidenceHub
    | EvidenceLedger
    | Callable[..., Any]
    | Any
    | None = None,
    outlet: Any = None,
    recorder: Any = None,
    registry: Any = None,
    sink: Any = None,
    evidence_sink: Any = None,
    adapters: Iterable[Any] | Mapping[str, Any] | None = None,
    **kwargs: Any,
) -> ScriptRun:
    configured = evidence if evidence is not None else outlet
    configured = configured if configured is not None else recorder
    configured = configured if configured is not None else registry
    selected_sink = sink if sink is not None else evidence_sink

    if isinstance(configured, EvidenceHub):
        hub = configured
    elif isinstance(configured, EvidenceLedger):
        hub = EvidenceHub(ledger=configured)
    elif configured is not None:
        hub = EvidenceHub(sink=configured)
    else:
        hub = EvidenceHub(sink=selected_sink)

    if isinstance(adapters, Mapping):
        for name, adapter in adapters.items():
            hub.register_adapter(name, adapter)
    elif adapters is not None:
        for adapter in adapters:
            hub.register_adapter(adapter)

    return hub.run_script(source, **kwargs)


EvidenceOutlet = EvidenceHub
EvidenceRegistry = EvidenceHub
AdapterRegistry = EvidenceHub
EvidenceCollector = EvidenceHub
AuditTrail = EvidenceHub
AuditLog = EvidenceLedger
EvidenceSink = EvidenceLedger
EvidenceRecorder = EvidenceHub
Receipt = EvidenceReceipt
SourceStatement = SourceLocation
CallEvidence = EvidenceRecord


@dataclass(frozen=True)
class ReconciliationMatch(DictAccess):
    function_name: str
    status: str
    backend_index: int | None = None
    sequence: int | None = None
    call_id: str | None = None
    receipt_id: str | None = None
    script_id: str | None = None
    caller: str | None = None
    adapter_id: str | None = None
    source_statement: str | None = None
    lineno: int | None = None

    _aliases = {
        "index": "backend_index",
        "line_number": "lineno",
        "name": "function_name",
        "owner": "caller",
    }

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend_index": self.backend_index,
            "index": self.backend_index,
            "sequence": self.sequence,
            "function_name": self.function_name,
            "status": self.status,
            "call_id": self.call_id,
            "receipt_id": self.receipt_id,
            "script_id": self.script_id,
            "caller": self.caller,
            "adapter_id": self.adapter_id,
            "source_statement": self.source_statement,
            "lineno": self.lineno,
        }


@dataclass(frozen=True)
class ReconciliationReport:
    matches: tuple[ReconciliationMatch, ...] = ()
    ok: bool = True
    unmatched_backend_indexes: tuple[int, ...] = ()
    missing_backend_call_ids: tuple[str, ...] = ()

    @property
    def issues(self) -> tuple[str, ...]:
        issues: list[str] = []
        issues.extend(
            f"backend_record_without_evidence:{index}"
            for index in self.unmatched_backend_indexes
        )
        issues.extend(
            f"evidence_without_backend_record:{call_id}"
            for call_id in self.missing_backend_call_ids
        )
        return tuple(issues)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "matches": [match.to_dict() for match in self.matches],
            "issues": list(self.issues),
            "unmatched_backend_indexes": list(self.unmatched_backend_indexes),
            "missing_backend_call_ids": list(self.missing_backend_call_ids),
        }


def trace_records(
    records: Iterable[EvidenceRecord], call_id: str
) -> tuple[EvidenceRecord, ...]:
    items = tuple(records)
    related = {call_id}
    changed = True
    while changed:
        changed = False
        for record in items:
            if (
                record.parent_call_id in related
                and record.call_id
                and record.call_id not in related
            ):
                related.add(record.call_id)
                changed = True
    return tuple(
        sorted(
            (record for record in items if record.call_id in related),
            key=lambda record: record.sequence,
        )
    )


def reconcile_records(
    records: Iterable[EvidenceRecord],
    backend_records: Iterable[Any],
    *,
    script_id: str | None = None,
) -> ReconciliationReport:
    """Correlate function-name-only backend rows with evidence receipts."""
    items = tuple(records)
    starts = [
        record
        for record in items
        if record.kind == CALL_STARTED
        and (script_id is None or record.script_id == script_id)
    ]
    by_call_id = {
        record.call_id: record for record in starts if record.call_id
    }
    used: set[str] = set()
    matches: list[ReconciliationMatch] = []
    unmatched_backend: list[int] = []

    for index, raw in enumerate(backend_records):
        external_id: str | None = None
        if isinstance(raw, Mapping):
            function_name = (
                raw.get("function_name") or raw.get("name") or raw.get("func")
            )
            external_id = (
                raw.get("call_id")
                or raw.get("receipt_id")
                or raw.get("evidence_id")
            )
        else:
            function_name = raw
        if not isinstance(function_name, str):
            function_name = str(function_name)

        start: EvidenceRecord | None = None
        status = "matched_by_order"
        if external_id and external_id in by_call_id:
            start = by_call_id[str(external_id)]
            status = "matched_by_call_id"
        else:
            for candidate in starts:
                if (
                    candidate.call_id not in used
                    and candidate.function_name == function_name
                ):
                    start = candidate
                    break

        if start is None or start.call_id is None:
            unmatched_backend.append(index)
            matches.append(
                ReconciliationMatch(
                    backend_index=index,
                    function_name=function_name,
                    status="missing_evidence",
                )
            )
            continue

        used.add(start.call_id)
        matches.append(
            ReconciliationMatch(
                backend_index=index,
                sequence=start.sequence,
                function_name=function_name,
                status=status,
                call_id=start.call_id,
                receipt_id=start.receipt_id or start.call_id,
                script_id=start.script_id,
                caller=start.caller,
                adapter_id=start.adapter_id,
                source_statement=(
                    None if start.source is None else start.source.statement
                ),
                lineno=None if start.source is None else start.source.lineno,
            )
        )

    missing_backend = [
        record.call_id
        for record in starts
        if record.call_id is not None and record.call_id not in used
    ]
    for call_id in missing_backend:
        start = by_call_id[call_id]
        matches.append(
            ReconciliationMatch(
                backend_index=None,
                sequence=start.sequence,
                function_name=start.function_name or "<unknown>",
                status="missing_backend_record",
                call_id=call_id,
                receipt_id=start.receipt_id or call_id,
                script_id=start.script_id,
                caller=start.caller,
                adapter_id=start.adapter_id,
                source_statement=(
                    None if start.source is None else start.source.statement
                ),
                lineno=None if start.source is None else start.source.lineno,
            )
        )

    matches.sort(
        key=lambda match: (
            10**9 if match.backend_index is None else match.backend_index
        )
    )
    ok = not unmatched_backend and not missing_backend
    return ReconciliationReport(
        matches=tuple(matches),
        ok=ok,
        unmatched_backend_indexes=tuple(unmatched_backend),
        missing_backend_call_ids=tuple(missing_backend),
    )


def _ledger_trace(
    self: EvidenceLedger, call_id: str
) -> tuple[EvidenceRecord, ...]:
    return trace_records(self.records, call_id)


def _ledger_reconcile(
    self: EvidenceLedger, backend_records: Iterable[Any], **kwargs: Any
) -> ReconciliationReport:
    return reconcile_records(self.records, backend_records, **kwargs)


def _report_trace(
    self: EvidenceReport, call_id: str
) -> tuple[EvidenceRecord, ...]:
    return trace_records(self.records, call_id)


def _hub_trace(self: EvidenceHub, call_id: str) -> tuple[EvidenceRecord, ...]:
    return self.ledger.trace(call_id)


def _hub_reconcile(
    self: EvidenceHub, backend_records: Iterable[Any], **kwargs: Any
) -> ReconciliationReport:
    return self.ledger.reconcile(backend_records, **kwargs)


EvidenceLedger.trace = _ledger_trace  # type: ignore[attr-defined]
EvidenceLedger.reconcile = _ledger_reconcile  # type: ignore[attr-defined]
EvidenceReport.trace = _report_trace  # type: ignore[attr-defined]
EvidenceHub.trace = _hub_trace  # type: ignore[attr-defined]
EvidenceHub.reconcile = _hub_reconcile  # type: ignore[attr-defined]
Receipt = EvidenceReceipt
SourceStatement = SourceLocation
FunctionRegistry = EvidenceHub
FunctionAdapterRegistry = EvidenceHub
CallerAdapterRegistry = EvidenceHub
EvidenceExporter = EvidenceHub
EvidenceBackend = EvidenceLedger
EvidenceStore = EvidenceLedger
CallEvidence = EvidenceRecord
AuditEvent = EvidenceRecord


def _ledger_retries(
    self: EvidenceLedger, call_id: str
) -> tuple[EvidenceRecord, ...]:
    return tuple(
        record
        for record in self.trace(call_id)
        if record.kind in (ATTEMPT_FAILED, RETRY_SCHEDULED)
    )


def _hub_retries(
    self: EvidenceHub, call_id: str
) -> tuple[EvidenceRecord, ...]:
    return self.ledger.retries(call_id)


EvidenceLedger.get_receipt = EvidenceLedger.receipt
EvidenceLedger.get_receipts = EvidenceLedger.receipts
EvidenceLedger.trace_call = _ledger_trace
EvidenceLedger.call_chain = _ledger_trace
EvidenceLedger.retries = _ledger_retries
EvidenceHub.get_receipt = EvidenceHub.receipt
EvidenceHub.get_receipts = EvidenceHub.receipts
EvidenceHub.trace_call = EvidenceHub.trace
EvidenceHub.call_chain = EvidenceHub.trace
EvidenceHub.retries = _hub_retries
EvidenceHub.register = EvidenceHub.register_adapter
EvidenceHub.register_function_adapter = EvidenceHub.register_function
EvidenceReport.trace_call = EvidenceReport.trace
EvidenceReport.call_chain = EvidenceReport.trace
EvidenceReport.safe_dict = EvidenceReport.to_dict
EvidenceReport.redacted = True
