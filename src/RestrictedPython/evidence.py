"""Optional provenance records for calls into approved host functions.

RestrictedPython normally only sees the names written by a restricted script.
An application which exposes approved host functions can use the helpers in
this module to keep an evidence trail next to the restricted execution.  A
receipt binds the identity of the script, the source statement which made the
call and the adapter which the caller registered for that name.

Receipts intentionally contain metadata only.  Arguments, return values,
exception messages and other values originating in restricted code are never
stored in an :class:`EvidenceReport`.
"""

from __future__ import annotations

import ast
import contextvars
import dataclasses
import io
import keyword
import threading
import time
import tokenize
import types
import typing
import weakref

from RestrictedPython.Guards import safe_builtins
from RestrictedPython.compile import CompileResult
from RestrictedPython.compile import _compile_restricted_mode
from RestrictedPython.transformer import RestrictingNodeTransformer
from RestrictedPython.transformer import copy_locations


ReceiptStatus: typing.TypeAlias = typing.Literal['started', 'ok', 'error']
DeliveryStatus: typing.TypeAlias = typing.Literal[
    'not_configured', 'pending', 'delivered', 'failed']
T_CompileSource: typing.TypeAlias = (
    str | bytes | bytearray | ast.Module | ast.Expression | ast.Interactive)


class EvidenceSink(typing.Protocol):
    """A destination for completed receipts.

    A sink is either a callable accepting one receipt or an object providing
    a ``write(receipt)`` method (for example an opened file which serialises
    receipts itself).
    """

    def write(self, receipt: 'CallReceipt') -> typing.Any:
        ...


@dataclasses.dataclass(frozen=True)
class FunctionAdapter:
    """An approved host function registered under a restricted source name."""

    name: str
    adapter_id: str
    function: typing.Callable[..., typing.Any]

    def __call__(self, *args: typing.Any, **kwargs: typing.Any) -> typing.Any:
        return self.function(*args, **kwargs)

    def __repr__(self) -> str:
        return (
            f'{self.__class__.__name__}(name={self.name!r}, '
            f'adapter_id={self.adapter_id!r})')


@dataclasses.dataclass(frozen=True)
class CallReceipt:
    """Metadata about one call from restricted code into a host adapter.

    ``statement`` is the restricted source statement containing the call and
    ``expression`` is the call expression itself.  Neither restricted argument
    values nor return values are part of a receipt.
    """

    call_id: str
    sequence: int
    script_id: str
    call_site_id: str
    function_name: str
    adapter_id: str
    statement: str
    expression: str
    lineno: int
    end_lineno: int
    col_offset: int
    end_col_offset: int
    parent_call_id: str | None
    depth: int
    attempt: int
    previous_call_id: str | None
    status: ReceiptStatus
    error_type: str | None
    delivery_status: DeliveryStatus
    delivery_attempts: int
    delivery_error_type: str | None
    started_at: float
    finished_at: float | None

    @property
    def complete(self) -> bool:
        """Whether the adapter call has finished (successfully or not)."""
        return self.status != 'started'

    @property
    def source(self) -> str:
        """The source statement which made the call."""
        return self.statement

    @property
    def function(self) -> str:
        """The source-level function name."""
        return self.function_name

    @property
    def adapter(self) -> str:
        """The caller-registered adapter id."""
        return self.adapter_id

    @property
    def parent_id(self) -> str | None:
        """The parent call id, if any."""
        return self.parent_call_id

    @property
    def retry(self) -> bool:
        """Whether this invocation repeated an earlier call site."""
        return self.attempt > 1

    def as_dict(self) -> dict[str, typing.Any]:
        """Return a JSON-friendly receipt without restricted values."""
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class EvidenceTrace:
    """The call chain leading to a receipt.

    ``missing_call_ids`` lists parents whose receipts are absent.  This keeps a
    partial trail explainable instead of silently pretending it is complete.
    """

    receipts: tuple[CallReceipt, ...]
    missing_call_ids: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class EvidenceReport:
    """An immutable view over the receipts of one or more scripts."""

    script_id: str | None
    receipts: tuple[CallReceipt, ...]
    missing_sequences: tuple[int, ...] = ()

    @classmethod
    def from_receipts(
            cls,
            receipts: typing.Iterable[CallReceipt],
            *,
            script_id: str | None = None,
            expected_sequences: typing.Iterable[int] | None = None,
    ) -> 'EvidenceReport':
        """Build a report from a partial or external set of receipts.

        ``expected_sequences`` allows callers to reconcile records recovered
        from a sink even when the original recorder is no longer available.
        """
        selected = tuple(sorted(receipts, key=lambda item: item.sequence))
        if script_id is not None:
            selected = tuple(
                receipt for receipt in selected
                if receipt.script_id == script_id)
        present = {receipt.sequence for receipt in selected}
        if expected_sequences is None:
            missing: tuple[int, ...] = ()
        else:
            missing = tuple(sorted(set(expected_sequences) - present))
        return cls(script_id, selected, missing)

    @property
    def records(self) -> tuple[CallReceipt, ...]:
        """The receipts in this report."""
        return self.receipts

    @property
    def missing(self) -> tuple[int, ...]:
        """The missing sequence numbers."""
        return self.missing_sequences

    def __iter__(self) -> typing.Iterator[CallReceipt]:
        return iter(self.receipts)

    def get(self, call_id: str) -> CallReceipt | None:
        for receipt in self.receipts:
            if receipt.call_id == call_id:
                return receipt
        return None

    def for_script(self, script_id: str) -> 'EvidenceReport':
        return EvidenceReport(
            script_id,
            tuple(
                receipt for receipt in self.receipts
                if receipt.script_id == script_id))

    def for_adapter(self, adapter_id: str) -> tuple[CallReceipt, ...]:
        return tuple(
            receipt for receipt in self.receipts
            if receipt.adapter_id == adapter_id)

    def for_function(self, function_name: str) -> tuple[CallReceipt, ...]:
        return tuple(
            receipt for receipt in self.receipts
            if receipt.function_name == function_name)

    def for_call_site(self, call_site_id: str) -> tuple[CallReceipt, ...]:
        return tuple(
            receipt for receipt in self.receipts
            if receipt.call_site_id == call_site_id)

    def roots(self) -> tuple[CallReceipt, ...]:
        known = {receipt.call_id for receipt in self.receipts}
        return tuple(
            receipt for receipt in self.receipts
            if receipt.parent_call_id not in known)

    def children(self, call_id: str) -> tuple[CallReceipt, ...]:
        return tuple(
            receipt for receipt in self.receipts
            if receipt.parent_call_id == call_id)

    def trace(self, call_id: str) -> EvidenceTrace:
        """Return the root-to-``call_id`` chain, including missing parents."""
        by_id = {receipt.call_id: receipt for receipt in self.receipts}
        chain: list[CallReceipt] = []
        missing: list[str] = []
        current = call_id
        seen: set[str] = set()
        while current is not None and current not in seen:
            seen.add(current)
            receipt = by_id.get(current)
            if receipt is None:
                missing.append(current)
                break
            chain.append(receipt)
            current = receipt.parent_call_id
        chain.reverse()
        missing.reverse()
        return EvidenceTrace(tuple(chain), tuple(missing))

    def as_dict(self) -> dict[str, typing.Any]:
        return {
            'script_id': self.script_id,
            'receipts': [receipt.as_dict() for receipt in self.receipts],
            'missing_sequences': list(self.missing_sequences),
        }


@dataclasses.dataclass(frozen=True)
class _CallFrame:
    call_id: str
    depth: int


@dataclasses.dataclass(frozen=True)
class _CallSite:
    script_id: str
    function_name: str
    adapter_id: str
    statement: str
    expression: str
    lineno: int
    end_lineno: int
    col_offset: int
    end_col_offset: int
    call_site_id: str


class EvidenceRecorder:
    """Collect call receipts and optionally deliver them to a sink.

    Sink delivery is retried up to ``max_delivery_attempts`` times.  A receipt
    stays in :attr:`receipts` even when delivery fails, so the trail can be
    inspected and :meth:`flush` can retry later.  Sequence numbers are issued
    monotonically; gaps in :attr:`EvidenceReport.missing_sequences` expose
    partial records.
    """

    def __init__(
            self,
            sink: EvidenceSink | typing.Callable[[CallReceipt], typing.Any]
            | None = None,
            *,
            max_delivery_attempts: int = 2):
        if max_delivery_attempts < 1:
            raise ValueError('max_delivery_attempts must be at least 1')
        self.sink = sink
        self.max_delivery_attempts = max_delivery_attempts
        self._lock = threading.RLock()
        self._next_sequence = 0
        self._records: dict[int, CallReceipt] = {}
        self._issued: dict[str, set[int]] = {}
        self._attempts: dict[tuple[str, str, str | None], int] = {}
        self._previous: dict[tuple[str, str, str | None], str] = {}
        self._context: contextvars.ContextVar[_CallFrame | None] = (
            contextvars.ContextVar(
                f'RestrictedPython.evidence.{id(self)}', default=None))

    @property
    def receipts(self) -> tuple[CallReceipt, ...]:
        with self._lock:
            return tuple(
                self._records[sequence]
                for sequence in sorted(self._records))

    @property
    def records(self) -> tuple[CallReceipt, ...]:
        """The receipts held by the recorder."""
        return self.receipts

    def get(self, call_id: str) -> CallReceipt | None:
        with self._lock:
            for receipt in self._records.values():
                if receipt.call_id == call_id:
                    return receipt
        return None

    def report(
            self,
            script_id: str | None = None,
            *,
            expected_sequences: typing.Iterable[int] | None = None,
    ) -> EvidenceReport:
        with self._lock:
            receipts = tuple(
                self._records[sequence]
                for sequence in sorted(self._records)
                if script_id is None
                or self._records[sequence].script_id == script_id)
            present = {receipt.sequence for receipt in receipts}
            if expected_sequences is None:
                issued: set[int] = set()
                for issued_script, sequences in self._issued.items():
                    if script_id is None or issued_script == script_id:
                        issued.update(sequences)
            else:
                issued = set(expected_sequences)
            missing = tuple(sorted(issued - present))
        return EvidenceReport(script_id, receipts, missing)

    def flush(self) -> int:
        """Retry delivery for failed or pending receipts.

        Returns the number of receipts delivered during this call.
        """
        if self.sink is None:
            return 0
        delivered = 0
        with self._lock:
            candidates = tuple(
                receipt for receipt in self._records.values()
                if receipt.delivery_status in ('failed', 'pending'))
        for receipt in candidates:
            updated = self._deliver(receipt)
            with self._lock:
                self._records[updated.sequence] = updated
            if updated.delivery_status == 'delivered':
                delivered += 1
        return delivered

    def invoke(
            self,
            site: _CallSite,
            caller: typing.Callable[..., typing.Any],
            args: tuple[typing.Any, ...],
            kwargs: dict[str, typing.Any],
    ) -> typing.Any:
        """Invoke ``caller`` and record metadata before and after the call."""
        parent = self._context.get()
        parent_id = parent.call_id if parent is not None else None
        depth = parent.depth + 1 if parent is not None else 0
        with self._lock:
            sequence = self._next_sequence
            self._next_sequence += 1
            call_id = f'{site.script_id}:{sequence}'
            key = (site.script_id, site.call_site_id, parent_id)
            attempt = self._attempts.get(key, 0) + 1
            self._attempts[key] = attempt
            previous_call_id = self._previous.get(key)
            self._previous[key] = call_id
            started_at = time.monotonic()
            receipt = CallReceipt(
                call_id=call_id,
                sequence=sequence,
                script_id=site.script_id,
                call_site_id=site.call_site_id,
                function_name=site.function_name,
                adapter_id=site.adapter_id,
                statement=site.statement,
                expression=site.expression,
                lineno=site.lineno,
                end_lineno=site.end_lineno,
                col_offset=site.col_offset,
                end_col_offset=site.end_col_offset,
                parent_call_id=parent_id,
                depth=depth,
                attempt=attempt,
                previous_call_id=previous_call_id,
                status='started',
                error_type=None,
                delivery_status='pending',
                delivery_attempts=0,
                delivery_error_type=None,
                started_at=started_at,
                finished_at=None,
            )
            self._records[sequence] = receipt
            self._issued.setdefault(site.script_id, set()).add(sequence)

        token = self._context.set(_CallFrame(call_id, depth))
        try:
            result = caller(*args, **kwargs)
        except BaseException as error:
            self._finish(sequence, 'error', type(error).__name__)
            raise
        else:
            self._finish(sequence, 'ok', None)
            return result
        finally:
            self._context.reset(token)

    def _finish(
            self,
            sequence: int,
            status: ReceiptStatus,
            error_type: str | None) -> None:
        with self._lock:
            receipt = dataclasses.replace(
                self._records[sequence],
                status=status,
                error_type=error_type,
                finished_at=time.monotonic())
            self._records[sequence] = receipt
        delivered = self._deliver(receipt)
        with self._lock:
            self._records[sequence] = delivered

    def _deliver(self, receipt: CallReceipt) -> CallReceipt:
        sink = self.sink
        if sink is None:
            return dataclasses.replace(
                receipt,
                delivery_status='not_configured',
                delivery_attempts=0,
                delivery_error_type=None)

        error_type = None
        for attempt in range(1, self.max_delivery_attempts + 1):
            candidate = dataclasses.replace(
                receipt,
                delivery_status='delivered',
                delivery_attempts=attempt,
                delivery_error_type=None)
            try:
                if callable(sink):
                    sink(candidate)
                else:
                    sink.write(candidate)
            except Exception as error:
                error_type = type(error).__name__
            else:
                return candidate
        return dataclasses.replace(
            receipt,
            delivery_status='failed',
            delivery_attempts=self.max_delivery_attempts,
            delivery_error_type=error_type)


class _BindingCollector(ast.NodeVisitor):
    """Collect names bound in one lexical scope, without nested scopes."""

    def __init__(self) -> None:
        self.bound: set[str] = set()
        self.globals: set[str] = set()
        self.nonlocals: set[str] = set()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.bound.add(node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.bound.add(node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.bound.add(node.name)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return None

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.bound.add(node.id)

    def visit_arg(self, node: ast.arg) -> None:
        self.bound.add(node.arg)

    def visit_alias(self, node: ast.alias) -> None:
        self.bound.add(node.asname or node.name.split('.')[0])

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.bound.add(node.name)
        self.generic_visit(node)

    def visit_Global(self, node: ast.Global) -> None:
        self.globals.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.nonlocals.update(node.names)

def _module_bindings(node: ast.Module) -> set[str]:
    collector = _BindingCollector()
    for statement in node.body:
        collector.visit(statement)
    return collector.bound - collector.globals


def _function_bindings(
        node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda) -> set[str]:
    collector = _BindingCollector()
    arguments = node.args
    collected_args = [
        *arguments.posonlyargs,
        *arguments.args,
        *arguments.kwonlyargs,
    ]
    if arguments.vararg is not None:
        collected_args.append(arguments.vararg)
    if arguments.kwarg is not None:
        collected_args.append(arguments.kwarg)
    for argument in collected_args:
        collector.bound.add(argument.arg)
    body = node.body if isinstance(node.body, list) else [node.body]
    for statement in body:
        collector.visit(statement)
    return (collector.bound - collector.globals) - collector.nonlocals


class _EvidenceNodeTransformer(RestrictingNodeTransformer):
    """Instrument calls to adapters registered with an evidence session."""

    def __init__(
            self,
            errors: list[str] | None = None,
            warnings: list[str] | None = None,
            used_names: dict[str, bool] | None = None,
            *,
            session: 'EvidenceSession',
            source: str | None = None):
        super().__init__(errors, warnings, used_names)
        self._session = session
        self._source = source
        self._annotated = False
        self._statement_by_node: dict[int, ast.stmt] = {}
        self._bound_names: list[set[str]] = []

    def visit(self, node: ast.AST) -> typing.Any:
        if not self._annotated:
            self._annotate_statements(node, None)
            self._annotated = True
        return super().visit(node)

    def _annotate_statements(
            self,
            node: ast.AST,
            statement: ast.stmt | None) -> None:
        if isinstance(node, ast.stmt):
            statement = node
        if isinstance(node, ast.expr) and statement is not None:
            self._statement_by_node[id(node)] = statement
        for child in ast.iter_child_nodes(node):
            self._annotate_statements(child, statement)

    def _name_is_bound(self, name: str) -> bool:
        return any(name in names for names in self._bound_names)

    def visit_Module(self, node: ast.Module) -> typing.Any:
        self._bound_names.append(_module_bindings(node))
        try:
            return super().visit_Module(node)
        finally:
            self._bound_names.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> typing.Any:
        self._bound_names.append(_function_bindings(node))
        try:
            return super().visit_FunctionDef(node)
        finally:
            self._bound_names.pop()

    def visit_AsyncFunctionDef(
            self, node: ast.AsyncFunctionDef) -> typing.Any:
        self._bound_names.append(_function_bindings(node))
        try:
            return super().visit_AsyncFunctionDef(node)
        finally:
            self._bound_names.pop()

    def visit_Lambda(self, node: ast.Lambda) -> typing.Any:
        self._bound_names.append(_function_bindings(node))
        try:
            return super().visit_Lambda(node)
        finally:
            self._bound_names.pop()

    def _source_segment(self, node: ast.AST) -> str:
        if self._source is not None:
            segment = ast.get_source_segment(self._source, node)
            if segment is not None:
                return segment.strip()
        return ast.unparse(node)

    def visit_Call(self, node: ast.Call) -> typing.Any:
        adapter = None
        if isinstance(node.func, ast.Name):
            adapter = self._session._adapters.get(node.func.id)
        if adapter is None or self._name_is_bound(adapter.name):
            return super().visit_Call(node)

        statement_node = self._statement_by_node.get(id(node), node)
        statement = self._source_segment(statement_node)
        expression = self._source_segment(node)
        lineno = node.lineno
        end_lineno = node.end_lineno
        col_offset = node.col_offset
        end_col_offset = node.end_col_offset
        site = _CallSite(
            script_id=self._session.script_id,
            function_name=adapter.name,
            adapter_id=adapter.adapter_id,
            statement=statement,
            expression=expression,
            lineno=lineno,
            end_lineno=end_lineno or lineno,
            col_offset=col_offset,
            end_col_offset=end_col_offset or col_offset,
            call_site_id=(
                f'{self._session.script_id}:{adapter.adapter_id}:'
                f'{lineno}:{col_offset}'),
        )

        transformed = super().visit_Call(node)
        if not isinstance(transformed, ast.Call):
            return transformed

        hidden_name = self._session._hidden_names[adapter.name]
        if isinstance(transformed.func, ast.Name):
            if transformed.func.id == adapter.name:
                transformed.func.id = hidden_name
                caller = transformed.func
            elif (transformed.func.id == '_apply_'
                    and transformed.args
                    and isinstance(transformed.args[0], ast.Name)
                    and transformed.args[0].id == adapter.name):
                transformed.args[0].id = hidden_name
                caller = transformed.func
            else:  # pragma: no cover - defensive fallback
                return transformed
        else:  # pragma: no cover - defensive fallback
            return transformed

        meta = ast.Tuple(
            elts=[
                ast.Constant(site.script_id),
                ast.Constant(site.function_name),
                ast.Constant(site.adapter_id),
                ast.Constant(site.statement),
                ast.Constant(site.expression),
                ast.Constant(site.lineno),
                ast.Constant(site.end_lineno),
                ast.Constant(site.col_offset),
                ast.Constant(site.end_col_offset),
                ast.Constant(site.call_site_id),
            ],
            ctx=ast.Load())
        evidence_call = ast.Call(
            func=ast.Name(self._session._helper_name, ast.Load()),
            args=[meta, caller, *transformed.args],
            keywords=transformed.keywords)
        copy_locations(evidence_call, transformed)
        ast.fix_missing_locations(evidence_call)
        return evidence_call


def _source_text(source: T_CompileSource) -> str | None:
    if isinstance(source, str):
        return source
    if isinstance(source, (bytes, bytearray)):
        raw = bytes(source)
        try:
            encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
            return raw.decode(encoding)
        except (SyntaxError, UnicodeDecodeError):
            return None
    return None


def _policy_class(
        policy: type[RestrictingNodeTransformer],
) -> type[_EvidenceNodeTransformer]:
    if issubclass(policy, _EvidenceNodeTransformer):
        return policy
    if policy is RestrictingNodeTransformer:
        return _EvidenceNodeTransformer
    return typing.cast(
        type[_EvidenceNodeTransformer],
        type(
            f'Evidence{policy.__name__}',
            (_EvidenceNodeTransformer, policy),
            {}))


_COMPILED_SESSIONS: weakref.WeakKeyDictionary[
    types.CodeType, 'EvidenceSession'] = weakref.WeakKeyDictionary()


class EvidenceCompileResult(CompileResult):
    """A CompileResult which can resolve its evidence session."""

    __slots__ = ()

    @property
    def session(self) -> 'EvidenceSession | None':
        code = self.code
        if code is None:
            return None
        return _COMPILED_SESSIONS.get(code)

    def install_globals(self, globals: dict[str, typing.Any]) -> None:
        """Install hidden adapter names for this compilation."""
        session = self.session
        if session is not None:
            session.install_globals(globals)


@dataclasses.dataclass(frozen=True)
class EvidenceRunResult:
    """The result of :meth:`EvidenceSession.run`."""

    session: 'EvidenceSession'
    compile_result: CompileResult
    globals: dict[str, typing.Any]
    locals: dict[str, typing.Any]
    value: typing.Any
    receipts: tuple[CallReceipt, ...] = ()

    @property
    def code(self) -> types.CodeType | None:
        return self.compile_result.code

    @property
    def errors(self) -> typing.Sequence[str]:
        return self.compile_result.errors

    @property
    def warnings(self) -> typing.Sequence[str]:
        return self.compile_result.warnings

    @property
    def namespace(self) -> dict[str, typing.Any]:
        """Alias for the execution locals."""
        return self.locals

    @property
    def result(self) -> typing.Any:
        """Alias for the eval mode value (None for exec mode)."""
        return self.value

    @property
    def report(self) -> EvidenceReport:
        return self.session.report()


class EvidenceSession:
    """Compile and run one restricted script with an evidence trail.

    The caller registers approved host callables under the names used by the
    restricted source.  Registrations are local to the session, so two teams
    can use the same source-level function name without their receipts being
    confused.
    """

    _token_lock = threading.Lock()
    _next_token = 0

    def __init__(
            self,
            script_id: str,
            *,
            adapters: typing.Mapping[
                str, typing.Callable[..., typing.Any] | FunctionAdapter]
            | None = None,
            recorder: EvidenceRecorder | None = None,
            sink: EvidenceSink | typing.Callable[[CallReceipt], typing.Any]
            | None = None,
            max_delivery_attempts: int = 2):
        if not isinstance(script_id, str) or not script_id:
            raise ValueError('script_id must be a non-empty string')
        if recorder is not None and sink is not None:
            raise ValueError('pass either recorder or sink, not both')
        self.script_id = script_id
        self.recorder = (
            recorder
            if recorder is not None
            else EvidenceRecorder(
                sink=sink,
                max_delivery_attempts=max_delivery_attempts))
        with self._token_lock:
            token = self._next_token
            self.__class__._next_token += 1
        self._token = token
        self._helper_name = f'_evidence_call_{token}'
        self._adapters: dict[str, FunctionAdapter] = {}
        self._adapter_by_id: dict[str, FunctionAdapter] = {}
        self._hidden_names: dict[str, str] = {}
        _register_adapters(self, adapters)

    @property
    def adapters(self) -> dict[str, FunctionAdapter]:
        return dict(self._adapters)

    def register_adapter(
            self,
            name: str,
            function: typing.Callable[..., typing.Any] | FunctionAdapter,
            *,
            adapter_id: str | None = None,
            replace: bool = False) -> FunctionAdapter:
        """Register an approved host function for ``name``.

        ``adapter_id`` identifies the caller-provided adapter in receipts.  It
        defaults to ``<script_id>:<name>``.
        """
        if not isinstance(name, str) or not name.isidentifier():
            raise ValueError('adapter name must be a valid identifier')
        if keyword.iskeyword(name) or name.startswith('_'):
            raise ValueError(
                'adapter name must be usable by restricted source')
        if name in self._adapters and not replace:
            raise ValueError(f'adapter {name!r} is already registered')

        if isinstance(function, FunctionAdapter):
            if function.name != name:
                raise ValueError(
                    'adapter name does not match its registration name')
            adapter = function
        else:
            adapter = FunctionAdapter(
                name=name,
                adapter_id=adapter_id or f'{self.script_id}:{name}',
                function=function)
        if adapter_id is not None and adapter.adapter_id != adapter_id:
            raise ValueError('adapter_id does not match the adapter')
        existing = self._adapter_by_id.get(adapter.adapter_id)
        if existing is not None and existing.name != name:
            raise ValueError(
                f'adapter_id {adapter.adapter_id!r} is already in use')

        old = self._adapters.get(name)
        if old is not None:
            self._adapter_by_id.pop(old.adapter_id, None)
        self._adapters[name] = adapter
        self._adapter_by_id[adapter.adapter_id] = adapter
        self._hidden_names[name] = (
            f'_evidence_adapter_{self._token}_{len(self._hidden_names)}')
        return adapter

    def install_globals(self, globals: dict[str, typing.Any]) -> None:
        """Install the hidden adapter and helper names into ``globals``."""
        globals[self._helper_name] = self._invoke
        for name, adapter in self._adapters.items():
            globals[self._hidden_names[name]] = adapter

    def compile(
            self,
            source: T_CompileSource,
            filename: str | bytes | typing.Any = '<string>',
            mode: typing.Literal['exec', 'eval', 'single'] = 'exec',
            flags: int = 0,
            dont_inherit: bool = False,
            policy: type[RestrictingNodeTransformer] = (
                RestrictingNodeTransformer),
            adapters: typing.Mapping[
                str, typing.Callable[..., typing.Any] | FunctionAdapter]
            | None = None,
    ) -> EvidenceCompileResult:
        """Compile restricted source with call evidence enabled."""
        _register_adapters(self, adapters)
        result = _compile_restricted_mode(
            source,
            filename=filename,
            mode=mode,
            flags=flags,
            dont_inherit=dont_inherit,
            policy=_policy_class(policy),
            _policy_kwargs={
                'session': self,
                'source': _source_text(source),
            })
        if result.code is not None:
            _COMPILED_SESSIONS[result.code] = self
        return EvidenceCompileResult(
            result.code, result.errors, result.warnings, result.used_names)

    def run(
            self,
            source: T_CompileSource,
            globals: dict[str, typing.Any] | None = None,
            locals: dict[str, typing.Any] | None = None,
            filename: str | bytes | typing.Any = '<string>',
            mode: typing.Literal['exec', 'eval', 'single'] = 'exec',
            flags: int = 0,
            dont_inherit: bool = False,
            policy: type[RestrictingNodeTransformer] = (
                RestrictingNodeTransformer),
            adapters: typing.Mapping[
                str, typing.Callable[..., typing.Any] | FunctionAdapter]
            | None = None,
    ) -> EvidenceRunResult:
        """Compile and execute ``source``, recording adapter calls."""
        _register_adapters(self, adapters)
        result = self.compile(
            source,
            filename=filename,
            mode=mode,
            flags=flags,
            dont_inherit=dont_inherit,
            policy=policy)
        if result.errors:
            raise SyntaxError(result.errors)

        global_ns = {} if globals is None else globals
        if '__builtins__' not in global_ns:
            global_ns['__builtins__'] = safe_builtins.copy()
        local_ns = global_ns if locals is None else locals
        self.install_globals(global_ns)

        code = result.code
        if code is None:  # pragma: no cover - result.errors was empty
            raise RuntimeError('compilation produced no code')
        first_sequence = self.recorder._next_sequence
        if mode == 'eval':
            value = eval(code, global_ns, local_ns)
        else:
            exec(code, global_ns, local_ns)
            value = None
        receipts = tuple(
            receipt for receipt in self.report().receipts
            if receipt.sequence >= first_sequence)
        return EvidenceRunResult(
            session=self,
            compile_result=result,
            globals=global_ns,
            locals=local_ns,
            value=value,
            receipts=receipts)

    @property
    def receipts(self) -> tuple[CallReceipt, ...]:
        """Receipts recorded for this session's script."""
        return self.report().receipts

    @property
    def records(self) -> tuple[CallReceipt, ...]:
        """The receipts for this session's script."""
        return self.receipts

    def report(
            self,
            *,
            expected_sequences: typing.Iterable[int] | None = None,
    ) -> EvidenceReport:
        return self.recorder.report(
            self.script_id,
            expected_sequences=expected_sequences)

    def _invoke(
            self,
            meta: tuple[
                str, str, str, str, str, int, int, int, int, str],
            caller: typing.Callable[..., typing.Any],
            /,
            *args: typing.Any,
            **kwargs: typing.Any) -> typing.Any:
        site = _CallSite(
            script_id=meta[0],
            function_name=meta[1],
            adapter_id=meta[2],
            statement=meta[3],
            expression=meta[4],
            lineno=meta[5],
            end_lineno=meta[6],
            col_offset=meta[7],
            end_col_offset=meta[8],
            call_site_id=meta[9])
        return self.recorder.invoke(site, caller, args, kwargs)


def _session_for(
        session: EvidenceSession | None,
        script_id: str | None,
        recorder: EvidenceRecorder | None,
        sink: EvidenceSink | typing.Callable[[CallReceipt], typing.Any]
        | None,
        max_delivery_attempts: int,
) -> EvidenceSession:
    if session is not None:
        if script_id is not None:
            raise TypeError('pass either session or script_id, not both')
        if recorder is not None or sink is not None:
            raise TypeError('recorder/sink belong to the session')
        return session
    if script_id is None:
        raise TypeError('script_id is required without a session')
    return EvidenceSession(
        script_id,
        recorder=recorder,
        sink=sink,
        max_delivery_attempts=max_delivery_attempts)


def _register_adapters(
        session: EvidenceSession,
        adapters: typing.Mapping[
            str, typing.Callable[..., typing.Any] | FunctionAdapter]
        | None) -> None:
    if adapters is None:
        return
    for name, function in adapters.items():
        if name in session._adapters:
            continue
        session.register_adapter(name, function)


def compile_restricted_evidence(
        source: T_CompileSource,
        session: EvidenceSession | None = None,
        *,
        script_id: str | None = None,
        adapters: typing.Mapping[
            str, typing.Callable[..., typing.Any] | FunctionAdapter]
        | None = None,
        recorder: EvidenceRecorder | None = None,
        sink: EvidenceSink | typing.Callable[[CallReceipt], typing.Any]
        | None = None,
        max_delivery_attempts: int = 2,
        filename: str | bytes | typing.Any = '<string>',
        mode: typing.Literal['exec', 'eval', 'single'] = 'exec',
        flags: int = 0,
        dont_inherit: bool = False,
        policy: type[RestrictingNodeTransformer] = (
            RestrictingNodeTransformer),
) -> EvidenceCompileResult:
    """Compile restricted source and prepare it for evidence recording."""
    active_session = _session_for(
        session, script_id, recorder, sink, max_delivery_attempts)
    _register_adapters(active_session, adapters)
    return active_session.compile(
        source,
        filename=filename,
        mode=mode,
        flags=flags,
        dont_inherit=dont_inherit,
        policy=policy)


def run_restricted_evidence(
        source: T_CompileSource,
        session: EvidenceSession | None = None,
        *,
        script_id: str | None = None,
        adapters: typing.Mapping[
            str, typing.Callable[..., typing.Any] | FunctionAdapter]
        | None = None,
        recorder: EvidenceRecorder | None = None,
        sink: EvidenceSink | typing.Callable[[CallReceipt], typing.Any]
        | None = None,
        max_delivery_attempts: int = 2,
        globals: dict[str, typing.Any] | None = None,
        locals: dict[str, typing.Any] | None = None,
        filename: str | bytes | typing.Any = '<string>',
        mode: typing.Literal['exec', 'eval', 'single'] = 'exec',
        flags: int = 0,
        dont_inherit: bool = False,
        policy: type[RestrictingNodeTransformer] = (
            RestrictingNodeTransformer),
) -> EvidenceRunResult:
    """Compile and run restricted source while collecting evidence receipts."""
    active_session = _session_for(
        session, script_id, recorder, sink, max_delivery_attempts)
    _register_adapters(active_session, adapters)
    return active_session.run(
        source,
        globals=globals,
        locals=locals,
        filename=filename,
        mode=mode,
        flags=flags,
        dont_inherit=dont_inherit,
        policy=policy)


run_restricted = run_restricted_evidence
execute_restricted = run_restricted_evidence
compile_restricted_with_evidence = compile_restricted_evidence
