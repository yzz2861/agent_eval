"""Optional byte-level source (provenance) tracking for parsed values.

The tracking infrastructure in this module is opt-in: when no :class:`SourceTracer` is
active, the regular cstruct read path is unchanged and does not pay for any of the bookkeeping
in this module.

The central concepts are:

* :class:`ByteSpan`: a half-open, absolute byte range in the underlying stream, optionally
  narrowed to individual bits for bit fields.
* :class:`SourceNode`: a node in the provenance graph, describing one parsed value, the byte
  spans that evidenced it, the nodes it depends on (e.g. a dynamic array length) and any
  sub-nodes for nested fields, array elements and pointer dereferences.
* :class:`SourceGraph`: the root container of a tracked read, with overlap analysis that
  distinguishes shared evidence (aliasing, unions) from accidental overwrites.
* :class:`SourceTracer`: the active recorder, exposed through a :class:`contextvars.ContextVar`
  and paired with :class:`TracingStream`, the thin stream wrapper that observes raw reads.

Only the Python standard library is used; there is no third-party tracking dependency.
"""

from __future__ import annotations

__all__ = [
    "ByteSpan",
    "NodeKind",
    "OverlapKind",
    "ReadEvent",
    "SourceGraph",
    "SourceNode",
    "SourceTracer",
    "TracingStream",
    "activate",
    "current_tracer",
    "reset_tracer",
    "trace_read",
]

import contextvars
import io
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, BinaryIO, NamedTuple

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from typing_extensions import Self

#: Context variable holding the currently active tracer, if any.
_ACTIVE_TRACER: contextvars.ContextVar[SourceTracer | None] = contextvars.ContextVar(
    "cstruct_source_tracer", default=None
)


class OverlapKind(str, Enum):
    """How two byte spans relate to each other."""

    NONE = "none"
    SHARED_EVIDENCE = "shared_evidence"
    """The same bytes intentionally evidence more than one value (union members, pointer aliases)."""

    OVERWRITE = "overwrite"
    """Bytes were read more than once without a structural reason, suggesting an accidental overwrite."""


class NodeKind(str, Enum):
    """The kind of value a :class:`SourceNode` describes."""

    STRUCT = "struct"
    UNION = "union"
    ARRAY = "array"
    FIELD = "field"
    ELEMENT = "element"
    DEREFERENCE = "dereference"
    VALUE = "value"
    UNKNOWN = "unknown"


class ByteSpan(NamedTuple):
    """A half-open, absolute byte range ``[start, end)`` in the underlying stream.

    For bit fields, ``bit_start`` and ``bit_end`` narrow the span to individual bits, numbered
    globally from the start of the stream (bit ``8 * start + offset_within_byte``). Both are
    ``None`` for ordinary byte-granular values.
    """

    start: int
    end: int
    bit_start: int | None = None
    bit_end: int | None = None

    def __len__(self) -> int:
        return self.end - self.start

    @property
    def is_partial(self) -> bool:
        """Whether this span only covers part of a byte (a bit field)."""
        return self.bit_start is not None

    def overlaps(self, other: ByteSpan) -> bool:
        if self.start >= other.end or other.start >= self.end:
            return False
        if self.bit_start is None or other.bit_start is None:
            return True
        return self.bit_start < other.bit_end and other.bit_start < self.bit_end

    def intersection(self, other: ByteSpan) -> ByteSpan | None:
        if not self.overlaps(other):
            return None
        start, end = max(self.start, other.start), min(self.end, other.end)
        if self.bit_start is None or other.bit_start is None:
            return ByteSpan(start, end)
        bit_start, bit_end = max(self.bit_start, other.bit_start), min(self.bit_end, other.bit_end)
        return ByteSpan(start, end, bit_start, bit_end)


def _span_order(span: ByteSpan) -> tuple[int, int]:
    return span.start, span.end


def merge_spans(spans: Sequence[ByteSpan]) -> list[ByteSpan]:
    """Merge overlapping or adjacent byte spans into a minimal ordered list."""
    bit_spans = [span for span in spans if span.bit_start is not None]
    byte_spans = sorted((span for span in spans if span.bit_start is None), key=_span_order)
    merged = []
    for span in byte_spans:
        if merged and span.start <= merged[-1].end:
            previous = merged[-1]
            merged[-1] = ByteSpan(previous.start, max(previous.end, span.end))
        else:
            merged.append(span)
    return sorted(merged + bit_spans, key=_span_bit_order)


@dataclass
class ReadEvent:
    """A single read of a byte range from the underlying stream.

    The same range can be read more than once. Every read is recorded separately so shared evidence
    (multiple observers of the same bytes) is distinguished from an unexpected overwrite (the same
    bytes observed at different points without a structural reason).

    Attributes:
        span: The byte range that was read.
        order: The global, monotonically increasing order in which the read happened.
        overlap: How this read relates to the overlapping reads observed before it.
        partial: Whether the read returned fewer bytes than requested (a truncated failure).
        consumers: Dotted paths of the nodes this read is attributed to.
    """

    span: ByteSpan
    order: int
    overlap: OverlapKind
    partial: bool = False
    consumers: set[str] = field(default_factory=set)


@dataclass
class SourceNode:
    """A node in the :class:`SourceGraph`, describing the provenance of a single parsed value.

    Attributes:
        path: The dotted path of the value, relative to the root of the parse (e.g. ``header.flags[1].a``).
        kind: The kind of value the node represents.
        type_name: The name of the cstruct type that produced the value.
        spans: The byte ranges that directly contain the bytes of the value.
        children: Nodes for nested values (structure fields, array elements, pointer dereferences, ...).
        depends_on: Paths of other nodes that determined a derived value, such as a dynamic array length or a
            branch condition.
        bit_width: The width in bits of a bit field, or ``None`` for byte-aligned values.
        unresolved: Explicit reason why no exact range can be given, or ``None`` when the node is fully resolved.
        dereferences: Child nodes produced by pointer dereferences.
    """

    path: str
    kind: NodeKind
    type_name: str
    name: str = ""
    spans: list[ByteSpan] = field(default_factory=list)
    children: list[SourceNode] = field(default_factory=list)
    depends_on: list[str] = field(default_factory=list)
    bit_width: int | None = None
    unresolved: str | None = None
    target_address: int | None = None
    partial: bool = False
    dereferences: list[SourceNode] = field(default_factory=list)

    def leaf_spans(self) -> list[ByteSpan]:
        """Return the spans of this node and all of its (nested) children."""
        result = list(self.spans)
        for child in [*self.children, *self.dereferences]:
            result.extend(child.leaf_spans())
        return result

    def walk(self) -> Iterator[SourceNode]:
        """Yield this node and all of its descendants in declaration order."""
        yield self
        for child in self.children:
            yield from child.walk()
        for deref in self.dereferences:
            yield from deref.walk()

    def find(self, path: str) -> SourceNode | None:
        """Find a descendant node by its dotted path."""
        for node in self.walk():
            if node.path == path:
                return node
        return None

    @property
    def resolved(self) -> bool:
        """Whether the node and all of its descendants have an exact, non-fabricated range."""
        return self.unresolved is None and all(child.resolved for child in self.walk() if child is not self)

    def evidence(self) -> list[ByteSpan]:
        """Return the merged, ordered list of byte ranges needed to reconstruct the proven value."""
        return merge_spans(self.leaf_spans())

    def to_dict(self) -> dict[str, Any]:
        """Return a plain ``dict`` representation of the node, suitable for serialization."""
        result: dict[str, Any] = {
            "path": self.path,
            "kind": self.kind.value,
            "type": self.type_name,
            "spans": [span._asdict() for span in merge_spans(self.spans)],
        }
        if self.bit_width is not None:
            result["bit_width"] = self.bit_width
        if self.depends_on:
            result["depends_on"] = list(self.depends_on)
        if self.unresolved is not None:
            result["unresolved"] = self.unresolved
        if self.target_address is not None:
            result["target_address"] = self.target_address
        if self.partial:
            result["partial"] = True
        if self.children:
            result["fields"] = [child.to_dict() for child in self.children]
        if self.dereferences:
            result["dereferences"] = [deref.to_dict() for deref in self.dereferences]
        return result


class SourceGraph:
    """The provenance graph produced by a single traced :class:`~dissect.cstruct.cstruct.cstruct` read.

    The graph is a tree of :class:`SourceNode` objects that mirrors the parsed value (structures, arrays,
    pointers), augmented with every raw :class:`ReadEvent` observed on the stream. It can be queried for the
    exact bytes backing any field, rebuilt from those bytes, or inspected for overlapping evidence.
    """

    def __init__(self, root_type: str):
        self.root = SourceNode(path="$", kind=NodeKind.STRUCT, type_name=root_type)
        self.events: list[ReadEvent] = []

    def find(self, path: str) -> SourceNode | None:
        """Find a node by its dotted path, e.g. ``header.count`` or ``items[2].value``."""
        return self.root.find(path)

    def record_read(
        self, span: ByteSpan, *, partial: bool = False, current_consumers: set[str] | None = None
    ) -> ReadEvent:
        """Record a raw stream read and classify how it relates to the reads already observed."""
        kind = OverlapKind.NONE
        related: set[str] = set()
        current_consumers = current_consumers or set()

        for previous in self.events:
            if not previous.span.overlaps(span):
                continue

            related.update(previous.consumers)
            structural = self._is_structural_alias(previous.consumers | current_consumers)
            if kind is OverlapKind.NONE:
                if previous.partial or partial or structural:
                    kind = OverlapKind.SHARED_EVIDENCE
                else:
                    kind = OverlapKind.OVERWRITE
            elif kind is OverlapKind.OVERWRITE and (previous.partial or partial or structural):
                kind = OverlapKind.SHARED_EVIDENCE

        event = ReadEvent(span=span, order=len(self.events), overlap=kind, partial=partial)
        if related:
            event.consumers.update(related)
        self.events.append(event)
        return event

    def _is_structural_alias(self, consumers: set[str]) -> bool:
        """Whether overlapping consumers share bytes for a structural reason (union, pointer alias)."""
        for path in consumers:
            if NodeKind.DEREFERENCE.value in path or ".dereference" in path:
                return True
            node = self.find(path)
            if node is None:
                continue
            if node.kind in (NodeKind.DEREFERENCE, NodeKind.UNION):
                return True
            if any(part.kind is NodeKind.DEREFERENCE for part in node.walk()):
                return True
        return False

    def overlaps(self) -> list[dict[str, Any]]:
        """Return all overlapping read events, distinguishing shared evidence from unexpected overwrites."""
        return [
            {
                "span": event.span._asdict(),
                "order": event.order,
                "overlap": event.overlap.value,
                "partial": event.partial,
                "consumers": sorted(event.consumers),
            }
            for event in self.events
            if event.overlap is not OverlapKind.NONE
        ]

    def _all_nodes(self) -> Iterator[SourceNode]:
        yield from self.root.walk()

    def unresolved_nodes(self) -> list[SourceNode]:
        """Return the nodes that explicitly declare they cannot be located precisely in the stream."""
        return [node for node in self._all_nodes() if node.unresolved is not None]

    def proven_fields(self) -> list[SourceNode]:
        """Return the leaf nodes whose value is fully backed by concrete stream evidence."""
        return [
            node
            for node in self._all_nodes()
            if not node.children and node.resolved and node.evidence() and not node.partial
        ]

    def reconstruct(self, stream: BinaryIO) -> dict[str, bytes]:
        """Re-read the proven bytes of every proven leaf field from the stream, keyed by node path.

        Only fields with exact, complete spans are included. Unresolved or partially read fields are omitted
        rather than guessed, so the mapping can never contain fabricated ranges.
        """
        result: dict[str, bytes] = {}
        for node in self.proven_fields():
            span = node.evidence()[0]
            stream.seek(span.start)
            result[node.path] = stream.read(span.end - span.start)
        return result

    def to_dict(self) -> dict[str, Any]:
        """Return a plain ``dict`` representation of the whole graph, suitable for serialization."""
        return {
            "root": self.root.to_dict(),
            "reads": [
                {
                    "span": event.span._asdict(),
                    "order": event.order,
                    "overlap": event.overlap.value,
                    "partial": event.partial,
                    "consumers": sorted(event.consumers),
                }
                for event in self.events
            ],
        }


class SourceTracer:
    """Stateful recorder that builds a :class:`SourceGraph` while types read from a stream.

    A tracer maintains a stack of :class:`SourceNode` scopes. Types open a scope around every read and
    close it afterwards, attaching the byte ranges that were actually read. Nested types, arrays,
    bit fields and pointer dereferences each get their own node, so the resulting graph mirrors the
    parsed value structure.

    Use :class:`TracingStream` to capture raw reads; the tracer itself never touches the stream.
    """

    def __init__(self, root_type_name: str = "root"):
        self.graph = SourceGraph(root_type_name)
        self._stack: list[SourceNode] = [self.graph.root]
        self._depth_counters: list[dict[str, int]] = [{}]
        self._path_index: dict[str, SourceNode] = {root_type_name: self.graph.root}
        self._active_consumers: list[str] = [root_type_name]
        self._element_attributor = None
        self._deref_counters = {}

    @property
    def current(self) -> SourceNode:
        return self._stack[-1]

    @property
    def current_path(self) -> str:
        return self.current.path

    def _child_name(self, name: str) -> str:
        counters = self._depth_counters[-1]
        index = counters.get(name, 0)
        counters[name] = index + 1
        if index:
            return f"{name}[{index}]"
        return name

    def begin_on(self, parent: SourceNode, name: str, kind: NodeKind, type_name: str) -> SourceNode:
        """Open a node under an explicit parent (used for pointer dereferences)."""
        child_name = self._child_name_on(parent, name)
        node = SourceNode(
            path=f"{parent.path}.{child_name}" if parent.path else child_name,
            name=child_name,
            kind=kind,
            type_name=type_name,
        )
        parent.dereferences.append(node)
        self._stack.append(node)
        self._depth_counters.append({})
        self._path_index[node.path] = node
        return node

    def _child_name_on(self, parent: SourceNode, name: str) -> str:
        counters = self._deref_counters.setdefault(id(parent), {})
        index = counters.get(name, 0)
        counters[name] = index + 1
        return f"{name}[{index}]" if index else name

    def begin(self, name: str, kind: NodeKind, type_name: str) -> SourceNode:
        child_name = self._child_name(name)
        parent = self.current
        node = SourceNode(
            path=f"{parent.path}.{child_name}" if parent.path else child_name,
            name=child_name,
            kind=kind,
            type_name=type_name,
        )
        parent.children.append(node)
        self._stack.append(node)
        self._depth_counters.append({})
        self._path_index[node.path] = node
        return node

    def end(self) -> SourceNode:
        """Close the current node, returning it."""
        self._depth_counters.pop()
        return self._stack.pop()

    @contextmanager
    def scope(self, name: str, kind: NodeKind, type_name: str) -> Iterator[SourceNode]:
        """Context manager wrapping :meth:`begin` and :meth:`end`."""
        node = self.begin(name, kind, type_name)
        try:
            yield node
        finally:
            self.end()

    def record(self, span: ByteSpan, *, partial: bool = False) -> ReadEvent:
        """Attribute a raw byte range to the currently open node.

        Every distinct read gets its own ReadEvent, even when it hits the same range again.
        """
        event = self.graph.record_read(span, partial=partial, current_consumers={self.current_path})
        event.consumers.add(self.current_path)
        node = self.current
        node.spans.append(span)
        if partial:
            node.partial = True
        return event

    def record_bits(self, span: ByteSpan, bit_start: int, bit_end: int) -> ReadEvent:
        """Record a bit-level slice of a byte range for a bit field."""
        precise = ByteSpan(span.start, span.end, bit_start, bit_end)
        event = self.graph.record_read(precise, current_consumers={self.current_path})
        event.consumers.add(self.current_path)
        self.current.spans.append(precise)
        return event

    def mark_unresolved(self, reason: str) -> None:
        """Explicitly declare that the current node has no provable byte range."""
        self.current.unresolved = reason

    def depend_on(self, path: str) -> None:
        """Link the current node to the node that decided its length or branch."""
        current = self.current
        if path not in current.depends_on:
            current.depends_on.append(path)


class TracingStream:
    """Stream wrapper that records every read against a SourceTracer.

    Reads are attributed to whichever node is currently open on the tracer. Seek and tell are
    delegated so that pointer dereferences and aligned fields keep their absolute offsets.
    """

    def __init__(self, stream: BinaryIO, tracer: SourceTracer, base_offset: int = 0):
        self._stream = stream
        self._tracer = tracer
        self._base_offset = base_offset

    @property
    def tracer(self) -> SourceTracer:
        return self._tracer

    def tell(self) -> int:
        return self._stream.tell()

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self._stream.seek(offset, whence)

    def seekable(self) -> bool:
        try:
            return self._stream.seekable()
        except Exception:
            return False

    def read(self, size: int = -1) -> bytes:
        start = self._stream.tell()
        data = self._stream.read(size)
        end = self._stream.tell()
        if end > start:
            requested = None if size in (-1, None) else size
            partial = requested is not None and len(data) < requested
            span = ByteSpan(self._base_offset + start, self._base_offset + end)
            attributor = self._tracer._element_attributor
            if attributor is not None:
                attributor.attribute(span)
            self._tracer.record(span, partial=partial)
        return data

    def __getattr__(self, attr: str) -> Any:
        return getattr(self._stream, attr)


def current_tracer(stream: object) -> SourceTracer | None:
    """Return the SourceTracer attached to a tracing stream, or None for an ordinary stream."""
    return getattr(stream, "tracer", None)


def expression_identifiers(expression: object) -> list[str]:
    """Return the identifiers referenced by an Expression, so derived lengths can cite their decision fields."""
    from dissect.cstruct.lexer import IDENTIFIER_TYPES

    return [token.value for token in expression._tokens if token.type in IDENTIFIER_TYPES]


def field_traceable(type_: object) -> bool:
    """Whether a type promises provable byte evidence. Custom types opt out explicitly."""
    return getattr(type_, "__traceable__", True) is not False


def activate(tracer: SourceTracer) -> contextvars.Token:
    """Install a tracer on the current context and return a reset token (use with reset_tracer)."""
    return _ACTIVE_TRACER.set(tracer)


def reset_tracer(token: contextvars.Token) -> None:
    """Restore the tracer state of the current context to before activate()."""
    _ACTIVE_TRACER.reset(token)


class trace_read:
    """Context manager that enables provenance tracking for the enclosed parse.

    The parsed stream must support tell (and, for pointer dereferences, seek) so that reads can be attributed
    to absolute byte ranges. After the block, graph holds the resulting SourceGraph.

    Example:
        with trace_read("Header") as traced:
            header = cs.Header(stream)
        graph = traced.graph
        graph.find("$.magic").evidence()
        graph.reconstruct(stream)
    """

    def __init__(self, root_type_name: str = "root"):
        self.tracer = SourceTracer(root_type_name)
        self._token = None

    def __enter__(self) -> Self:
        self._token = activate(self.tracer)
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        reset_tracer(self._token)
        return False

    @property
    def graph(self) -> SourceGraph:
        return self.tracer.graph


def bit_span(
    byte_start: int,
    byte_end: int,
    consumed_low: int,
    field_bits: int,
    total_bits: int,
    little_endian: bool,
) -> ByteSpan:
    """Compute the global bit range of a bit field inside its backing bytes."""
    if little_endian:
        bit_start = byte_start * 8 + consumed_low
    else:
        bit_start = byte_start * 8 + (total_bits - consumed_low - field_bits)
    return ByteSpan(byte_start, byte_end, bit_start, bit_start + field_bits)


def attach_dependencies(tracer: SourceTracer, identifiers: list[str], path_resolver: object) -> None:
    """Link the current node to the fields named by a derived length or branch expression."""
    for identifier in identifiers:
        head = identifier.split(".")[0]
        target = path_resolver(head)
        if target is not None:
            tracer.depend_on(target)


def declare_unresolved(tracer: SourceTracer, type_name: str) -> None:
    """Explicitly mark the current node as having no provable range for a non-traceable custom type."""
    tracer.mark_unresolved("type " + type_name + " does not declare provable byte evidence (__traceable__ = False)")


class _ElementAttributor:
    """Temporarily splits a bulk array read into per-element spans for byte aligned array types."""

    def __init__(self, tracer: SourceTracer, element_name: str, element_size: int):
        self.tracer = tracer
        self.element_name = element_name
        self.element_size = element_size

    def __enter__(self) -> Self:
        self.tracer._element_attributor = self
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        self.tracer._element_attributor = None
        return False

    def attribute(self, span: ByteSpan) -> None:
        for start in range(span.start, span.end, self.element_size):
            end = min(start + self.element_size, span.end)
            piece = ByteSpan(start, end)
            node = self.tracer.begin(self.element_name, NodeKind.ELEMENT, self.element_name)
            event = self.tracer.graph.record_read(piece)
            event.consumers.add(node.path)
            node.spans.append(piece)
            self.tracer.end()


def _span_bit_order(span: ByteSpan) -> tuple[int, int, int]:
    return span.start, span.end, span.bit_start or 0
