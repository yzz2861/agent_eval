from __future__ import annotations

import logging
from dataclasses import dataclass, field, replace
from enum import Enum
from numbers import Number
from typing import TYPE_CHECKING, Any, Iterable, Literal, cast

from .exceptions import FormParserError, NestedMultipartError, ScopeError
from .multipart import DEFAULT_MAX_HEADER_COUNT, DEFAULT_MAX_HEADER_SIZE, END, MultipartParser, parse_options_header

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping
    from typing import Protocol

    class SupportsRead(Protocol):
        def read(self, __n: int) -> bytes: ...


RAW_TRANSFER_ENCODINGS = frozenset({b"7bit", b"8bit", b"binary"})
KNOWN_TRANSFER_ENCODINGS = RAW_TRANSFER_ENCODINGS | {b"base64", b"quoted-printable"}

_MissingHandler = Literal["reject", "error", "allow"]
_UnknownEncodingHandler = Literal["reject", "opaque", "error"]


def _normalize_media_type(value: str | bytes | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("latin-1")
    return value.split(";", 1)[0].strip().lower() or None


def _normalize_media_types(value: Iterable[str | bytes] | str | bytes | None) -> frozenset[str] | None:
    if value is None:
        return None
    if isinstance(value, (str, bytes)):
        value = (value,)
    normalized = {_normalize_media_type(item) for item in value}
    normalized.discard(None)
    return frozenset(cast("set[str]", normalized))


def _normalize_bytes(value: str | bytes | None) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value.encode("latin-1")
    return value


def _intersect_optional(left: frozenset[str] | None, right: frozenset[str] | None) -> frozenset[str] | None:
    if left is None:
        return right
    if right is None:
        return left
    return left & right


def _min_optional(left: int | None, right: int | None) -> int | None:
    if left is None:
        return right
    if right is None:
        return left
    return min(left, right)


class PartPath(tuple[int, ...]):
    """A structural path to a part.

    The root package has the empty path.  A top-level part has path ``(0,)``,
    and its first child has path ``(0, 0)``.  Paths, not names, identify parts:
    two siblings may both be named ``attachment`` without becoming ambiguous.

    ``PartPath`` is a :class:`tuple` subclass, so ``(0, 0) == PartPath((0, 0))``
    and the usual tuple indexing and hashing apply.  The string form is
    slash-separated, with ``/`` representing the root.
    """

    def __new__(cls, indices: Iterable[int] | str | int | None = ()) -> PartPath:
        if isinstance(indices, PartPath):
            values = tuple(indices)
        elif isinstance(indices, str):
            text = indices.strip()
            if text in ("", "/", "."):
                values = ()
            else:
                values = tuple(int(part) for part in text.replace(".", "/").split("/") if part)
        elif isinstance(indices, int):
            values = (indices,)
        elif indices is None:
            values = ()
        else:
            values = tuple(int(item) for item in indices)

        if any(item < 0 for item in values):
            raise ScopeError("Part path indices must be non-negative")
        return super().__new__(cls, values)

    @property
    def indices(self) -> tuple[int, ...]:
        return tuple(self)

    @property
    def parent(self) -> PartPath:
        return PartPath(self[:-1])

    @property
    def depth(self) -> int:
        return len(self)

    @property
    def is_root(self) -> bool:
        return not self

    def child(self, index: int) -> PartPath:
        if index < 0:
            raise ScopeError("Part path indices must be non-negative")
        return PartPath((*self, index))

    @classmethod
    def parse(cls, value: PartPath | Iterable[int] | str | int | None) -> PartPath:
        return cls(value)

    def __str__(self) -> str:
        return "/".join(str(item) for item in self) if self else "/"

    def __repr__(self) -> str:
        return f"PartPath({tuple(self)!r})"


class ReceiveDecision(str, Enum):
    """The decision recorded for one part."""

    ACCEPTED = "accepted"
    REJECTED = "rejected"
    UNDECLARED = "undeclared"
    PENDING = "pending"


@dataclass(frozen=True)
class ApprovalScope:
    """An approval scope attached to a structural path.

    A scope describes the part at ``path``.  The scope's own identity fields
    (``name``, ``content_type`` and ``correlation_id``) must match that part if
    present.  Child restrictions only take effect when this is the scope for
    the part itself; a parent scope never authorizes or fills in a child.

    Args:
        path: Structural path of the part being approved.  The root package is
            ``PartPath(())``.
        name: Optional local form-data name of the part.
        content_type: Optional media type of the part.
        correlation_id: Optional local correlation identifier.  It is scoped to
            the part's containing package; an identical identifier in another
            package is a different identifier.
        allowed_types: Media types allowed for direct children of this part, if
            it is a package.  ``None`` means no extra restriction.
        allowed_nested_types: Media types among its direct children that may be
            parsed recursively as packages.  ``None`` means no extra
            restriction; the parent's effective set still applies.
        max_depth: Maximum allowed length of a descendant structural path.
    """

    path: PartPath | tuple[int, ...] | str | int | None = PartPath()
    name: bytes | str | None = None
    content_type: str | bytes | None = None
    correlation_id: bytes | str | None = None
    allowed_types: frozenset[str] | Iterable[str | bytes] | str | bytes | None = None
    allowed_nested_types: frozenset[str] | Iterable[str | bytes] | str | bytes | None = None
    max_depth: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", PartPath(self.path))
        object.__setattr__(self, "name", _normalize_bytes(self.name))
        object.__setattr__(self, "content_type", _normalize_media_type(self.content_type))
        object.__setattr__(self, "correlation_id", _normalize_bytes(self.correlation_id))
        object.__setattr__(self, "allowed_types", _normalize_media_types(self.allowed_types))
        object.__setattr__(self, "allowed_nested_types", _normalize_media_types(self.allowed_nested_types))
        if self.max_depth is not None and (not isinstance(self.max_depth, int) or self.max_depth < 0):
            raise ScopeError("max_depth must be a non-negative integer or None")

    @property
    def _path(self) -> PartPath:
        return cast("PartPath", self.path)

    @property
    def allowed_type_set(self) -> frozenset[str] | None:
        return cast("frozenset[str] | None", self.allowed_types)

    @property
    def allowed_nested_type_set(self) -> frozenset[str] | None:
        return cast("frozenset[str] | None", self.allowed_nested_types)

    @property
    def scope_path(self) -> PartPath:
        return self._path

    @property
    def package_path(self) -> PartPath:
        """The package in which this declaration appears."""
        return self._path.parent

    @property
    def local_id(self) -> bytes | None:
        return cast("bytes | None", self.correlation_id)

    @property
    def local_correlation_id(self) -> bytes | None:
        return cast("bytes | None", self.correlation_id)

    def matches(self, name: bytes | None, media_type: str | None, correlation_id: bytes | None) -> bool:
        if self.name is not None and self.name != name:
            return False
        if self.content_type is not None and self.content_type != media_type:
            return False
        if self.correlation_id is not None and self.correlation_id != correlation_id:
            return False
        return True

    def has_identity(self) -> bool:
        return self.name is not None or self.content_type is not None or self.correlation_id is not None


ScopeDeclaration = ApprovalScope
Declaration = ApprovalScope
PartDeclaration = ApprovalScope
NestedScope = ApprovalScope
ReceiveScope = ApprovalScope


@dataclass(frozen=True)
class ScopeMatch:
    """Result of looking up a scope for a concrete part."""

    scope: ApprovalScope | None
    declared_at: PartPath | None
    same_path: bool
    own_package: bool
    identity_matches: bool
    ambiguous: bool = False


@dataclass(frozen=True)
class ApprovalPolicy:
    """Policy for the opt-in nested receiving mode.

    Args:
        scopes: Approval scopes keyed by structural path.
        allowed_types: Ceiling for direct-child media types at the root.
        allowed_nested_types: Ceiling for media types that may be recursively
            parsed as packages.  ``None`` leaves the choice to the root scope;
            if neither supplies a set, nesting is disabled.
        require_declaration: When true (the default), a part is only accepted
            when a scope exists at exactly its own path.  Approving a parent
            package never satisfies this test for a child.  Set it to false
            for receipt-only inspection.
        missing_child_header: What to do when a part has no
            ``Content-Disposition`` header or no ``name`` parameter:
            ``"reject"`` records a rejected receipt, ``"error"`` raises, and
            ``"allow"`` records the part with an ``None`` name.
        unknown_encoding: What to do with an unrecognised
            ``Content-Transfer-Encoding``: ``"reject"`` records a rejected
            receipt, ``"opaque"`` accepts it as raw bytes, and ``"error"``
            raises.
        correlation_id_header: Header that carries a package-local correlation
            identifier.  Local identifiers are compared inside the package
            where they appear, never globally by name alone.
        max_depth: Maximum structural path depth for nested packages.
    """

    scopes: ApprovalScope | tuple[ApprovalScope, ...] | Iterable[ApprovalScope] = ()
    allowed_types: frozenset[str] | Iterable[str | bytes] | str | bytes | None = None
    allowed_nested_types: frozenset[str] | Iterable[str | bytes] | str | bytes | None = None
    require_declaration: bool = True
    missing_child_header: _MissingHandler = "reject"
    unknown_encoding: _UnknownEncodingHandler = "reject"
    correlation_id_header: bytes | str = b"x-correlation-id"
    max_depth: int | None = 8

    def __post_init__(self) -> None:
        scopes: tuple[ApprovalScope, ...]
        if isinstance(self.scopes, ApprovalScope):
            scopes = (self.scopes,)
        else:
            scopes = tuple(self.scopes)
        object.__setattr__(self, "scopes", scopes)
        object.__setattr__(self, "allowed_types", _normalize_media_types(self.allowed_types))
        object.__setattr__(self, "allowed_nested_types", _normalize_media_types(self.allowed_nested_types))
        correlation_header = _normalize_bytes(self.correlation_id_header)
        if correlation_header is not None:
            correlation_header = correlation_header.strip().lower()
        object.__setattr__(self, "correlation_id_header", correlation_header)

        if self.missing_child_header not in ("reject", "error", "allow"):
            raise ScopeError("missing_child_header must be 'reject', 'error', or 'allow'")
        if self.unknown_encoding not in ("reject", "opaque", "error"):
            raise ScopeError("unknown_encoding must be 'reject', 'opaque', or 'error'")
        if self.max_depth is not None and (not isinstance(self.max_depth, int) or self.max_depth < 0):
            raise ScopeError("max_depth must be a non-negative integer or None")

        seen: set[PartPath] = set()
        for scope in scopes:
            if not isinstance(scope, ApprovalScope):
                raise ScopeError(f"Expected an ApprovalScope, got {type(scope).__name__}")
            if scope._path in seen:
                raise ScopeError(f"Duplicate approval scope for path {scope._path}")
            seen.add(scope._path)

    @property
    def scope_list(self) -> tuple[ApprovalScope, ...]:
        return cast("tuple[ApprovalScope, ...]", self.scopes)

    @property
    def allowed_type_set(self) -> frozenset[str] | None:
        return cast("frozenset[str] | None", self.allowed_types)

    @property
    def allowed_nested_type_set(self) -> frozenset[str] | None:
        return cast("frozenset[str] | None", self.allowed_nested_types)

    @property
    def correlation_header(self) -> bytes | None:
        return cast("bytes | None", self.correlation_id_header)

    def scope_at(self, path: PartPath | tuple[int, ...] | str | int | None) -> ApprovalScope | None:
        wanted = PartPath(path)
        for scope in self.scope_list:
            if scope._path == wanted:
                return scope
        return None

    def lookup(
        self, path: PartPath, name: bytes | None, media_type: str | None, correlation_id: bytes | None
    ) -> ScopeMatch:
        exact = self.scope_at(path)
        if exact is not None:
            return ScopeMatch(
                scope=exact,
                declared_at=path,
                same_path=True,
                own_package=True,
                identity_matches=exact.matches(name, media_type, correlation_id),
            )

        # Only a scope at the same structural depth can describe this part.  A
        # scope attached to an ancestor package is not a declaration for one of
        # its children, even if the names happen to coincide.
        matches = [
            scope
            for scope in self.scope_list
            if scope._path.depth == path.depth
            and scope._path != path
            and scope.has_identity()
            and scope.matches(name, media_type, correlation_id)
        ]
        if not matches:
            return ScopeMatch(None, None, False, False, False)

        # Prefer a declaration in the same package, then one in a sibling
        # package, then any declaration at the same structural depth.
        same_package = [scope for scope in matches if scope._path.parent == path.parent]
        sibling_package = [
            scope
            for scope in matches
            if scope._path.parent != path.parent and scope._path.parent.parent == path.parent.parent
        ]
        any_depth = [scope for scope in matches if scope._path.depth == path.depth]

        for candidates in (same_package, sibling_package, any_depth, matches):
            if candidates:
                found = sorted(candidates, key=lambda scope: scope._path)[0]
                return ScopeMatch(
                    scope=found,
                    declared_at=found._path,
                    same_path=False,
                    own_package=found._path.parent == path.parent,
                    identity_matches=True,
                    ambiguous=len(candidates) > 1,
                )
        return ScopeMatch(None, None, False, False, False)  # pragma: no cover


def _text(value: bytes | None) -> str | None:
    return value.decode("latin-1") if value is not None else None


@dataclass(frozen=True)
class PartReceipt:
    """A completed (or explicitly pending) decision for one part."""

    path: PartPath
    name: bytes | None
    file_name: bytes | None
    content_type: str | None
    media_type: str | None
    content_transfer_encoding: bytes
    correlation_id: bytes | None
    size: int
    depth: int
    is_package: bool
    complete: bool
    decision: ReceiveDecision
    reason: str | None = None
    reasons: tuple[str, ...] = ()
    declared_at: PartPath | None = None
    declared_in_own_package: bool = False
    declared_for_this_part: bool = False
    declaration: ApprovalScope | None = None
    effective_types: frozenset[str] | None = None
    effective_nested_types: frozenset[str] | None = None
    effective_max_depth: int | None = None
    children: tuple[PartReceipt, ...] = ()

    @property
    def field_name(self) -> bytes | None:
        """Alias for :attr:`name`."""
        return self.name

    @property
    def filename(self) -> bytes | None:
        """Alias for :attr:`file_name`."""
        return self.file_name

    @property
    def is_file(self) -> bool:
        return self.file_name is not None

    @property
    def path_string(self) -> str:
        return str(self.path)

    @property
    def package_path(self) -> PartPath:
        """Structural path of the package that actually contains this part."""
        return self.path.parent

    @property
    def declaration_package(self) -> PartPath | None:
        """Structural path of the package where the matching declaration lives."""
        return self.declared_at.parent if self.declared_at is not None else None

    @property
    def declaration_scope(self) -> PartPath | None:
        """Alias for :attr:`declared_at`."""
        return self.declared_at

    @property
    def belongs_to(self) -> PartPath:
        """Where the part belongs according to the declaration lookup."""
        return self.declared_at if self.declared_at is not None else self.path

    @property
    def accepted(self) -> bool:
        return self.decision is ReceiveDecision.ACCEPTED

    @property
    def rejected(self) -> bool:
        return self.decision is ReceiveDecision.REJECTED

    @property
    def undeclared(self) -> bool:
        return self.decision is ReceiveDecision.UNDECLARED

    @property
    def pending(self) -> bool:
        return self.decision is ReceiveDecision.PENDING

    @property
    def local_id(self) -> bytes | None:
        return self.correlation_id

    @property
    def local_correlation_id(self) -> bytes | None:
        return self.correlation_id

    @property
    def correlation_scope(self) -> PartPath:
        """Package in which :attr:`correlation_id` is local."""
        return self.package_path

    @property
    def has_rejected_children(self) -> bool:
        return any(child.decision is ReceiveDecision.REJECTED for child in self.children)

    def walk(self) -> Iterator[PartReceipt]:
        yield self
        for child in self.children:
            yield from child.walk()

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "package_path": str(self.package_path),
            "name": _text(self.name),
            "file_name": _text(self.file_name),
            "content_type": self.content_type,
            "media_type": self.media_type,
            "content_transfer_encoding": _text(self.content_transfer_encoding),
            "correlation_id": _text(self.correlation_id),
            "correlation_scope": str(self.package_path),
            "size": self.size,
            "depth": self.depth,
            "is_package": self.is_package,
            "complete": self.complete,
            "decision": self.decision.value,
            "reason": self.reason,
            "reasons": list(self.reasons),
            "declared_at": str(self.declared_at) if self.declared_at is not None else None,
            "declaration": str(self.declaration.scope_path) if self.declaration is not None else None,
            "declared_in_own_package": self.declared_in_own_package,
            "declared_for_this_part": self.declared_for_this_part,
            "belongs_to": str(self.belongs_to),
            "effective_types": sorted(self.effective_types) if self.effective_types is not None else None,
            "effective_nested_types": (
                sorted(self.effective_nested_types) if self.effective_nested_types is not None else None
            ),
            "effective_max_depth": self.effective_max_depth,
            "children": [child.to_dict() for child in self.children],
        }

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(path={self.path!r}, name={self.name!r}, "
            f"decision={self.decision.value!r}, declared_at={self.declared_at!r})"
        )


@dataclass(frozen=True)
class NestedReceipt:
    """The final receipt for a nested upload."""

    roots: tuple[PartReceipt, ...] = ()
    receipts: tuple[PartReceipt, ...] = ()
    complete: bool = False

    def __iter__(self) -> Iterator[PartReceipt]:
        return iter(self.receipts)

    def __len__(self) -> int:
        return len(self.receipts)

    def __getitem__(self, key: int | str | PartPath | tuple[int, ...]) -> PartReceipt:
        if isinstance(key, int):
            return self.receipts[key]
        return self.by_path[PartPath(key)]

    @property
    def by_path(self) -> dict[PartPath, PartReceipt]:
        return {receipt.path: receipt for receipt in self.receipts}

    def get(self, path: PartPath | tuple[int, ...] | str | int, default: Any = None) -> Any:
        return self.by_path.get(PartPath(path), default)

    @property
    def accepted(self) -> tuple[PartReceipt, ...]:
        return tuple(receipt for receipt in self.receipts if receipt.decision is ReceiveDecision.ACCEPTED)

    @property
    def rejected(self) -> tuple[PartReceipt, ...]:
        return tuple(receipt for receipt in self.receipts if receipt.decision is ReceiveDecision.REJECTED)

    @property
    def undeclared(self) -> tuple[PartReceipt, ...]:
        return tuple(receipt for receipt in self.receipts if receipt.decision is ReceiveDecision.UNDECLARED)

    @property
    def pending(self) -> tuple[PartReceipt, ...]:
        return tuple(receipt for receipt in self.receipts if receipt.decision is ReceiveDecision.PENDING)

    @property
    def packages(self) -> tuple[PartReceipt, ...]:
        return tuple(receipt for receipt in self.receipts if receipt.is_package)

    @property
    def leaves(self) -> tuple[PartReceipt, ...]:
        return tuple(receipt for receipt in self.receipts if not receipt.is_package)

    def walk(self) -> Iterator[PartReceipt]:
        for root in self.roots:
            yield from root.walk()

    def to_dict(self) -> dict[str, Any]:
        return {
            "complete": self.complete,
            "roots": [receipt.to_dict() for receipt in self.roots],
            "receipts": [receipt.to_dict() for receipt in self.receipts],
        }

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(complete={self.complete!r}, receipts={self.receipts!r})"


Receipt = NestedReceipt
ReceiveReceipt = NestedReceipt
ReceivePolicy = ApprovalPolicy


@dataclass
class _OpenPart:
    index: int
    path: PartPath
    headers: dict[bytes, bytes] = field(default_factory=dict)
    name: bytes | None = None
    file_name: bytes | None = None
    content_type: str | None = None
    media_type: str | None = None
    boundary: bytes | None = None
    content_transfer_encoding: bytes = b"7bit"
    correlation_id: bytes | None = None
    size: int = 0
    is_package: bool = False
    child: _Level | None = None
    children: tuple[PartReceipt, ...] = ()
    declaration: ApprovalScope | None = None
    declared_at: PartPath | None = None
    declared_in_own_package: bool = False
    declared_for_this_part: bool = False
    rejected: bool = False
    reasons: list[str] = field(default_factory=list)
    effective_types: frozenset[str] | None = None
    effective_nested_types: frozenset[str] | None = None
    effective_max_depth: int | None = None


class _Level:
    def __init__(
        self,
        owner: NestedMultipartParser,
        package_path: PartPath,
        boundary: bytes | str,
        *,
        depth: int,
        effective_types: frozenset[str] | None,
        effective_nested_types: frozenset[str] | None,
        max_depth: int | None,
    ) -> None:
        self.owner = owner
        self.package_path = package_path
        self.depth = depth
        self.effective_types = effective_types
        self.effective_nested_types = effective_nested_types
        self.max_depth = max_depth
        self.parts: list[PartReceipt] = []
        self.next_index = 0
        self.current: _OpenPart | None = None
        self.complete = False
        self._finalized = False
        self._header_name: list[bytes] = []
        self._header_value: list[bytes] = []

        self.parser = MultipartParser(
            boundary,
            callbacks={
                "on_part_begin": self._part_begin,
                "on_part_data": self._part_data,
                "on_part_end": self._part_end,
                "on_header_begin": self._header_begin,
                "on_header_field": self._header_field,
                "on_header_value": self._header_value_cb,
                "on_header_end": self._header_end,
                "on_headers_finished": self._headers_finished,
                "on_end": self._end_of_package,
            },
            max_size=float("inf"),
            max_header_count=owner.max_header_count,
            max_header_size=owner.max_header_size,
        )

    def write(self, data: bytes) -> int:
        return self.parser.write(data)

    def finalize(self) -> None:
        if self._finalized:
            return
        self._finalized = True
        self.parser.finalize()
        if self.current is not None:
            self._finish_current(complete_hint=False)
        self.complete = self.parser.state is END

    def _part_begin(self) -> None:
        if self.current is not None:  # pragma: no cover - defensive
            self._finish_current(complete_hint=False)
        part = _OpenPart(index=self.next_index, path=self.package_path.child(self.next_index))
        self.next_index += 1
        self.current = part
        self.owner._invoke("on_part_begin")
        self.owner._invoke("on_part_begin_path", part.path)

    def _part_data(self, data: bytes, start: int, end: int) -> None:
        part = self.current
        if part is None or end <= start:  # pragma: no cover - callback precondition
            return
        part.size += end - start
        self.owner._invoke_data("on_part_data_path", part.path, data, start, end)
        if part.child is not None:
            part.child.write(data[start:end])
        else:
            self.owner._invoke_data("on_part_data", None, data, start, end)

    def _part_end(self) -> None:
        self._finish_current(complete_hint=True)
        self.owner._invoke("on_part_end")

    def _header_begin(self) -> None:
        self._header_name.clear()
        self._header_value.clear()
        self.owner._invoke("on_header_begin")

    def _header_field(self, data: bytes, start: int, end: int) -> None:
        self._header_name.append(data[start:end])
        self.owner._invoke_data("on_header_field", None, data, start, end)

    def _header_value_cb(self, data: bytes, start: int, end: int) -> None:
        self._header_value.append(data[start:end])
        self.owner._invoke_data("on_header_value", None, data, start, end)

    def _header_end(self) -> None:
        part = self.current
        if part is not None:
            part.headers[b"".join(self._header_name).lower()] = b"".join(self._header_value)
        self._header_name.clear()
        self._header_value.clear()
        self.owner._invoke("on_header_end")

    def _headers_finished(self) -> None:
        part = self.current
        if part is None:  # pragma: no cover - defensive
            raise NestedMultipartError("Headers finished without an open part")
        policy = self.owner.policy
        self.owner._invoke("on_part_headers", part.path, dict(part.headers))

        content_disposition = part.headers.get(b"content-disposition")
        if content_disposition is None:
            self._missing_header(part, "missing_content_disposition")
        else:
            _, options = parse_options_header(content_disposition)
            part.name = options.get(b"name")
            part.file_name = options.get(b"filename")
            if part.name is None:
                self._missing_header(part, "missing_name")

        content_type = part.headers.get(b"content-type")
        if content_type is not None:
            media_type, parameters = parse_options_header(content_type)
            part.media_type = media_type.decode("latin-1").lower() or None
            part.content_type = content_type.decode("latin-1")
            part.boundary = parameters.get(b"boundary")

        part.content_transfer_encoding = part.headers.get(b"content-transfer-encoding", b"7bit").strip().lower()
        correlation_header = policy.correlation_header
        if correlation_header is not None:
            correlation_value = part.headers.get(correlation_header)
            if correlation_value is None:
                for fallback in (b"x-correlation-id", b"x-part-id", b"x-local-id", b"content-id"):
                    correlation_value = part.headers.get(fallback)
                    if correlation_value is not None:
                        break
            if correlation_value is not None:
                part.correlation_id = correlation_value.strip()

        match = policy.lookup(part.path, part.name, part.media_type, part.correlation_id)
        part.declaration = match.scope
        part.declared_at = match.declared_at
        part.declared_in_own_package = match.own_package
        part.declared_for_this_part = match.same_path
        if (
            part.media_type is None
            and match.same_path
            and match.scope is not None
            and match.scope.content_type is not None
        ):
            self._reject(part, "missing_content_type")
        if match.same_path and not match.identity_matches:
            self._reject(part, "declaration_mismatch")
        if match.ambiguous:
            self._reject(part, "ambiguous_declaration")

        if self.effective_types is not None and part.media_type is not None:
            if part.media_type not in self.effective_types:
                self._reject(part, "type_not_allowed")
                return

        if part.content_transfer_encoding not in KNOWN_TRANSFER_ENCODINGS:
            self._unknown_encoding(part)

        is_multipart = part.media_type is not None and part.media_type.startswith("multipart/")
        if not is_multipart:
            return

        if part.boundary is None:
            self._reject(part, "missing_boundary")
            return

        if self.effective_nested_types is None or part.media_type not in self.effective_nested_types:
            self._reject(part, "nested_type_not_allowed")
            return

        if part.content_transfer_encoding not in RAW_TRANSFER_ENCODINGS:
            self._reject(part, "encoded_nested_package")
            return

        if self.max_depth is not None and self.depth >= self.max_depth:
            self._reject(part, "max_depth_exceeded")
            return

        child_types, child_nested_types, child_max_depth = self._child_constraints(part)
        try:
            child = _Level(
                self.owner,
                part.path,
                part.boundary,
                depth=self.depth + 1,
                effective_types=child_types,
                effective_nested_types=child_nested_types,
                max_depth=child_max_depth,
            )
        except (FormParserError, ValueError) as exc:
            self._reject(part, f"invalid_nested_boundary: {exc}")
            return

        part.is_package = True
        part.child = child
        part.effective_types = child_types
        part.effective_nested_types = child_nested_types
        part.effective_max_depth = child_max_depth
        self.owner._invoke_package(part.path, part.content_type)

    def _child_constraints(self, part: _OpenPart) -> tuple[frozenset[str] | None, frozenset[str] | None, int | None]:
        child_types = self.effective_types
        child_nested_types = self.effective_nested_types
        child_max_depth = self.max_depth
        declaration = part.declaration if part.declared_for_this_part else None
        if declaration is not None:
            child_types = _intersect_optional(child_types, declaration.allowed_type_set)
            child_nested_types = _intersect_optional(child_nested_types, declaration.allowed_nested_type_set)
            child_max_depth = _min_optional(child_max_depth, declaration.max_depth)
        if child_nested_types is None:  # pragma: no cover - root initializes a set
            child_nested_types = frozenset()
        return child_types, child_nested_types, child_max_depth

    def _missing_header(self, part: _OpenPart, reason: str) -> None:
        handler = self.owner.policy.missing_child_header
        if handler == "error":
            raise NestedMultipartError(f"{reason} at part {part.path}")
        if handler == "reject":
            self._reject(part, reason)
        else:
            part.reasons.append(f"{reason}_allowed")

    def _unknown_encoding(self, part: _OpenPart) -> None:
        handler = self.owner.policy.unknown_encoding
        if handler == "error":
            raise NestedMultipartError(
                f"Unknown Content-Transfer-Encoding {part.content_transfer_encoding!r} at part {part.path}"
            )
        if handler == "reject":
            self._reject(part, "unknown_content_transfer_encoding")
        else:
            part.reasons.append("unknown_content_transfer_encoding_opaque")

    def _reject(self, part: _OpenPart, reason: str) -> None:
        part.rejected = True
        if reason not in part.reasons:
            part.reasons.append(reason)

    def _finish_current(self, *, complete_hint: bool) -> None:
        part = self.current
        if part is None:  # pragma: no cover - defensive
            return
        self.current = None

        complete = complete_hint
        if part.child is not None:
            if not part.child._finalized:
                part.child.finalize()
            part.children = tuple(part.child.parts)
            complete = complete and part.child.complete
        if not complete:
            if part.rejected:
                part.reasons.append("incomplete_subtree")
            else:
                self._reject(part, "incomplete_subtree")

        decision = self._decision(part, complete)
        receipt = PartReceipt(
            path=part.path,
            name=part.name,
            file_name=part.file_name,
            content_type=part.content_type,
            media_type=part.media_type,
            content_transfer_encoding=part.content_transfer_encoding,
            correlation_id=part.correlation_id,
            size=part.size,
            depth=part.path.depth,
            is_package=part.is_package,
            complete=complete,
            decision=decision,
            reason=part.reasons[0] if part.reasons else None,
            reasons=tuple(part.reasons),
            declared_at=part.declared_at,
            declared_in_own_package=part.declared_in_own_package,
            declared_for_this_part=part.declared_for_this_part,
            declaration=part.declaration,
            effective_types=part.effective_types,
            effective_nested_types=part.effective_nested_types,
            effective_max_depth=part.effective_max_depth,
            children=part.children,
        )
        self.parts.append(receipt)
        self.owner._emit_receipt(receipt)

    def _decision(self, part: _OpenPart, complete: bool) -> ReceiveDecision:
        if not complete:
            return ReceiveDecision.PENDING
        if part.rejected:
            return ReceiveDecision.REJECTED
        if part.declared_for_this_part:
            return ReceiveDecision.ACCEPTED
        if part.declared_at is not None:
            if self.owner.policy.require_declaration:
                reason = (
                    "declaration_for_other_part" if part.declared_in_own_package else "declaration_in_other_package"
                )
                self._reject(part, reason)
                return ReceiveDecision.REJECTED
            if "declaration_in_other_package" not in part.reasons:
                part.reasons.append("declaration_in_other_package")
            return ReceiveDecision.ACCEPTED
        if self.owner.policy.require_declaration:
            if "not_declared_at_path" not in part.reasons:
                part.reasons.append("not_declared_at_path")
            return ReceiveDecision.UNDECLARED
        return ReceiveDecision.ACCEPTED

    def _end_of_package(self) -> None:
        self.complete = True
        if self.package_path.is_root:
            self.owner._invoke("on_end")


class NestedMultipartParser:
    """A streaming multipart parser with opt-in nested MIME packages.

    The parser keeps the normal ``MultipartParser`` callbacks.  In addition,
    every completed subtree produces a :class:`PartReceipt` through
    ``on_receipt``.  A receipt is only emitted once the subtree is structurally
    complete; an unterminated child is reported as ``pending`` instead of being
    guessed at.

    The parser also offers path-aware callbacks, which are useful because two
    nested parts may have the same name:

    ``on_part_begin_path(path)``
        Called when a part starts, with its structural path.

    ``on_part_headers(path, headers)``
        Called once the part headers are available, with a copy of the header map.

    ``on_part_data_path(path, data, start, end)``
        Raw bytes for every part, including package containers.

    ``on_package(path, content_type)``
        Called when a part is accepted for recursive parsing.

    The legacy ``on_part_data`` callback receives leaf data only.  Container
    bytes are consumed by the child parser and are available through
    ``on_part_data_path``.

    Args:
        boundary: Boundary of the top-level multipart package.
        callbacks: Existing multipart callbacks, plus ``on_receipt``,
            ``on_part_data_path`` and ``on_package``.
        policy: An :class:`ApprovalPolicy`.  The remaining keyword arguments
            override individual policy fields when given.
        scope: A single :class:`ApprovalScope` or an iterable of them.
        scopes: Alias for a collection of approval scopes.
        declarations: Alias for ``scopes``.
        max_size: Maximum number of bytes in the top-level body.
        max_header_count: Maximum headers per part at every nesting level.
        max_header_size: Maximum header line size at every nesting level.
    """

    def __init__(
        self,
        boundary: bytes | str,
        callbacks: Mapping[str, Callable[..., Any]] | None = None,
        *,
        policy: ApprovalPolicy | None = None,
        scope: ApprovalScope | ApprovalPolicy | Iterable[ApprovalScope] | None = None,
        scopes: Iterable[ApprovalScope] | None = None,
        declarations: Iterable[ApprovalScope] | None = None,
        allowed_types: frozenset[str] | Iterable[str | bytes] | str | bytes | None = None,
        allowed_nested_types: frozenset[str] | Iterable[str | bytes] | str | bytes | None = None,
        nested_types: frozenset[str] | Iterable[str | bytes] | str | bytes | None = None,
        require_declaration: bool | None = None,
        missing_child_header: _MissingHandler | None = None,
        unknown_encoding: _UnknownEncodingHandler | None = None,
        correlation_id_header: bytes | str | None = None,
        max_depth: int | None = None,
        max_size: float = float("inf"),
        max_header_count: int = DEFAULT_MAX_HEADER_COUNT,
        max_header_size: int = DEFAULT_MAX_HEADER_SIZE,
    ) -> None:
        self.logger = logging.getLogger(__name__)
        self.callbacks: dict[str, Callable[..., Any]] = dict(callbacks or {})
        self.max_header_count = max_header_count
        self.max_header_size = max_header_size

        if not isinstance(max_size, Number) or max_size < 1:
            raise ValueError("max_size must be a positive number, not %r" % max_size)
        self.max_size = max_size
        self._current_size = 0

        selected_scopes: list[ApprovalScope] = []
        if scope is not None:
            if isinstance(scope, ApprovalPolicy):
                if policy is not None:
                    raise ScopeError("Pass either policy or scope, not both as policies")
                policy = scope
            elif isinstance(scope, ApprovalScope):
                selected_scopes.append(scope)
            else:
                selected_scopes.extend(scope)
        if scopes is not None:
            selected_scopes.extend(scopes)
        if declarations is not None:
            selected_scopes.extend(declarations)

        if policy is None:
            policy = ApprovalPolicy(scopes=tuple(selected_scopes))
        elif selected_scopes:
            policy = replace(policy, scopes=(*policy.scope_list, *selected_scopes))

        overrides: dict[str, Any] = {}
        if allowed_types is not None:
            overrides["allowed_types"] = allowed_types
        nested = allowed_nested_types if allowed_nested_types is not None else nested_types
        if nested is not None:
            overrides["allowed_nested_types"] = nested
        if require_declaration is not None:
            overrides["require_declaration"] = require_declaration
        if missing_child_header is not None:
            overrides["missing_child_header"] = missing_child_header
        if unknown_encoding is not None:
            overrides["unknown_encoding"] = unknown_encoding
        if correlation_id_header is not None:
            overrides["correlation_id_header"] = correlation_id_header
        if max_depth is not None:
            overrides["max_depth"] = max_depth
        if overrides:
            policy = replace(policy, **overrides)

        self.policy = policy
        self._finalized = False
        self._complete = False
        self._all_receipts: list[PartReceipt] = []

        root_scope = policy.scope_at(PartPath())
        if policy.allowed_type_set is None:
            initial_types = root_scope.allowed_type_set if root_scope is not None else None
        else:
            initial_types = _intersect_optional(
                policy.allowed_type_set, root_scope.allowed_type_set if root_scope is not None else None
            )

        if policy.allowed_nested_type_set is None:
            initial_nested = root_scope.allowed_nested_type_set if root_scope is not None else frozenset()
        else:
            initial_nested = _intersect_optional(
                policy.allowed_nested_type_set, root_scope.allowed_nested_type_set if root_scope is not None else None
            )
        if initial_nested is None:
            initial_nested = frozenset()

        initial_depth = _min_optional(policy.max_depth, root_scope.max_depth if root_scope is not None else None)

        self._root = _Level(
            self,
            PartPath(),
            boundary,
            depth=0,
            effective_types=initial_types,
            effective_nested_types=initial_nested,
            max_depth=initial_depth,
        )
        self.parser = self._root.parser

    @property
    def receipt(self) -> NestedReceipt:
        return NestedReceipt(
            roots=tuple(self._root.parts),
            receipts=tuple(self._all_receipts),
            complete=self._complete and self._root.complete,
        )

    @property
    def receipts(self) -> tuple[PartReceipt, ...]:
        return tuple(self._all_receipts)

    def get_receipt(self, path: PartPath | tuple[int, ...] | str | int) -> PartReceipt | None:
        return cast("PartReceipt | None", self.receipt.get(path))

    def write(self, data: bytes) -> int:
        if self._finalized:
            raise FormParserError("Cannot write after finalize()")
        data_len = len(data)
        if (self._current_size + data_len) > self.max_size:
            data_len = int(self.max_size - self._current_size)
        written = self._root.write(data[:data_len])
        self._current_size += written
        return written

    def finalize(self) -> None:
        if self._finalized:
            return
        self._finalized = True
        self._root.finalize()
        self._complete = self._root.complete

    def close(self) -> None:
        self.finalize()

    def _callbacks_for(self, name: str) -> Callable[..., Any] | None:
        callback = self.callbacks.get(name)
        if callback is None:
            callback = self.callbacks.get(name[3:] if name.startswith("on_") else f"on_{name}")
        return callback

    def _invoke(self, name: str, *args: Any) -> None:
        callback = self._callbacks_for(name)
        if callback is not None:
            callback(*args)

    def _invoke_data(self, name: str, path: PartPath | None, data: bytes, start: int, end: int) -> None:
        if end <= start:  # pragma: no cover - callback precondition
            return
        callback = self._callbacks_for(name)
        if callback is None:
            return
        if path is None:
            callback(data, start, end)
        else:
            callback(path, data, start, end)

    def _invoke_package(self, path: PartPath, content_type: str | None) -> None:
        callback = self._callbacks_for("on_package")
        if callback is not None:
            callback(path, content_type)

    def _emit_receipt(self, receipt: PartReceipt) -> None:
        self._all_receipts.append(receipt)
        callback = self._callbacks_for("on_receipt")
        if callback is not None:
            callback(receipt)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(boundary={self._root.parser.boundary!r})"


NestedFormParser = NestedMultipartParser


def create_nested_form_parser(
    headers: Mapping[str, bytes | str], callbacks: Mapping[str, Callable[..., Any]] | None = None, **kwargs: Any
) -> NestedMultipartParser:
    """Create a nested parser from request headers.

    The top-level content type must be ``multipart/form-data`` or another
    ``multipart/*`` type.  Its ``boundary`` parameter is required.
    """

    content_type_header = headers.get("Content-Type") or headers.get("content-type")
    if content_type_header is None:
        raise ValueError("No Content-Type header given!")
    content_type, params = parse_options_header(content_type_header)
    if not content_type.startswith(b"multipart/"):
        raise FormParserError(f"Expected a multipart content type, got {content_type.decode('latin-1')!r}")
    boundary = params.get(b"boundary")
    if boundary is None:
        raise FormParserError("No boundary given")
    return NestedMultipartParser(boundary, callbacks, **kwargs)


def parse_nested_form(
    headers: Mapping[str, bytes | str],
    input_stream: SupportsRead,
    callbacks: Mapping[str, Callable[..., Any]] | None = None,
    *,
    chunk_size: int = 1048576,
    **kwargs: Any,
) -> NestedReceipt:
    """Parse a stream and return the final nested receipt.

    This mirrors :func:`python_multipart.parse_form`: bytes are read in chunks
    and passed to the parser, so neither the request nor nested packages need
    to be buffered as a whole.
    """

    if chunk_size < 1:
        raise ValueError(f"chunk_size must be a positive number, not {chunk_size!r}")

    parser = create_nested_form_parser(headers, callbacks, **kwargs)

    content_length: int | float | bytes | str | None = headers.get("Content-Length") or headers.get("content-length")
    if content_length is not None:
        content_length = int(content_length)
        if content_length < 0:
            raise ValueError("Content-Length must be non-negative")
    else:
        content_length = float("inf")

    bytes_read = 0
    while True:
        max_readable = int(min(content_length - bytes_read, chunk_size))
        buff = input_stream.read(max_readable)
        parser.write(buff)
        bytes_read += len(buff)
        if len(buff) != max_readable or bytes_read == content_length:
            break

    parser.finalize()
    return parser.receipt


parse_nested_multipart = parse_nested_form


__all__ = (
    "ApprovalPolicy",
    "ApprovalScope",
    "Declaration",
    "NestedMultipartError",
    "NestedFormParser",
    "NestedMultipartParser",
    "NestedReceipt",
    "PartDeclaration",
    "PartPath",
    "PartReceipt",
    "Receipt",
    "ReceiveDecision",
    "ReceivePolicy",
    "ReceiveScope",
    "ReceiveReceipt",
    "ScopeDeclaration",
    "ScopeError",
    "ScopeMatch",
    "NestedScope",
    "create_nested_form_parser",
    "parse_nested_form",
    "parse_nested_multipart",
)
