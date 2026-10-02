"""Static analysis of route declarations for routing conflicts.

This module implements a startup-time conflict check for Litestar applications. It inspects the *declared* routes
(``app.routes``) - without ever invoking a handler - and reports declarations that compete for the same requests:

* ``shadowed``: two declarations collapse onto the same routing-trie node and share at least one method, so the
  later registration silently replaces the earlier one.
* ``param_overlap``: two parameterized declarations with different shapes accept a common set of paths.
* ``unknown``: the overlap cannot be decided because a path parameter uses a converter that is not statically
  analyzable (only ``str``, ``int``, ``uuid`` and ``path`` are fully supported).

Normal priority rules are *not* reported as conflicts: a static (fully literal) route taking precedence over a
parameterized one, and mount routes taking precedence over handlers below their prefix, are by design.

Every confirmed conflict carries a witness (a concrete method and path) that can be verified both against the
declarations and against the actual router.
"""

from __future__ import annotations

import enum
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast
from uuid import UUID

from litestar.exceptions import ImproperlyConfiguredException
from litestar.types.internal_types import PathParameterDefinition
from litestar.utils import get_name, normalize_path

if TYPE_CHECKING:
    from litestar.app import Litestar
    from litestar.routes import ASGIRoute
    from litestar.routes.base import BaseRoute
    from litestar.types import RouteHandlerType

__all__ = (
    "ConflictKind",
    "RouteConflict",
    "RouteConflictCheckMode",
    "RouteConflictReport",
    "RouteDeclaration",
    "check_route_conflicts",
)

logger = logging.getLogger("litestar.route_conflicts")

RouteConflictCheckMode = Literal["off", "warn", "strict"]
"""Available modes for the startup route conflict check.

* ``"off"``: no check is performed.
* ``"warn"``: conflicts and unknowns are logged, startup continues.
* ``"strict"``: any confirmed conflict raises
  :class:`ImproperlyConfiguredException <litestar.exceptions.ImproperlyConfiguredException>` and prevents startup.
"""

# path parameter types whose single-segment acceptance sets are statically analyzable
_SINGLE_SEGMENT_TYPES = frozenset({str, int, UUID})
# all statically analyzable path parameter types (including the multi-segment 'path' type)
_DECIDABLE_TYPES = frozenset({str, int, UUID, Path})

# candidate sample values used to build concrete witness paths; a salt rotates the choice so that multiple
# distinct witnesses can be tried when verifying against the actual router
_STR_SAMPLES = ("litestar", "sample", "value", "x")
_INT_SAMPLES = ("1", "2", "42", "7")
_UUID_SAMPLES = (
    "12345678-1234-1234-1234-123456789012",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
)
# 32 digit-only strings are valid both as 'int' and as 'UUID' (32 hex digits, dashes optional)
_INT_UUID_SAMPLES = ("1" * 32, "2" * 32)

_MAX_WITNESS_ATTEMPTS = 8


class ConflictKind(enum.Enum):
    """Classification of a detected route conflict."""

    SHADOWED = "shadowed"
    """Two declarations map to the same routing node; the later registration replaces the earlier one."""
    PARAM_OVERLAP = "param_overlap"
    """Two parameterized declarations with different shapes accept a common set of paths."""
    UNKNOWN = "unknown"
    """Overlap cannot be decided because a non-analyzable path parameter converter is involved."""


class _Overlap(enum.Enum):
    """Result of a static overlap check between two path patterns."""

    YES = "yes"
    NO = "no"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class RouteDeclaration:
    """A description of a single route declaration involved in a conflict."""

    path: str
    """The normalized path of the route."""
    methods: tuple[str, ...]
    """The methods the route responds to (HTTP methods, ``"websocket"`` or ``"asgi"``)."""
    handler_names: tuple[str, ...]
    """Names of the route handlers declared on the route."""
    is_mount: bool
    """Whether the route is a mount (ASGI prefix) route."""

    def describe(self) -> str:
        """Return a human-readable description of the declaration.

        Returns:
            A string describing the declaration.
        """
        mount = ", mount" if self.is_mount else ""
        return f"{', '.join(self.methods)} {self.path} (handlers: {', '.join(self.handler_names)}{mount})"


@dataclass(frozen=True)
class RouteConflict:
    """A single detected conflict (or undecidable pair) between two route declarations."""

    kind: ConflictKind
    """The classification of the conflict."""
    declarations: tuple[RouteDeclaration, RouteDeclaration]
    """The two declarations involved."""
    methods: tuple[str, ...]
    """The methods for which the declarations compete."""
    reason: str
    """A human-readable explanation of the conflict."""
    witness_method: str | None
    """A concrete method that demonstrates the problem, if one could be determined."""
    witness_path: str | None
    """A concrete path accepted by both declarations, if one could be determined."""
    resolved_to: RouteDeclaration | None
    """The declaration the actual router currently selects for the witness, if verified."""

    def render(self) -> str:
        """Render the conflict as human-readable text.

        Returns:
            A multi-line string describing the conflict.
        """
        first, second = self.declarations
        lines = [
            f"[{self.kind.value}] {first.describe()} <-> {second.describe()}",
            f"  reason: {self.reason}",
        ]
        if self.witness_path is not None:
            witness = f"  witness: {self.witness_method or 'ASGI'} {self.witness_path}"
            if self.resolved_to is not None:
                witness += f" -> routed to {self.resolved_to.describe()}"
            lines.append(witness)
        return "\n".join(lines)


@dataclass
class RouteConflictReport:
    """The result of a route conflict analysis."""

    conflicts: list[RouteConflict] = field(default_factory=list)
    """Confirmed conflicts (of kind ``shadowed`` or ``param_overlap``)."""
    unknowns: list[RouteConflict] = field(default_factory=list)
    """Pairs for which overlap could not be decided (of kind ``unknown``)."""

    @property
    def ok(self) -> bool:
        """Whether no confirmed conflicts were found."""
        return not self.conflicts

    def __bool__(self) -> bool:
        return bool(self.conflicts or self.unknowns)

    def __len__(self) -> int:
        return len(self.conflicts) + len(self.unknowns)

    def render(self) -> str:
        """Render the full report as human-readable text.

        Returns:
            A multi-line string describing all findings.
        """
        lines = [f"route conflict report: {len(self.conflicts)} conflict(s), {len(self.unknowns)} unknown(s)"]
        for conflict in (*self.conflicts, *self.unknowns):
            lines.append(conflict.render())
        return "\n".join(lines)


@dataclass
class _RoutePattern:
    """The analyzed view of a single route declaration."""

    route: BaseRoute
    segments: tuple[str | PathParameterDefinition, ...]
    methods: frozenset[str]
    is_mount: bool
    declaration: RouteDeclaration
    handlers: tuple[RouteHandlerType, ...]

    @property
    def has_params(self) -> bool:
        return any(not isinstance(segment, str) for segment in self.segments)


def _pick(samples: tuple[str, ...], salt: int) -> str:
    return samples[salt % len(samples)]


def _is_path_param(segment: str | PathParameterDefinition) -> bool:
    return isinstance(segment, PathParameterDefinition) and segment.type is Path


def _param_accepts(param_type: Any, value: str) -> bool | None:
    """Check whether a path parameter of the given type accepts the concrete segment value.

    Returns:
        True or False if decidable, None if the parameter type is not statically analyzable.
    """
    if param_type is str or param_type is Path:
        return True
    if param_type is int:
        try:
            int(value)
        except ValueError:
            return False
        return True
    if param_type is UUID:
        try:
            UUID(value)
        except (ValueError, AttributeError, TypeError):
            return False
        return True
    return None


def _sample_for(param_type: Any, salt: int) -> str | None:
    """Return a concrete segment value accepted by the given parameter type, if decidable."""
    if param_type is str or param_type is Path:
        return _pick(_STR_SAMPLES, salt)
    if param_type is int:
        return _pick(_INT_SAMPLES, salt)
    if param_type is UUID:
        return _pick(_UUID_SAMPLES, salt)
    return None


def _combined_sample(type_a: Any, type_b: Any, salt: int) -> str | None:
    """Return a concrete segment value accepted by both parameter types, if decidable."""
    if type_a not in _SINGLE_SEGMENT_TYPES or type_b not in _SINGLE_SEGMENT_TYPES:
        return None
    if type_a is str and type_b is str:
        return _pick(_STR_SAMPLES, salt)
    if type_a is str:
        return _sample_for(type_b, salt)
    if type_b is str:
        return _sample_for(type_a, salt)
    if type_a is type_b:
        return _sample_for(type_a, salt)
    # one of them is 'int' and the other 'UUID': a 32 digit-only string is accepted by both
    return _pick(_INT_UUID_SAMPLES, salt)


def _concretize(
    segments: tuple[str | PathParameterDefinition, ...],
    start: int,
    min_segments: int,
    tail: bool,
    salt: int,
) -> tuple[_Overlap, list[str] | None]:
    """Build a concrete witness for the remainder of a pattern, or explain why that is impossible."""
    witness: list[str] = []
    for segment in segments[start:]:
        if isinstance(segment, str):
            witness.append(segment)
        elif segment.type is Path:
            # a 'path' parameter accepts any number (>= 1) of remaining segments
            while len(witness) < min_segments - 1:
                witness.append(_pick(_STR_SAMPLES, salt))
            witness.append(_pick(_STR_SAMPLES, salt))
            return _Overlap.YES, witness
        else:
            sample = _sample_for(segment.type, salt)
            if sample is None:
                return _Overlap.UNKNOWN, None
            witness.append(sample)
    if len(witness) < min_segments:
        if not tail:
            return _Overlap.NO, None
        while len(witness) < min_segments:
            witness.append(_pick(_STR_SAMPLES, salt))
    return _Overlap.YES, witness


def _routes_overlap(  # noqa: C901
    segments_a: tuple[str | PathParameterDefinition, ...],
    tail_a: bool,
    segments_b: tuple[str | PathParameterDefinition, ...],
    tail_b: bool,
    salt: int,
) -> tuple[_Overlap, list[str] | None]:
    """Check whether two route patterns accept a common path, returning a witness path if they do.

    The tails model mount routes, which accept any path below (and including) their prefix.
    """

    def rec(i: int, j: int) -> tuple[_Overlap, list[str] | None]:  # noqa: C901
        a_done = i >= len(segments_a)
        b_done = j >= len(segments_b)
        if a_done and b_done:
            return _Overlap.YES, []
        if a_done:
            if not tail_a:
                return _Overlap.NO, None
            return _concretize(segments_b, j, 0, tail_b, salt)
        if b_done:
            if not tail_b:
                return _Overlap.NO, None
            return _concretize(segments_a, i, 0, tail_a, salt)
        segment_a = segments_a[i]
        segment_b = segments_b[j]
        if _is_path_param(segment_a):
            # a 'path' parameter consumes the remainder of the path (at least one segment)
            return _concretize(segments_b, j, 1, tail_b, salt)
        if _is_path_param(segment_b):
            return _concretize(segments_a, i, 1, tail_a, salt)
        if isinstance(segment_a, str) and isinstance(segment_b, str):
            if segment_a != segment_b:
                return _Overlap.NO, None
            status, rest = rec(i + 1, j + 1)
            return status, ([segment_a, *rest] if status is _Overlap.YES else None)
        if isinstance(segment_a, str) or isinstance(segment_b, str):
            literal = segment_a if isinstance(segment_a, str) else segment_b
            parameter = segment_b if isinstance(segment_a, str) else segment_a
            accepted = _param_accepts(parameter.type, literal)  # type: ignore[union-attr]
            if accepted is False:
                return _Overlap.NO, None
            status, rest = rec(i + 1, j + 1)
            if status is not _Overlap.YES:
                return status, None
            if accepted is None:
                return _Overlap.UNKNOWN, None
            return _Overlap.YES, [literal, *rest]  # type: ignore[list-item]
        sample = _combined_sample(segment_a.type, segment_b.type, salt)  # type: ignore[union-attr]
        status, rest = rec(i + 1, j + 1)
        if status is not _Overlap.YES:
            return status, None
        if sample is None:
            return _Overlap.UNKNOWN, None
        return _Overlap.YES, [sample, *rest]

    return rec(0, 0)


def _is_auto_options_handler(handler: RouteHandlerType) -> bool:
    """Check whether the handler is the auto-generated OPTIONS handler added to every HTTP route."""
    fn = getattr(handler, "fn", None)
    return getattr(fn, "__qualname__", "") == "create_options_handler.<locals>.options_handler"


def _build_pattern(route: BaseRoute) -> _RoutePattern | None:
    from litestar.routes import HTTPRoute, WebSocketRoute

    route_handler = getattr(route, "route_handler", None)
    is_mount = bool(getattr(route_handler, "is_mount", False))

    if isinstance(route, HTTPRoute):
        handlers = tuple(handler for handler in route.route_handlers if not _is_auto_options_handler(handler))
        methods = frozenset(
            str(getattr(method, "value", method)) for handler in handlers for method in handler.http_methods
        )
    elif isinstance(route, WebSocketRoute):
        handlers = (route.route_handler,)
        methods = frozenset({"websocket"})
    else:
        handlers = (cast("ASGIRoute", route).route_handler,)
        methods = frozenset({"asgi"})

    if not methods:
        return None  # pragma: no cover

    declaration = RouteDeclaration(
        path=route.path,
        methods=tuple(sorted(methods)),
        handler_names=tuple(handler.name or get_name(handler.fn) for handler in handlers),
        is_mount=is_mount,
    )
    return _RoutePattern(
        route=route,
        segments=tuple(route.path_components),
        methods=methods,
        is_mount=is_mount,
        declaration=declaration,
        handlers=handlers,
    )


def _structurally_identical(pattern_a: _RoutePattern, pattern_b: _RoutePattern) -> bool:
    """Check whether two patterns collapse onto the same routing-trie node.

    The trie maps every path parameter - regardless of name or type - onto the same sentinel key, so two
    patterns share a node when their literal segments are equal and their parameter positions align.
    """
    if len(pattern_a.segments) != len(pattern_b.segments):
        return False
    for segment_a, segment_b in zip(pattern_a.segments, pattern_b.segments, strict=True):
        if isinstance(segment_a, str) != isinstance(segment_b, str):
            return False
        if isinstance(segment_a, str) and segment_a != segment_b:
            return False
    return True


def _select_witness_method(methods: frozenset[str]) -> str:
    return sorted(methods, key=lambda method: (method == "OPTIONS", method))[0]


def _verify_witness(
    app: Litestar,
    witness_segments: list[str],
    witness_method: str,
    pattern_a: _RoutePattern,
    pattern_b: _RoutePattern,
    handler_to_pattern: dict[int, _RoutePattern],
) -> _RoutePattern | None:
    """Resolve the witness against the actual router and return the winning pattern, if it is one of the pair."""
    path = normalize_path("/" + "/".join(witness_segments))
    method = witness_method if witness_method not in ("websocket", "asgi") else None
    try:
        _, handler, *_ = app.asgi_router.handle_routing(path=path, method=method)
    except Exception:  # noqa: BLE001
        return None
    winner = handler_to_pattern.get(id(handler))
    if winner is pattern_a or winner is pattern_b:
        return winner
    return None


def _shadowed_witness(loser: _RoutePattern, winner: _RoutePattern, salt: int) -> list[str]:
    """Build a concrete path accepted by both patterns of a shadowed pair.

    The patterns are structurally identical, so their parameter positions align; a combined sample is used so
    the witness falls into the acceptance range of both declarations. Placeholders are used for parameter
    types that are not statically analyzable.
    """
    witness = []
    for loser_segment, winner_segment in zip(loser.segments, winner.segments, strict=True):
        if isinstance(loser_segment, str):
            witness.append(loser_segment)
        else:
            loser_type = loser_segment.type  # type: ignore[union-attr]
            winner_type = winner_segment.type  # type: ignore[union-attr]
            sample = _combined_sample(loser_type, winner_type, salt)
            if sample is None and winner_type is Path:
                sample = _sample_for(loser_type, salt)
            if sample is None and loser_type is Path:
                sample = _sample_for(winner_type, salt)
            witness.append(sample or _pick(_STR_SAMPLES, salt))
    return witness


def _undecidable_type_names(*patterns: _RoutePattern) -> list[str]:
    names = set()
    for pattern in patterns:
        for segment in pattern.segments:
            if not isinstance(segment, str) and segment.type not in _DECIDABLE_TYPES:
                names.add(getattr(segment.type, "__name__", str(segment.type)))
    return sorted(names)


def _report_shadowed(
    app: Litestar,
    pattern_a: _RoutePattern,
    pattern_b: _RoutePattern,
    methods: tuple[str, ...],
    handler_to_pattern: dict[int, _RoutePattern],
    report: RouteConflictReport,
) -> None:
    # pattern_b is registered later, so its handlers replace pattern_a's handlers on the shared trie node
    loser, winner = pattern_a, pattern_b
    witness_path: str | None = None
    witness_method: str | None = _select_witness_method(frozenset(methods))
    resolved_to: RouteDeclaration | None = None
    for salt in range(_MAX_WITNESS_ATTEMPTS):
        witness_segments = _shadowed_witness(loser, winner, salt)
        verified = _verify_witness(app, witness_segments, witness_method, loser, winner, handler_to_pattern)
        if verified is not None:
            witness_path = normalize_path("/" + "/".join(witness_segments))
            resolved_to = verified.declaration
            break
    else:
        witness_method = None
    method_list = ", ".join(methods)
    reason = (
        f"both declarations map to the same routing node for method(s) {method_list}; "
        f"'{winner.declaration.handler_names[0]}' ({winner.declaration.path}) is registered later and handles "
        f"matching requests, so '{loser.declaration.handler_names[0]}' ({loser.declaration.path}) is unreachable "
        f"for method(s) {method_list}"
    )
    report.conflicts.append(
        RouteConflict(
            kind=ConflictKind.SHADOWED,
            declarations=(loser.declaration, winner.declaration),
            methods=methods,
            reason=reason,
            witness_method=witness_method,
            witness_path=witness_path,
            resolved_to=resolved_to,
        )
    )


def _check_pair(
    app: Litestar,
    pattern_a: _RoutePattern,
    pattern_b: _RoutePattern,
    handler_to_pattern: dict[int, _RoutePattern],
    report: RouteConflictReport,
) -> None:
    shared_methods = pattern_a.methods & pattern_b.methods
    if not shared_methods:
        return
    methods = tuple(sorted(shared_methods))

    if _structurally_identical(pattern_a, pattern_b):
        _report_shadowed(app, pattern_a, pattern_b, methods, handler_to_pattern, report)
        return

    if pattern_a.is_mount or pattern_b.is_mount:
        # a mount route takes precedence over everything at or below its prefix; this is by design
        return

    if not pattern_a.has_params or not pattern_b.has_params:
        # a fully static route takes precedence over a parameterized one; this is by design
        return

    witness_method = _select_witness_method(frozenset(methods))
    status: _Overlap = _Overlap.NO
    witness_path: str | None = None
    resolved_to: RouteDeclaration | None = None
    for salt in range(_MAX_WITNESS_ATTEMPTS):
        status, witness_segments = _routes_overlap(
            pattern_a.segments, pattern_a.is_mount, pattern_b.segments, pattern_b.is_mount, salt
        )
        if status is not _Overlap.YES:
            break
        winner = _verify_witness(app, witness_segments or [], witness_method, pattern_a, pattern_b, handler_to_pattern)
        if winner is not None:
            witness_path = normalize_path("/" + "/".join(witness_segments or []))
            resolved_to = winner.declaration
            break

    method_list = ", ".join(methods)
    if status is _Overlap.NO:
        return
    if status is _Overlap.UNKNOWN:
        undecidable = ", ".join(_undecidable_type_names(pattern_a, pattern_b))
        report.unknowns.append(
            RouteConflict(
                kind=ConflictKind.UNKNOWN,
                declarations=(pattern_a.declaration, pattern_b.declaration),
                methods=methods,
                reason=(
                    f"cannot determine whether the declarations overlap for method(s) {method_list}: path "
                    f"parameter type(s) {undecidable} are not statically analyzable (supported types are "
                    f"str, int, uuid and path)"
                ),
                witness_method=None,
                witness_path=None,
                resolved_to=None,
            )
        )
        return
    if witness_path is None:
        # the acceptance ranges overlap, but no generated witness could be verified against the actual
        # router (another declaration takes precedence for every candidate path)
        report.unknowns.append(
            RouteConflict(
                kind=ConflictKind.UNKNOWN,
                declarations=(pattern_a.declaration, pattern_b.declaration),
                methods=methods,
                reason=(
                    f"the parameter ranges of both declarations overlap for method(s) {method_list}, but no "
                    f"witness path could be verified against the router; another declaration may take precedence"
                ),
                witness_method=None,
                witness_path=None,
                resolved_to=None,
            )
        )
        return
    report.conflicts.append(
        RouteConflict(
            kind=ConflictKind.PARAM_OVERLAP,
            declarations=(pattern_a.declaration, pattern_b.declaration),
            methods=methods,
            reason=(
                f"the parameter ranges of both declarations overlap for method(s) {method_list}; "
                f"e.g. '{witness_path}' is accepted by both and is routed to "
                f"'{(resolved_to or pattern_a.declaration).handler_names[0]}' "
                f"({(resolved_to or pattern_a.declaration).path})"
            ),
            witness_method=witness_method,
            witness_path=witness_path,
            resolved_to=resolved_to,
        )
    )


def _analyze(app: Litestar) -> RouteConflictReport:
    patterns = [pattern for route in app.routes if (pattern := _build_pattern(route)) is not None]
    handler_to_pattern = {id(handler): pattern for pattern in patterns for handler in pattern.handlers}
    report = RouteConflictReport()
    for index, pattern_a in enumerate(patterns):
        for pattern_b in patterns[index + 1 :]:
            _check_pair(app, pattern_a, pattern_b, handler_to_pattern, report)
    return report


def check_route_conflicts(app: Litestar, *, strict: bool = False) -> RouteConflictReport:
    """Analyze the route declarations of the given application for routing conflicts.

    The analysis is purely static: it inspects the declared routes and the routing trie, and never invokes
    any handler. Normal priority rules (static routes winning over parameterized ones, mount routes winning
    below their prefix) are not reported. Pairs whose overlap depends on path parameter converters that are
    not statically analyzable are reported as ``unknown`` rather than guessed.

    Args:
        app: The Litestar application instance to check.
        strict: If True, raise an :class:`ImproperlyConfiguredException <litestar.exceptions.ImproperlyConfiguredException>`
            when confirmed conflicts are found.

    Raises:
        ImproperlyConfiguredException: If ``strict`` is True and confirmed conflicts exist.

    Returns:
        A report containing all confirmed conflicts and undecidable pairs.
    """
    report = _analyze(app)
    if strict and report.conflicts:
        raise ImproperlyConfiguredException(report.render())
    return report
