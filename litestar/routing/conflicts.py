from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from itertools import combinations
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, NamedTuple, cast
from uuid import UUID

from litestar.routes import HTTPRoute
from litestar.types.internal_types import PathParameterDefinition
from litestar.utils import normalize_path

__all__ = (
    "ConflictKind",
    "RouteConflict",
    "RouteConflictReport",
    "RouteDeclaration",
    "RouteWitness",
    "check_route_conflicts",
)


if TYPE_CHECKING:
    from collections.abc import Sequence

    from litestar.app import Litestar
    from litestar.routes.base import BaseRoute
    from litestar.types import Method


class ConflictKind(str, Enum):
    """Classification of a relationship between two route declarations."""

    STATIC_PRIORITY = "static_priority"
    """The declarations both accept some concrete path, but the router deterministically prefers the static/literal
    declaration. This is normal behaviour (static routes win), nothing is blocked."""

    SHADOWED = "shadowed"
    """A declaration is completely covered by another for structural reasons (identical path template or a greedy
    ``path`` parameter swallowing the remainder) and can never handle a request."""

    OVERLAPPING = "overlapping"
    """Two parameter routes accept overlapping (or structurally merged) ranges on the same method, and which
    declaration receives a shared path is decided by registration order rather than by static priority."""

    UNKNOWN = "unknown"
    """A path parameter uses a converter whose accepted range cannot be decided without executing it. No assumption
    of mutual exclusion is made."""


_Kind = Literal["static", "int", "uuid", "path", "unknown"]

# concrete single-segment sample values accepted by each built-in converter
_SAMPLE: dict[str, str] = {
    "str": "value",
    "int": "1",
    "uuid": "00000000-0000-0000-0000-000000000001",
}

# a sample that every built-in single-segment converter accepts (an unsigned integer)
_UNIVERSAL_SAMPLE = "1"


def _kind(component: str | PathParameterDefinition) -> _Kind:
    if not isinstance(component, PathParameterDefinition):
        return "static"
    param_type = component.type
    if param_type is str:
        return "str"
    if param_type is int:
        return "int"
    if param_type is UUID:
        return "uuid"
    if param_type is Path:
        return "path"
    return "unknown"


class RouteWitness(NamedTuple):
    """A concrete request demonstrating a relationship between two declarations."""

    method: Method | Literal["websocket", "asgi"]
    """The request method (``websocket`` / ``asgi`` for the respective scope kinds)."""
    path: str
    """A normalized concrete path with all parameters filled in."""
    resolved_handler: str | None
    """Name of the handler the live router resolves the path to, or ``None`` if no route matches."""

    def __str__(self) -> str:
        method = self.method.upper()
        return f"{method} {self.path} -> {self.resolved_handler or '<no route>'}"


@dataclass(frozen=True)
class RouteDeclaration:
    """A single method-scoped route declaration participating in conflict analysis."""

    route: BaseRoute
    method: Method | Literal["websocket", "asgi"]
    handler: Any
    order: int

    @property
    def handler_name(self) -> str:
        return getattr(self.handler, "handler_name", self.handler.__class__.__name__)

    @property
    def path(self) -> str:
        return self.route.path

    @property
    def components(self) -> list[str | PathParameterDefinition]:
        return list(self.route.path_components)

    @property
    def is_mount(self) -> bool:
        return bool(getattr(self.route, "route_handler", None) and getattr(self.route.route_handler, "is_mount", False))

    def describe(self) -> str:
        method = self.method.upper()
        return f"{method} {self.path} -> {self.handler_name}"

    def _concrete_components(self) -> list[str]:
        return [_component_sample(component) for component in self.route.path_components]


@dataclass(frozen=True)
class RouteConflict:
    """A finding about a pair of route declarations."""

    kind: ConflictKind
    first: RouteDeclaration
    second: RouteDeclaration
    reason: str
    witness: RouteWitness

    @property
    def blocks_startup(self) -> bool:
        """Whether the finding represents a hard conflict."""
        return self.kind in (ConflictKind.SHADOWED, ConflictKind.OVERLAPPING)

    def format(self) -> str:
        return (
            f"[{self.kind.value}] {self.first.describe()} vs {self.second.describe()}\n"
            f"  reason: {self.reason}\n"
            f"  witness: {self.witness}"
        )


class RouteConflictReport:
    """Result of a route conflict check.

    Findings of kind :attr:`ConflictKind.STATIC_PRIORITY` and :attr:`ConflictKind.UNKNOWN` are informational;
    findings of kind :attr:`ConflictKind.SHADOWED` and :attr:`ConflictKind.OVERLAPPING` are hard conflicts.
    """

    __slots__ = ("findings",)

    def __init__(self, findings: Sequence[RouteConflict]) -> None:
        self.findings: tuple[RouteConflict, ...] = tuple(findings)

    def __iter__(self):
        return iter(self.findings)

    def __getitem__(self, index: int) -> RouteConflict:
        return self.findings[index]

    def __len__(self) -> int:
        return len(self.findings)

    @property
    def conflicts(self) -> tuple[RouteConflict, ...]:
        return tuple(f for f in self.findings if f.blocks_startup)

    @property
    def unknown(self) -> tuple[RouteConflict, ...]:
        return tuple(f for f in self.findings if f.kind is ConflictKind.UNKNOWN)

    @property
    def is_clean(self) -> bool:
        return not self.conflicts

    def verify(self, app: Litestar) -> tuple[RouteConflict, ...]:
        """Re-resolve every witness on the live router without invoking any handler.

        Returns:
            A tuple of findings whose witness no longer resolves as recorded. Empty when the report matches the
            actual router.
        """
        mismatched: list[RouteConflict] = []
        for finding in self.findings:
            resolved = _resolve_witness(app, finding.witness.method, finding.witness.path)
            if resolved != finding.witness.resolved_handler:
                mismatched.append(finding)
        return tuple(mismatched)


def _resolve_witness(
    app_or_router: Any,
    method: Method | Literal["websocket", "asgi"],
    path: str,
) -> str | None:
    """Resolve a concrete path using the live routing trie.

    Only the routing lookup is performed: no handler, middleware stack or lifespan is invoked.
    """
    router = getattr(app_or_router, "asgi_router", app_or_router)
    lookup_method = None if method == "websocket" else ("GET" if method == "asgi" else method)
    try:
        _app, handler, _path, _params, _template = router.handle_routing(path=normalize_path(path), method=lookup_method)
    except Exception:  # NotFound / MethodNotAllowed / conversion failures all mean "no declaration receives it"
        return None
    return getattr(handler, "handler_name", handler.__class__.__name__)


def _has_unknown_parameter(declaration: RouteDeclaration) -> bool:
    return any(
        isinstance(component, PathParameterDefinition) and _kind(component) == "unknown"
        for component in declaration.components
    )


def _component_sample(component: str | PathParameterDefinition) -> str:
    if not isinstance(component, PathParameterDefinition):
        return component
    kind = _kind(component)
    if kind == "path":
        return _SAMPLE["str"]
    if kind == "unknown":
        return _UNIVERSAL_SAMPLE
    return _SAMPLE[kind]


def _concrete_path(components: Sequence[str | PathParameterDefinition]) -> str:
    segments = [_component_sample(component) for component in components]
    return normalize_path("/" + "/".join(segment for segment in segments if segment))


def _build_witness(
    app: Litestar,
    method: Method | Literal["websocket", "asgi"],
    path: str,
) -> RouteWitness:
    return RouteWitness(method=method, path=normalize_path(path), resolved_handler=_resolve_witness(app, method, path))


def _accepts_literal(component: str | PathParameterDefinition, literal: str) -> bool | None:
    """Whether a single segment component can match a concrete literal segment.

    Returns ``True``/``False`` when decidable for the supported converters, and ``None`` for unsupported custom
    converters (the converter is never executed).
    """
    if not isinstance(component, PathParameterDefinition):
        return component == literal
    kind = _kind(component)
    if kind == "str":
        return True
    if kind == "path":
        return bool(literal)
    if kind == "unknown":
        return None
    try:
        if kind == "int":
            parsed: object = int(cast("str", literal))
        elif kind == "uuid":
            parsed = UUID(literal)
        else:  # pragma: no cover
            return None
    except (ValueError, AttributeError, TypeError):
        return False
    return True


def _analyse_pair(
    app: Litestar,
    method: Method | Literal["websocket", "asgi"],
    first: RouteDeclaration,
    second: RouteDeclaration,
) -> RouteConflict | None:
    """Structurally compare two declarations sharing a method and verify a witness on the live router.

    The comparison mirrors the trie construction / traversal rules exactly:

    * exact duplicate paths share one node (last declaration wins),
    * literal children are checked before the parameter sentinel at every level (static priority),
    * a ``path`` parameter greedily consumes the remaining components,
    * all parameter types at one position share a single sentinel node (registration order decides).
    """

    first_components = first.components
    second_components = second.components

    if first.is_mount or second.is_mount:
        return _analyse_mount_pair(app, method, first, second)

    divergence = _find_divergence(first_components, second_components)
    if divergence == len(first_components) == len(second_components):
        if first_components == second_components:
            return _shadowed_conflict(app, method, first, second, "identical path templates share one trie node")
        # same length, every position merges into the same trie children, but converters differ: one shared leaf
        return _same_skeleton_conflict(app, method, first, second)

    a = first_components[divergence] if divergence < len(first_components) else None
    b = second_components[divergence] if divergence < len(second_components) else None

    if a is not None and b is not None and not isinstance(a, PathParameterDefinition) and not isinstance(b, PathParameterDefinition):
        # distinct literal segments: the branches are disjoint below the trie node
        return None

    if (
        a is not None
        and b is not None
        and isinstance(a, PathParameterDefinition)
        and isinstance(b, PathParameterDefinition)
        and len(first_components) == len(second_components)
    ):
        # one shared sentinel node all the way down to the leaf: registration order decides
        return _same_skeleton_conflict(app, method, first, second)

    return _different_skeleton_conflict(app, method, first, second)


def _shadowed_conflict(
    app: Litestar,
    method: Method | Literal["websocket", "asgi"],
    first: RouteDeclaration,
    second: RouteDeclaration,
    reason_detail: str,
    *,
    witness_components: Sequence[str | PathParameterDefinition] | None = None,
) -> RouteConflict:
    """Build a finding for a pair where one declaration wins a shared structural node.

    Unknown converters downgrade the result to :attr:`ConflictKind.UNKNOWN`.
    """
    components = witness_components if witness_components is not None else second.components
    path = _concrete_path(components)

    resolved_name = _resolve_witness(app, method, path)
    winner = first if resolved_name == first.handler_name else second
    loser = second if winner is first else first
    witness = _build_witness(app, method, path)

    if _has_unknown_parameter(loser) or _has_unknown_parameter(winner):
        return RouteConflict(
            kind=ConflictKind.UNKNOWN,
            first=first,
            second=second,
            reason=(
                f"{reason_detail}; the relation cannot be proven because a parameter uses an unsupported custom "
                "converter whose accepted range cannot be determined without executing it"
            ),
            witness=witness,
        )

    return RouteConflict(
        kind=ConflictKind.SHADOWED,
        first=first,
        second=second,
        reason=f"{reason_detail}; '{loser.describe()}' never receives a request",
        witness=witness,
    )


def _same_skeleton_conflict(
    app: Litestar,
    method: Method | Literal["websocket", "asgi"],
    first: RouteDeclaration,
    second: RouteDeclaration,
) -> RouteConflict | None:
    """Handle same-length declarations that collapse to one trie leaf but use different parameter converters."""
    unknown_positions: list[int] = []
    disjoint_positions: list[int] = []
    overlap_positions: list[int] = []

    for index, (a, b) in enumerate(zip(first.components, second.components, strict=True)):
        if not isinstance(a, PathParameterDefinition) or not isinstance(b, PathParameterDefinition):
            continue
        ka, kb = _kind(a), _kind(b)
        if ka == kb:
            continue
        if "unknown" in (ka, kb):
            unknown_positions.append(index)
        elif {ka, kb} == {"int", "uuid"}:
            disjoint_positions.append(index)
        else:
            overlap_positions.append(index)

    if not unknown_positions and not disjoint_positions and not overlap_positions:
        return _shadowed_conflict(app, method, first, second, "identical path templates share one trie node")

    if unknown_positions:
        components = list(second.components)
        for index in unknown_positions:
            components[index] = _component_sample(second.components[index])
        path = _concrete_path(components)
        resolved_name = _resolve_witness(app, method, path)
        return RouteConflict(
            kind=ConflictKind.UNKNOWN,
            first=first,
            second=second,
            reason=(
                "the parameter routes share one trie node, but a parameter uses an unsupported custom converter; "
                "their accepted ranges may overlap or be disjoint, which cannot be determined without executing "
                "the converter"
            ),
            witness=_build_witness(app, method, path),
        )

    index = (disjoint_positions or overlap_positions)[0]
    if disjoint_positions:
        first_kind = _kind(first.components[index])
        components = list(second.components)
        components[index] = _SAMPLE[first_kind] if first_kind in _SAMPLE else _UNIVERSAL_SAMPLE
        path = _concrete_path(components)
        detail = "the converters accept disjoint value sets, yet they share one trie node, so one declaration 404s"
    else:
        components = list(second.components)
        components[index] = _component_sample(first.components[index])
        path = _concrete_path(components)
        detail = "the parameter converters accept overlapping ranges while sharing one trie node"

    resolved_name = _resolve_witness(app, method, path)
    winner = first if resolved_name == first.handler_name else second
    loser = second if winner is first else first
    return RouteConflict(
        kind=ConflictKind.OVERLAPPING,
        first=first,
        second=second,
        reason=f"{detail}; '{loser.describe()}' never receives a request because '{winner.describe()}' owns the node",
        witness=_build_witness(app, method, path),
    )


def _find_divergence(
    first_components: Sequence[str | PathParameterDefinition],
    second_components: Sequence[str | PathParameterDefinition],
) -> int:
    """Index of the first segment that does not merge into the same trie child."""
    limit = min(len(first_components), len(second_components))
    for index in range(limit):
        a, b = first_components[index], second_components[index]
        a_param = isinstance(a, PathParameterDefinition)
        b_param = isinstance(b, PathParameterDefinition)
        if a_param and b_param:
            # every parameter type shares the single sentinel child; a 'path' parameter, however, terminates
            # the traversal and greedily consumes the remainder, so it diverges from a continuing route
            if _kind(a) == "path" or _kind(b) == "path":
                return index
            continue
        if a_param != b_param or a != b:
            return index
    return limit


def _different_skeleton_conflict(
    app: Litestar,
    method: Method | Literal["websocket", "asgi"],
    first: RouteDeclaration,
    second: RouteDeclaration,
) -> RouteConflict | None:
    first_components = first.components
    second_components = second.components
    divergence = _find_divergence(first_components, second_components)

    a = first_components[divergence] if divergence < len(first_components) else None
    b = second_components[divergence] if divergence < len(second_components) else None

    prefix_components = list(first_components[:divergence])

    # one declaration ends at this position while the other continues
    if a is None or b is None:
        continuing_components = first_components if a is not None else second_components
        continuing = continuing_components[divergence]
        if isinstance(continuing, PathParameterDefinition) and _kind(continuing) == "path":
            # a 'path' parameter ending here greedily swallows the other side's remaining segments
            return _path_greedy_conflict(app, method, first, second, divergence)
        # a trailing literal / single-segment parameter needs one more segment, so the path sets are disjoint
        return None

    if isinstance(a, str) and isinstance(b, str) and a != b:
        return None

    # a ``path`` parameter greedily swallows every remaining component at the divergence position
    if (isinstance(a, PathParameterDefinition) and _kind(a) == "path") or (
        isinstance(b, PathParameterDefinition) and _kind(b) == "path"
    ):
        return _path_greedy_conflict(app, method, first, second, divergence)

    if (
        a is not None
        and b is not None
        and isinstance(a, PathParameterDefinition)
        and isinstance(b, PathParameterDefinition)
    ):
        # both are single-segment parameters with different tails below the shared sentinel; literal children
        # below the sentinel are tried first, so the tails are reachable independently unless the remaining
        # templates coincide, in which case both routes merge at the same node
        return _parameter_tails_conflict(app, method, first, second, divergence)

    # one side is a literal, the other is a parameter: static priority decides for every path the literal
    # can accept; only report when the literal is provably inside the parameter's accepted range
    literal_side: RouteDeclaration
    literal_component: str
    param_component: str | PathParameterDefinition
    if isinstance(a, str) and isinstance(b, PathParameterDefinition):
        literal_side = first
        literal_component, param_component = a, b
    elif isinstance(b, str) and isinstance(a, PathParameterDefinition):
        literal_side = second
        literal_component, param_component = b, a
    else:
        # length-based split where one template ends and the other continues: no concrete path satisfies both
        return None

    acceptance = _accepts_literal(param_component, literal_component)
    if acceptance is False:
        return None
    if acceptance is None:
        return _unknown_literal_conflict(
            app,
            method,
            first=first,
            second=second,
            prefix_components=prefix_components,
            literal_side=literal_side,
            literal_component=literal_component,
        )

    # the literal route and parameter route share a concrete path; static priority resolves it deterministically,
    # so this is normal "static route wins" behaviour
    param_name = getattr(param_component, "name", "?")
    param_type_name = getattr(getattr(param_component, "type", None), "__name__", "?")
    witness_path = _concrete_path([*prefix_components, literal_component])
    return RouteConflict(
        kind=ConflictKind.STATIC_PRIORITY,
        first=first,
        second=second,
        reason=(
            f"the static segment '{literal_component}' also matches the parameter "
            f"{{{param_name}:{param_type_name}}}; "
            "the router prefers the static declaration, so both remain reachable"
        ),
        witness=_build_witness(app, method, witness_path),
    )


def _unknown_literal_conflict(
    app: Litestar,
    method: Method | Literal["websocket", "asgi"],
    *,
    first: RouteDeclaration,
    second: RouteDeclaration,
    prefix_components: list[str | PathParameterDefinition],
    literal_side: RouteDeclaration,
    literal_component: str,
) -> RouteConflict:
    witness_path = _concrete_path([*prefix_components, literal_component])
    return RouteConflict(
        kind=ConflictKind.UNKNOWN,
        first=first,
        second=second,
        reason=(
            f"the static segment '{literal_component}' may match an unsupported custom converter on "
            f"'{literal_side.handler_name}'; mutual exclusion cannot be proven without executing the converter"
        ),
        witness=_build_witness(app, method, witness_path),
    )


def _path_greedy_conflict(
    app: Litestar,
    method: Method | Literal["websocket", "asgi"],
    first: RouteDeclaration,
    second: RouteDeclaration,
    divergence: int,
) -> RouteConflict | None:
    """Handle a divergence where one side is a greedy ``path`` parameter."""
    first_components = first.components
    second_components = second.components

    def is_path_at(components: Sequence[str | PathParameterDefinition]) -> bool:
        return divergence < len(components) and isinstance(components[divergence], PathParameterDefinition) and _kind(
            components[divergence]
        ) == "path"

    first_is_path = is_path_at(first_components)
    path_side = first if first_is_path else second
    other_side = second if first_is_path else first
    path_components = first_components if first_is_path else second_components
    other_components = second_components if first_is_path else first_components

    prefix_components = list(path_components[:divergence])
    other_component = other_components[divergence] if divergence < len(other_components) else None

    if other_component is None:
        # the other declaration ends exactly where the path parameter starts: no concrete path satisfies both
        return None

    if not isinstance(other_component, PathParameterDefinition):
        # a literal sibling of the path sentinel is matched before the parameter branch, so the static
        # declaration keeps its own path(s) and the path declaration handles the rest: static priority
        if len(other_components) == divergence + 1:
            shared_path = _concrete_path([*prefix_components, other_component])
        else:
            shared_path = _concrete_path(list(other_components))
        return RouteConflict(
            kind=ConflictKind.STATIC_PRIORITY,
            first=first,
            second=second,
            reason=(
                f"the static segment(s) of '{other_side.describe()}' are matched before the greedy 'path' "
                f"parameter of '{path_side.describe()}'; the static declaration keeps its paths, the path "
                "declaration handles everything else"
            ),
            witness=_build_witness(app, method, shared_path),
        )

    # the other declaration also enters the (single) parameter sentinel at this position; the router commits to
    # the path branch and greedily consumes the remainder, so the other declaration can never be reached
    other_remaining = other_components[divergence:]
    if _has_unknown_parameter(other_side):
        kind = ConflictKind.UNKNOWN
        reason = (
            f"the greedy 'path' parameter of '{path_side.describe()}' appears to swallow every request meant for "
            f"'{other_side.describe()}'; an unsupported custom converter prevents proving the accepted ranges"
        )
    else:
        kind = ConflictKind.SHADOWED
        reason = (
            f"the greedy 'path' parameter of '{path_side.describe()}' swallows every remaining segment once the "
            f"shared parameter branch is entered, so '{other_side.describe()}' (which continues below it) can "
            "never be reached"
        )

    witness_path = _concrete_path(list(other_components))
    return RouteConflict(
        kind=kind,
        first=first,
        second=second,
        reason=reason,
        witness=_build_witness(app, method, witness_path),
    )


def _parameter_tails_conflict(
    app: Litestar,
    method: Method | Literal["websocket", "asgi"],
    first: RouteDeclaration,
    second: RouteDeclaration,
    divergence: int,
) -> RouteConflict | None:
    """Both sides diverge on single-segment parameters and may have tails under the shared sentinel."""
    first_tail = first.components[divergence + 1 :]
    second_tail = second.components[divergence + 1 :]

    if not first_tail or not second_tail:
        # one declaration terminates at the parameter, the other continues: a concrete path cannot both end and
        # have more segments, so the accepted ranges are disjoint
        return None

    tail_divergence = _find_divergence(first_tail, second_tail)
    ta = first_tail[tail_divergence] if tail_divergence < len(first_tail) else None
    tb = second_tail[tail_divergence] if tail_divergence < len(second_tail) else None

    if isinstance(ta, str) and isinstance(tb, str) and ta != tb:
        return None
    if (ta is None or tb is None) and tail_divergence == min(len(first_tail), len(second_tail)):
        return None

    if isinstance(ta, PathParameterDefinition) or isinstance(tb, PathParameterDefinition):
        # literal children below the sentinel are still matched before the nested parameter, so the tails stay
        # independently reachable via static priority
        return None

    # tails coincide structurally all the way: both routes merge at the same deeper node; registration order
    # decides, and different converters at the divergence only affect who 404s
    return _shadowed_conflict(
        app,
        method,
        first,
        second,
        "parameter routes merge at the same trie node after their parameter sentinel",
    )


def _analyse_mount_pair(
    app: Litestar,
    method: Method | Literal["websocket", "asgi"],
    first: RouteDeclaration,
    second: RouteDeclaration,
) -> RouteConflict | None:
    """Analyse pairs involving a mount (prefix-greedy ASGI) declaration.

    A mount handles its own prefix and every path nested under it. Exact path collisions between a mount and a
    regular handler are rejected by the existing trie validation; nested static handlers take priority over the
    mount (normal static priority).
    """
    if first.is_mount and second.is_mount:
        mount_a = normalize_path(first.path)
        mount_b = normalize_path(second.path)
        if mount_a == mount_b:
            return _shadowed_conflict(app, method, first, second, "duplicate mount prefixes share one node")
        short, long_ = sorted((mount_a, mount_b), key=len)
        if long_.startswith(f"{short}/"):
            # the outer mount's prefix regex greedily claims the nested mount's prefix, so the nested mount
            # never receives a request
            path = long_
            resolved_name = _resolve_witness(app, method, path)
            winner = first if resolved_name == first.handler_name else second
            loser = second if winner is first else first
            return RouteConflict(
                kind=ConflictKind.SHADOWED,
                first=first,
                second=second,
                reason=(
                    f"mount prefix '{loser.path}' is nested inside '{winner.path}', whose prefix match claims it "
                    "first; the nested mount never receives a request"
                ),
                witness=_build_witness(app, method, path),
            )
        return None

    mount = first if first.is_mount else second
    other = second if first.is_mount else first
    mount_path = normalize_path(mount.path)
    other_path = normalize_path(other.path)

    if other_path == mount_path:
        return _shadowed_conflict(app, method, first, second, "a declaration shares the exact mount prefix")

    if other_path.startswith(f"{mount_path}/"):
        has_parameter = any(isinstance(component, PathParameterDefinition) for component in other.components)
        if not has_parameter:
            # a nested static declaration always wins for its own exact path: normal static priority
            return RouteConflict(
                kind=ConflictKind.STATIC_PRIORITY,
                first=first,
                second=second,
                reason=(
                    f"'{other.describe()}' is nested under mount prefix '{mount_path}' and takes priority for its "
                    "exact path, while the mount handles the rest"
                ),
                witness=_build_witness(app, other.method, other_path),
            )
        # a parameter route nested under a mount is rejected at trie validation; nothing to report here
        return None
    return None


def _collect_declarations(
    routes: Sequence[BaseRoute],
) -> tuple[
    dict[Method | Literal["websocket", "asgi"], list[RouteDeclaration]],
    list[RouteDeclaration],
]:
    """Group method-scoped declarations in registration order.

    Mounts are returned separately: they are prefix-greedy and compete with every HTTP method scope.
    """
    buckets: dict[Method | Literal["websocket", "asgi"], list[RouteDeclaration]] = {}
    mounts: list[RouteDeclaration] = []
    order = 0
    for route in routes:
        if isinstance(route, HTTPRoute):
            for http_method, handler in route.route_handler_map.items():
                buckets.setdefault(http_method, []).append(
                    RouteDeclaration(route=route, method=http_method, handler=handler, order=order)
                )
                order += 1
        else:
            handler = route.route_handler
            is_mount = bool(getattr(handler, "is_mount", False))
            declaration = RouteDeclaration(
                route=route, method="asgi" if is_mount else "websocket", handler=handler, order=order
            )
            if is_mount:
                mounts.append(declaration)
            else:
                buckets.setdefault(declaration.method, []).append(declaration)
            order += 1
    return buckets, mounts


def check_route_conflicts(app: Litestar) -> RouteConflictReport:
    """Check the application's registered routes for conflicting declarations at startup time.

    The check is purely declarative: it compares normalized path templates using the same rules as the router
    (literal segments win, parameters share sentinel nodes, ``path`` is greedy) and verifies each finding by
    resolving concrete paths through the live routing trie. No handler is ever invoked.

    Args:
        app: A configured :class:`~litestar.app.Litestar` instance whose routing trie has been built.

    Returns:
        A :class:`RouteConflictReport` describing shadowed declarations, overlapping parameter routes,
        informational static-priority relationships and unknown relations involving custom converters.
    """
    findings: list[RouteConflict] = []
    buckets, mounts = _collect_declarations(app.routes)
    for method, declarations in buckets.items():
        for first, second in combinations(declarations, 2):
            finding = _analyse_pair(app, method, first, second)
            if finding is not None:
                findings.append(finding)
    for mount, other_mount in combinations(mounts, 2):
        mount_finding = _analyse_mount_pair(app, "asgi", mount, other_mount)
        if mount_finding is not None:
            findings.append(mount_finding)
    for mount in mounts:
        for method, declarations in buckets.items():
            for declaration in declarations:
                finding = _analyse_mount_pair(app, method, mount, declaration)
                if finding is not None:
                    findings.append(finding)
    return RouteConflictReport(findings)
