from __future__ import annotations

import dataclasses
import heapq
import inspect
from typing import TYPE_CHECKING, Any

from litestar.exceptions import ImproperlyConfiguredException
from litestar.middleware.base import ASGIMiddleware, DefineMiddleware

if TYPE_CHECKING:
    from collections.abc import Sequence

    from litestar.types import Middleware

__all__ = (
    "DuplicateMiddlewareNameError",
    "MiddlewareCycleError",
    "MiddlewareExecutionOrder",
    "MiddlewareLayerError",
    "MiddlewareOrderingError",
    "MissingMiddlewareError",
    "get_middleware_execution_order",
    "middleware_layer_label",
    "resolve_middleware_order",
)


class MiddlewareOrderingError(ImproperlyConfiguredException):
    """Base exception for errors raised while resolving middleware ordering."""


class DuplicateMiddlewareNameError(MiddlewareOrderingError):
    """Raised when multiple middlewares declare the same stable name."""


class MissingMiddlewareError(MiddlewareOrderingError):
    """Raised when a name-based ordering constraint references a middleware name that
    is not registered on the application.
    """


class MiddlewareLayerError(MiddlewareOrderingError):
    """Raised when satisfying an ordering constraint would require moving a middleware
    across a layer (application / router / controller / handler) boundary.
    """


class MiddlewareCycleError(MiddlewareOrderingError):
    """Raised when ordering constraints form a cycle."""


@dataclasses.dataclass(frozen=True)
class MiddlewareExecutionOrder:
    """The resolved order in which middleware is executed for a route handler."""

    enter: tuple[str, ...]
    """Display names of the middleware in the order they see the incoming request
    (outermost first)."""
    exit: tuple[str, ...]
    """Display names of the middleware in the order they see the outgoing response
    (innermost first)."""


def _fully_qualified_name(obj: Any) -> str:
    return f"{obj.__module__}.{obj.__qualname__}"


def _display_name(middleware: Middleware) -> str:
    """Return the display name for a middleware: its stable 'name' if it declares
    one, otherwise a fully qualified name of the middleware or its type.
    """
    if isinstance(middleware, ASGIMiddleware) and middleware.name:
        return middleware.name
    if isinstance(middleware, DefineMiddleware):
        return _fully_qualified_name(middleware.middleware)
    if inspect.isfunction(middleware) or inspect.isclass(middleware):
        return _fully_qualified_name(middleware)
    return _fully_qualified_name(type(middleware))


def middleware_layer_label(owner: Any) -> str:
    """Return a human-readable label for the layer 'owner' (an application, router
    or controller) represents in the middleware hierarchy.
    """
    from litestar.app import Litestar
    from litestar.router import Router

    if isinstance(owner, Litestar):
        return "application"
    if isinstance(owner, Router):
        controller = getattr(owner, "_controller", None)
        if controller is not None:
            return f"controller {type(controller).__name__!r}"
        return f"router {owner.path!r}"
    return f"layer {owner!r}"


@dataclasses.dataclass
class _MiddlewareEntry:
    index: int
    layer: str
    rank: int
    middleware: Middleware
    name: str | None
    before: tuple[str, ...]
    after: tuple[str, ...]

    @property
    def description(self) -> str:
        identifier = f"name {self.name!r}" if self.name is not None else repr(_display_name(self.middleware))
        return f"{identifier} (layer {self.layer!r}, index {self.index})"


def _ordering_info(middleware: Middleware) -> tuple[str | None, tuple[str, ...], tuple[str, ...]]:
    """Extract (name, before_names, after_names) ordering info from a middleware.

    Only 'ASGIMiddleware' instances can declare a stable name and name-based ordering
    constraints; anything else is treated as an unconstrained, unnamed middleware.
    """
    if not isinstance(middleware, ASGIMiddleware):
        return None, (), ()

    constraints = middleware.constraints
    if constraints is None:
        return middleware.name, (), ()

    before = tuple(constraint for constraint in constraints.before if isinstance(constraint, str))
    after = tuple(constraint for constraint in constraints.after if isinstance(constraint, str))
    return middleware.name, before, after


def _check_duplicate_names(entries: list[_MiddlewareEntry]) -> dict[str, _MiddlewareEntry]:
    by_name: dict[str, list[_MiddlewareEntry]] = {}
    for entry in entries:
        if entry.name is not None:
            by_name.setdefault(entry.name, []).append(entry)

    duplicates = {name: named_entries for name, named_entries in by_name.items() if len(named_entries) > 1}
    if duplicates:
        details = []
        for name, named_entries in duplicates.items():
            locations = "\n".join(
                f"  - {_display_name(entry.middleware)!r} in layer {entry.layer!r} at index {entry.index}"
                for entry in named_entries
            )
            details.append(f"Middleware name {name!r} is declared {len(named_entries)} times:\n{locations}")
        msg = "Duplicate middleware names found:\n" + "\n".join(details)
        raise DuplicateMiddlewareNameError(msg)

    return {name: named_entries[0] for name, named_entries in by_name.items()}


def _build_edges(
    entries: list[_MiddlewareEntry], by_name: dict[str, _MiddlewareEntry], strict: bool
) -> dict[int, set[int]]:
    """Build the 'must come before' graph.

    An edge 'u -> v' means the middleware at index 'u' must be executed before the
    middleware at index 'v'. If 'strict' is False, constraints referencing names
    that are not present are skipped instead of raising an error.
    """
    edges: dict[int, set[int]] = {entry.index: set() for entry in entries}
    missing: list[str] = []

    for entry in entries:
        for direction, names in (("before", entry.before), ("after", entry.after)):
            for name in names:
                target = by_name.get(name)
                if target is None:
                    if not strict:
                        continue
                    entry_name = entry.name or _display_name(entry.middleware)
                    chain = f"{entry_name!r} -> {name!r}" if direction == "before" else f"{name!r} -> {entry_name!r}"
                    missing.append(
                        f"Middleware {entry.description} requires a middleware named {name!r} to be "
                        f"present ({direction} constraint), but no middleware with that name is registered. "
                        f"Chain: {chain}"
                    )
                    continue
                if direction == "before":
                    edges[entry.index].add(target.index)
                else:
                    edges[target.index].add(entry.index)

    if missing:
        msg = "Missing middleware referenced by ordering constraints:\n" + "\n".join(missing)
        raise MissingMiddlewareError(msg)

    return edges


def _check_layer_violations(entries: list[_MiddlewareEntry], edges: dict[int, set[int]]) -> None:
    by_index = {entry.index: entry for entry in entries}
    violations = []
    for source, targets in edges.items():
        source_entry = by_index[source]
        for target in targets:
            target_entry = by_index[target]
            if source_entry.rank > target_entry.rank:
                source_name = source_entry.name or _display_name(source_entry.middleware)
                target_name = target_entry.name or _display_name(target_entry.middleware)
                violations.append(
                    f"Middleware {source_entry.description} must come before "
                    f"{target_entry.description}, but middleware of layer {source_entry.layer!r} cannot "
                    f"be moved before middleware of layer {target_entry.layer!r}. Chain: "
                    f"{source_name!r} -> {target_name!r}"
                )
    if violations:
        msg = (
            "Middleware ordering constraints cannot be satisfied without moving middleware across "
            "layers:\n" + "\n".join(violations)
        )
        raise MiddlewareLayerError(msg)


def _find_cycle(graph: dict[int, set[int]], nodes: set[int]) -> list[int]:
    """Find a cycle within 'nodes' and return it as a list of indices."""
    color: dict[int, int] = {}
    stack: list[int] = []

    def dfs(node: int) -> list[int] | None:
        color[node] = 1
        stack.append(node)
        for neighbor in graph.get(node, ()):
            if neighbor not in nodes:
                continue
            if color.get(neighbor) == 1:
                return [*stack[stack.index(neighbor) :], neighbor]
            if color.get(neighbor) is None:
                cycle = dfs(neighbor)
                if cycle:
                    return cycle
        stack.pop()
        color[node] = 2
        return None

    for node in sorted(nodes):
        if color.get(node) is None and (cycle := dfs(node)) is not None:
            return cycle
    return sorted(nodes)  # pragma: no cover


def _topological_sort(entries: list[_MiddlewareEntry], edges: dict[int, set[int]]) -> tuple[Middleware, ...]:
    """Sort the middleware, honoring the constraint edges.

    Uses Kahn's algorithm, always selecting the available middleware with the lowest
    original index, so middleware unaffected by constraints keeps its original
    relative order.
    """
    by_index = {entry.index: entry for entry in entries}
    # edges crossing layer boundaries in the allowed direction are satisfied
    # implicitly by the layer order, so only same-layer edges need to be sorted
    graph = {
        source: {target for target in targets if by_index[target].rank == by_index[source].rank}
        for source, targets in edges.items()
    }
    in_degree = {entry.index: 0 for entry in entries}
    for targets in graph.values():
        for target in targets:
            in_degree[target] += 1

    heap = [index for index, degree in in_degree.items() if degree == 0]
    heapq.heapify(heap)
    sorted_indices: list[int] = []
    while heap:
        index = heapq.heappop(heap)
        sorted_indices.append(index)
        for target in graph[index]:
            in_degree[target] -= 1
            if in_degree[target] == 0:
                heapq.heappush(heap, target)

    if len(sorted_indices) != len(entries):
        remaining = set(in_degree) - set(sorted_indices)
        cycle = _find_cycle(graph, remaining)
        chain = " -> ".join(repr(by_index[index].name or _display_name(by_index[index].middleware)) for index in cycle)
        layers = "; ".join(
            f"{by_index[index].name or _display_name(by_index[index].middleware)!r} in layer {by_index[index].layer!r}"
            for index in cycle[:-1]
        )
        msg = f"Circular middleware ordering constraints detected: {chain}. Layers involved: {layers}"
        raise MiddlewareCycleError(msg)

    return tuple(by_index[index].middleware for index in sorted_indices)


def resolve_middleware_order(
    middleware: Sequence[tuple[str, Middleware]], *, strict: bool = True
) -> tuple[Middleware, ...]:
    """Resolve the execution order of layered middleware.

    Args:
        middleware: A sequence of (layer_label, middleware) pairs, ordered from the
            outermost layer (application) to the innermost one (route handler). Each
            contiguous run of equal labels is treated as a single layer.
        strict: If True, raise 'MissingMiddlewareError' for name-based constraints
            referencing a name that is not declared by any of the given middleware.
            If False, such constraints are ignored. This is useful when resolving
            the order of a partial set of layers.

    Returns:
        The middleware, sorted according to their name-based ordering constraints.
        Middleware without constraints keeps its original relative order, and no
        middleware is moved across layer boundaries.

    Raises:
        DuplicateMiddlewareNameError: If multiple middlewares declare the same name.
        MissingMiddlewareError: If a name-based constraint references a name that is
            not declared by any middleware.
        MiddlewareLayerError: If satisfying a constraint would require moving a
            middleware across a layer boundary.
        MiddlewareCycleError: If the constraints form a cycle.
    """
    entries: list[_MiddlewareEntry] = []
    rank = -1
    previous_layer: str | None = None
    for index, (layer, middleware_item) in enumerate(middleware):
        if layer != previous_layer:
            rank += 1
            previous_layer = layer
        name, before, after = _ordering_info(middleware_item)
        entries.append(
            _MiddlewareEntry(
                index=index,
                layer=layer,
                rank=rank,
                middleware=middleware_item,
                name=name,
                before=before,
                after=after,
            )
        )

    if not any(entry.name is not None or entry.before or entry.after for entry in entries):
        # fast path: no names or constraints declared, keep the original order
        return tuple(entry.middleware for entry in entries)

    by_name = _check_duplicate_names(entries)
    edges = _build_edges(entries, by_name, strict=strict)
    _check_layer_violations(entries, edges)
    return _topological_sort(entries, edges)


def get_middleware_execution_order(middleware: Sequence[Middleware]) -> MiddlewareExecutionOrder:
    """Return the order in which the given middleware is entered and exited when
    handling a request.

    Args:
        middleware: The resolved middleware of a route handler, in the order it is
        applied (outermost first).
    """
    names = tuple(_display_name(middleware_item) for middleware_item in middleware)
    return MiddlewareExecutionOrder(enter=names, exit=tuple(reversed(names)))
