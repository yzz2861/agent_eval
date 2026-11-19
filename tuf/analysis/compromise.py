# Copyright 2026, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Minimum key-compromise analysis for a single TUF target.

This module is a read-only, offline analysis helper intended to be embedded
in a release/publishing backend. Given already verified repository metadata
and a target path it computes the smallest set of signing keyids whose
compromise would let an attacker publish an unauthorized update for that
target.

The analysis treats the trust graph as a whole rather than inspecting role
thresholds in isolation:

* A target may be reachable through several alternative delegation paths;
  the attacker only needs to defeat one of them.
* Every role on a chosen path is a "gate" that requires ``threshold`` of its
  delegator-defined keys to be compromised.
* The same keyid may guard more than one gate (and the top-level timestamp,
  snapshot and targets roles). Shared keyids are deduplicated: one
  compromised key unlocks every gate it appears in and is counted once.

The solver is an exact branch-and-bound search over the key universe of the
relevant graph. An independent, deliberately simple exhaustive solver is
provided and used by the test-suite to cross-check the optimized solver on
small graphs.

The analyzer reads public metadata only. It never requires or accesses a
private key and it never mutates the metadata objects it is given.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import combinations
from typing import TYPE_CHECKING

from tuf.api.metadata import Root, Snapshot, Targets, Timestamp

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = [
    "LIMIT_DEFAULTS",
    "AnalysisLimits",
    "Assumption",
    "CompromiseAnalysis",
    "CompromiseLimitReachedError",
    "MinimalityWitness",
    "analyze_target_compromise",
    "exhaustive_minimum_keyids",
]


@dataclass(frozen=True)
class AnalysisLimits:
    """Upper bounds that keep the combinatorial search predictable.

    The minimum-compromise problem is NP-hard. The search aborts with an
    incomplete result instead of running unbounded, so that an embedding
    service can guarantee its latency.

    Args:
        max_keys: Maximum number of distinct keyids in the analyzed
            sub-graph. Graphs larger than this are not solved exactly.
        max_gates: Maximum number of signing gates considered.
        max_routes: Maximum number of distinct complete delegation routes
            enumerated for the target.
        max_subsets: Maximum number of key subsets inspected by the
            branch-and-bound or exhaustive search.
    """

    max_keys: int = 64
    max_gates: int = 256
    max_routes: int = 4096
    max_subsets: int = 200_000


LIMIT_DEFAULTS = AnalysisLimits()


class CompromiseLimitReachedError(RuntimeError):
    """Raised when an exact search exceeds the configured ``AnalysisLimits``.

    The high level :func:`analyze_target_compromise` never raises this: it
    translates the condition into an incomplete :class:`CompromiseAnalysis`.
    The standalone exhaustive solver raises it so callers can distinguish
    "too large to prove" from a genuine result.
    """


@dataclass(frozen=True)
class Assumption:
    """An analysis boundary that the result does *not* cover.

    Args:
        code: Stable machine-readable identifier of the boundary.
        message: Human-readable explanation of what was not modeled.
    """

    code: str
    message: str


@dataclass(frozen=True)
class MinimalityWitness:
    """Evidence that the reported key set cannot be made any smaller.

    A result is witnessed by:

    * the set of signing gates that had to be defeated, each with its
      delegator-defined threshold and accepted keyids;
    * every alternative delegation route that was compared (the attacker
      picks the cheapest one);
    * the proof method used and, for the exhaustive proof, the number of
      key subsets inspected;
    * the list of all minimum-size solutions, which makes key reuse visible.

    Args:
        gates: Mapping of gate name to ``(threshold, keyids)`` requirements.
        routes: All complete routes enumerated for the target.
        proof: ``"exhaustive"`` or ``"branch-and-bound"``.
        subsets_inspected: Number of key subsets visited by the solver.
        alternative_minima: Every minimum keyid set found.
    """

    gates: dict[str, tuple[int, tuple[str, ...]]]
    routes: tuple[tuple[str, ...], ...]
    proof: str
    subsets_inspected: int
    alternative_minima: tuple[frozenset[str], ...]


@dataclass(frozen=True)
class CompromiseAnalysis:
    """Result of analyzing one target path.

    Args:
        target_path: The analyzed target path.
        reachable: ``True`` if an existing, verified role currently publishes
            the target. ``False`` means no reachable role holds it, so it
            cannot be updated without first adding it (out of model scope).
        complete: ``True`` if the minimum was proven. ``False`` means a limit
            was hit; ``minimum_keyids`` is then only a best effort.
        minimum_keyids: Smallest proven (or best effort) keyid set.
        witness: Minimality evidence.
        assumptions: Boundaries not covered by the analysis.
    """

    target_path: str
    reachable: bool
    complete: bool
    minimum_keyids: frozenset[str]
    witness: MinimalityWitness | None
    assumptions: tuple[Assumption, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class _Gate:
    """A single signing requirement on a delegation route.

    A gate models the threshold check a client performs when loading one
    piece of metadata. ``keyids`` are the keys accepted by the *delegator*
    for this specific link, so the same role reached through different
    delegators yields distinct gates (matching client verification).
    """

    name: str
    threshold: int
    keyids: frozenset[str]


@dataclass(frozen=True)
class _Route:
    """One complete way to deliver the target, expressed as gates."""

    roles: tuple[str, ...]
    gates: tuple[_Gate, ...]


def _top_level_gates(root: Root) -> dict[str, _Gate]:
    """Return the timestamp/snapshot/targets gates defined by root."""

    gates = {}
    for role_name in (Timestamp.type, Snapshot.type, Targets.type):
        role = root.roles[role_name]
        gates[role_name] = _Gate(
            role_name, role.threshold, frozenset(role.keyids)
        )
    return gates


def _child_roles(
    targets: Targets, target_path: str
) -> tuple[tuple[str, bool, int, tuple[str, ...]], ...]:
    """Return delegated children matching target_path, in delegation order.

    Each item carries the child name, its terminating flag and the
    delegator-defined threshold and accepted keyids for this link.
    """

    delegations = targets.delegations
    if delegations is None:
        return ()

    results: list[tuple[str, bool, int, tuple[str, ...]]] = []
    if delegations.roles is not None:
        for role in delegations.roles.values():
            if not role.is_delegated_path(target_path):
                continue
            results.append(
                (
                    role.name,
                    role.terminating,
                    role.threshold,
                    tuple(role.keyids),
                )
            )
    elif delegations.succinct_roles is not None:
        succinct = delegations.succinct_roles
        name = succinct.get_role_for_target(target_path)
        results.append(
            (
                name,
                True,
                succinct.threshold,
                tuple(succinct.keyids),
            )
        )
    return tuple(results)


def _enumerate_routes(
    targets_metadata: Mapping[str, Targets],
    top_gates: Mapping[str, _Gate],
    target_path: str,
    limits: AnalysisLimits,
) -> tuple[tuple[_Route, ...], tuple[Assumption, ...]]:
    """Enumerate every complete delegation route for ``target_path``.

    A route starts with the root-defined timestamp, snapshot and targets
    gates and continues through matching delegations. A route is "complete"
    when its final role currently publishes the target. Roles already on the
    current path are not re-entered, which breaks delegation cycles.
    """

    assumptions: list[Assumption] = []
    routes: list[_Route] = []
    base_gates = (
        top_gates[Timestamp.type],
        top_gates[Snapshot.type],
        top_gates[Targets.type],
    )
    base_roles = (Timestamp.type, Snapshot.type, Targets.type)

    def visit(
        role_name: str,
        roles: tuple[str, ...],
        gates: tuple[_Gate, ...],
    ) -> None:
        if len(routes) >= limits.max_routes:
            return

        signed = targets_metadata.get(role_name)
        if signed is None:
            assumptions.append(
                Assumption(
                    "missing-metadata",
                    f"Verified metadata for role '{role_name}' was not "
                    "provided; routes through it are not modeled",
                )
            )
            return

        if target_path in signed.targets:
            routes.append(_Route(roles, gates))

        for child_name, _terminating, threshold, keyids in _child_roles(
            signed, target_path
        ):
            if child_name in roles or len(routes) >= limits.max_routes:
                if child_name in roles:
                    assumptions.append(
                        Assumption(
                            "delegation-cycle",
                            f"Role '{child_name}' appears again on a route; "
                            "the cycle was not followed",
                        )
                    )
                continue

            child_gate = _Gate(
                f"{role_name}->{child_name}", threshold, frozenset(keyids)
            )
            visit(
                child_name,
                (*roles, child_name),
                (*gates, child_gate),
            )

    visit(Targets.type, base_roles, base_gates)

    if len(routes) >= limits.max_routes:
        assumptions.append(
            Assumption(
                "route-limit",
                f"More than {limits.max_routes} delegation routes exist; "
                "not all routes were enumerated",
            )
        )

    return tuple(routes), tuple(assumptions)


def _route_key_universe(routes: tuple[_Route, ...]) -> frozenset[str]:
    """All distinct keyids guarding any gate on any route."""

    universe: set[str] = set()
    for route in routes:
        for gate in route.gates:
            universe.update(gate.keyids)
    return frozenset(universe)


def _all_gates(routes: tuple[_Route, ...]) -> dict[str, _Gate]:
    """Collect every distinct gate, keyed by its unique gate name."""

    gates: dict[str, _Gate] = {}
    for route in routes:
        for gate in route.gates:
            gates[gate.name] = gate
    return gates


def _defeats_route(compromised: frozenset[str], route: _Route) -> bool:
    """True if ``compromised`` meets the threshold of every route gate.

    A keyid is tested against every gate but counted only once because
    ``compromised`` is a set: shared keys naturally unlock multiple gates.
    """

    return all(
        len(gate.keyids & compromised) >= gate.threshold for gate in route.gates
    )


def exhaustive_minimum_keyids(
    routes: tuple[_Route, ...], limits: AnalysisLimits = LIMIT_DEFAULTS
) -> tuple[frozenset[str], int]:
    """Return every minimum key set using a simple exhaustive search.

    This is the independent reference solver: it enumerates key subsets in
    strictly increasing size and returns the first size that defeats a
    route. The deliberately simple implementation is cross-checked against
    the branch-and-bound solver on small graphs.

    Raises :class:`CompromiseLimitReachedError` if the universe or the subset
    budget configured in ``limits`` is exceeded.
    """

    universe = _route_key_universe(routes)
    if len(universe) > limits.max_keys:
        raise CompromiseLimitReachedError(
            f"key universe has {len(universe)} keys, limit is {limits.max_keys}"
        )

    ordered = tuple(universe)
    inspected = 0
    size = 1
    while size <= len(ordered):
        minima: list[frozenset[str]] = []
        for combo in combinations(range(len(ordered)), size):
            inspected += 1
            if inspected > limits.max_subsets:
                raise CompromiseLimitReachedError(
                    f"inspected {inspected} subsets, limit is "
                    f"{limits.max_subsets}"
                )
            candidate = frozenset(ordered[i] for i in combo)
            if any(_defeats_route(candidate, route) for route in routes):
                minima.append(candidate)
        if minima:
            return tuple(minima), inspected
        size += 1
    raise CompromiseLimitReachedError("no key subset can defeat any route")


def _route_lower_bound(
    route: _Route,
    chosen: frozenset[str],
    available: frozenset[str],
) -> int:
    """Minimum extra distinct keys needed to satisfy one route.

    Each unsatisfied gate contributes its remaining threshold deficit;
    keys already chosen are reused and never double counted. This is a
    valid (admissible) lower bound because a key can satisfy at most one
    unit of a single gate threshold.
    """

    # A route is still completable only if every unsatisfied gate has
    # enough unchosen keys left to meet its threshold. The largest single
    # gate deficit is an admissible lower bound: the same key may satisfy
    # several gates, but one key can never cover more than one threshold
    # slot of a single gate.
    largest_deficit = 0
    for gate in route.gates:
        deficit = gate.threshold - len(gate.keyids & chosen)
        if deficit <= 0:
            continue
        if len((gate.keyids & available) - chosen) < deficit:
            return -1
        largest_deficit = max(largest_deficit, deficit)
    return largest_deficit


class _SearchState:
    """Shared mutable state for the branch-and-bound walks."""

    def __init__(
        self,
        routes: tuple[_Route, ...],
        universe: tuple[str, ...],
        limits: AnalysisLimits,
    ) -> None:
        self.routes = routes
        self.universe = universe
        self.limits = limits
        self.inspected = 0

    def tick(self) -> None:
        self.inspected += 1
        if self.inspected > self.limits.max_subsets:
            raise CompromiseLimitReachedError(
                f"inspected {self.inspected} subsets, limit is "
                f"{self.limits.max_subsets}"
            )

    def bound_of(self, chosen: frozenset[str], index: int) -> int:
        # Smallest possible completion using keys not decided against.
        available = frozenset(self.universe[index:]) | chosen
        bound = len(self.universe) + 1
        for route in self.routes:
            extra = _route_lower_bound(route, chosen, available)
            if extra >= 0:
                bound = min(bound, len(chosen) + extra)
        return bound

    def defeats(self, chosen: frozenset[str]) -> bool:
        return any(_defeats_route(chosen, route) for route in self.routes)


def _find_minimum_size(
    state: _SearchState, index: int, chosen: frozenset[str]
) -> int:
    """Phase one: return the smallest defeating set size."""

    state.tick()
    if state.defeats(chosen):
        return len(chosen)
    if index == len(state.universe):
        return len(state.universe) + 1
    key = state.universe[index]
    include = _find_minimum_size(state, index + 1, chosen | frozenset((key,)))
    # The exclusion branch is worth visiting only if its bound can still
    # beat the incumbent reached through inclusion.
    if state.bound_of(chosen, index + 1) < include:
        exclude = _find_minimum_size(state, index + 1, chosen)
        return min(include, exclude)
    return include


def _collect_minima(
    state: _SearchState,
    index: int,
    chosen: frozenset[str],
    minimum_size: int,
    minima: list[frozenset[str]],
) -> None:
    """Phase two: gather every defeating set of exactly minimum_size."""

    state.tick()
    if len(chosen) > minimum_size:
        return
    if len(chosen) == minimum_size:
        if state.defeats(chosen):
            minima.append(chosen)
        return
    if index == len(state.universe):
        return
    if state.bound_of(chosen, index) > minimum_size:
        return
    key = state.universe[index]
    _collect_minima(
        state, index + 1, chosen | frozenset((key,)), minimum_size, minima
    )
    _collect_minima(state, index + 1, chosen, minimum_size, minima)


def _branch_and_bound(
    routes: tuple[_Route, ...], limits: AnalysisLimits
) -> tuple[tuple[frozenset[str], ...], int]:
    """Exact branch-and-bound minimum over the route key universe.

    Phase one finds the smallest defeating set size with an admissible
    per-route lower bound. Phase two fixes that size and enumerates every
    set of exactly that size, so all minimum solutions are reported even
    when phase one pruned equal-size branches. Shared keyids live in one
    set, so a reused key is counted once.
    """

    universe = tuple(sorted(_route_key_universe(routes)))
    state = _SearchState(routes, universe, limits)

    minimum_size = _find_minimum_size(state, 0, frozenset())
    if minimum_size > len(universe):
        raise CompromiseLimitReachedError("no key subset can defeat any route")

    minima: list[frozenset[str]] = []
    _collect_minima(state, 0, frozenset(), minimum_size, minima)
    if not minima:
        raise CompromiseLimitReachedError("no key subset can defeat any route")
    unique_minima = tuple(
        sorted(set(minima), key=lambda item: tuple(sorted(item)))
    )
    return unique_minima, state.inspected


def analyze_target_compromise(
    root: Root,
    targets_metadata: Mapping[str, Targets],
    target_path: str,
    limits: AnalysisLimits = LIMIT_DEFAULTS,
) -> CompromiseAnalysis:
    """Analyze the minimum key compromise for one target path.

    Args:
        root: Verified root metadata. It defines the timestamp, snapshot
            and targets role keys and thresholds.
        targets_metadata: Verified targets metadata keyed by role name.
            Must include the top-level ``"targets"`` role and any delegated
            targets role that should be considered.
        target_path: The target whose unauthorized update is analyzed.
        limits: Search bounds. Exceeding them yields an incomplete result
            rather than an unbounded computation.

    Returns:
        A :class:`CompromiseAnalysis`. The result is never ``None``; limit
        and reachability conditions are reported through ``complete``,
        ``reachable`` and ``assumptions``.
    """

    assumptions: list[Assumption] = [
        Assumption(
            "root-trusted",
            "Root metadata is assumed trustworthy: root key compromise is"
            " not modeled",
        )
    ]

    top_gates = _top_level_gates(root)
    routes, route_assumptions = _enumerate_routes(
        targets_metadata, top_gates, target_path, limits
    )
    assumptions.extend(route_assumptions)

    satisfiable: list[_Route] = []
    for route in routes:
        bad = next(
            (gate for gate in route.gates if len(gate.keyids) < gate.threshold),
            None,
        )
        if bad is None:
            satisfiable.append(route)
        else:
            assumptions.append(
                Assumption(
                    "unsatisfiable-gate",
                    f"Gate {bad.name} needs {bad.threshold} keys but only "
                    f"{len(bad.keyids)} are defined; route excluded",
                )
            )
    routes = tuple(satisfiable)

    if not routes:
        return CompromiseAnalysis(
            target_path=target_path,
            reachable=False,
            complete=True,
            minimum_keyids=frozenset(),
            witness=None,
            assumptions=tuple(_dedupe(assumptions)),
        )

    gates = _all_gates(routes)
    universe = _route_key_universe(routes)
    if len(gates) > limits.max_gates or len(universe) > limits.max_keys:
        assumptions.append(
            Assumption(
                "size-limit",
                f"Graph has {len(gates)} gates and {len(universe)} distinct"
                f" keys; exceeds limits, no exact minimum was proven",
            )
        )
        return CompromiseAnalysis(
            target_path=target_path,
            reachable=True,
            complete=False,
            minimum_keyids=frozenset(),
            witness=None,
            assumptions=tuple(_dedupe(assumptions)),
        )

    proof = "exhaustive"
    try:
        minima, subsets = exhaustive_minimum_keyids(routes, limits)
    except CompromiseLimitReachedError:
        proof = "branch-and-bound"
        try:
            minima, subsets = _branch_and_bound(routes, limits)
        except CompromiseLimitReachedError:
            assumptions.append(
                Assumption(
                    "search-limit",
                    "Search budget exhausted before a minimum was proven",
                )
            )
            return CompromiseAnalysis(
                target_path=target_path,
                reachable=True,
                complete=False,
                minimum_keyids=frozenset(),
                witness=None,
                assumptions=tuple(_dedupe(assumptions)),
            )

    witness = MinimalityWitness(
        gates={
            name: (gate.threshold, tuple(sorted(gate.keyids)))
            for name, gate in gates.items()
        },
        routes=tuple(route.roles for route in routes),
        proof=proof,
        subsets_inspected=subsets,
        alternative_minima=tuple(minima),
    )
    return CompromiseAnalysis(
        target_path=target_path,
        reachable=True,
        complete=True,
        minimum_keyids=minima[0],
        witness=witness,
        assumptions=tuple(_dedupe(assumptions)),
    )


def _dedupe(assumptions: list[Assumption]) -> list[Assumption]:
    """Remove duplicate assumptions while preserving order."""

    seen: set[tuple[str, str]] = set()
    unique: list[Assumption] = []
    for assumption in assumptions:
        marker = (assumption.code, assumption.message)
        if marker not in seen:
            seen.add(marker)
            unique.append(assumption)
    return unique
