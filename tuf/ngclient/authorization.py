# Copyright 2026, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Offline comparison of two TUF targets delegation configurations.

This module answers a publishing question: after a delegation change, which
target paths are now authorized for the first time by a different set of
signing keys than before?

The comparison is fully offline: it operates on already available
``Metadata[Targets]`` objects and never downloads metadata or contacts a
repository.  It is intentionally separate from ``Updater``: the client update
workflow is unchanged, while this module performs a static analysis of the
delegation graph semantics.

For every concrete witness path inside the requested scope, the module
simulates the same pre-order depth-first delegation traversal that
``Updater.get_targetinfo`` uses, taking into account:

* the ordered list of delegated roles of every delegator,
* ``terminating`` delegations (which stop backtracking),
* arbitrarily nested delegations and diamond-shaped graphs,
* roles that are reachable through more than one parent (only the first
  arrival, in traversal order, is authoritative),
* cycles (a role already visited is never visited twice).

Because target paths can be matched by glob patterns and by hash-prefix
delegations, the analysis distinguishes comparable from incomparable input:

* A literal scope (a path without glob metacharacters) is always comparable,
  even when hash-prefix roles exist elsewhere in the graph.
* A glob scope is only comparable if every delegated role that could match a
  path in the scope uses ordinary ``paths`` patterns.  As soon as a
  ``path_hash_prefixes`` or succinct-roles delegation could match the scope,
  its exact membership cannot be derived from the patterns alone, so the
  scope is reported as unknown instead of guessing.

The result contains concrete witness paths together with the complete
authorization chain on both sides rather than a comparison of raw JSON
fields.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from tuf.api.metadata import DelegatedRole, Metadata, Targets

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

#: Default upper bound for the number of delegated roles visited while
#: resolving a single witness path. Mirrors ``UpdaterConfig.max_delegations``.
DEFAULT_MAX_ROLES = 256

#: Default upper bound for the number of concrete witness paths generated for
#: a comparison.
DEFAULT_MAX_WITNESSES = 256

_GLOB_METACHARACTERS = frozenset("*?[")


class ChangeType(Enum):
    """Kind of difference detected for a witness path."""

    #: The first delegated role that may answer for the path, or its
    #: signing keys, differs between the two configurations.
    OWNERSHIP_CHANGED = "ownership_changed"

    #: The first delegated role and its keys are unchanged, but a later
    #: link of the authorization chain (a nested delegation) differs.
    CHAIN_CHANGED = "chain_changed"


class AuthorizationError(ValueError):
    """Raised when an authorization comparison cannot be completed."""


class UnknownScopeError(AuthorizationError):
    """Raised when a scope cannot be compared offline.

    This happens for a glob scope when one of the bundles uses
    ``path_hash_prefixes`` or succinct-role (hash bin) delegations:
    whether a concrete path belongs to such a role depends on a hash
    preimage that a glob pattern cannot enumerate.
    """


class LimitExceededError(AuthorizationError):
    """Raised when a configured graph or witness limit is exceeded."""


@dataclass(frozen=True)


class AuthorizationLimits:
    """Deterministic caps for the offline comparison.

    Args:
        max_roles: Maximum number of role visits while resolving one
            witness path. Guards against pathological delegation graphs.
        max_witnesses: Maximum number of concrete witness paths generated
            for the whole comparison.
    """

    max_roles: int = DEFAULT_MAX_ROLES
    max_witnesses: int = DEFAULT_MAX_WITNESSES
    def __post_init__(self) -> None:
        """Validate the configured limits."""
        if self.max_roles < 1 or self.max_witnesses < 1:
            raise ValueError("limits must be positive integers")


@dataclass(frozen=True)


class RoleAuthorization:
    """One link of an :class:`AuthorizationChain`.

    Attributes:
        role: Name of the delegated targets role.
        keyids: Key identifiers authorized for the role by its delegator,
            in the order stored in the delegation.
        threshold: Number of authorized keys required to sign the role.
        terminating: Whether the role terminates target lookup backtracking.
        matched_paths: Ordinary path patterns of this role. Empty for the
            top-level role and for hash-prefix delegations.
        hash_prefixes: ``path_hash_prefixes`` of this role. Empty for
            ordinary path delegations.
    """

    role: str
    keyids: tuple[str, ...]
    threshold: int
    terminating: bool
    matched_paths: tuple[str, ...] = ()
    hash_prefixes: tuple[str, ...] = ()


@dataclass(frozen=True)


class AuthorizationChain:
    """Concrete authorization path for one witness target path.

    The first element is always the top-level ``targets`` role; following
    elements are the delegated roles reached during the pre-order
    depth-first traversal, in traversal order. A role reachable through
    several parents appears only once, at its first arrival.

    Attributes:
        witness: Concrete target path the chain was resolved for.
        roles: Ordered role authorization links.
        missing_role: Role whose targets metadata is absent from the
            bundle, if traversal ran off the end of the known graph.
    """

    witness: str
    roles: tuple[RoleAuthorization, ...]
    missing_role: str | None = None

    @property
    def first_delegated_role(self) -> RoleAuthorization | None:
        """First delegated role reached, or ``None`` for top-level only."""

        if len(self.roles) > 1:
            return self.roles[1]
        return None


@dataclass(frozen=True)


class AuthorizationChange:
    """A semantic authorization difference with concrete evidence.

    Attributes:
        kind: Whether the owning role/keys changed or only a nested link.
        witness_paths: Concrete target paths that exhibit this exact pair
            of chains. The first entry is the canonical deterministic
            witness for the change.
        old_chain: Complete authorization chain in the old delegation.
        new_chain: Complete authorization chain in the new delegation.
    """

    kind: ChangeType
    witness_paths: tuple[str, ...]
    old_chain: AuthorizationChain
    new_chain: AuthorizationChain


@dataclass(frozen=True)


class AuthorizationDiff:
    """Result of an offline authorization surface comparison.

    Attributes:
        changes: Distinct chain-pair changes, deterministically ordered by
            their first witness path.
    """

    changes: tuple[AuthorizationChange, ...]
    def __bool__(self) -> bool:
        """Return whether any authorization change was detected."""
        return bool(self.changes)

    @property
    def changed_paths(self) -> tuple[str, ...]:
        """Every witness path whose authorization chain changed."""

        paths: list[str] = []
        for change in self.changes:
            paths.extend(change.witness_paths)
        return tuple(paths)


@dataclass(frozen=True)


class TargetsBundle:
    """Offline snapshot of every targets role in one repository version.

    The top-level targets role is keyed by ``"targets"``. Bundles contain
    only already trusted metadata and never trigger network access: they
    are the complete input of the offline authorization comparison.
    """

    targets: dict[str, Metadata[Targets]]
    def get(self, role_name: str) -> Targets | None:
        """Return the signed targets payload of ``role_name`` if present."""
        metadata = self.targets.get(role_name)
        if metadata is None:
            return None
        return metadata.signed
    @classmethod
    def from_mapping(
        cls, targets_metadata: Mapping[str, Metadata[Targets]]
    ) -> TargetsBundle:
        """Build a bundle, requiring the top-level targets role."""
        if Targets.type not in targets_metadata:
            raise ValueError("bundle must include the top-level targets role")
        return cls(dict(targets_metadata))


class _GlobIntersection:
    """Find a concrete path matching two TUF path patterns, if one exists.

    TUF patterns are shell-style globs (see :func:`fnmatch.fnmatchcase`)
    split on ``/``: a target path matches only if it has the same number
    of path segments and every segment matches the corresponding pattern
    segment. The intersection of two patterns is computed one segment at a
    time with an explicit product automaton.

    The search alphabet contains the literal characters appearing in the
    patterns plus fallback symbols. It is sufficient because a wildcard or
    character class only distinguishes literal characters that appear in
    some pattern: any accepted word can be mapped to one spelled with
    these symbols.
    """

    _SPECIAL = frozenset("*?[]!^-")
    @classmethod
    def _alphabet(cls, patterns: Sequence[str]) -> tuple[str, ...]:
        """Build the finite symbol alphabet used by the product NFA."""
        symbols = {"a", "0"}
        for pattern in patterns:
            for char in pattern:
                if char not in cls._SPECIAL and char != "/":
                    symbols.add(char)
        return tuple(sorted(symbols))
    @staticmethod
    def _epsilon_closure(pattern: str, position: int) -> tuple[int, ...]:
        """Positions reachable from ``position`` without consuming a char."""
        reached: list[int] = []
        seen: set[int] = set()
        stack = [position]
        while stack:
            pos = stack.pop()
            if pos in seen:
                continue
            seen.add(pos)
            reached.append(pos)
            if pos < len(pattern) and pattern[pos] == "*":
                stack.append(pos + 1)
        return tuple(sorted(reached))
    @staticmethod
    def _class_matches(body: str, char: str) -> bool:
        """Return whether ``char`` belongs to glob class body ``body``."""
        index = 0
        while index < len(body):
            if index + 2 < len(body) and body[index + 1] == "-":
                low, high = body[index], body[index + 2]
                if low <= char <= high:
                    return True
                index += 3
            else:
                if body[index] == char:
                    return True
                index += 1
        return False
    @classmethod
    def _advance(cls, pattern: str, position: int, char: str) -> int:
        """Position after matching ``char`` at ``position`` or -1."""
        if position >= len(pattern):
            return -1
        token = pattern[position]
        if token == "*":
            # A star consumes the character and stays on the star token;
            # the epsilon closure applied by the caller also offers the
            # alternative of skipping the star entirely.
            return position
        if token == "?":
            return position + 1
        if token == "[":
            close = pattern.index("]", position + 1)
            body = pattern[position + 1 : close]
            negated = body[:1] in ("!", "^")
            if negated:
                body = body[1:]
            matched = cls._class_matches(body, char)
            if matched != negated:
                return close + 1
            return -1
        if token == char:
            return position + 1
        return -1
    def segment_witness(
        self, pattern1: str, pattern2: str
    ) -> str | None:
        """Return a non-empty string matching both segment patterns."""
        alphabet = self._alphabet([pattern1, pattern2])
        length1, length2 = len(pattern1), len(pattern2)
        accept1 = set(self._epsilon_closure(pattern1, length1))
        accept2 = set(self._epsilon_closure(pattern2, length2))
        start1 = set(self._epsilon_closure(pattern1, 0))
        start2 = set(self._epsilon_closure(pattern2, 0))
        accept_states = frozenset(
            (a, b) for a in accept1 for b in accept2
        )
        # Roots exclude accepting states: an accepting product must be
        # reached by consuming at least one character, so star-only
        # patterns still produce a non-empty witness.
        start_set = frozenset(
            (a, b)
            for a in start1
            for b in start2
            if (a, b) not in accept_states
        )
        frontier = set(start_set)
        parents: dict[tuple[int, int], tuple[tuple[int, int], str]] = {
            state: (state, "") for state in start_set
        }
        state_cap = (length1 + 1) * (length2 + 1)
        while frontier:
            next_layer: dict[tuple[int, int], tuple[tuple[int, int], str]] = {}
            for product in sorted(frontier):
                pos1, pos2 = product
                closure1 = self._epsilon_closure(pattern1, pos1)
                closure2 = self._epsilon_closure(pattern2, pos2)
                for char in alphabet:
                    next1: set[int] = set()
                    for nfa_state in closure1:
                        nxt = self._advance(pattern1, nfa_state, char)
                        if nxt >= 0:
                            next1.update(self._epsilon_closure(pattern1, nxt))
                    next2: set[int] = set()
                    for nfa_state in closure2:
                        nxt = self._advance(pattern2, nfa_state, char)
                        if nxt >= 0:
                            next2.update(self._epsilon_closure(pattern2, nxt))
                    for state1 in next1:
                        for state2 in next2:
                            child = (state1, state2)
                            if child not in parents and child not in next_layer:
                                next_layer[child] = (product, char)
            accepting = {
                state
                for state in next_layer
                if state[0] in accept1
                and state[1] in accept2
            }
            if accepting:
                target = min(accepting)
                parents.update(next_layer)
                return self._reconstruct(parents, target, start_set)
            if len(parents) + len(next_layer) > state_cap + len(start_set):
                return None
            parents.update(next_layer)
            frontier = set(next_layer)
        return None

    @staticmethod
    def _reconstruct(
        parents: dict[tuple[int, int], tuple[tuple[int, int], str]],
        target: tuple[int, int],
        start_set: frozenset[tuple[int, int]],
    ) -> str:
        """Rebuild the shortest accepted word from BFS parent pointers."""
        chars: list[str] = []
        state = target
        while state not in start_set:
            predecessor, char = parents[state]
            chars.append(char)
            state = predecessor
        chars.reverse()
        return "".join(chars)
    def path_witness(
        self, pattern1: str, pattern2: str
    ) -> str | None:
        """Return a concrete target path matching both patterns or None."""
        segments1 = pattern1.split("/")
        segments2 = pattern2.split("/")
        if len(segments1) != len(segments2):
            return None
        result: list[str] = []
        for seg1, seg2 in zip(segments1, segments2, strict=True):
            witness = self.segment_witness(seg1, seg2)
            if witness is None:
                return None
            result.append(self._non_empty_segment(witness, seg1, seg2))
        return "/".join(result)
    @staticmethod
    def _non_empty_segment(
        witness: str, pattern1: str, pattern2: str
    ) -> str:
        """Replace an empty star-only segment with a matching literal."""
        if witness:
            return witness
        alphabet = _GlobIntersection._alphabet([pattern1, pattern2])
        # The BFS shortest match consumed zero leading characters. Prepend
        # each alphabet symbol (and the same symbol plus the original
        # witness) until both patterns accept a non-empty segment.
        for char in alphabet:
            for candidate in (char, char + witness):
                if fnmatch.fnmatchcase(
                    candidate, pattern1
                ) and fnmatch.fnmatchcase(candidate, pattern2):
                    return candidate
        return witness


class _AuthorizationResolver:
    """Resolve the complete trust chain of a target path in one bundle."""
    def __init__(
        self, bundle: TargetsBundle, limits: AuthorizationLimits
    ) -> None:
        """Prepare a resolver over one offline bundle."""
        self._bundle = bundle
        self._limits = limits
        self._visit_count = 0
    @staticmethod
    def _role_link(role: DelegatedRole) -> RoleAuthorization:
        """Build an immutable link description for a delegated role."""
        return RoleAuthorization(
            role=role.name,
            keyids=tuple(role.keyids),
            threshold=role.threshold,
            terminating=role.terminating,
            matched_paths=tuple(role.paths) if role.paths is not None else (),
            hash_prefixes=(
                tuple(role.path_hash_prefixes)
                if role.path_hash_prefixes is not None
                else ()
            ),
        )
    def _matching_children(
        self, delegator: Targets, target_path: str
    ) -> list[tuple[DelegatedRole, bool]]:
        """Return matching child roles with their terminating flag."""
        delegations = delegator.delegations
        if delegations is None:
            return []
        children: list[tuple[DelegatedRole, bool]] = []
        if delegations.roles is not None:
            for role in delegations.roles.values():
                if role.is_delegated_path(target_path):
                    children.append((role, role.terminating))
        elif delegations.succinct_roles is not None:
            succinct = delegations.succinct_roles
            role_name = succinct.get_role_for_target(target_path)
            bin_role = DelegatedRole(
                role_name,
                list(succinct.keyids),
                succinct.threshold,
                True,
                paths=["*"],
            )
            children.append((bin_role, True))
        return children
    def resolve(self, target_path: str) -> AuthorizationChain:
        """Mirror the ``Updater`` pre-order DFS for one concrete path."""
        root = RoleAuthorization(
            role=Targets.type,
            keyids=(),
            threshold=1,
            terminating=False,
        )
        stack: list[tuple[str, RoleAuthorization | None]] = [
            (Targets.type, None)
        ]
        # Links of roles in their first-arrival traversal order. A role
        # reachable through several parents is recorded once, at its most
        # trusted (first) arrival. Cycles are cut by the visited set.
        links: list[RoleAuthorization] = []
        link_by_role: dict[str, RoleAuthorization] = {Targets.type: root}
        visited: set[str] = set()
        missing_role: str | None = None
        while stack:
            self._visit_count += 1
            if self._visit_count > self._limits.max_roles:
                raise LimitExceededError(
                    "delegation graph exceeded max_roles while resolving "
                    f"{target_path!r}"
                )
            role_name, role_link = stack.pop()
            if role_name in visited:
                continue
            visited.add(role_name)
            if role_link is not None:
                link_by_role[role_name] = role_link
            links.append(link_by_role[role_name])
            signed = self._bundle.get(role_name)
            if signed is None:
                missing_role = role_name
                break
            children = self._matching_children(signed, target_path)
            child_visits: list[tuple[str, RoleAuthorization | None]] = []
            for role, terminating in children:
                child_visits.append((role.name, self._role_link(role)))
                if terminating:
                    stack = []
                    break
            child_visits.reverse()
            stack.extend(child_visits)
        return AuthorizationChain(
            witness=target_path,
            roles=tuple(links),
            missing_role=missing_role,
        )


def _has_magic(pattern: str) -> bool:
    """Return whether ``pattern`` contains a glob metacharacter."""
    return any(char in pattern for char in _GLOB_METACHARACTERS)


def _bundle_uses_hash_prefixes(bundle: TargetsBundle) -> bool:
    """Return whether any role in ``bundle`` uses hash-based matching."""
    for metadata in bundle.targets.values():
        delegations = metadata.signed.delegations
        if delegations is None:
            continue
        if delegations.succinct_roles is not None:
            return True
        if delegations.roles is not None:
            for role in delegations.roles.values():
                if role.path_hash_prefixes is not None:
                    return True
    return False


def _plain_patterns(bundle: TargetsBundle) -> list[str]:
    """Collect all ordinary path patterns delegated in ``bundle``."""
    patterns: list[str] = []
    for metadata in bundle.targets.values():
        delegations = metadata.signed.delegations
        if delegations is None or delegations.roles is None:
            continue
        for role in delegations.roles.values():
            if role.paths is not None:
                patterns.extend(role.paths)
    return patterns


class _WitnessGenerator:
    """Enumerate concrete witness paths for an explicit glob subset."""
    def __init__(
        self,
        old: TargetsBundle,
        new: TargetsBundle,
        limits: AuthorizationLimits,
    ) -> None:
        """Prepare a witness generator for two offline bundles."""
        self._old = old
        self._new = new
        self._limits = limits
        self._glob = _GlobIntersection()
    def _candidates_for_glob(self, scope: str) -> list[str]:
        """Produce concrete in-scope witnesses for one glob scope."""
        candidates: list[str] = []
        seen: set[str] = set()

        def add(candidate: str) -> None:
            """Record an in-scope candidate once."""
            if (
                candidate
                and candidate not in seen
                and fnmatch.fnmatchcase(candidate, scope)
            ):
                seen.add(candidate)
                candidates.append(candidate)

        old_patterns = _plain_patterns(self._old)
        new_patterns = _plain_patterns(self._new)
        patterns = old_patterns + new_patterns
        # Scope vs. every delegated pattern: one witness per region a
        # single role claims inside the scope.
        for pattern in patterns:
            witness = self._glob.path_witness(scope, pattern)
            if witness is not None:
                add(witness)
        # Pairwise pattern intersections projected into the scope: these
        # cover regions claimed by two roles (e.g. an area only the new
        # delegation covers) that the single-pattern witnesses miss.
        for index, first in enumerate(patterns):
            for second in patterns[index + 1 :]:
                shared = self._glob.path_witness(first, second)
                if shared is None:
                    continue
                if fnmatch.fnmatchcase(shared, scope):
                    add(shared)
                else:
                    projected = self._glob.path_witness(scope, shared)
                    if projected is not None:
                        add(projected)
        return candidates
    def generate(self, scopes: Sequence[str]) -> list[str]:
        """Generate bounded concrete witnesses for all scopes."""
        witnesses: list[str] = []
        seen: set[str] = set()

        def add(candidate: str) -> bool:
            """Append a witness while enforcing the witness cap."""
            if candidate in seen:
                return True
            if len(witnesses) >= self._limits.max_witnesses:
                return False
            seen.add(candidate)
            witnesses.append(candidate)
            return True

        for scope in scopes:
            if not _has_magic(scope):
                if not add(scope):
                    raise LimitExceededError(
                        "witness set exceeded max_witnesses"
                    )
                continue
            if _bundle_uses_hash_prefixes(
                self._old
            ) or _bundle_uses_hash_prefixes(self._new):
                raise UnknownScopeError(
                    f"scope {scope!r} overlaps hash-prefix delegations: "
                    "membership cannot be decided offline for a glob"
                )
            for candidate in self._candidates_for_glob(scope):
                if not add(candidate):
                    raise LimitExceededError(
                        "witness set exceeded max_witnesses"
                    )
        return witnesses


def _chain_signature(
    chain: AuthorizationChain,
) -> tuple[tuple[RoleAuthorization, ...], str | None]:
    """Identity of a resolved chain, including an unresolved role."""
    return tuple(chain.roles), chain.missing_role


def compare_authorization(
    old: TargetsBundle,
    new: TargetsBundle,
    scopes: Sequence[str],
    limits: AuthorizationLimits | None = None,
) -> AuthorizationDiff:
    """Compare path ownership between two targets delegations offline.

    For each concrete witness path derived from ``scopes``, resolve the
    complete authorization chain in both bundles and report a change when
    the trust chain differs. The comparison is semantic: it re-runs the
    client delegation walk (role order, terminating roles, nested and
    duplicate delegation arrivals) instead of comparing JSON fields.

    Args:
        old: Trusted targets roles before the delegation change.
        new: Trusted targets roles after the delegation change.
        scopes: Explicit target paths or glob patterns limiting the
            comparison. A glob is rejected with :class:`UnknownScopeError`
            when either bundle uses hash-prefix or succinct delegations,
            because glob membership there cannot be enumerated offline.
        limits: Graph and witness caps guaranteeing deterministic
            termination. Defaults to :class:`AuthorizationLimits`.

    Raises:
        UnknownScopeError: A glob scope cannot be compared against
            hash-prefix/succinct delegations.
        LimitExceededError: The configured graph or witness limits were
            exceeded.
        ValueError: No scope was provided or a scope is invalid.

    Returns:
        :class:`AuthorizationDiff` with one entry per distinct changed
        chain pair and concrete witness paths.
    """
    if limits is None:
        limits = AuthorizationLimits()
    if not scopes:
        raise ValueError("at least one scope is required")
    if any(not isinstance(scope, str) or not scope for scope in scopes):
        raise ValueError("scopes must be non-empty strings")

    witnesses = _WitnessGenerator(old, new, limits).generate(scopes)
    old_resolver = _AuthorizationResolver(old, limits)
    new_resolver = _AuthorizationResolver(new, limits)

    grouped: dict[
        tuple[object, object], tuple[AuthorizationChange, list[str]]
    ] = {}
    for witness in witnesses:
        old_chain = old_resolver.resolve(witness)
        new_chain = new_resolver.resolve(witness)
        old_signature = _chain_signature(old_chain)
        new_signature = _chain_signature(new_chain)
        if old_signature == new_signature:
            continue
        key = (old_signature, new_signature)
        entry = grouped.get(key)
        if entry is None:
            if old_chain.first_delegated_role != new_chain.first_delegated_role:
                kind = ChangeType.OWNERSHIP_CHANGED
            else:
                kind = ChangeType.CHAIN_CHANGED
            change = AuthorizationChange(
                kind=kind,
                witness_paths=(),
                old_chain=old_chain,
                new_chain=new_chain,
            )
            entry = (change, [])
            grouped[key] = entry
        entry[1].append(witness)

    changes = tuple(
        sorted(
            (
                AuthorizationChange(
                    kind=change.kind,
                    witness_paths=tuple(paths),
                    old_chain=change.old_chain,
                    new_chain=change.new_chain,
                )
                for change, paths in grouped.values()
            ),
            key=lambda change: change.witness_paths[0],
        )
    )
    return AuthorizationDiff(changes=changes)


__all__ = [
    "AuthorizationChange",
    "AuthorizationChain",
    "AuthorizationError",
    "AuthorizationDiff",
    "AuthorizationLimits",
    "ChangeType",
    "LimitExceededError",
    "RoleAuthorization",
    "TargetsBundle",
    "UnknownScopeError",
    "compare_authorization",
]

