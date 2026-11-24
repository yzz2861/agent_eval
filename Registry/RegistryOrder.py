"""
Partial-order backend for registry persistence analysis.

This module builds a partial order (poset) over registry change events
observed across multiple parsed hive snapshots.  It exists because
sorting events mechanically by key LastWrite timestamps misplaces events
recorded while the system clock was rolled back.

Design notes:

- The trusted backbone is the *explicit collection interval*
  (not_before, not_after] supplied by the caller for every snapshot.
  This module never reads the system clock and never calls Windows APIs;
  all times come from the parsed hives and the caller.
- A key's LastWrite timestamp constrains only that key's own last write.
  It is never propagated to child keys: a parent key's timestamp is not
  evidence that its children changed.
- Only structural changes actually supported by the snapshots become
  constraints (creation, deletion, modification of the observed value
  set, and LastWrite monotonicity of a continuously present key).
- When constraints contradict each other the module reports a minimal
  conflicting subset together with its provenance (the snapshots and key
  involved).  It never forces a linear order over inconsistent data.
- Reports keep facts (direct observations) separate from inferences
  (derived events and order relations), and admit that several legal
  linear extensions of the event poset may exist.

Existing read-only parsing behavior is untouched; this module only
consumes already-parsed snapshots.
"""

from dataclasses import dataclass, field
from datetime import datetime
from itertools import combinations
from collections.abc import Mapping

# Relations between two events or snapshots.
BEFORE = "before"                    # definitely earlier
AFTER = "after"                      # definitely later
POSSIBLY_CONCURRENT = "possibly_concurrent"  # bounded intervals overlap
INCOMPARABLE = "incomparable"        # insufficient bounds to compare
EQUAL = "equal"                      # same event

# Event kinds.
CREATED = "created"
DELETED = "deleted"
MODIFIED = "modified"

# Constraint rules.
RULE_TS_WITHIN_COLLECTION = "last_write_within_collection"
RULE_MONOTONIC_LAST_WRITE = "monotonic_last_write"
RULE_CHANGE_BUMPS_LAST_WRITE = "change_bumps_last_write"
RULE_CREATED_AFTER_ABSENT = "created_after_absent"


def _freeze(value):
    """Convert a registry value payload into a hashable, comparable form."""
    if isinstance(value, (str, bytes, int, float, bool, type(None))):
        return value
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze(item) for item in value)
    if isinstance(value, Mapping):
        return tuple(sorted((key, _freeze(item)) for key, item in value.items()))
    return repr(value)


def _freeze_values(values):
    """Normalize a mapping or iterable of (name, payload) pairs."""
    if isinstance(values, Mapping):
        items = values.items()
    else:
        items = values
    return frozenset((name, _freeze(payload)) for name, payload in items)


@dataclass(frozen=True)
class KeyState:
    """The observed state of one key in one snapshot.

    values is a frozenset of (name, frozen_payload) pairs.
    """
    exists: bool
    last_write: datetime = None
    values: frozenset = field(default_factory=frozenset)

    @classmethod
    def present(cls, last_write=None, values=()):
        return cls(exists=True, last_write=last_write,
                   values=_freeze_values(values))

    @classmethod
    def absent(cls):
        return cls(exists=False)


class Snapshot(object):
    """One parsed hive plus its explicit collection interval.

    not_before / not_after are datetimes bounding when the hive was
    acquired, or None when unknown.  states maps key path to KeyState;
    a key missing from the mapping was simply not observed in this
    snapshot (distinct from observed-absent).
    """

    def __init__(self, label, not_before, not_after, states):
        if not_before is not None and not_after is not None \
                and not_before > not_after:
            raise ValueError(
                "snapshot %r: not_before %r is after not_after %r"
                % (label, not_before, not_after))
        self.label = label
        self.not_before = not_before
        self.not_after = not_after
        self.states = dict(states)

    def __repr__(self):
        return "Snapshot(label=%r, keys=%d)" % (self.label, len(self.states))


def snapshot_from_registry(registry, label, not_before, not_after):
    """Build a Snapshot by walking an already-parsed Registry.Registry.

    Each key's own LastWrite timestamp is recorded for that key only;
    parent timestamps are never inherited by children.
    """
    states = {}

    def walk(key):
        values = frozenset(
            (value.name(), _freeze(value.value())) for value in key.values())
        states[key.path()] = KeyState.present(
            last_write=key.timestamp(), values=values)
        for subkey in key.subkeys():
            walk(subkey)

    walk(registry.root())
    return Snapshot(label=label, not_before=not_before,
                    not_after=not_after, states=states)


@dataclass(frozen=True)
class Observation:
    """A fact: one key's state as directly observed in one snapshot."""
    snapshot: str
    key: str
    exists: bool
    last_write: datetime
    values: frozenset


@dataclass(frozen=True)
class Event:
    """An inference: a structural change between two ordered snapshots.

    The event occurred in the interval (lower, upper]; both bounds are
    collection times of the bracketing snapshots.
    """
    id: str
    kind: str
    key: str
    lower: datetime
    upper: datetime
    from_snapshot: str
    to_snapshot: str
    changes: tuple = ()


@dataclass(frozen=True)
class Constraint:
    """One checkable constraint with its provenance."""
    rule: str
    key: str
    snapshots: tuple
    holds: bool
    detail: str = ""


@dataclass(frozen=True)
class Conflict:
    """A minimal subset of constraints that cannot hold simultaneously."""
    constraints: tuple
    explanation: str

    @property
    def provenance(self):
        keys = sorted({c.key for c in self.constraints})
        snapshots = sorted({s for c in self.constraints for s in c.snapshots})
        rules = sorted({c.rule for c in self.constraints})
        return {"rules": rules, "keys": keys, "snapshots": snapshots}


def _snapshot_sort_key(snapshot):
    # Snapshots with unknown bounds sort last, deterministically.
    return (snapshot.not_before is None,
            snapshot.not_before or datetime.min,
            snapshot.not_after is None,
            snapshot.not_after or datetime.min,
            snapshot.label)


def _interval_relation(a_lower, a_upper, b_lower, b_upper):
    """Relation of interval (a_lower, a_upper] to (b_lower, b_upper].

    None bounds mean unknown; without both relevant bounds no order can
    be established, and concurrency is only claimed for fully bounded
    overlapping intervals.
    """
    if a_upper is not None and b_lower is not None and a_upper <= b_lower:
        return BEFORE
    if b_upper is not None and a_lower is not None and b_upper <= a_lower:
        return AFTER
    bounded = None not in (a_lower, a_upper, b_lower, b_upper)
    if bounded and a_lower < b_upper and b_lower < a_upper:
        return POSSIBLY_CONCURRENT
    return INCOMPARABLE


def _invert(relation):
    if relation == BEFORE:
        return AFTER
    if relation == AFTER:
        return BEFORE
    return relation


def _minimal_cores(constraints):
    """Collect minimal inconsistent subsets of the constraint pool.

    Consistency is evaluated over the constraints' holds flags, so a
    single violated constraint is already minimal; the generic
    deletion-based minimization below also covers future constraints
    whose consistency depends on combinations.
    """
    def inconsistent(pool):
        return any(not c.holds for c in pool)

    def minimize(pool):
        core = list(pool)
        for candidate in list(core):
            trial = [c for c in core if c is not candidate]
            if inconsistent(trial):
                core = trial
        return tuple(core)

    remaining = list(constraints)
    cores = []
    while inconsistent(remaining):
        core = minimize(remaining)
        cores.append(core)
        remaining = [c for c in remaining if c is not core[0]]
    return cores


def _explain(core):
    parts = []
    for c in core:
        parts.append("%s on key %s (snapshots %s): %s"
                     % (c.rule, c.key, "->".join(c.snapshots), c.detail))
    return "; ".join(parts)


class OrderReport(object):
    """Result of analyzing a set of snapshots.

    Facts (observations) are kept separate from inferences
    (events, constraints, conflicts, order relations).
    """

    def __init__(self, snapshots, observations, events, constraints,
                 conflicts, snapshot_relations):
        self.snapshots = tuple(snapshots)
        self.observations = tuple(observations)
        self.events = tuple(events)
        self.constraints = tuple(constraints)
        self.conflicts = tuple(conflicts)
        self._snapshot_relations = dict(snapshot_relations)
        self._events_by_id = {event.id: event for event in self.events}

    def is_consistent(self):
        return not self.conflicts

    def snapshot_relation(self, label_a, label_b):
        if label_a == label_b:
            return EQUAL
        if (label_a, label_b) in self._snapshot_relations:
            return self._snapshot_relations[(label_a, label_b)]
        return _invert(self._snapshot_relations[(label_b, label_a)])

    def relation(self, event_id_a, event_id_b):
        """Relation between two events, by event id."""
        if event_id_a == event_id_b:
            return EQUAL
        a = self._events_by_id[event_id_a]
        b = self._events_by_id[event_id_b]
        return _interval_relation(a.lower, a.upper, b.lower, b.upper)

    def relation_graph(self):
        """Full symmetric matrix of event relations, keyed by event id."""
        graph = {event.id: {} for event in self.events}
        for a, b in combinations(self.events, 2):
            rel = self.relation(a.id, b.id)
            graph[a.id][b.id] = rel
            graph[b.id][a.id] = _invert(rel)
        return graph

    def linear_extension_count(self, cap=1000):
        """Number of legal total orders of the event poset, capped.

        A count greater than one means several legal orders exist and no
        single timeline should be presented as fact.
        """
        ids = [event.id for event in self.events]
        predecessors = {event_id: set() for event_id in ids}
        for a, b in combinations(self.events, 2):
            if self.relation(a.id, b.id) == BEFORE:
                predecessors[b.id].add(a.id)
            elif self.relation(a.id, b.id) == AFTER:
                predecessors[a.id].add(b.id)
        count = [0]

        def extend(remaining):
            if not remaining:
                count[0] += 1
                return
            for event_id in sorted(remaining):
                if count[0] >= cap:
                    return
                if not predecessors[event_id] & remaining:
                    extend(remaining - {event_id})

        extend(frozenset(ids))
        return min(count[0], cap)


def analyze(snapshots):
    """Build an OrderReport from an iterable of Snapshots.

    The result is independent of the input order: snapshots are
    canonicalized by (not_before, not_after, label) before analysis.
    """
    snaps = sorted(snapshots, key=_snapshot_sort_key)
    labels = [s.label for s in snaps]
    if len(set(labels)) != len(labels):
        raise ValueError("snapshot labels must be unique")

    observations = []
    constraints = []
    for snap in snaps:
        for key in sorted(snap.states):
            state = snap.states[key]
            observations.append(Observation(
                snapshot=snap.label, key=key, exists=state.exists,
                last_write=state.last_write, values=state.values))
            if state.exists and state.last_write is not None \
                    and snap.not_after is not None:
                constraints.append(Constraint(
                    rule=RULE_TS_WITHIN_COLLECTION, key=key,
                    snapshots=(snap.label,),
                    holds=state.last_write <= snap.not_after,
                    detail="last_write %r vs collection end %r"
                           % (state.last_write, snap.not_after)))

    snapshot_relations = {}
    for a, b in combinations(snaps, 2):
        snapshot_relations[(a.label, b.label)] = _interval_relation(
            a.not_before, a.not_after, b.not_before, b.not_after)

    events = []
    for prev, curr in zip(snaps, snaps[1:]):
        # Events are only derived between snapshots whose collection
        # intervals are strictly ordered; overlapping or undated
        # snapshots yield no ordering inference.
        if prev.not_after is None or curr.not_before is None \
                or prev.not_after > curr.not_before:
            continue
        pair = (prev.label, curr.label)
        for key in sorted(set(prev.states) | set(curr.states)):
            before = prev.states.get(key)
            after = curr.states.get(key)
            if before is None or after is None:
                continue  # key not observed in one snapshot: no inference
            event_id = None
            kind = None
            changes = ()
            if not before.exists and after.exists:
                kind = CREATED
                event_id = "%s:%s:%s->%s" % (CREATED, key, *pair)
                if after.last_write is not None:
                    constraints.append(Constraint(
                        rule=RULE_CREATED_AFTER_ABSENT, key=key,
                        snapshots=pair,
                        holds=after.last_write > prev.not_after,
                        detail="created with last_write %r but absent "
                               "from snapshot collected by %r"
                               % (after.last_write, prev.not_after)))
            elif before.exists and not after.exists:
                kind = DELETED
                event_id = "%s:%s:%s->%s" % (DELETED, key, *pair)
            elif before.exists and after.exists:
                if before.last_write is not None \
                        and after.last_write is not None:
                    constraints.append(Constraint(
                        rule=RULE_MONOTONIC_LAST_WRITE, key=key,
                        snapshots=pair,
                        holds=before.last_write <= after.last_write,
                        detail="last_write moved %r -> %r"
                               % (before.last_write, after.last_write)))
                removed = before.values - after.values
                added = after.values - before.values
                if removed or added:
                    changed = tuple(sorted(
                        name for name, _ in removed | added))
                    constraints.append(Constraint(
                        rule=RULE_CHANGE_BUMPS_LAST_WRITE, key=key,
                        snapshots=pair,
                        holds=(before.last_write is None
                               or after.last_write is None
                               or before.last_write < after.last_write),
                        detail="values %s changed but last_write moved "
                               "%r -> %r" % (list(changed),
                                             before.last_write,
                                             after.last_write)))
                    changes += tuple("value:%s" % name for name in changed)
                if before.last_write != after.last_write:
                    changes += ("last_write",)
                if changes:
                    kind = MODIFIED
                    event_id = "%s:%s:%s->%s" % (MODIFIED, key, *pair)
            if event_id is not None:
                events.append(Event(
                    id=event_id, kind=kind, key=key,
                    lower=prev.not_after, upper=curr.not_after,
                    from_snapshot=prev.label, to_snapshot=curr.label,
                    changes=changes))

    conflicts = tuple(Conflict(constraints=core, explanation=_explain(core))
                      for core in _minimal_cores(constraints))
    return OrderReport(snaps, observations, events, constraints,
                       conflicts, snapshot_relations)
