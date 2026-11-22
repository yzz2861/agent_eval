# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  reconcile.py

<Author>
  in-toto contributors

<Copyright>
  See LICENSE for licensing information.

<Purpose>

  Offline reconciliation of late-arriving in-toto evidence.

  Acceptance workflows regularly receive link metadata and material
  statements some time after the first verification pass. This module
  replays such *deliveries* (handover records) in arrival order against a
  caller-approved, versioned, partial material index, and explains for each
  verifiable step why an artifact was blocked at first and what later made
  it releasable.

  Design invariants:

  - The material index is partial and explicitly approved by the caller.
    Materials it does not cover are "unvouched": they neither pass nor
    block a step on their own.
  - Late submissions, replacements and contradictory statements are
    annotated onto the same verifiable step they arrived for.
  - A valid signature never revives a denied material. Only a new,
    explicitly approved index version can.
  - Reconciliation is a pure function of its inputs: re-running it with
    the same deliveries and index versions yields the same state changes,
    and every decision records the index version it relied on.

"""

import json
import logging

import attr
import securesystemslib.exceptions

from in_toto.exceptions import SignatureVerificationError

LOG = logging.getLogger(__name__)


class MaterialStatus:
    """Admissibility of a material under a ``MaterialIndex``."""

    APPROVED = "APPROVED"
    DENIED = "DENIED"
    CONTRADICTED = "CONTRADICTED"
    UNVOUCHED = "UNVOUCHED"


class StepState:
    """Release decision for the artifact(s) of a verifiable step."""

    BLOCKED = "BLOCKED"
    RELEASABLE = "RELEASABLE"


class EventKind:
    """Annotations recorded while replaying deliveries."""

    RECEIVED = "RECEIVED"
    LATE_SUBMISSION = "LATE_SUBMISSION"
    REPLACEMENT = "REPLACEMENT"
    CONTRADICTION = "CONTRADICTION"
    DENIAL_HELD = "DENIAL_HELD"
    INDEX_UPDATED = "INDEX_UPDATED"


@attr.s
class MaterialIndex:
    """Caller-approved, versioned, partial material index.

    Attributes:
      version: Monotonically increasing version of this index. Every
          reconciliation decision records the version it relied on.
      approved: Dict of material name to expected hash dict. A declared
          material matches if all shared hash algorithms agree.
      denied: Set of material names the caller has explicitly denied.
          Denied materials block their step and are never revived by a
          valid signature; only a newer approved index may re-admit them.

    """

    version = attr.ib()
    approved = attr.ib(factory=dict)
    denied = attr.ib(factory=set)

    def classify(self, name, hashdict):
        """Classify a declared material against this index.

        Returns a tuple of a ``MaterialStatus`` and a human-readable
        detail string.

        """
        if name in self.denied:
            return (
                MaterialStatus.DENIED,
                f"material '{name}' is denied by index v{self.version}",
            )

        if name not in self.approved:
            return (
                MaterialStatus.UNVOUCHED,
                f"material '{name}' is not covered by index v{self.version}",
            )

        expected = self.approved[name]
        shared = set(expected) & set(hashdict or {})
        if not shared:
            return (
                MaterialStatus.UNVOUCHED,
                f"material '{name}' shares no hash algorithm with index "
                f"v{self.version}",
            )

        mismatched = [
            algorithm
            for algorithm in sorted(shared)
            if hashdict[algorithm] != expected[algorithm]
        ]
        if mismatched:
            return (
                MaterialStatus.CONTRADICTED,
                f"material '{name}' contradicts index v{self.version} "
                f"on: {', '.join(mismatched)}",
            )

        return (
            MaterialStatus.APPROVED,
            f"material '{name}' matches index v{self.version}",
        )


@attr.s
class Delivery:
    """A single handover record of late-arriving evidence.

    Attributes:
      sequence: Arrival order of this delivery. Sequences must be unique
          and strictly increasing across deliveries.
      links: List of signed link metadata (``Metablock`` objects carrying
          a ``Link``) delivered for verifiable steps.
      materials: Standalone material statements, as a dict of step name to
          a dict of material name to hash dict.
      note: Optional free-form note carried through to the report.

    """

    sequence = attr.ib()
    links = attr.ib(factory=list)
    materials = attr.ib(factory=dict)
    note = attr.ib(default="")


@attr.s
class ReconciliationEvent:
    """An annotation on a verifiable step, in arrival order."""

    sequence = attr.ib()
    step = attr.ib()
    kind = attr.ib()
    detail = attr.ib()
    index_version = attr.ib()
    material = attr.ib(default=None)
    signature_valid = attr.ib(default=None)

    def to_dict(self):
        """Returns the JSON-serializable dict representation of self."""
        return {
            "sequence": self.sequence,
            "step": self.step,
            "kind": self.kind,
            "detail": self.detail,
            "index_version": self.index_version,
            "material": self.material,
            "signature_valid": self.signature_valid,
        }


@attr.s
class Decision:
    """A state change for a step, with the index version it relied on."""

    sequence = attr.ib()
    step = attr.ib()
    state = attr.ib()
    reason = attr.ib()
    index_version = attr.ib()

    def to_dict(self):
        """Returns the JSON-serializable dict representation of self."""
        return {
            "sequence": self.sequence,
            "step": self.step,
            "state": self.state,
            "reason": self.reason,
            "index_version": self.index_version,
        }


class _StepAccount:
    """Internal per-step ledger built up while replaying deliveries."""

    def __init__(self, name):
        self.name = name
        self.link = None
        self.link_signature_valid = False
        self.declared = {}
        self.decided = False
        self.state = None

    def material_view(self):
        """Returns the current material view: statements plus link."""
        view = dict(self.declared)
        if self.link is not None:
            view.update(self.link.signed.materials)
        return view


@attr.s
class ReconciliationReport:
    """Result of reconciling a set of deliveries against material indexes.

    Attributes:
      events: All annotations in arrival order.
      decisions: All step state changes, each with the index version it
          relied on.
      final_states: Final ``StepState`` per step.
      material_statuses: Final ``MaterialStatus`` per step and material.

    """

    events = attr.ib(factory=list)
    decisions = attr.ib(factory=list)
    final_states = attr.ib(factory=dict)
    material_statuses = attr.ib(factory=dict)
    _inputs = attr.ib(default=None, repr=False)

    def to_dict(self):
        """Returns a deterministic, JSON-serializable representation."""
        return {
            "events": [event.to_dict() for event in self.events],
            "decisions": [decision.to_dict() for decision in self.decisions],
            "final_states": self.final_states,
            "material_statuses": self.material_statuses,
        }

    def dumps(self):
        """Returns a canonical JSON string of ``to_dict``.

        Re-running reconciliation with the same inputs yields the same
        string, which makes state changes replayable and comparable.

        """
        return json.dumps(self.to_dict(), indent=1, sort_keys=True)

    def replay(self):
        """Re-runs reconciliation from the recorded inputs.

        Returns a new ``ReconciliationReport`` that must be identical to
        this one (compare via ``dumps``).

        """
        if self._inputs is None:
            raise ValueError("report does not retain its inputs")
        return reconcile(**self._inputs)


def _verify_link_signature(metablock, keys):
    """Returns True if any passed key verifies a signature on metablock."""
    for key in keys.values():
        try:
            metablock.verify_signature(key)
            return True

        except (
            SignatureVerificationError,
            securesystemslib.exceptions.FormatError,
            securesystemslib.exceptions.UnsupportedAlgorithmError,
        ) as error:
            LOG.debug("link signature check failed: %s", error)

    return False


class _Reconciler:
    """Stateful replay of deliveries against approved material indexes."""

    def __init__(self, initial_index, keys, index_updates):
        self.index = initial_index
        self.keys = keys
        self.index_updates = index_updates
        self.accounts = {}
        self.events = []
        self.decisions = []

    def _annotate(self, sequence, step, kind, detail, **extra):
        self.events.append(
            ReconciliationEvent(
                sequence=sequence,
                step=step,
                kind=kind,
                detail=detail,
                index_version=self.index.version,
                **extra,
            )
        )

    def _apply_index_update(self, sequence):
        if sequence not in self.index_updates:
            return
        new_index = self.index_updates[sequence]
        if new_index.version <= self.index.version:
            raise ValueError(
                f"index version must increase: got v{new_index.version}"
                f" after v{self.index.version}"
            )
        self.index = new_index
        self._annotate(
            sequence,
            None,
            EventKind.INDEX_UPDATED,
            f"caller approved material index v{self.index.version}",
        )

    def _check_material(self, sequence, step, name, hashdict, signature_valid):
        """Classifies one declared material and annotates denial/conflict."""
        status, detail = self.index.classify(name, hashdict)
        if status == MaterialStatus.DENIED:
            self._annotate(
                sequence,
                step,
                EventKind.DENIAL_HELD,
                detail
                + "; denial upheld"
                + (" despite valid signature" if signature_valid else ""),
                material=name,
                signature_valid=signature_valid,
            )
        elif status == MaterialStatus.CONTRADICTED:
            self._annotate(
                sequence,
                step,
                EventKind.CONTRADICTION,
                detail,
                material=name,
                signature_valid=signature_valid,
            )

    def _process_link(self, sequence, metablock):
        step = metablock.signed.name
        account = self.accounts.setdefault(step, _StepAccount(step))
        signature_valid = _verify_link_signature(metablock, self.keys)

        if account.link is None:
            kind = (
                EventKind.LATE_SUBMISSION
                if account.decided
                else EventKind.RECEIVED
            )
        else:
            current = account.link.signed
            replaced = (
                current.materials != metablock.signed.materials
                or current.products != metablock.signed.products
            )
            kind = (
                EventKind.REPLACEMENT if replaced else EventKind.LATE_SUBMISSION
            )

        detail = (
            f"link for step '{step}' accepted as evidence"
            if signature_valid
            else f"link for step '{step}' has no valid signature;"
            " not admissible"
        )
        self._annotate(
            sequence, step, kind, detail, signature_valid=signature_valid
        )

        if not signature_valid:
            return

        account.link = metablock
        account.link_signature_valid = True
        for name, hashdict in sorted(metablock.signed.materials.items()):
            self._check_material(
                sequence, step, name, hashdict, signature_valid=True
            )

    def _process_statements(self, sequence, step, materials):
        account = self.accounts.setdefault(step, _StepAccount(step))
        for name, hashdict in sorted(materials.items()):
            if name in account.declared and account.declared[name] != hashdict:
                self._annotate(
                    sequence,
                    step,
                    EventKind.REPLACEMENT,
                    f"statement for material '{name}' replaces an"
                    " earlier statement",
                    material=name,
                )
            account.declared[name] = hashdict
            self._check_material(
                sequence, step, name, hashdict, signature_valid=None
            )

    def _evaluate(self, sequence):
        for step in sorted(self.accounts):
            account = self.accounts[step]
            state, reason = self._step_state(account)
            if not account.decided or account.state != state:
                self.decisions.append(
                    Decision(
                        sequence=sequence,
                        step=step,
                        state=state,
                        reason=reason,
                        index_version=self.index.version,
                    )
                )
                account.state = state
            account.decided = True

    def _step_state(self, account):
        if account.link is None:
            return StepState.BLOCKED, "no admissible link evidence"
        for name, hashdict in sorted(account.material_view().items()):
            status, detail = self.index.classify(name, hashdict)
            if status in (
                MaterialStatus.DENIED,
                MaterialStatus.CONTRADICTED,
            ):
                return StepState.BLOCKED, detail
        return StepState.RELEASABLE, "all recorded materials admissible"

    def run(self, deliveries):
        """Processes all deliveries in order and returns the final
        per-step states and material statuses."""
        for delivery in deliveries:
            self._apply_index_update(delivery.sequence)
            for metablock in delivery.links:
                self._process_link(delivery.sequence, metablock)
            for step, materials in sorted(delivery.materials.items()):
                self._process_statements(delivery.sequence, step, materials)
            self._evaluate(delivery.sequence)

        final_states = {}
        material_statuses = {}
        for step in sorted(self.accounts):
            account = self.accounts[step]
            final_states[step] = account.state
            material_statuses[step] = {
                name: self.index.classify(name, hashdict)[0]
                for name, hashdict in sorted(account.material_view().items())
            }
        return final_states, material_statuses


def reconcile(initial_index, deliveries, keys, index_updates=None):
    """Replays deliveries in arrival order against approved material indexes.

    Arguments:
      initial_index: The caller-approved ``MaterialIndex`` in effect before
          the first delivery.
      deliveries: List of ``Delivery`` handover records with unique,
          strictly increasing sequence numbers.
      keys: Dict of verification keyid to public key dict, used to assess
          link signatures. A link without a valid signature is not
          admissible as evidence.
      index_updates: Optional dict of delivery sequence to a new
          caller-approved ``MaterialIndex``, applied before that delivery
          is processed. Versions must strictly increase.

    Raises:
      ValueError: Duplicate or unordered delivery sequences, or a
          non-increasing index version.

    Returns:
      A ``ReconciliationReport`` with all annotations and state changes.

    """
    index_updates = index_updates or {}
    deliveries = sorted(deliveries, key=lambda delivery: delivery.sequence)
    sequences = [delivery.sequence for delivery in deliveries]
    if len(set(sequences)) != len(sequences):
        raise ValueError(f"duplicate delivery sequences: {sequences}")

    reconciler = _Reconciler(initial_index, keys, index_updates)
    final_states, material_statuses = reconciler.run(deliveries)

    return ReconciliationReport(
        events=reconciler.events,
        decisions=reconciler.decisions,
        final_states=final_states,
        material_statuses=material_statuses,
        inputs={
            "initial_index": initial_index,
            "deliveries": deliveries,
            "keys": keys,
            "index_updates": index_updates,
        },
    )
