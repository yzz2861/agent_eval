# Copyright (c) 2026 Red Hat, Inc.
# License: LGPLv3+

"""
Scoring-history layer on top of the versioned CVSS scoring objects.

An advisory may be corrected long after it was published, and the correction can change a
threat (temporal) metric. Recomputing the vector "today" therefore hides the basis on which the
on-call team originally judged the issue. This module keeps every event (the original advisory,
late errata and revocations) and reconstructs the vector which was actually available at a
known time while only applying changes whose business effective time has been reached.

Two views are offered for the same business point in time:

* :meth:`ScoringHistory.as_of` -- what the on-call team could have known at ``known_at``;
* :meth:`ScoringHistory.hindsight` -- the same point in time recomputed with everything known
  afterwards, so late events influence the recomputation while the original basis stays intact.

Only threat metrics are allowed to be updated by an erratum; base metrics are frozen by the
advisory. A revocation restores the value the metric had immediately before the revoked erratum.
"""

from __future__ import unicode_literals

from collections import namedtuple

from .cvss2 import CVSS2
from .cvss3 import CVSS3
from .cvss4 import CVSS4
from .exceptions import (
    CVSSHistoryError,
    CVSSHistoryReferenceError,
    CVSSHistoryRevocationError,
    CVSSHistoryValidationError,
)

ADVISORY = "advisory"
ERRATUM = "erratum"
REVOCATION = "revocation"

# Only threat/temporal indicators may change after publication; base metrics are immutable.
UPDATEABLE_METRICS = {
    "CVSS:2.0": ("E", "RL", "RC"),
    "CVSS:3.0": ("E", "RL", "RC"),
    "CVSS:3.1": ("E", "RL", "RC"),
    "CVSS:4.0": ("E",),
}

_SCORING_CLASSES = {
    "CVSS:2.0": CVSS2,
    "CVSS:3.0": CVSS3,
    "CVSS:3.1": CVSS3,
    "CVSS:4.0": CVSS4,
}

# Applicable events, ordered so the reconstructed state is deterministic when timestamps tie.
_EVENT_ORDER = {ADVISORY: 0, ERRATUM: 1, REVOCATION: 2}


class HistoryEvent(
    namedtuple(
        "HistoryEvent",
        [
            "event_type",
            "event_id",
            "advisory_id",
            "known_at",
            "effective_at",
            "vector",
            "metric",
            "value",
            "reference_prefix",
            "revokes_event_id",
        ],
    )
):
    """
    Immutable record of a single scoring-history event.

    ``advisory`` events carry the full baseline ``vector``; ``erratum`` events carry one
    ``metric``/``value`` pair; ``revocation`` events reference the erratum they revoke.
    """

    __slots__ = ()


class ScoringBasis(
    namedtuple(
        "ScoringBasis",
        [
            "advisory_id",
            "known_at",
            "effective_at",
            "cvss_prefix",
            "vector",
            "scores",
            "severities",
            "applied_event_ids",
            "revoked_event_ids",
            "metric_provenance",
        ],
    )
):
    """
    A complete scoring basis reconstructed for one point in time.

    ``metric_provenance`` maps every non-default metric abbreviation to the id of the event which
    supplied its current value, making the judgment trail fully inspectable.
    """

    __slots__ = ()


def _detect_prefix(vector):
    head = vector.split("/", 1)[0]
    if head == "CVSS:4.0":
        return "CVSS:4.0"
    if head in ("CVSS:3.0", "CVSS:3.1"):
        return head
    return "CVSS:2.0"


class ScoringHistory(object):
    """
    Holds the ordered event history of one or more advisories and reconstructs scoring bases.
    """

    def __init__(self):
        self.events = []
        self._advisories = {}
        self._event_counters = {}

    def add_advisory(self, advisory_id, vector, known_at, effective_at):
        """
        Records the original advisory and freezes its base metrics.

        Raises:
            CVSSHistoryValidationError: if the vector cannot be parsed or the id is duplicated.
        """
        if advisory_id in self._advisories:
            raise CVSSHistoryValidationError(
                'Advisory "{0}" has already been recorded'.format(advisory_id)
            )
        prefix = _detect_prefix(vector)
        try:
            _SCORING_CLASSES[prefix](vector)
        except CVSSHistoryError:
            raise
        except Exception as exc:  # malformed vectors raise version-specific CVSS errors
            raise CVSSHistoryValidationError(
                'Advisory "{0}" carries an invalid {1} vector: {2}'.format(
                    advisory_id, prefix, exc
                )
            )
        event = HistoryEvent(
            ADVISORY,
            self._event_id(advisory_id, ADVISORY),
            advisory_id,
            known_at,
            effective_at,
            vector,
            None,
            None,
            prefix,
            None,
        )
        self._advisories[advisory_id] = event
        self.events.append(event)
        return event

    def add_erratum(
        self,
        advisory_id,
        metric,
        value,
        known_at,
        effective_at,
        event_id=None,
        reference_prefix=None,
    ):
        """
        Records a late correction changing a single updateable (threat) metric.

        Args:
            advisory_id: advisory being corrected.
            metric: metric abbreviation, must be one of the version's updateable metrics.
            value: new metric value; ``X`` restores the "not defined" default.
            known_at: when the correction became known to the team.
            effective_at: business time from which the correction applies.
            event_id: optional explicit id, generated when omitted.
            reference_prefix: CVSS prefix the correction claims to speak for. Must match the
                advisory; a mismatch is an illegal cross-version reference and is raised so it
                can be traced.

        Raises:
            CVSSHistoryReferenceError: unknown advisory or cross-version prefix mismatch.
            CVSSHistoryValidationError: metric not updateable or value illegal for the metric.
        """
        advisory = self._require_advisory(advisory_id)
        prefix = advisory.reference_prefix
        resolved_event_id = event_id or self._event_id(advisory_id, ERRATUM)
        if reference_prefix is not None and reference_prefix != prefix:
            raise CVSSHistoryReferenceError(
                'Erratum for advisory "{0}" references {1} but the advisory is {2}'.format(
                    advisory_id, reference_prefix, prefix
                ),
                event_id=resolved_event_id,
                advisory_id=advisory_id,
                referenced_prefix=reference_prefix,
            )
        if metric not in UPDATEABLE_METRICS[prefix]:
            raise CVSSHistoryValidationError(
                'Erratum for advisory "{0}" may only update one of {1}, not "{2}"'.format(
                    advisory_id, ", ".join(UPDATEABLE_METRICS[prefix]), metric
                )
            )
        self._validate_value(prefix, advisory, metric, value, advisory_id)
        event = HistoryEvent(
            ERRATUM,
            resolved_event_id,
            advisory_id,
            known_at,
            effective_at,
            None,
            metric,
            value,
            prefix,
            None,
        )
        self._ensure_unique_event_id(event.event_id)
        self.events.append(event)
        return event

    def add_revocation(
        self, advisory_id, revokes_event_id, known_at, effective_at, event_id=None
    ):
        """
        Records the revocation of a previously filed erratum.

        The revoked erratum is excluded from every later reconstruction, so the metric reverts to
        the value it held immediately before that erratum.

        Raises:
            CVSSHistoryReferenceError: unknown advisory.
            CVSSHistoryRevocationError: target event is missing, not an erratum of the same
                advisory, or already revoked.
        """
        advisory = self._require_advisory(advisory_id)
        target = self._find_event(revokes_event_id)
        if target is None or target.event_type != ERRATUM or target.advisory_id != advisory_id:
            raise CVSSHistoryRevocationError(
                'Cannot revoke "{0}": not an active erratum of advisory "{1}"'.format(
                    revokes_event_id, advisory_id
                )
            )
        if any(
            event.event_type == REVOCATION and event.revokes_event_id == revokes_event_id
            for event in self.events
        ):
            raise CVSSHistoryRevocationError(
                'Erratum "{0}" has already been revoked'.format(revokes_event_id)
            )
        event = HistoryEvent(
            REVOCATION,
            event_id or self._event_id(advisory_id, REVOCATION),
            advisory_id,
            known_at,
            effective_at,
            None,
            target.metric,
            None,
            advisory.reference_prefix,
            revokes_event_id,
        )
        self._ensure_unique_event_id(event.event_id)
        self.events.append(event)
        return event

    def as_of(self, advisory_id, known_at, effective_at):
        """
        Reconstructs the basis available at ``known_at`` for business time ``effective_at``.

        Events filed after ``known_at`` are invisible, preserving the original judgment trail.
        """
        return self._reconstruct(advisory_id, known_at, effective_at)

    def hindsight(self, advisory_id, effective_at, known_at=None):
        """
        Recomputes the same business point with every event filed so far.

        Late errata and revocations therefore influence the recomputation. Pass ``known_at`` to
        cap the hindsight at a later filing date instead of using everything on record.
        """
        return self._reconstruct(advisory_id, known_at, effective_at)

    def _reconstruct(self, advisory_id, known_at, effective_at):
        advisory = self._require_advisory(advisory_id)
        prefix = advisory.reference_prefix

        applicable = [
            event
            for event in self.events
            if event.advisory_id == advisory_id
            and (known_at is None or event.known_at <= known_at)
            and event.effective_at <= effective_at
        ]
        applicable.sort(key=lambda event: (event.effective_at, event.known_at,
                                           _EVENT_ORDER[event.event_type]))

        revoked = set()
        for event in applicable:
            if event.event_type == REVOCATION:
                revoked.add(event.revokes_event_id)

        metrics = {}
        provenance = {}
        applied = []
        for event in applicable:
            if event.event_type == REVOCATION or event.event_id in revoked:
                continue
            if event.event_type == ADVISORY:
                for metric, value in self._parse_metrics(prefix, event.vector):
                    if value != "X":
                        metrics[metric] = value
                        provenance[metric] = event.event_id
            else:
                if event.value == "X":
                    metrics.pop(event.metric, None)
                    provenance.pop(event.metric, None)
                else:
                    metrics[event.metric] = event.value
                    provenance[event.metric] = event.event_id
            applied.append(event.event_id)

        scoring_object = _SCORING_CLASSES[prefix](self._build_vector(prefix, metrics))
        return ScoringBasis(
            advisory_id=advisory_id,
            known_at=known_at,
            effective_at=effective_at,
            cvss_prefix=prefix,
            vector=scoring_object.clean_vector(),
            scores=scoring_object.scores(),
            severities=scoring_object.severities(),
            applied_event_ids=tuple(applied),
            revoked_event_ids=tuple(sorted(revoked)),
            metric_provenance=dict(provenance),
        )

    @staticmethod
    def _parse_metrics(prefix, vector):
        scoring_object = _SCORING_CLASSES[prefix](vector)
        # Only metrics explicitly present in the vector count; `.metrics` may also hold the
        # X/default placeholders added by add_missing_optional() for v3 and v4 objects.
        explicit = getattr(scoring_object, "original_metrics", None)
        if explicit is None:
            explicit = scoring_object.metrics
        return [(metric, value) for metric, value in explicit.items() if value != "X"]

    @staticmethod
    def _build_vector(prefix, metrics):
        if prefix == "CVSS:2.0":
            return "/".join("{0}:{1}".format(metric, value) for metric, value in metrics.items())
        return prefix + "/" + "/".join(
            "{0}:{1}".format(metric, value) for metric, value in metrics.items()
        )

    def _validate_value(self, prefix, advisory, metric, value, advisory_id):
        probe = dict(self._parse_metrics(prefix, advisory.vector))
        probe[metric] = value
        try:
            _SCORING_CLASSES[prefix](self._build_vector(prefix, probe))
        except Exception as exc:
            raise CVSSHistoryValidationError(
                'Erratum for advisory "{0}" sets illegal value "{1}:{2}": {3}'.format(
                    advisory_id, metric, value, exc
                )
            )

    def _require_advisory(self, advisory_id):
        advisory = self._advisories.get(advisory_id)
        if advisory is None:
            raise CVSSHistoryReferenceError(
                'Unknown advisory "{0}"'.format(advisory_id), advisory_id=advisory_id
            )
        return advisory

    def _find_event(self, event_id):
        for event in self.events:
            if event.event_id == event_id:
                return event
        return None

    def _ensure_unique_event_id(self, event_id):
        if self._find_event(event_id) is not None:
            raise CVSSHistoryValidationError('Event id "{0}" is already used'.format(event_id))

    def _event_id(self, advisory_id, event_type):
        key = (advisory_id, event_type)
        sequence = self._event_counters.get(key, 0) + 1
        self._event_counters[key] = sequence
        return "{0}:{1}:{2}".format(advisory_id, event_type, sequence)
