# Copyright (c) 2026 Red Hat, Inc.
# License: LGPLv3+

"""
Collaborative CVSS scoring of a single security advisory by several responders.

Responder *receipts* are treated as external, untrusted input. Every receipt carries the
vector version the responder was looking at when editing (optimistic concurrency control).
Revisions touching different CVSS metrics coexist; revisions whose values disagree are rejected.
Everything is recorded in an append-only journal, so withdrawn revisions still leave a traceable
record of the values that were publicly visible at the time.
"""

from __future__ import unicode_literals

from collections import OrderedDict

from .constants3 import METRICS_ABBREVIATIONS, METRICS_VALUES
from .cvss3 import CVSS3
from .exceptions import CVSSError


class AdvisoryScoringError(CVSSError):
    """General exception for advisory scoring receipts."""

    pass


class ReceiptValidationError(AdvisoryScoringError):
    """Raised when a receipt cannot be parsed or references unknown CVSS data."""

    pass


class ReceiptConflictError(AdvisoryScoringError):
    """Raised when a receipt conflicts with a revision already accepted for the same metric."""

    pass


class StaleReceiptError(AdvisoryScoringError):
    """Raised when a receipt is based on a vector version that is no longer current."""

    pass


def _validate_metric(metric, value):
    if metric not in METRICS_ABBREVIATIONS:
        raise ReceiptValidationError('Unknown CVSS metric "{0}"'.format(metric))
    if value not in METRICS_VALUES[metric]:
        raise ReceiptValidationError('Unknown value "{0}" for metric "{1}"'.format(value, metric))


class RevisionReceipt(object):
    """
    A single external submission from a responder.

    Args:
        receipt_id: unique id used to make repeated delivery idempotent
        responder: identifier of the responder submitting the revision
        fields: mapping of CVSS metric abbreviations to their new values
        base_version: vector version the responder saw before editing
        seq: delivery order assigned by the transport; ``deliver`` processes receipts in
             this order regardless of the order they are handed to the ledger
    """

    def __init__(self, receipt_id, responder, fields, base_version, seq):
        self.receipt_id = receipt_id
        self.responder = responder
        self.base_version = base_version
        self.seq = seq
        self.fields = OrderedDict()
        for metric, value in fields.items():
            _validate_metric(metric, value)
            self.fields[metric] = value
        if not self.fields:
            raise ReceiptValidationError(
                'Receipt "{0}" does not revise any metric'.format(receipt_id)
            )


class AdvisoryScoring(object):
    """
    Append-only ledger coordinating CVSS revisions for one advisory.

    All state changes are stored as events and numbered monotonically. A *vector version* is
    the journal sequence number of the last event that changed the visible vector; receipts
    quote the version they were based on so stale edits can be detected.
    """

    def __init__(self, advisory_id, base_vector):
        self.advisory_id = advisory_id
        self._cvss = CVSS3(base_vector)
        self.spec_version = "3.{0}".format(self._cvss.minor_version)

        self._metrics = OrderedDict(self._cvss.original_metrics)
        self._vector_version = 0
        self._seq = 0
        self._events = []
        self._receipt_index = {}
        self._revisions = {}
        self._previous_values = {}
        self._metric_versions = {}
        self._publications = {}

        self._record(
            "initialized",
            OrderedDict(
                [
                    ("advisory_id", advisory_id),
                    ("vector", self.current_vector()),
                    ("vector_version", 0),
                ]
            ),
        )
        self._publications["initial"] = self._snapshot(0)

    def _record(self, kind, payload):
        event = OrderedDict([("seq", self._seq), ("kind", kind), ("payload", payload)])
        self._events.append(event)
        self._seq += 1
        return event

    def _snapshot(self, vector_version):
        vector = self._build_vector(self._metrics)
        cvss = CVSS3(vector)
        return OrderedDict(
            [
                ("advisory_id", self.advisory_id),
                ("vector_version", vector_version),
                ("vector", cvss.clean_vector()),
                ("base_score", cvss.scores()[0]),
                ("severity", cvss.severities()[0]),
            ]
        )

    def _build_vector(self, metrics):
        parts = ["CVSS:{0}".format(self.spec_version)]
        for metric in METRICS_ABBREVIATIONS:
            if metric in metrics and metrics[metric] != "X":
                parts.append("{0}:{1}".format(metric, metrics[metric]))
        return "/".join(parts)

    def current_vector(self):
        return self._build_vector(self._metrics)

    @property
    def vector_version(self):
        """Vector version a newly authored receipt must quote as its base version."""
        return self._vector_version

    def journal(self):
        """Returns a copy of every recorded event, including rejected and withdrawn ones."""
        return [self._copy_event(event) for event in self._events]

    @staticmethod
    def _copy_event(event):
        return OrderedDict(
            [
                ("seq", event["seq"]),
                ("kind", event["kind"]),
                ("payload", OrderedDict(event["payload"])),
            ]
        )

    def _reject(self, receipt, reason, conflicts=None):
        event = self._record(
            "rejected",
            OrderedDict(
                [
                    ("receipt_id", receipt.receipt_id),
                    ("responder", receipt.responder),
                    ("base_version", receipt.base_version),
                    ("reason", reason),
                    ("conflicts", list(conflicts or [])),
                    ("fields", OrderedDict(receipt.fields)),
                ]
            ),
        )
        return event

    def deliver(self, *receipts):
        """
        Feeds a stream of external receipts into the recalculation entry point in delivery
        order. Rejected or stale receipts raise, but every receipt, including the failure, is
        already recorded in the journal, so callers can keep processing the remaining stream.
        """
        results = []
        for receipt in sorted(receipts, key=lambda item: item.seq):
            results.append(self.submit(receipt))
        return results

    def submit(self, receipt):
        """
        Feeds one external receipt into the CVSS recalculation entry point.

        Compatible field revisions are merged and trigger a recalculation. Repeated delivery of
        the same receipt id returns the original outcome without changing the vector. Conflicting
        or stale receipts are rejected and signed back to the responder via an exception and a
        journal event.

        Returns:
            OrderedDict: the stored event describing the accepted, duplicate, or rejected outcome

        Raises:
            ReceiptConflictError: the receipt changes a metric to a value different from the
                value of an already accepted revision
            StaleReceiptError: the receipt quotes a vector version older than the current one
        """
        if receipt.receipt_id in self._receipt_index:
            original_seq = self._receipt_index[receipt.receipt_id]
            event = self._record(
                "duplicate",
                OrderedDict(
                    [
                        ("receipt_id", receipt.receipt_id),
                        ("responder", receipt.responder),
                        ("original_seq", original_seq),
                    ]
                ),
            )
            return event

        self._receipt_index[receipt.receipt_id] = self._seq

        # Two responders editing disjoint metrics can both start from the same vector version
        # and have their revisions coexist. Re-submitting the same value is a harmless no-op for
        # that field, while a different value for an already-owned field is a hard conflict.
        conflicts = []
        for metric, value in receipt.fields.items():
            owner = self._revisions.get(metric)
            if owner is not None and value != self._metrics[metric]:
                current_value = self._metrics[metric]
                conflicts.append(
                    OrderedDict(
                        [
                            ("metric", metric),
                            ("submitted_value", value),
                            ("current_value", current_value),
                            ("owner_receipt", owner),
                        ]
                    )
                )
        if conflicts:
            event = self._reject(receipt, "conflicting field revision", conflicts)
            raise ReceiptConflictError(event["payload"]["reason"])

        if receipt.base_version > self._vector_version:
            event = self._reject(
                receipt,
                "unknown future base version {0}, current vector version is {1}".format(
                    receipt.base_version, self._vector_version
                ),
            )
            raise StaleReceiptError(event["payload"]["reason"])

        # A receipt is stale only when a metric it touches changed after the version it read.
        # Disjoint revisions authored against the same version still merge cleanly.
        touched_versions = [self._metric_versions.get(metric, 0) for metric in receipt.fields]
        if touched_versions and receipt.base_version < max(touched_versions):
            event = self._reject(
                receipt,
                "stale base version {0}, current vector version is {1}".format(
                    receipt.base_version, self._vector_version
                ),
            )
            raise StaleReceiptError(event["payload"]["reason"])

        changed = OrderedDict()
        for metric, value in receipt.fields.items():
            if self._metrics.get(metric) != value:
                changed[metric] = value
                if metric not in self._previous_values:
                    self._previous_values[metric] = self._metrics.get(metric)
                self._metrics[metric] = value
                self._metric_versions[metric] = self._seq
            if metric not in self._revisions:
                self._revisions[metric] = receipt.receipt_id

        self._vector_version = self._seq
        snapshot = self._snapshot(self._vector_version)
        event = self._record(
            "accepted",
            OrderedDict(
                [
                    ("receipt_id", receipt.receipt_id),
                    ("responder", receipt.responder),
                    ("base_version", receipt.base_version),
                    ("vector_version", self._vector_version),
                    ("fields", OrderedDict(receipt.fields)),
                    ("changed", OrderedDict(changed)),
                    (
                        "previous_values",
                        OrderedDict(
                            (metric, self._previous_values.get(metric)) for metric in changed
                        ),
                    ),
                    ("base_score", snapshot["base_score"]),
                    ("severity", snapshot["severity"]),
                    ("vector", snapshot["vector"]),
                ]
            ),
        )
        return event

    def publish(self, label):
        """Publishes the current vector as a named historical release point."""
        snapshot = self._snapshot(self._vector_version)
        snapshot["label"] = label
        event = self._record("published", OrderedDict(snapshot))
        self._publications[label] = snapshot
        return event

    def withdraw(self, receipt_id, responder):
        """
        Withdraws a previously accepted revision.

        The accepted and withdrawn events both stay in the journal, and the values that were
        publicly visible remain recoverable through the historical snapshots. Restoring a metric
        requires a new receipt based on the current vector version; withdrawal only releases the
        responder's claim and records the rollback target.
        """
        accepted = self._find_accepted(receipt_id)
        if accepted is None:
            raise AdvisoryScoringError(
                'Receipt "{0}" has no accepted revision to withdraw'.format(receipt_id)
            )

        fields = accepted["payload"]["fields"]
        rollback_values = OrderedDict()
        for metric in fields:
            if self._revisions.get(metric) == receipt_id:
                previous = self._previous_values.get(metric)
                rollback_values[metric] = previous
                if previous is None:
                    self._metrics.pop(metric, None)
                else:
                    self._metrics[metric] = previous
                self._revisions.pop(metric, None)
                self._previous_values.pop(metric, None)

        event = self._record(
            "withdrawn",
            OrderedDict(
                [
                    ("receipt_id", receipt_id),
                    ("responder", responder),
                    ("base_version", self._vector_version),
                    ("fields", OrderedDict(fields)),
                    ("rollback_values", rollback_values),
                    ("last_public_vector", self.last_published_snapshot()["vector"]),
                ]
            ),
        )
        return event

    def _find_accepted(self, receipt_id):
        for event in self._events:
            if event["kind"] == "accepted" and event["payload"]["receipt_id"] == receipt_id:
                return event
        return None

    def last_published_snapshot(self):
        latest_label = next(reversed(self._publications))
        return OrderedDict(self._publications[latest_label])

    def publications(self):
        """Returns every historical release point ever displayed in a report."""
        return OrderedDict(
            (label, OrderedDict(snapshot)) for label, snapshot in self._publications.items()
        )

    def publication(self, label):
        return OrderedDict(self._publications[label])

    def recompute_at(self, label):
        """
        Recalculates a named historical release point from the vector displayed in the report.

        The stored vector is fed back through the CVSS recalculation entry point, so the result
        can be checked against the score and severity displayed at that release point.
        """
        snapshot = self.publication(label)
        cvss = CVSS3(snapshot["vector"])
        return OrderedDict(
            [
                ("advisory_id", self.advisory_id),
                ("label", label),
                ("vector_version", snapshot["vector_version"]),
                ("vector", cvss.clean_vector()),
                ("base_score", cvss.scores()[0]),
                ("severity", cvss.severities()[0]),
                ("displayed_score", snapshot["base_score"]),
                ("displayed_severity", snapshot["severity"]),
                (
                    "matches_display",
                    cvss.scores()[0] == snapshot["base_score"]
                    and cvss.severities()[0] == snapshot["severity"],
                ),
            ]
        )

    def current_result(self):
        return self._snapshot(self._vector_version)
