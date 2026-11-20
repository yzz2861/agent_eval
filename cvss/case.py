# Copyright (c) 2026 Red Hat, Inc.
# License: LGPLv3+

from __future__ import unicode_literals

import copy
import hashlib
import json
from datetime import datetime, timezone

from .cvss2 import CVSS2
from .cvss3 import CVSS3
from .cvss4 import CVSS4
from .exceptions import CVSSCaseInvalid, CVSSCaseNotFound

__all__ = [
    "Assessment",
    "ProductEvaluation",
    "VulnerabilityCase",
    "DispositionRule",
    "ThresholdRule",
    "CallableRule",
    "DispositionDecision",
    "QueueTicket",
]

_CVSS_CLASSES = {
    "2.0": CVSS2,
    "3.0": CVSS3,
    "3.1": CVSS3,
    "4.0": CVSS4,
}

# Score kinds selectable by a disposition rule, mapped to the position in the
# tuple returned by the CVSS classes scores() method.
_SCORE_KIND_INDEX = {
    "base": 0,
    "temporal": 1,
    "environmental": 2,
}


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _detect_cvss_version(vector):
    # Returns the canonical CVSS version string for a raw vector.
    prefix = vector.split("/", 1)[0]
    if vector.startswith("CVSS:3."):
        return prefix.split(":", 1)[1]
    if vector.startswith("CVSS:4."):
        return "4.0"
    return "2.0"


def _build_cvss(version, vector):
    # Builds a CVSS object for the given version and vector.
    # Raises CVSSCaseInvalid on unknown version or an unparseable vector.
    version = str(version)
    if version in ("2", "3", "4"):
        if version == "2":
            version = "2.0"
        elif version == "4":
            version = "4.0"
        else:
            version = _detect_cvss_version(vector) if vector.startswith("CVSS:3.") else "3.1"
    if version not in _CVSS_CLASSES:
        raise CVSSCaseInvalid("Unknown CVSS version {0!r}".format(version))
    detected = _detect_cvss_version(vector)
    if vector.startswith("CVSS:") and detected != version:
        raise CVSSCaseInvalid(
            "CVSS version {0!r} does not match vector prefix of {1!r}".format(version, vector)
        )
    try:
        return _CVSS_CLASSES[version](vector)
    except Exception as exc:  # all parser errors are CVSSError subclasses
        raise CVSSCaseInvalid(
            "Invalid CVSS{0} vector {1!r}: {2}".format(version, vector, exc)
        )


def _canonical_basis(basis):
    # Canonicalizes the free-form evidence basis into a stable string used for
    # identity hashing. The basis itself is kept untouched on the object.
    if basis is None:
        basis = {}
    if not isinstance(basis, dict):
        raise CVSSCaseInvalid("Assessment basis must be a dictionary of evidence")
    return json.dumps(basis, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


class _Frozen(object):
    # Mix-in making an object immutable after its constructor finishes.

    _frozen = False

    def _freeze(self):
        self._frozen = True

    def __setattr__(self, name, value):
        if self._frozen:
            raise AttributeError(
                "{0} objects are immutable; create a revision instead".format(
                    self.__class__.__name__
                )
            )
        super(_Frozen, self).__setattr__(name, value)


class Assessment(_Frozen):
    # An immutable, independently reviewable CVSS evaluation.
    #
    # Two assessments are the same assessment if and only if their CVSS version,
    # raw vector, and evidence basis are identical -- even when the computed
    # scores happen to be equal. The assessment id is a content hash of exactly
    # those inputs, so the same inputs always resolve to the same id (allowing
    # several products to reference one shared assessment) and different versions
    # or vectors never collapse into one.

    def __init__(self, vector, basis=None, cvss_version=None, created_at=None):
        if not isinstance(vector, str) or not vector.strip():
            raise CVSSCaseInvalid("Assessment vector must be a non-empty string")
        vector = vector.strip()
        if cvss_version is None:
            cvss_version = _detect_cvss_version(vector)
        cvss = _build_cvss(cvss_version, vector)
        if vector.startswith("CVSS:"):
            canonical_version = _detect_cvss_version(vector)
        else:
            if str(cvss_version).startswith(("3", "4")):
                raise CVSSCaseInvalid(
                    "CVSS {0} vectors must carry the CVSS: prefix".format(cvss_version)
                )
            canonical_version = "2.0"
        self.cvss_version = canonical_version
        self.vector = vector
        self.basis = copy.deepcopy(basis) if basis is not None else {}
        if not isinstance(self.basis, dict):
            raise CVSSCaseInvalid("Assessment basis must be a dictionary of evidence")
        self.scores = tuple(float(score) if score is not None else None
                             for score in cvss.scores())
        self.severities = tuple(cvss.severities())
        self.created_at = created_at or _now_iso()
        identity = "{0}|{1}|{2}".format(
            self.cvss_version, self.vector, _canonical_basis(self.basis)
        )
        self.assessment_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
        self._freeze()

    def score(self, kind="base"):
        # Returns one score by kind: "base", "temporal", or "environmental".
        # Temporal/environmental scores are only defined for CVSS v2 and v3.
        if kind not in _SCORE_KIND_INDEX:
            raise CVSSCaseInvalid(
                "Unknown score kind {0!r}; expected one of {1}".format(
                    kind, sorted(_SCORE_KIND_INDEX)
                )
            )
        index = _SCORE_KIND_INDEX[kind]
        if index >= len(self.scores) or self.scores[index] is None:
            raise CVSSCaseInvalid(
                "Score kind {0!r} is not defined for CVSS {1} assessments".format(
                    kind, self.cvss_version
                )
            )
        return self.scores[index]

    def as_dict(self):
        # Returns a plain-data representation safe to serialize to JSON.
        return {
            "assessment_id": self.assessment_id,
            "cvss_version": self.cvss_version,
            "vector": self.vector,
            "basis": copy.deepcopy(self.basis),
            "scores": list(self.scores),
            "severities": list(self.severities),
            "created_at": self.created_at,
        }

    def __eq__(self, other):
        return isinstance(other, Assessment) and other.assessment_id == self.assessment_id

    def __hash__(self):
        return hash(self.assessment_id)

    def __repr__(self):
        return "Assessment(id={0!r}, cvss={1}, vector={2!r})".format(
            self.assessment_id, self.cvss_version, self.vector
        )


class ProductEvaluation(object):
    # The current evaluation of one product line within a vulnerability case.
    #
    # The product never mutates the underlying assessment. Remediating one
    # environment appends a new immutable assessment as a revision and records
    # the change in the remediation history, leaving the previous assessment
    # available for review and for any ticket that already cited it.

    def __init__(self, product, assessment, note=None):
        if not isinstance(product, str) or not product.strip():
            raise CVSSCaseInvalid("Product identifier must be a non-empty string")
        if not isinstance(assessment, Assessment):
            raise CVSSCaseInvalid("Product evaluation requires an Assessment instance")
        self.product = product.strip()
        self.revisions = [assessment]
        self.remediation_history = [
            {
                "assessment_id": assessment.assessment_id,
                "reason": note or "initial assessment",
                "recorded_at": assessment.created_at,
            }
        ]

    @property
    def assessment(self):
        # Returns the current (latest) assessment for the product.
        return self.revisions[-1]

    @property
    def assessment_id(self):
        return self.assessment.assessment_id

    def add_revision(self, assessment, reason):
        # Appends a new assessment revision, e.g. after one environment is fixed.
        # Re-adding the identical assessment is a no-op so repeated remediation
        # records cannot fabricate new revisions.
        if not isinstance(assessment, Assessment):
            raise CVSSCaseInvalid("Revision requires an Assessment instance")
        if assessment.assessment_id == self.assessment_id:
            return self.assessment
        self.revisions.append(assessment)
        self.remediation_history.append(
            {
                "assessment_id": assessment.assessment_id,
                "reason": reason,
                "recorded_at": _now_iso(),
            }
        )
        return assessment

    def get_revision(self, assessment_id):
        # Returns a historical assessment by id, even after later remediation.
        for revision in self.revisions:
            if revision.assessment_id == assessment_id:
                return revision
        raise CVSSCaseNotFound(
            "Product {0!r} has no assessment {1!r}".format(self.product, assessment_id)
        )

    def as_dict(self):
        return {
            "product": self.product,
            "current_assessment_id": self.assessment_id,
            "revisions": [revision.as_dict() for revision in self.revisions],
            "remediation_history": copy.deepcopy(self.remediation_history),
        }


class DispositionDecision(_Frozen):
    # The outcome of evaluating one product against a disposition rule.

    def __init__(self, product, queued, reason, rule_name, score_kind, score_value,
                 threshold=None, assessment_id=None, decided_at=None):
        self.product = product
        self.queued = bool(queued)
        self.reason = reason
        self.rule_name = rule_name
        self.score_kind = score_kind
        self.score_value = score_value
        self.threshold = threshold
        self.assessment_id = assessment_id
        self.decided_at = decided_at or _now_iso()
        self._freeze()

    def as_dict(self):
        return {
            "product": self.product,
            "queued": self.queued,
            "reason": self.reason,
            "rule_name": self.rule_name,
            "score_kind": self.score_kind,
            "score_value": self.score_value,
            "threshold": self.threshold,
            "assessment_id": self.assessment_id,
            "decided_at": self.decided_at,
        }


class QueueTicket(_Frozen):
    # An immutable queued-work ticket capturing everything needed to explain
    # later why the product entered the queue, including full snapshots of the
    # product vector, evidence basis, and the disposition condition.

    def __init__(self, ticket_id, case_id, decision, assessment):
        self.ticket_id = ticket_id
        self.case_id = case_id
        self.decision = decision.as_dict()
        # Snapshot the independent assessment itself so the ticket stays
        # explainable even if the product is remediated or revised afterwards.
        self.assessment_snapshot = assessment.as_dict()
        self.created_at = _now_iso()
        self._freeze()

    def as_dict(self):
        return {
            "ticket_id": self.ticket_id,
            "case_id": self.case_id,
            "created_at": self.created_at,
            "decision": copy.deepcopy(self.decision),
            "assessment": copy.deepcopy(self.assessment_snapshot),
        }


class DispositionRule(object):
    # Base class for caller-supplied disposition rules.

    name = "disposition-rule"
    score_kind = "base"

    def decide(self, product, assessment):
        # Returns a DispositionDecision for one product assessment.
        raise NotImplementedError


class ThresholdRule(DispositionRule):
    # Queues a product when the selected score meets or exceeds a threshold.

    def __init__(self, threshold, score_kind="base", name=None):
        if score_kind not in _SCORE_KIND_INDEX:
            raise CVSSCaseInvalid(
                "Unknown score kind {0!r}; expected one of {1}".format(
                    score_kind, sorted(_SCORE_KIND_INDEX)
                )
            )
        self.threshold = float(threshold)
        self.score_kind = score_kind
        self.name = name or "threshold-{0}-{1}".format(score_kind, threshold)

    def decide(self, product, assessment):
        value = assessment.score(self.score_kind)
        queued = value >= self.threshold
        if queued:
            reason = "{0} score {1} meets threshold {2}".format(
                self.score_kind, value, self.threshold
            )
        else:
            reason = "{0} score {1} below threshold {2}".format(
                self.score_kind, value, self.threshold
            )
        return DispositionDecision(
            product=product,
            queued=queued,
            reason=reason,
            rule_name=self.name,
            score_kind=self.score_kind,
            score_value=value,
            threshold=self.threshold,
            assessment_id=assessment.assessment_id,
        )


class CallableRule(DispositionRule):
    # Adapts any caller-supplied predicate
    # f(product, assessment) -> (queued, reason) or just a boolean.

    def __init__(self, predicate, score_kind="base", name="callable-rule"):
        if not callable(predicate):
            raise CVSSCaseInvalid("CallableRule requires a callable predicate")
        if score_kind not in _SCORE_KIND_INDEX:
            raise CVSSCaseInvalid(
                "Unknown score kind {0!r}; expected one of {1}".format(
                    score_kind, sorted(_SCORE_KIND_INDEX)
                )
            )
        self.predicate = predicate
        self.score_kind = score_kind
        self.name = name

    def decide(self, product, assessment):
        value = assessment.score(self.score_kind)
        result = self.predicate(product, assessment)
        if isinstance(result, tuple):
            queued, reason = result
        else:
            queued = bool(result)
            reason = "callable predicate returned {0}".format(queued)
        return DispositionDecision(
            product=product,
            queued=bool(queued),
            reason=reason,
            rule_name=self.name,
            score_kind=self.score_kind,
            score_value=value,
            threshold=None,
            assessment_id=assessment.assessment_id,
        )


class VulnerabilityCase(object):
    # A small vulnerability case bundling several product lines.
    #
    # Each product keeps its own ProductEvaluation built from an independent,
    # immutable Assessment. Products may explicitly reference another product
    # assessment; identical assessments are deduplicated by content id so one
    # independent assessment can back several products while still being
    # individually reviewable.

    def __init__(self, case_id, title=None):
        if not isinstance(case_id, str) or not case_id.strip():
            raise CVSSCaseInvalid("Case id must be a non-empty string")
        self.case_id = case_id.strip()
        self.title = title
        self._evaluations = {}
        self._assessments = {}
        self._shared_refs = []
        self._audit = []
        self._tickets = {}
        self._ticket_counter = 0

    def _record(self, action, **details):
        entry = {"action": action, "recorded_at": _now_iso()}
        entry.update(details)
        self._audit.append(entry)
        return entry

    def _store_assessment(self, assessment):
        existing = self._assessments.get(assessment.assessment_id)
        if existing is None:
            self._assessments[assessment.assessment_id] = assessment
            return assessment, False
        return existing, True

    def add_assessment(self, vector, basis=None, cvss_version=None):
        # Creates and registers an independent assessment. Re-registering the
        # same (version, vector, basis) always returns the same object and id.
        assessment = Assessment(vector, basis=basis, cvss_version=cvss_version)
        stored, reused = self._store_assessment(assessment)
        self._record(
            "register_assessment",
            assessment_id=stored.assessment_id,
            reused=reused,
            cvss_version=stored.cvss_version,
        )
        return stored

    def add_product(self, product, vector=None, basis=None, cvss_version=None,
                    assessment=None, note=None):
        # Adds a product line either from a raw vector/evidence pair or by
        # attaching an existing Assessment (possibly one already used by another
        # product). Exactly one input style must be supplied.
        if product in self._evaluations:
            raise CVSSCaseInvalid("Product {0!r} already exists in case {1!r}".format(
                product, self.case_id))
        if assessment is not None and vector is not None:
            raise CVSSCaseInvalid("Provide either an assessment or a vector, not both")
        if assessment is not None:
            if not isinstance(assessment, Assessment):
                raise CVSSCaseInvalid("assessment must be an Assessment instance")
            stored, _ = self._store_assessment(assessment)
        else:
            if vector is None:
                raise CVSSCaseInvalid("Provide either an assessment or a vector")
            stored = self.add_assessment(vector, basis=basis, cvss_version=cvss_version)
        evaluation = ProductEvaluation(product, stored, note=note)
        self._evaluations[product] = evaluation
        self._record("add_product", product=product, assessment_id=stored.assessment_id)
        return evaluation

    def share_assessment(self, source_product, target_product, note=None):
        # Lets one product reference the current assessment of another product.
        # Both products point at the same immutable assessment id, yet either one
        # can later be revised independently without affecting the other.
        if source_product not in self._evaluations:
            raise CVSSCaseNotFound("Unknown source product {0!r}".format(source_product))
        if target_product in self._evaluations:
            raise CVSSCaseInvalid("Target product {0!r} already exists".format(target_product))
        source = self._evaluations[source_product]
        shared = source.assessment
        self._evaluations[target_product] = ProductEvaluation(target_product, shared, note=note)
        self._shared_refs.append({
            "source_product": source_product,
            "target_product": target_product,
            "assessment_id": shared.assessment_id,
            "reason": note or "shared assessment reference",
        })
        self._record(
            "share_assessment",
            source_product=source_product,
            target_product=target_product,
            assessment_id=shared.assessment_id,
        )
        return self._evaluations[target_product]

    def remediate_environment(self, product, vector, basis=None, cvss_version=None,
                              reason="environment remediation"):
        # Records that one environment of a product was fixed by appending a new
        # assessment revision. Historical revisions and any tickets citing them
        # remain intact and reviewable.
        if product not in self._evaluations:
            raise CVSSCaseNotFound("Unknown product {0!r}".format(product))
        new_assessment = self.add_assessment(vector, basis=basis, cvss_version=cvss_version)
        evaluation = self._evaluations[product]
        previous_id = evaluation.assessment_id
        evaluation.add_revision(new_assessment, reason)
        self._record(
            "remediate_environment",
            product=product,
            previous_assessment_id=previous_id,
            new_assessment_id=new_assessment.assessment_id,
            reason=reason,
        )
        return new_assessment

    def get_product(self, product):
        if product not in self._evaluations:
            raise CVSSCaseNotFound("Unknown product {0!r}".format(product))
        return self._evaluations[product]

    def get_assessment(self, assessment_id):
        # Returns the independent assessment by id regardless of which product
        # references it.
        if assessment_id not in self._assessments:
            raise CVSSCaseNotFound("Unknown assessment {0!r}".format(assessment_id))
        return self._assessments[assessment_id]

    def products(self):
        return sorted(self._evaluations)

    def shared_references(self):
        return copy.deepcopy(self._shared_refs)

    def audit_log(self):
        return copy.deepcopy(self._audit)

    def apply_disposition(self, rule):
        # Evaluates every product against the caller-supplied rule, records a
        # decision for each, and opens immutable tickets for queued products.
        # Returns the list of newly created QueueTicket objects.
        if not isinstance(rule, DispositionRule):
            raise CVSSCaseInvalid("rule must be a DispositionRule instance")
        tickets = []
        for product in sorted(self._evaluations):
            evaluation = self._evaluations[product]
            assessment = evaluation.assessment
            decision = rule.decide(product, assessment)
            self._record(
                "disposition_decision",
                product=product,
                queued=decision.queued,
                rule_name=decision.rule_name,
                assessment_id=assessment.assessment_id,
            )
            if decision.queued:
                self._ticket_counter += 1
                ticket_id = "{0}-T{1:04d}".format(self.case_id, self._ticket_counter)
                ticket = QueueTicket(ticket_id, self.case_id, decision, assessment)
                self._tickets[ticket_id] = ticket
                self._record(
                    "queue_ticket",
                    ticket_id=ticket_id,
                    product=product,
                    assessment_id=assessment.assessment_id,
                )
                tickets.append(ticket)
        return tickets

    def explain_ticket(self, ticket_id):
        # Returns a full, self-contained explanation of why a ticket entered the
        # queue: disposition condition plus the product line own vector, evidence
        # basis, and the independent assessment it was derived from.
        if ticket_id not in self._tickets:
            raise CVSSCaseNotFound("Unknown ticket {0!r}".format(ticket_id))
        ticket = self._tickets[ticket_id].as_dict()
        product = ticket["decision"]["product"]
        evaluation = self._evaluations[product]
        cited_id = ticket["decision"]["assessment_id"]
        return {
            "ticket_id": ticket["ticket_id"],
            "case_id": ticket["case_id"],
            "product": product,
            "disposition": copy.deepcopy(ticket["decision"]),
            "cited_assessment_id": cited_id,
            "cited_assessment": evaluation.get_revision(cited_id).as_dict(),
            "current_assessment_id": evaluation.assessment_id,
            "current_assessment": evaluation.assessment.as_dict(),
            "remediation_history": copy.deepcopy(evaluation.remediation_history),
        }

    def tickets(self):
        return sorted(self._tickets)

    def as_dict(self):
        return {
            "case_id": self.case_id,
            "title": self.title,
            "products": [self._evaluations[name].as_dict()
                         for name in sorted(self._evaluations)],
            "assessments": [a.as_dict() for a in self._assessments.values()],
            "shared_references": copy.deepcopy(self._shared_refs),
            "tickets": [self._tickets[t].as_dict() for t in sorted(self._tickets)],
            "audit_log": copy.deepcopy(self._audit),
        }
