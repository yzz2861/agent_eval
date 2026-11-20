"""
Offline reconciliation helpers for queue rule migrations between CVSS versions.

The helpers in this module deliberately keep the two vectors, the two rule sets,
and the two decisions separate.  They only compare dimensions which both rule
sets explicitly declare and never derive a missing vector from the other one.
"""

from __future__ import unicode_literals

import re

from .cvss3 import CVSS3
from .cvss4 import CVSS4
from .exceptions import CVSSError


CHANGED = "changed"
UNCHANGED = "unchanged"
NOT_COMPARABLE = "not_comparable"

MISSING_EVIDENCE = "missing_evidence"
OLD_RULE_NOT_APPLICABLE = "old_rule_not_applicable"
NEW_RULE_NOT_APPLICABLE = "new_rule_not_applicable"
INVALID_VECTOR = "invalid_vector"
NO_RULE_MATCHED = "no_rule_matched"

SCORING_DATA_CHANGED = "scoring_data_changed"
RULE_CHANGED = "rule_changed"

SUPPORTED = "supported"
REJECTED = "rejected"
POSSIBLE = "possible"

_SEVERITIES = ("None", "Low", "Medium", "High", "Critical")
_SEVERITY_LOOKUP = dict((severity.lower(), severity) for severity in _SEVERITIES)
_METRICS = {
    "3.0": ("base", "temporal", "environmental"),
    "3.1": ("base", "temporal", "environmental"),
    "4.0": ("base",),
}
_RH_VECTOR = re.compile(r"^\d+(?:\.\d+)?/(CVSS:\d+\.\d+/.*)$")


class QueueRuleError(ValueError):
    """Raised when a queue rule set is malformed or cannot be evaluated."""

    pass


def _normalise_version(version):
    value = str(version).strip()
    if value.upper().startswith("CVSS:"):
        value = value[5:]
    if value not in _METRICS:
        raise QueueRuleError(
            'Unsupported CVSS version "{0}", expected one of {1}'.format(
                version, ", ".join(sorted(_METRICS))
            )
        )
    return value


def _normalise_metric(metric, version, kind):
    value = str(metric).strip().lower()
    if value not in _METRICS[version]:
        raise QueueRuleError(
            'Unsupported {0} metric "{1}" for CVSS {2}'.format(kind, metric, version)
        )
    return value


def _normalise_basis(basis):
    if isinstance(basis, str):
        basis = (basis,)
    values = set()
    for value in basis:
        value = str(value).strip().lower()
        if value not in ("score", "severity"):
            raise QueueRuleError(
                'Unsupported declared basis "{0}", expected "score" or "severity"'.format(value)
            )
        values.add(value)
    return tuple(value for value in ("score", "severity") if value in values)


def _normalise_severities(severities):
    if severities is None:
        return None
    if isinstance(severities, str):
        severities = (severities,)
    result = []
    for severity in severities:
        key = str(severity).strip().lower()
        if key not in _SEVERITY_LOOKUP:
            raise QueueRuleError(
                'Unsupported severity "{0}", expected one of {1}'.format(
                    severity, ", ".join(_SEVERITIES)
                )
            )
        canonical = _SEVERITY_LOOKUP[key]
        if canonical not in result:
            result.append(canonical)
    return tuple(result)


def _number(value, name):
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise QueueRuleError('{0} must be a number, got "{1}"'.format(name, value))
    if number < 0.0 or number > 10.0:
        raise QueueRuleError("{0} must be between 0.0 and 10.0".format(name))
    return number


def _format_value(value):
    if value is None:
        return "None"
    return str(value)


def _object_version(cvss_object):
    if isinstance(cvss_object, CVSS4):
        return "4.0"
    if isinstance(cvss_object, CVSS3):
        return "3.1" if cvss_object.minor_version == 1 else "3.0"
    raise QueueRuleError("Unsupported CVSS object {0!r}".format(cvss_object))


def _parse_vector(vector):
    """Parse standard or Red Hat notation vectors, always recomputing the score."""
    if not isinstance(vector, str):
        raise QueueRuleError("CVSS vector must be a string")
    value = vector.strip()
    if not value:
        raise QueueRuleError("CVSS vector is empty")
    match = _RH_VECTOR.match(value)
    if match:
        # A leading Red Hat score is intentionally ignored.  The score is always
        # recomputed by the library and is never trusted as independent evidence.
        value = match.group(1)
    if value.startswith("CVSS:4.0/"):
        return CVSS4(value)
    if value.startswith("CVSS:3.1/") or value.startswith("CVSS:3.0/"):
        return CVSS3(value)
    raise QueueRuleError(
        'Unsupported vector "{0}", expected a CVSS 3.0, 3.1 or 4.0 vector'.format(vector)
    )


class QueueRule(object):
    """
    One ordered queue band.  The first matching rule wins.

    Conditions are combined with logical AND and may only use the dimensions
    explicitly declared by the containing :class:`QueueRuleSet`.
    """

    def __init__(
        self,
        queue,
        min_score=None,
        max_score=None,
        min_inclusive=True,
        max_inclusive=True,
        severities=None,
        description=None,
    ):
        if not isinstance(queue, str) or not queue.strip():
            raise QueueRuleError("Queue name must be a non-empty string")
        self.queue = queue
        self.min_score = None if min_score is None else _number(min_score, "min_score")
        self.max_score = None if max_score is None else _number(max_score, "max_score")
        if (
            self.min_score is not None
            and self.max_score is not None
            and self.min_score > self.max_score
        ):
            raise QueueRuleError("min_score must not be greater than max_score")
        self.min_inclusive = bool(min_inclusive)
        self.max_inclusive = bool(max_inclusive)
        self.severities = _normalise_severities(severities)
        self.description = description
        if self.severities is not None and not self.severities:
            raise QueueRuleError("severities must not be empty when provided")

    @classmethod
    def from_dict(cls, data):
        if isinstance(data, cls):
            return data
        if not isinstance(data, dict):
            raise QueueRuleError("Queue rule must be a QueueRule or a dictionary")
        values = dict(data)
        try:
            queue = values.pop("queue")
        except KeyError:
            raise QueueRuleError('Queue rule is missing "queue"')
        return cls(queue, **values)

    @property
    def uses_score(self):
        return self.min_score is not None or self.max_score is not None

    @property
    def uses_severity(self):
        return self.severities is not None

    @property
    def is_catch_all(self):
        return not self.uses_score and not self.uses_severity

    def matches(self, observation):
        score = observation.get("score")
        severity = observation.get("severity")
        if self.uses_score:
            if score is None:
                raise QueueRuleError("Rule uses score but no score is available")
            if self.min_score is not None:
                if self.min_inclusive and score < self.min_score:
                    return False
                if not self.min_inclusive and score <= self.min_score:
                    return False
            if self.max_score is not None:
                if self.max_inclusive and score > self.max_score:
                    return False
                if not self.max_inclusive and score >= self.max_score:
                    return False
        if self.uses_severity:
            if severity is None:
                raise QueueRuleError("Rule uses severity but no severity is available")
            if severity not in self.severities:
                return False
        return True

    def describe(self):
        conditions = []
        if self.min_score is not None:
            conditions.append(
                "score {0} {1}".format(
                    ">=" if self.min_inclusive else ">", _format_value(self.min_score)
                )
            )
        if self.max_score is not None:
            conditions.append(
                "score {0} {1}".format(
                    "<=" if self.max_inclusive else "<", _format_value(self.max_score)
                )
            )
        if self.severities is not None:
            conditions.append("severity in ({0})".format(", ".join(self.severities)))
        if not conditions:
            conditions.append("default")
        text = "{0} [{1}]".format(self.queue, " and ".join(conditions))
        if self.description:
            text += " ({0})".format(self.description)
        return text

    def as_dict(self):
        return {
            "queue": self.queue,
            "min_score": self.min_score,
            "max_score": self.max_score,
            "min_inclusive": self.min_inclusive,
            "max_inclusive": self.max_inclusive,
            "severities": None if self.severities is None else list(self.severities),
            "description": self.description,
        }


class QueueRuleSet(object):
    """
    An explicit queue rule set for one CVSS version.

    ``basis`` is mandatory and declares which dimensions this rule set is
    allowed to use.  Cross-computation in :func:`migrate_queues` only uses
    dimensions that both rule sets declare with the same metric.
    """

    def __init__(
        self,
        version,
        basis,
        rules=(),
        score_metric="base",
        severity_metric="base",
        default_queue=None,
        name=None,
    ):
        self.version = _normalise_version(version)
        self.basis = _normalise_basis(basis)
        self.rules = tuple(QueueRule.from_dict(rule) for rule in rules)
        self.score_metric = None if score_metric is None else str(score_metric).lower()
        self.severity_metric = None if severity_metric is None else str(severity_metric).lower()
        self.default_queue = default_queue
        self.name = name

        if "score" in self.basis:
            if self.score_metric is None:
                raise QueueRuleError('declared basis "score" requires score_metric')
            self.score_metric = _normalise_metric(self.score_metric, self.version, "score")
        if "severity" in self.basis:
            if self.severity_metric is None:
                raise QueueRuleError('declared basis "severity" requires severity_metric')
            self.severity_metric = _normalise_metric(self.severity_metric, self.version, "severity")
        if default_queue is not None and (
            not isinstance(default_queue, str) or not default_queue.strip()
        ):
            raise QueueRuleError("default_queue must be a non-empty string")
        if not self.rules and self.default_queue is None:
            raise QueueRuleError("Queue rule set needs at least one rule or a default_queue")

        for index, rule in enumerate(self.rules):
            if rule.uses_score and "score" not in self.basis:
                raise QueueRuleError(
                    'Rule for queue "{0}" uses score but basis does not declare it'.format(
                        rule.queue
                    )
                )
            if rule.uses_severity and "severity" not in self.basis:
                raise QueueRuleError(
                    'Rule for queue "{0}" uses severity but basis does not declare it'.format(
                        rule.queue
                    )
                )
            if rule.is_catch_all and index != len(self.rules) - 1:
                raise QueueRuleError(
                    'Catch-all rule for queue "{0}" must be the last rule'.format(rule.queue)
                )

        used = set()
        if any(rule.uses_score for rule in self.rules):
            used.add("score")
        if any(rule.uses_severity for rule in self.rules):
            used.add("severity")
        self.used_basis = tuple(value for value in ("score", "severity") if value in used)

    @classmethod
    def from_dict(cls, data):
        if isinstance(data, cls):
            return data
        if not isinstance(data, dict):
            raise QueueRuleError("Queue rule set must be a QueueRuleSet or a dictionary")
        values = dict(data)
        try:
            version = values.pop("version")
            basis = values.pop("basis")
        except KeyError as exc:
            raise QueueRuleError('Queue rule set is missing "{0}"'.format(exc.args[0]))
        return cls(version, basis, **values)

    def _select_values(self, cvss_object):
        scores = cvss_object.scores()
        severities = cvss_object.severities()
        if self.version == "4.0":
            score = float(scores[0])
            severity = severities[0]
            return score, severity
        index = {"base": 0, "temporal": 1, "environmental": 2}
        score_index = index[self.score_metric] if "score" in self.basis else 0
        severity_index = index[self.severity_metric] if "severity" in self.basis else 0
        score = float(scores[score_index])
        severity = severities[severity_index]
        return score, severity

    def _match(self, observation):
        for index, rule in enumerate(self.rules):
            if rule.matches(observation):
                return rule.queue, rule, index
        if self.default_queue is not None:
            return self.default_queue, None, None
        raise QueueRuleError("No queue rule matched and no default_queue is configured")

    def decide_values(self, score=None, severity=None):
        """Evaluate the bands against already supplied declared values."""
        observation = {"score": score, "severity": severity}
        for dimension in self.used_basis:
            if observation.get(dimension) is None:
                raise QueueRuleError(
                    'Rule set uses "{0}" but no value was supplied'.format(dimension)
                )
        queue, rule, index = self._match(observation)
        return queue, rule, index

    def evaluate(self, cvss_object, side=None):
        version = _object_version(cvss_object)
        base_score = float(cvss_object.scores()[0])
        base_severity = cvss_object.severities()[0]
        vector = getattr(cvss_object, "vector", None)
        common = {
            "side": side,
            "vector": vector,
            "version": version,
            "score_metric": self.score_metric if "score" in self.basis else "base",
            "severity_metric": self.severity_metric if "severity" in self.basis else "base",
            "base_score": base_score,
            "base_severity": base_severity,
            "rule_set_name": self.name,
        }
        if version != self.version:
            return QueueDecision(
                status="not_applicable",
                reason_code="rule_version_mismatch",
                reason="rule set targets CVSS {0} but evidence is CVSS {1}".format(
                    self.version, version
                ),
                score=base_score,
                severity=base_severity,
                **common,
            )
        score, severity = self._select_values(cvss_object)
        decision = QueueDecision(score=score, severity=severity, **common)
        try:
            queue, rule, index = self._match({"score": score, "severity": severity})
        except QueueRuleError as exc:
            decision.status = "no_rule_matched"
            decision.reason_code = NO_RULE_MATCHED
            decision.reason = str(exc)
            return decision
        decision.queue = queue
        decision.matched_rule = rule
        decision.matched_rule_index = index
        return decision

    def describe(self):
        details = ["targets CVSS {0}".format(self.version)]
        details.append(
            "declared basis: {0}".format(", ".join(self.basis) if self.basis else "none")
        )
        if "score" in self.basis:
            details.append("score metric: {0}".format(self.score_metric))
        if "severity" in self.basis:
            details.append("severity metric: {0}".format(self.severity_metric))
        prefix = "{0} ".format(self.name) if self.name else ""
        return "{0}({1})".format(prefix, "; ".join(details))

    def as_dict(self):
        return {
            "name": self.name,
            "version": self.version,
            "basis": list(self.basis),
            "score_metric": self.score_metric,
            "severity_metric": self.severity_metric,
            "default_queue": self.default_queue,
            "rules": [rule.as_dict() for rule in self.rules],
        }


class QueueDecision(object):
    """Result of evaluating one side (old or new) independently."""

    def __init__(
        self,
        side=None,
        status="computed",
        vector=None,
        version=None,
        score_metric=None,
        severity_metric=None,
        score=None,
        severity=None,
        base_score=None,
        base_severity=None,
        queue=None,
        matched_rule=None,
        matched_rule_index=None,
        reason_code=None,
        reason=None,
        rule_set_name=None,
    ):
        self.side = side
        self.status = status
        self.vector = vector
        self.version = version
        self.score_metric = score_metric
        self.severity_metric = severity_metric
        self.score = score
        self.severity = severity
        self.base_score = base_score
        self.base_severity = base_severity
        self.queue = queue
        self.matched_rule = matched_rule
        self.matched_rule_index = matched_rule_index
        self.reason_code = reason_code
        self.reason = reason
        self.rule_set_name = rule_set_name

    def describe(self):
        if self.status == "computed":
            if self.matched_rule is None:
                rule_text = "default"
            else:
                rule_text = "rule {0}: {1}".format(
                    self.matched_rule_index + 1, self.matched_rule.describe()
                )
            return "vector={0} version={1} score={2} severity={3} -> queue={4} ({5})".format(
                self.vector,
                self.version,
                _format_value(self.score if self.score is not None else self.base_score),
                self.severity if self.severity is not None else self.base_severity,
                self.queue,
                rule_text,
            )
        if self.status == "missing_evidence":
            return "missing evidence: {0}".format(self.reason)
        if self.status == "not_applicable":
            return "not applicable: {0}".format(self.reason)
        if self.status == "invalid_vector":
            return "invalid vector: {0}".format(self.reason)
        if self.status == "no_rule_matched":
            return "no rule matched: {0}".format(self.reason)
        return self.status

    def as_dict(self):
        return {
            "side": self.side,
            "status": self.status,
            "vector": self.vector,
            "version": self.version,
            "score_metric": self.score_metric,
            "severity_metric": self.severity_metric,
            "score": self.score,
            "severity": self.severity,
            "base_score": self.base_score,
            "base_severity": self.base_severity,
            "queue": self.queue,
            "matched_rule": (None if self.matched_rule is None else self.matched_rule.as_dict()),
            "matched_rule_index": self.matched_rule_index,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "rule_set_name": self.rule_set_name,
        }


class MigrationResult(object):
    """Complete, serialisable reconciliation result for one risk record."""

    def __init__(
        self,
        old,
        new,
        old_rules,
        new_rules,
        status,
        changed,
        common_basis,
        cross_computation,
        explanations,
        blockers,
        attribution,
    ):
        self.old = old
        self.new = new
        self.old_rules = old_rules
        self.new_rules = new_rules
        self.status = status
        self.changed = changed
        self.comparable = status != NOT_COMPARABLE
        self.common_basis = tuple(common_basis)
        self.cross_computation = cross_computation
        self.explanations = explanations
        self.blockers = blockers
        self.attribution = attribution
        self.possible_explanations = [
            item["hypothesis"] for item in explanations if item["status"] != REJECTED
        ]
        self.coexisting = len(self.possible_explanations) > 1
        supported = [item["hypothesis"] for item in explanations if item["status"] == SUPPORTED]
        if (
            status == CHANGED
            and len(self.possible_explanations) == 1
            and supported
            and supported[0] == self.possible_explanations[0]
        ):
            self.primary_explanation = supported[0]
        else:
            self.primary_explanation = None

    def as_dict(self):
        return {
            "status": self.status,
            "comparable": self.comparable,
            "changed": self.changed,
            "attribution": self.attribution,
            "primary_explanation": self.primary_explanation,
            "possible_explanations": self.possible_explanations,
            "coexisting": self.coexisting,
            "old": self.old.as_dict(),
            "new": self.new.as_dict(),
            "old_rules": self.old_rules.as_dict(),
            "new_rules": self.new_rules.as_dict(),
            "common_basis": list(self.common_basis),
            "cross_computation": self.cross_computation,
            "explanations": self.explanations,
            "blockers": self.blockers,
        }

    def report(self):
        lines = ["CVSS queue migration reconciliation"]
        lines.append("old rules: {0}".format(self.old_rules.describe()))
        lines.append("new rules: {0}".format(self.new_rules.describe()))
        lines.append("old evidence: {0}".format(self.old.describe()))
        lines.append("new evidence: {0}".format(self.new.describe()))
        if self.blockers:
            lines.append("decision: {0}".format(NOT_COMPARABLE))
            for blocker in self.blockers:
                lines.append(
                    "  blocker: {0} ({1}): {2}".format(
                        blocker["code"], blocker["side"], blocker["message"]
                    )
                )
        else:
            lines.append(
                "decision: {0} ({1} -> {2})".format(self.status, self.old.queue, self.new.queue)
            )
        if self.cross_computation["performed"]:
            details = self.cross_computation
            lines.append(
                "cross-computation: performed on declared common basis {0}".format(
                    _basis_text(self.common_basis, self.old_rules, self.new_rules)
                )
            )
            for dimension in self.common_basis:
                old_value = details["evidence"][dimension]["old"]
                new_value = details["evidence"][dimension]["new"]
                state = "changed" if old_value != new_value else "unchanged"
                lines.append(
                    "  {0}: {1} -> {2} ({3})".format(
                        dimension,
                        _format_value(old_value),
                        _format_value(new_value),
                        state,
                    )
                )
            counterfactuals = details["counterfactuals"]
            if counterfactuals["new_rules_on_old_evidence"] is not None:
                lines.append(
                    "  on old evidence: old rules -> {0}; new rules -> {1}".format(
                        self.old.queue, counterfactuals["new_rules_on_old_evidence"]
                    )
                )
            if counterfactuals["old_rules_on_new_evidence"] is not None:
                lines.append(
                    "  on new evidence: old rules -> {0}; new rules -> {1}".format(
                        counterfactuals["old_rules_on_new_evidence"], self.new.queue
                    )
                )
            if details["rules_differ"] is None:
                lines.append("  rule sets differ on identical evidence: unknown")
            else:
                lines.append(
                    "  rule sets differ on identical evidence: {0}".format(
                        "yes" if details["rules_differ"] else "no"
                    )
                )
        else:
            lines.append(
                "cross-computation: not performed ({0})".format(
                    self.cross_computation["not_performed_reason"]
                )
            )
        lines.append("explanations:")
        for explanation in self.explanations:
            lines.append(
                "  - {0}: {1} - {2}".format(
                    explanation["hypothesis"],
                    explanation["status"],
                    "; ".join(explanation["reasons"]),
                )
            )
        lines.append("attribution: {0}".format(self.attribution))
        if self.possible_explanations:
            lines.append("possible explanations: {0}".format(", ".join(self.possible_explanations)))
        return "\n".join(lines)

    def __str__(self):
        return self.report()


def _basis_text(common_basis, old_rules, new_rules):
    parts = []
    for dimension in common_basis:
        if dimension == "score":
            parts.append("score:{0}".format(old_rules.score_metric))
        else:
            parts.append("severity:{0}".format(old_rules.severity_metric))
    return ", ".join(parts) if parts else "none"


def _evaluate_side(side, vector, rule_set, not_applicable_code):
    if vector is None:
        return QueueDecision(
            side=side,
            status="missing_evidence",
            reason_code=MISSING_EVIDENCE,
            reason="no {0} vector supplied; no score or severity was inferred".format(side),
            rule_set_name=rule_set.name,
        )
    try:
        cvss_object = _parse_vector(vector)
    except (CVSSError, QueueRuleError, TypeError, ValueError) as exc:
        return QueueDecision(
            side=side,
            status="invalid_vector",
            reason_code=INVALID_VECTOR,
            reason=str(exc),
            vector=vector,
            rule_set_name=rule_set.name,
        )
    decision = rule_set.evaluate(cvss_object, side=side)
    if decision.status == "not_applicable":
        decision.reason_code = not_applicable_code
    return decision


def _blocker_code(decision):
    if decision.status == "missing_evidence":
        return MISSING_EVIDENCE
    if decision.status == "invalid_vector":
        return INVALID_VECTOR
    if decision.status == "no_rule_matched":
        return NO_RULE_MATCHED
    return decision.reason_code


def _common_basis(old_rules, new_rules):
    common = []
    notes = []
    for dimension in ("score", "severity"):
        if dimension not in old_rules.basis or dimension not in new_rules.basis:
            continue
        if dimension == "score":
            old_metric = old_rules.score_metric
            new_metric = new_rules.score_metric
        else:
            old_metric = old_rules.severity_metric
            new_metric = new_rules.severity_metric
        if old_metric == new_metric:
            common.append(dimension)
        else:
            notes.append(
                "{0} was not cross-computed because metrics differ ({1} vs {2})".format(
                    dimension, old_metric, new_metric
                )
            )
    return tuple(common), notes


def _copy_evidence_values(old, new, common_basis):
    values = {}
    for dimension in common_basis:
        values[dimension] = {
            "old": getattr(old, dimension),
            "new": getattr(new, dimension),
        }
    return values


def _apply_rules_to_evidence(rule_set, evidence, common_basis):
    needed = set(rule_set.used_basis)
    if not needed.issubset(set(common_basis)):
        return None, "rule set uses a dimension that is not declared by both sides"
    values = {}
    for dimension in rule_set.used_basis:
        value = getattr(evidence, dimension, None)
        if value is None:
            return None, 'evidence has no value for declared dimension "{0}"'.format(dimension)
        values[dimension] = value
    try:
        queue, _, _ = rule_set.decide_values(**values)
    except QueueRuleError as exc:
        return None, str(exc)
    return queue, None


def _change_reason(common_basis, old, new):
    parts = []
    for dimension in common_basis:
        old_value = getattr(old, dimension)
        new_value = getattr(new, dimension)
        parts.append(
            "{0} {1} -> {2}".format(dimension, _format_value(old_value), _format_value(new_value))
        )
    return ", ".join(parts)


def _explanation(hypothesis, status, reasons):
    return {"hypothesis": hypothesis, "status": status, "reasons": reasons}


def migrate_queues(old_vector, new_vector, old_rules, new_rules):
    """
    Reconcile one risk across two independent vectors and two queue rule sets.

    Args:
        old_vector (str or None): the old, independent vector.  ``None`` means the
            evidence is absent; it is never derived from ``new_vector``.
        new_vector (str or None): the new, independent vector.  ``None`` means the
            evidence is absent; it is never derived from ``old_vector``.
        old_rules (QueueRuleSet or dict): explicit old queue rules.
        new_rules (QueueRuleSet or dict): explicit new queue rules.

    Returns:
        MigrationResult: old and new decisions plus attribution and blockers.

    The two rule sets are applied independently to their own vector first.  A
    cross-computation is only performed on dimensions explicitly declared by
    both rule sets with the same metric.  Missing evidence, an inapplicable old
    rule set, and a genuine queue change are reported as separate conditions.
    """
    old_rules = QueueRuleSet.from_dict(old_rules)
    new_rules = QueueRuleSet.from_dict(new_rules)
    old = _evaluate_side("old", old_vector, old_rules, OLD_RULE_NOT_APPLICABLE)
    new = _evaluate_side("new", new_vector, new_rules, NEW_RULE_NOT_APPLICABLE)

    blockers = []
    for decision in (old, new):
        if decision.status != "computed":
            blockers.append(
                {
                    "code": _blocker_code(decision),
                    "side": decision.side,
                    "status": decision.status,
                    "message": decision.reason,
                }
            )

    comparable = not blockers
    changed = None
    if comparable:
        changed = old.queue != new.queue
        status = CHANGED if changed else UNCHANGED
    else:
        status = NOT_COMPARABLE

    common_basis, basis_notes = _common_basis(old_rules, new_rules)
    all_used = set(old_rules.used_basis) | set(new_rules.used_basis)
    coverage_complete = all_used.issubset(set(common_basis))

    cross_computation = {
        "performed": bool(comparable and common_basis),
        "common_basis": list(common_basis),
        "metric_notes": basis_notes,
        "coverage_complete": coverage_complete if comparable else None,
        "evidence": {},
        "counterfactuals": {
            "new_rules_on_old_evidence": None,
            "old_rules_on_new_evidence": None,
            "rules_differ_on_old_evidence": None,
            "rules_differ_on_new_evidence": None,
        },
        "data_changed": None,
        "rules_differ": None,
        "notes": list(basis_notes),
        "not_performed_reason": None,
    }

    if not comparable:
        cross_computation["not_performed_reason"] = "not comparable"
    elif not common_basis:
        cross_computation["not_performed_reason"] = (
            "no dimension was explicitly declared by both rule sets with the same metric"
        )

    new_rules_on_old = None
    old_rules_on_new = None
    rules_differ_old = None
    rules_differ_new = None
    data_changed = None

    if comparable and common_basis:
        cross_computation["evidence"] = _copy_evidence_values(old, new, common_basis)

        new_rules_on_old, new_on_old_error = _apply_rules_to_evidence(new_rules, old, common_basis)
        old_rules_on_new, old_on_new_error = _apply_rules_to_evidence(old_rules, new, common_basis)
        if new_on_old_error:
            cross_computation["notes"].append(
                "new rules on old evidence: {0}".format(new_on_old_error)
            )
        if old_on_new_error:
            cross_computation["notes"].append(
                "old rules on new evidence: {0}".format(old_on_new_error)
            )
        if new_rules_on_old is not None:
            rules_differ_old = new_rules_on_old != old.queue
        if old_rules_on_new is not None:
            rules_differ_new = old_rules_on_new != new.queue

        rule_results = [
            value for value in (rules_differ_old, rules_differ_new) if value is not None
        ]
        if any(value is True for value in rule_results):
            rules_differ = True
        elif len(rule_results) == 2 and all(value is False for value in rule_results):
            rules_differ = False
        else:
            rules_differ = None

        differences = []
        unknown = False
        for dimension in common_basis:
            old_value = getattr(old, dimension)
            new_value = getattr(new, dimension)
            if old_value is None or new_value is None:
                unknown = True
            elif old_value != new_value:
                differences.append(dimension)
        if differences:
            data_changed = True
        elif unknown:
            data_changed = None
        elif coverage_complete:
            data_changed = False
        else:
            data_changed = None

        cross_computation["counterfactuals"] = {
            "new_rules_on_old_evidence": new_rules_on_old,
            "old_rules_on_new_evidence": old_rules_on_new,
            "rules_differ_on_old_evidence": rules_differ_old,
            "rules_differ_on_new_evidence": rules_differ_new,
        }
        cross_computation["data_changed"] = data_changed
        cross_computation["rules_differ"] = rules_differ

    explanations = []
    scoring_reasons = []
    rule_reasons = []

    if not comparable:
        blocker_text = ", ".join(
            "{0} ({1})".format(item["code"], item["side"]) for item in blockers
        )
        scoring_reasons.append(
            "not comparable ({0}); no independent cross-check is possible".format(blocker_text)
        )
        rule_reasons.append(
            "not comparable ({0}); no independent cross-check is possible".format(blocker_text)
        )
        scoring_status = POSSIBLE
        rule_status = POSSIBLE
    elif not common_basis:
        scoring_reasons.append(
            "no dimension was explicitly declared by both rule sets; "
            "cross-computation was intentionally skipped"
        )
        rule_reasons.append(
            "no dimension was explicitly declared by both rule sets; "
            "cross-computation was intentionally skipped"
        )
        scoring_status = POSSIBLE
        rule_status = POSSIBLE
    else:
        if data_changed is True:
            scoring_status = SUPPORTED
            scoring_reasons.append(
                "declared common evidence changed: {0}".format(
                    _change_reason(common_basis, old, new)
                )
            )
        elif data_changed is False:
            scoring_status = REJECTED
            scoring_reasons.append(
                "declared common evidence is unchanged: {0}".format(
                    _change_reason(common_basis, old, new)
                )
            )
        else:
            scoring_status = POSSIBLE
            scoring_reasons.append(
                "the declared common evidence is incomplete or undeclared "
                "dimensions may differ; scoring data change cannot be excluded"
            )

        if rules_differ is True:
            rule_status = SUPPORTED
            details = []
            if rules_differ_old is True:
                details.append(
                    "on old evidence old rules -> {0}, new rules -> {1}".format(
                        old.queue, new_rules_on_old
                    )
                )
            if rules_differ_new is True:
                details.append(
                    "on new evidence old rules -> {0}, new rules -> {1}".format(
                        old_rules_on_new, new.queue
                    )
                )
            rule_reasons.append(
                "the rule sets disagree on identical evidence: {0}".format("; ".join(details))
            )
        elif rules_differ is False:
            rule_status = REJECTED
            rule_reasons.append("the rule sets produce the same queue on identical evidence")
        else:
            rule_status = POSSIBLE
            rule_reasons.append(
                "the rule comparison could not be completed on the declared common evidence"
            )

    explanations.append(_explanation(SCORING_DATA_CHANGED, scoring_status, scoring_reasons))
    explanations.append(_explanation(RULE_CHANGED, rule_status, rule_reasons))

    possible = [item["hypothesis"] for item in explanations if item["status"] != REJECTED]
    supported = [item["hypothesis"] for item in explanations if item["status"] == SUPPORTED]
    if status == NOT_COMPARABLE:
        attribution = "undetermined"
    elif changed is False:
        attribution = "no_change"
    elif len(possible) == 1 and supported and supported[0] == possible[0]:
        attribution = supported[0]
    elif len(possible) > 1 and len(supported) == len(possible):
        attribution = "both"
    else:
        attribution = "undetermined"

    return MigrationResult(
        old=old,
        new=new,
        old_rules=old_rules,
        new_rules=new_rules,
        status=status,
        changed=changed,
        common_basis=common_basis,
        cross_computation=cross_computation,
        explanations=explanations,
        blockers=blockers,
        attribution=attribution,
    )


def reconcile_queues(old_vector, new_vector, old_rules, new_rules):
    """Alias for :func:`migrate_queues`."""
    return migrate_queues(old_vector, new_vector, old_rules, new_rules)
