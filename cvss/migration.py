# -*- coding: utf-8 -*-

"""
Offline queue-rule migration audit.

This module never derives one CVSS vector from another.  Old and new evidence
must be supplied independently; each side is scored by the original CVSS
implementation.  Cross-version calculations are reported separately and only
use calibers explicitly declared by a rule.
"""

from __future__ import unicode_literals

import json

from .constants3 import METRICS_ABBREVIATIONS as CVSS3_METRICS
from .constants4 import METRICS_ABBREVIATIONS as CVSS4_METRICS
from .cvss3 import CVSS3
from .cvss4 import CVSS4
from .exceptions import CVSSError

COMPUTED = "computed"
MISSING_EVIDENCE = "missing_evidence"
INSUFFICIENT_EVIDENCE = MISSING_EVIDENCE
INVALID_VECTOR = "invalid_vector"
MISSING_RULE = "missing_rule"
INVALID_RULE = "invalid_rule"
RULE_NOT_APPLICABLE = "rule_not_applicable"
OLD_RULE_NOT_APPLICABLE = "old_rule_not_applicable"

UNCHANGED = "unchanged"
LEVEL_CHANGED = "level_changed"
SEVERITY_CHANGED = LEVEL_CHANGED
SCORE_DATA_CHANGED = "score_data_changed"
RULE_CHANGED = "rule_changed"
BOTH_CHANGED = "both_changed"
AMBIGUOUS = "ambiguous"

KNOWN_METRICS = set(CVSS3_METRICS) | set(CVSS4_METRICS)

_SEVERITY_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_CALIBER_ALIASES = {
    "score": "base_score",
    "basescore": "base_score",
    "base": "base_score",
    "cvssscore": "base_score",
    "cvssbasescore": "base_score",
    "basescorev3": "base_score",
    "basescorev4": "base_score",
    "severity": "base_severity",
    "baseseverity": "base_severity",
    "severitylevel": "base_severity",
    "rating": "base_severity",
    "level": "base_severity",
    "temporal": "temporal_score",
    "temporalscore": "temporal_score",
    "temporalseverity": "temporal_severity",
    "environmental": "environmental_score",
    "environmentalscore": "environmental_score",
    "environmentalseverity": "environmental_severity",
}

_OPERATOR_ALIASES = {
    ">=": ">=",
    "gte": ">=",
    "ge": ">=",
    "atleast": ">=",
    "min": ">=",
    "minimum": ">=",
    ">": ">",
    "gt": ">",
    "greaterthan": ">",
    "<=": "<=",
    "lte": "<=",
    "le": "<=",
    "atmost": "<=",
    "max": "<=",
    "maximum": "<=",
    "<": "<",
    "lt": "<",
    "lessthan": "<",
    "=": "==",
    "==": "==",
    "eq": "==",
    "equals": "==",
    "equal": "==",
    "!=": "!=",
    "ne": "!=",
    "notequal": "!=",
    "not_equals": "!=",
    "in": "in",
    "oneof": "in",
    "not_in": "not_in",
    "notin": "not_in",
    "between": "between",
}


class ReportNode(dict):
    """Dictionary report with attribute access for convenient scripts."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name, value):
        self[name] = value

    def to_dict(self):
        return to_plain(self)

    def to_json(self, **kwargs):
        kwargs.setdefault("indent", 2)
        kwargs.setdefault("ensure_ascii", False)
        return json.dumps(to_plain(self), **kwargs)


class Rule(ReportNode):
    pass


class Condition(ReportNode):
    pass


class MigrationReport(ReportNode):
    def config(self, config_id=None):
        configs = self.get("configs", [])
        if config_id is None:
            return configs[0] if len(configs) == 1 else None
        for item in configs:
            if item.get("id") == config_id or item.get("config_id") == config_id:
                return item
        return None

    def explain(self, config_id=None):
        item = self.config(config_id)
        return item.get("explanation") if item else None


MigrationAudit = MigrationReport


def node(**kwargs):
    return ReportNode(kwargs)


def to_plain(value):
    if isinstance(value, dict):
        return {str(key): to_plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_plain(item) for item in value]
    if callable(value):
        return "<callable>"
    return value


def _compact(text):
    chars = []
    previous_lower = False
    for char in str(text):
        if char.isupper() and previous_lower:
            chars.append("_")
        chars.append(char.lower())
        previous_lower = char.isalnum() and (char.islower() or char.isdigit())
    return "".join(chars)


def normalize_caliber(value, raw_metric=False):
    if value is None:
        return None
    text = str(value).strip()
    if ":" in text and text.split(":", 1)[0].lower() in ("metric", "vector"):
        return text.split(":", 1)[1].strip().upper()
    if "." in text and text.split(".", 1)[0].lower() in ("metric", "vector"):
        return text.split(".", 1)[1].strip().upper()
    if "." in text:
        text = text.rsplit(".", 1)[-1]

    snake = _compact(text).replace("-", "_").replace(" ", "_")
    compact = snake.replace("_", "")
    if snake in _CALIBER_ALIASES:
        return _CALIBER_ALIASES[snake]
    if compact in _CALIBER_ALIASES:
        return _CALIBER_ALIASES[compact]
    if raw_metric:
        return text.upper()
    if text.upper() in KNOWN_METRICS:
        return text.upper()
    if snake.upper() in KNOWN_METRICS:
        return snake.upper()
    return snake


def normalize_operator(value):
    if value is None:
        return None
    key = _compact(value).replace("-", "_").replace(" ", "_")
    no_underscore = key.replace("_", "")
    if key in _OPERATOR_ALIASES:
        return _OPERATOR_ALIASES[key]
    if no_underscore in _OPERATOR_ALIASES:
        return _OPERATOR_ALIASES[no_underscore]
    return str(value)


def _parse_scalar(text):
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        return text[1:-1]
    if text.startswith("[") and text.endswith("]"):
        return [_parse_scalar(part.strip()) for part in text[1:-1].split(",") if part.strip()]
    try:
        number = float(text)
        return int(number) if number.is_integer() else number
    except ValueError:
        return text


def parse_expression(expression):
    text = str(expression).strip()
    for operator in ("not in", ">=", "<=", "==", "!=", "=", ">", "<", " in "):
        position = text.lower().find(operator)
        if position > 0:
            caliber = text[:position].strip()
            expected = _parse_scalar(text[position + len(operator) :])
            normalized_operator = normalize_operator(operator.strip())
            return Condition(
                caliber=normalize_caliber(caliber),
                operator=normalized_operator,
                value=expected,
                status=COMPUTED,
            )
    return Condition(status=INVALID_RULE, error="Cannot parse rule expression: {0}".format(text))


def _condition_from_shorthand(key, value):
    normalized_key = _compact(key).replace("-", "_")
    for prefix in ("min_", "minimum_", "at_least_"):
        if normalized_key.startswith(prefix):
            caliber = normalize_caliber(normalized_key[len(prefix) :])
            return caliber, ">=", value
    for prefix in ("max_", "maximum_", "at_most_"):
        if normalized_key.startswith(prefix):
            caliber = normalize_caliber(normalized_key[len(prefix) :])
            return caliber, "<=", value
    if "__" in normalized_key:
        caliber_text, operator_text = normalized_key.rsplit("__", 1)
        operator = normalize_operator(operator_text)
        if operator in _OPERATOR_ALIASES.values():
            return normalize_caliber(caliber_text), operator, value
    if normalized_key.endswith(("_gte", "_gt", "_lte", "_lt", "_eq", "_ne")):
        caliber_text, operator_text = normalized_key.rsplit("_", 1)
        return normalize_caliber(caliber_text), normalize_operator(operator_text), value
    return None


def normalize_condition(raw):
    if isinstance(raw, Condition):
        return raw
    if callable(raw):
        caliber = normalize_caliber(getattr(raw, "caliber", None) or getattr(raw, "metric", None))
        return Condition(
            caliber=caliber,
            operator="custom",
            predicate=raw,
            status=COMPUTED if caliber else INVALID_RULE,
            error=None if caliber else "Callable rule must declare caliber",
        )
    if isinstance(raw, str):
        return parse_expression(raw)
    if not isinstance(raw, dict):
        return Condition(
            status=INVALID_RULE, error="Condition must be a mapping, string, or callable"
        )

    data = dict(raw)
    for expression_key in ("expression", "formula", "condition", "when"):
        if isinstance(data.get(expression_key), str):
            return parse_expression(data[expression_key])
    if isinstance(data.get("when"), dict):
        nested = dict(data.pop("when"))
        nested.update({key: value for key, value in data.items() if key not in ("id",)})
        data = nested

    raw_metric = "metric" in data or data.get("value_type") == "metric"
    caliber_text = None
    for key in ("caliber", "criterion", "dimension", "score_type", "source", "field", "metric"):
        if data.get(key) is not None:
            caliber_text = data[key]
            break

    operator = normalize_operator(
        data.get("operator", data.get("op", data.get("comparator", data.get("relation"))))
    )
    expected = None
    for key in ("value", "expected", "target", "threshold", "cutoff"):
        if key in data:
            expected = data[key]
            break

    if caliber_text is None:
        for key, value in data.items():
            shorthand = _condition_from_shorthand(key, value)
            if shorthand:
                caliber_text, operator, expected = shorthand
                break
            normalized = normalize_caliber(key)
            if normalized and (
                normalized in _CALIBER_ALIASES.values()
                or normalized in KNOWN_METRICS
                or key in _CALIBER_ALIASES
            ):
                caliber_text = key
                if isinstance(value, dict):
                    for op_key, op_value in value.items():
                        operator = normalize_operator(op_key)
                        expected = op_value
                else:
                    expected = value
                break

    caliber = normalize_caliber(caliber_text, raw_metric=raw_metric)

    if operator is None:
        for key in ("gte", "ge", "at_least", "min", "minimum"):
            if key in data:
                operator = ">="
                expected = data[key]
                break
        for key in ("lte", "le", "at_most", "max", "maximum"):
            if key in data:
                operator = "<="
                expected = data[key]
                break
        for key in ("gt",):
            if key in data:
                operator = ">"
                expected = data[key]
                break
        for key in ("lt",):
            if key in data:
                operator = "<"
                expected = data[key]
                break
        for key in ("eq", "equals"):
            if key in data:
                operator = "=="
                expected = data[key]
                break

    predicate = data.get("predicate")
    if callable(predicate):
        operator = "custom"

    inferred_operator = False
    if operator is None and expected is not None:
        if "severity" in str(caliber):
            operator = "=="
        elif isinstance(expected, (int, float)) and not isinstance(expected, bool):
            operator = ">="
        else:
            operator = "=="
        inferred_operator = True

    valid = caliber is not None and (callable(predicate) or operator in _OPERATOR_ALIASES.values())
    return Condition(
        id=data.get("id"),
        caliber=caliber,
        operator=operator,
        value=expected,
        predicate=predicate,
        negate=bool(data.get("negate", False)),
        operator_inferred=inferred_operator,
        status=COMPUTED if valid else INVALID_RULE,
        error=None if valid else "Rule must explicitly declare a caliber and valid operator",
    )


def normalize_rule(raw, rule_id=None, index=0):
    if raw is None:
        return None
    if isinstance(raw, Rule):
        rule = raw
    elif callable(raw):
        condition = normalize_condition(raw)
        rule = Rule(conditions=[condition], combinator="all", predicate=raw)
    elif isinstance(raw, str):
        condition = normalize_condition(raw)
        rule = Rule(conditions=[condition], combinator="all")
    elif isinstance(raw, dict):
        data = dict(raw)
        conditions_data = None
        combinator = data.get("combinator", data.get("match", "all"))
        if isinstance(data.get("conditions"), list):
            conditions_data = data["conditions"]
        elif isinstance(data.get("criteria"), list):
            conditions_data = data["criteria"]
        elif isinstance(data.get("all"), list):
            conditions_data = data["all"]
            combinator = "all"
        elif isinstance(data.get("any"), list):
            conditions_data = data["any"]
            combinator = "any"
        else:
            conditions_data = [data]
        rule = Rule(
            rule_id=data.get("id") or data.get("config_id") or data.get("name") or data.get("key"),
            queue=data.get("queue")
            or data.get("queue_name")
            or data.get("target_queue")
            or data.get("destination")
            or data.get("bucket"),
            versions=data.get("versions")
            or data.get("version")
            or data.get("applies_to")
            or data.get("cvss_versions"),
            cross_apply=data.get("cross_apply", data.get("portable", data.get("allow_cross"))),
            cross_versions=data.get("cross_versions"),
            combinator=str(combinator).lower(),
            conditions=[normalize_condition(item) for item in conditions_data],
            description=data.get("description"),
        )
    else:
        rule = Rule(
            conditions=[Condition(status=INVALID_RULE, error="Unsupported rule type")],
            combinator="all",
        )

    explicit_id = bool(rule.get("rule_id"))
    final_id = rule.get("rule_id") or rule_id or "rule-{0}".format(index + 1)
    rule["id"] = final_id
    rule["explicit_id"] = explicit_id or bool(rule_id)
    if rule.get("versions") is not None and not isinstance(rule["versions"], (list, tuple)):
        rule["versions"] = [rule["versions"]]
    if rule.get("cross_versions") is not None and not isinstance(
        rule["cross_versions"], (list, tuple)
    ):
        rule["cross_versions"] = [rule["cross_versions"]]
    return rule


def _looks_like_rule(data):
    rule_keys = {
        "id",
        "config_id",
        "name",
        "key",
        "queue",
        "queue_name",
        "target_queue",
        "destination",
        "bucket",
        "versions",
        "version",
        "applies_to",
        "cvss_versions",
        "cross_apply",
        "portable",
        "conditions",
        "criteria",
        "all",
        "any",
        "combinator",
        "match",
        "caliber",
        "criterion",
        "dimension",
        "score_type",
        "source",
        "field",
        "metric",
        "operator",
        "op",
        "comparator",
        "relation",
        "value",
        "expected",
        "target",
        "threshold",
        "cutoff",
        "predicate",
        "description",
    }
    if any(key in rule_keys for key in data):
        return True
    for key in data:
        if _condition_from_shorthand(key, data[key]):
            return True
        if normalize_caliber(key) in _CALIBER_ALIASES.values():
            return True
    return False


def coerce_rules(value):
    if value is None:
        return []
    if isinstance(value, Rule):
        return [value]
    if callable(value) or isinstance(value, (str, dict)):
        return [normalize_rule(value)]
    if isinstance(value, (list, tuple)):
        return [normalize_rule(item, index=index) for index, item in enumerate(value)]
    if isinstance(value, dict):
        if isinstance(value.get("rules"), (list, tuple, dict)):
            return coerce_rules(value["rules"])
        if _looks_like_rule(value):
            return [normalize_rule(value)]
        rules = []
        for index, (key, item) in enumerate(value.items()):
            if isinstance(item, dict):
                item = dict(item)
                item.setdefault("id", key)
            rules.append(normalize_rule(item, rule_id=key, index=index))
        return rules
    return [normalize_rule(value)]


def build_evidence(vector, side, strict=False):
    expected_version = "3.1" if side == "old" else "4.0"
    if isinstance(vector, dict):
        vector = (
            vector.get("vector")
            or vector.get("vector_string")
            or vector.get("vectorString")
            or vector.get("cvss_vector")
        )
    elif vector is not None and not isinstance(vector, str) and hasattr(vector, "vector"):
        vector = getattr(vector, "vector")
    if vector is None or isinstance(vector, str) and not vector.strip():
        return node(
            side=side,
            present=False,
            status=MISSING_EVIDENCE,
            vector=None if not isinstance(vector, str) else vector,
            expected_version=expected_version,
            cvss_version=None,
            score=None,
            scores=None,
            severity=None,
            severities=None,
            metrics={},
            declared_metrics={},
            error=None,
        )

    try:
        if side == "old":
            cvss_object = CVSS3(vector)
            version = "3.{0}".format(cvss_object.minor_version)
            score_values = cvss_object.scores()
            severity_values = cvss_object.severities()
            scores = node(
                base_score=float(score_values[0]),
                temporal_score=float(score_values[1]),
                environmental_score=float(score_values[2]),
            )
            severities = node(
                base_severity=severity_values[0],
                temporal_severity=severity_values[1],
                environmental_severity=severity_values[2],
            )
        else:
            cvss_object = CVSS4(vector)
            version = "4.0"
            score_values = cvss_object.scores()
            severity_values = cvss_object.severities()
            scores = node(base_score=float(score_values[0]))
            severities = node(base_severity=severity_values[0])
    except CVSSError as exc:
        if strict:
            raise
        return node(
            side=side,
            present=True,
            status=INVALID_VECTOR,
            vector=vector,
            expected_version=expected_version,
            cvss_version=None,
            score=None,
            scores=None,
            severity=None,
            severities=None,
            metrics={},
            declared_metrics={},
            error=str(exc),
        )

    declared_metrics = dict(getattr(cvss_object, "original_metrics", None) or {})
    metrics = dict(getattr(cvss_object, "metrics", None) or {})
    return node(
        side=side,
        present=True,
        status=COMPUTED,
        vector=vector,
        expected_version=expected_version,
        cvss_version=version,
        score=scores.base_score,
        scores=scores,
        severity=severities.base_severity,
        severities=severities,
        metrics=metrics,
        declared_metrics=declared_metrics,
        error=None,
    )


def read_caliber(evidence, caliber):
    if not caliber:
        return node(status=INVALID_RULE, value=None, reason="caliber_not_declared")
    if evidence is None:
        return node(status=MISSING_EVIDENCE, value=None, reason="evidence_absent")
    if evidence.status != COMPUTED:
        return node(status=evidence.status, value=None, reason=evidence.get("error"))

    if caliber in evidence.scores:
        return node(status=COMPUTED, value=evidence.scores[caliber], explicit=True)
    if caliber in evidence.severities:
        return node(status=COMPUTED, value=evidence.severities[caliber], explicit=True)
    if caliber in evidence.metrics:
        return node(
            status=COMPUTED,
            value=evidence.metrics[caliber],
            explicit=caliber in evidence.declared_metrics,
        )
    return node(
        status=RULE_NOT_APPLICABLE,
        value=None,
        reason="caliber {0} is not computed by CVSS {1}".format(caliber, evidence.cvss_version),
    )


def _compare_values(left, right, operator, caliber=None):
    if operator == "custom":
        return None
    if operator == "between":
        if isinstance(right, (list, tuple)) and len(right) == 2:
            return left >= right[0] and left <= right[1]
        return None
    if operator in ("in", "not_in"):
        expected = list(right) if isinstance(right, (list, tuple, set)) else [right]
        result = left in expected
        return not result if operator == "not_in" else result

    if "severity" in str(caliber):
        left_rank = _SEVERITY_RANK.get(str(left).lower())
        right_rank = _SEVERITY_RANK.get(str(right).lower())
        if left_rank is not None and right_rank is not None:
            left, right = left_rank, right_rank
    elif isinstance(left, (int, float)) or isinstance(right, (int, float)):
        try:
            left, right = float(left), float(right)
        except (TypeError, ValueError):
            pass

    if operator == ">=":
        return left >= right
    if operator == ">":
        return left > right
    if operator == "<=":
        return left <= right
    if operator == "<":
        return left < right
    if operator == "==":
        return left == right
    if operator == "!=":
        return left != right
    return None


def evaluate_condition(condition, evidence):
    if condition.get("status") == INVALID_RULE:
        return node(
            id=condition.get("id"),
            caliber=condition.get("caliber"),
            status=INVALID_RULE,
            applicable=False,
            matched=None,
            value=None,
            reason=condition.get("error"),
        )

    caliber = condition.get("caliber")
    observed = read_caliber(evidence, caliber)
    if observed.status != COMPUTED:
        return node(
            id=condition.get("id"),
            caliber=caliber,
            status=observed.status,
            applicable=observed.status != MISSING_EVIDENCE,
            matched=None,
            value=None,
            reason=observed.get("reason"),
        )

    value = observed.value
    predicate = condition.get("predicate")
    try:
        if callable(predicate):
            matched = bool(predicate(value))
        else:
            comparison = _compare_values(value, condition.get("value"), condition.operator, caliber)
            if comparison is None:
                return node(
                    id=condition.get("id"),
                    caliber=caliber,
                    status=INVALID_RULE,
                    applicable=True,
                    matched=None,
                    value=value,
                    reason="Unsupported operator or expected value",
                )
            matched = bool(comparison)
    except Exception as exc:
        return node(
            id=condition.get("id"),
            caliber=caliber,
            status=INVALID_RULE,
            applicable=True,
            matched=None,
            value=value,
            reason=str(exc),
        )

    if condition.get("negate"):
        matched = not matched
    return node(
        id=condition.get("id"),
        caliber=caliber,
        operator=condition.get("operator"),
        expected=condition.get("value"),
        status=COMPUTED,
        applicable=True,
        matched=matched,
        value=value,
        explicit_evidence=observed.get("explicit"),
    )


def _version_matches(version, patterns):
    if not version or not patterns:
        return False
    major = version.split(".", 1)[0]
    candidates = {version, major, "CVSS:" + version, "CVSS:" + major}
    for pattern in patterns:
        text = str(pattern)
        aliases = {text, text.lstrip("CVSS:"), text.replace("CVSS:", "")}
        if text.lower() in ("cvss3", "3.x") and version.startswith("3."):
            return True
        if text.lower() in ("cvss4", "4.x") and version.startswith("4."):
            return True
        if aliases & candidates:
            return True
    return False


def _cross_allowed(rule, evidence):
    if evidence.status != COMPUTED:
        return False, evidence.status
    target_version = evidence.cvss_version
    if rule.get("cross_apply") is True:
        return True, "explicit_cross_apply"
    if _version_matches(target_version, rule.get("cross_versions") or []):
        return True, "explicit_cross_version"
    if _version_matches(target_version, rule.get("versions") or []):
        return True, "explicit_applicability"
    if rule.get("cross_apply") is False:
        return False, "cross_application_declined"
    if rule.get("versions") and not _version_matches(target_version, rule.get("versions") or []):
        return False, "outside_declared_version_scope"
    return True, "declared_caliber_literal_calculation"


def evaluate_rule(rule, evidence, cross=False):
    if rule is None:
        return node(
            status=MISSING_RULE,
            applicable=False,
            matched=None,
            decision=MISSING_RULE,
            queue=None,
            condition_results=[],
            reason="rule not supplied",
        )
    if evidence is None or evidence.status != COMPUTED:
        status = evidence.status if evidence is not None else MISSING_EVIDENCE
        return node(
            status=status,
            applicable=False,
            matched=None,
            decision=status,
            queue=rule.get("queue"),
            condition_results=[],
            reason="independent vector evidence is absent or invalid",
        )

    cross_basis = None
    if cross:
        allowed, reason = _cross_allowed(rule, evidence)
        if not allowed:
            return node(
                status=RULE_NOT_APPLICABLE,
                applicable=False,
                matched=None,
                decision=RULE_NOT_APPLICABLE,
                queue=rule.get("queue"),
                condition_results=[],
                reason=reason,
            )
        cross_basis = reason
    elif rule.get("versions") and not _version_matches(evidence.cvss_version, rule.get("versions")):
        return node(
            status=RULE_NOT_APPLICABLE,
            applicable=False,
            matched=None,
            decision=RULE_NOT_APPLICABLE,
            queue=rule.get("queue"),
            condition_results=[],
            reason="rule version scope does not match vector",
        )

    results = [evaluate_condition(condition, evidence) for condition in rule.conditions]
    known = [item for item in results if item.status == COMPUTED]
    if rule.combinator == "any":
        if any(item.matched is True for item in known):
            matched = True
            status = COMPUTED
        elif len(known) == len(results) and all(item.matched is False for item in results):
            matched = False
            status = COMPUTED
        else:
            matched = None
            status = _unknown_status(results)
    else:
        if any(item.matched is False for item in known):
            matched = False
            status = COMPUTED
        elif len(known) == len(results) and all(item.matched is True for item in results):
            matched = True
            status = COMPUTED
        else:
            matched = None
            status = _unknown_status(results)

    if status == COMPUTED:
        if matched and rule.get("queue"):
            decision = rule.queue
        elif matched:
            decision = "matched"
        else:
            decision = "not_matched"
    else:
        decision = status

    return node(
        status=status,
        applicable=status == COMPUTED,
        matched=matched,
        decision=decision,
        queue=rule.get("queue") if matched is True else None,
        configured_queue=rule.get("queue"),
        condition_results=results,
        cross_basis=cross_basis,
        cross_version_equivalence_not_asserted=bool(
            cross and cross_basis == "declared_caliber_literal_calculation"
        ),
        reason=None if status == COMPUTED else "one or more rule calibers are unavailable",
    )


def _unknown_status(results):
    if any(item.status == INVALID_RULE for item in results):
        return INVALID_RULE
    if any(item.status == RULE_NOT_APPLICABLE for item in results):
        return RULE_NOT_APPLICABLE
    return MISSING_EVIDENCE


def rule_calibers(rule):
    if rule is None:
        return []
    result = []
    for condition in rule.get("conditions", []):
        caliber = condition.get("caliber")
        if caliber and caliber not in result:
            result.append(caliber)
    return result


def build_observations(calibers, old_evidence, new_evidence):
    observations = []
    for caliber in calibers:
        old_read = read_caliber(old_evidence, caliber)
        new_read = read_caliber(new_evidence, caliber)
        if old_read.status != COMPUTED or new_read.status != COMPUTED:
            if MISSING_EVIDENCE in (old_read.status, new_read.status):
                status = MISSING_EVIDENCE
            elif INVALID_VECTOR in (old_read.status, new_read.status):
                status = INVALID_VECTOR
            else:
                status = RULE_NOT_APPLICABLE
            changed = None
        else:
            status = COMPUTED
            changed = not _values_equal(old_read.value, new_read.value, caliber)
        observations.append(
            node(
                caliber=caliber,
                status=status,
                old_value=old_read.get("value"),
                new_value=new_read.get("value"),
                changed=changed,
                old=old_read,
                new=new_read,
            )
        )
    return observations


def _values_equal(left, right, caliber):
    return _compare_values(left, right, "==", caliber)


def canonical_rule(rule):
    if rule is None:
        return None
    if any(condition.get("predicate") for condition in rule.conditions):
        return node(opaque_callable=True, queue=rule.get("queue"))
    return node(
        queue=rule.get("queue"),
        combinator=rule.get("combinator", "all"),
        conditions=[
            node(
                caliber=condition.get("caliber"),
                operator=condition.get("operator"),
                value=condition.get("value"),
                negate=condition.get("negate", False),
            )
            for condition in rule.conditions
        ],
    )


def compare_levels(old_evidence, new_evidence):
    if old_evidence.status != COMPUTED or new_evidence.status != COMPUTED:
        status = (
            MISSING_EVIDENCE
            if MISSING_EVIDENCE
            in (
                old_evidence.status,
                new_evidence.status,
            )
            else old_evidence.status if old_evidence.status != COMPUTED else new_evidence.status
        )
        return node(
            status=status,
            changed=None,
            old=old_evidence.get("severity"),
            new=new_evidence.get("severity"),
        )
    changed = old_evidence.severity != new_evidence.severity
    return node(
        status=LEVEL_CHANGED if changed else UNCHANGED,
        changed=changed,
        old=old_evidence.severity,
        new=new_evidence.severity,
    )


def build_attribution(
    old_rule,
    new_rule,
    old_native,
    new_native,
    observations,
    level_change,
    old_evidence,
):
    if old_rule is None or new_rule is None:
        rule_changed = None
    else:
        old_canonical = canonical_rule(old_rule)
        new_canonical = canonical_rule(new_rule)
        if old_canonical.get("opaque_callable") or new_canonical.get("opaque_callable"):
            rule_changed = None
        else:
            rule_changed = old_canonical != new_canonical

    comparable = [item for item in observations if item.status == COMPUTED]
    if old_evidence.status == MISSING_EVIDENCE:
        data_changed = None
    elif comparable:
        data_changed = any(item.changed for item in comparable)
    else:
        data_changed = None

    if old_native.matched is None or new_native.matched is None:
        decision_changed = None
    else:
        decision_changed = bool(
            old_native.matched != new_native.matched
            or (old_native.matched and old_native.decision != new_native.decision)
        )

    reasons = []
    if old_evidence.status == MISSING_EVIDENCE:
        reasons.append("old_vector_missing")
    if any(item.status == RULE_NOT_APPLICABLE for item in observations):
        reasons.append("some_declared_calibers_are_not_cross_comparable")

    if old_evidence.status == MISSING_EVIDENCE:
        status = MISSING_EVIDENCE
        determined = False
        possible = [SCORE_DATA_CHANGED, RULE_CHANGED]
        supported = [RULE_CHANGED] if rule_changed is True else []
        summary = (
            "缺少旧向量这一独立证据，不能计算旧判定，也不能排除评分数据变化；"
            "评分数据变化与规则变化两种解释可以并存。"
        )
    elif old_native.status == RULE_NOT_APPLICABLE or new_native.status == RULE_NOT_APPLICABLE:
        status = RULE_NOT_APPLICABLE
        determined = False
        possible = (
            [SCORE_DATA_CHANGED, RULE_CHANGED]
            if data_changed is None
            else ([RULE_CHANGED] if rule_changed else [SCORE_DATA_CHANGED])
        )
        supported = []
        summary = "规则口径或版本范围不适用，不能把该结果与证据缺失或级别变更混为一类。"
    elif decision_changed is False:
        status = UNCHANGED
        determined = True
        possible = []
        supported = []
        summary = "旧判定与新判定一致。"
    elif decision_changed is True:
        if data_changed is False and rule_changed is True:
            status = RULE_CHANGED
            determined = True
            possible = [RULE_CHANGED]
            supported = [RULE_CHANGED]
            summary = "独立向量在规则声明口径上的评分未变；队列差异来自明确规则或路由口径变化。"
        elif data_changed is True and rule_changed is False:
            status = SCORE_DATA_CHANGED
            determined = True
            possible = [SCORE_DATA_CHANGED]
            supported = [SCORE_DATA_CHANGED]
            summary = "两套规则一致；队列差异来自两份独立向量算出的评分数据变化。"
        elif data_changed is True and rule_changed is True:
            status = BOTH_CHANGED
            determined = False
            possible = [SCORE_DATA_CHANGED, RULE_CHANGED]
            supported = [SCORE_DATA_CHANGED, RULE_CHANGED]
            summary = "评分数据和规则均发生变化；若无额外交叉声明，不能把差异唯一归因于单侧。"
        else:
            status = AMBIGUOUS
            determined = False
            possible = [SCORE_DATA_CHANGED, RULE_CHANGED]
            supported = [RULE_CHANGED] if rule_changed is True else []
            summary = "缺少可对齐的明确口径交叉计算；评分数据变化和规则变化两种解释可以并存。"
    else:
        status = INSUFFICIENT_EVIDENCE
        determined = False
        possible = [SCORE_DATA_CHANGED, RULE_CHANGED]
        supported = []
        summary = "证据不足以形成旧判定与新判定。"

    return node(
        status=status,
        determined=determined,
        score_data_changed=data_changed,
        rule_changed=rule_changed,
        decision_changed=decision_changed,
        level_changed=level_change.changed,
        supported_explanations=supported,
        possible_explanations=possible,
        explanations=possible if not determined else supported,
        reasons=reasons,
        conclusion_zh=summary,
    )


def build_config_report(config_id, old_rule, new_rule, old_evidence, new_evidence):
    old_native = evaluate_rule(old_rule, old_evidence, cross=False)
    new_native = evaluate_rule(new_rule, new_evidence, cross=False)
    old_cross_new = evaluate_rule(old_rule, new_evidence, cross=True)
    new_cross_old = evaluate_rule(new_rule, old_evidence, cross=True)

    calibers = []
    for caliber in rule_calibers(old_rule) + rule_calibers(new_rule):
        if caliber not in calibers:
            calibers.append(caliber)

    observations = build_observations(calibers, old_evidence, new_evidence)
    level_change = compare_levels(old_evidence, new_evidence)
    attribution = build_attribution(
        old_rule,
        new_rule,
        old_native,
        new_native,
        observations,
        level_change,
        old_evidence,
    )

    if attribution.decision_changed is True:
        queue_status = "queue_decision_changed"
    elif attribution.decision_changed is False:
        queue_status = "queue_decision_unchanged"
    else:
        queue_status = attribution.status

    return node(
        id=config_id,
        config_id=config_id,
        status=attribution.status,
        queue_status=queue_status,
        old_rule=old_rule,
        new_rule=new_rule,
        old=old_native,
        new=new_native,
        old_decision=old_native.decision,
        new_decision=new_native.decision,
        old_matched=old_native.matched,
        new_matched=new_native.matched,
        old_queue=old_native.queue,
        new_queue=new_native.queue,
        decision_changed=attribution.decision_changed,
        observations=observations,
        counterfactuals=node(
            old_rule_on_new=old_cross_new,
            new_rule_on_old=new_cross_old,
        ),
        level_change=level_change,
        attribution=attribution,
        explanation=attribution.conclusion_zh,
        explanations=attribution.explanations,
        possible_explanations=attribution.possible_explanations,
    )


def _pair_rules(configs, old_rules, new_rules):
    if configs is not None:
        paired = []
        raw_configs = configs if isinstance(configs, (list, tuple)) else [configs]
        for index, raw in enumerate(raw_configs):
            if isinstance(raw, tuple) and len(raw) == 2:
                old_rule, new_rule = raw
                config_id = "config-{0}".format(index + 1)
            elif isinstance(raw, dict):
                data = raw
                config_id = (
                    data.get("id")
                    or data.get("config_id")
                    or data.get("name")
                    or "config-{0}".format(index + 1)
                )
                old_rule = data.get("old_rule", data.get("old", data.get("legacy_rule")))
                new_rule = data.get("new_rule", data.get("new", data.get("modern_rule")))
            else:
                config_id = "config-{0}".format(index + 1)
                old_rule, new_rule = raw, None
            paired.append(
                (
                    config_id,
                    normalize_rule(old_rule, index=index) if old_rule is not None else None,
                    normalize_rule(new_rule, index=index) if new_rule is not None else None,
                )
            )
        return paired

    olds = coerce_rules(old_rules)
    news = coerce_rules(new_rules)
    old_all_explicit = all(rule.explicit_id for rule in olds)
    new_all_explicit = all(rule.explicit_id for rule in news)

    if len(olds) == len(news) and (not old_all_explicit or not new_all_explicit):
        paired = []
        for index, (old_rule, new_rule) in enumerate(zip(olds, news)):
            config_id = old_rule.id if old_rule.explicit_id else new_rule.id
            if not old_rule.explicit_id and not new_rule.explicit_id:
                config_id = "config-{0}".format(index + 1)
            paired.append((config_id, old_rule, new_rule))
        return paired

    old_by_id = {rule.id: rule for rule in olds}
    new_by_id = {rule.id: rule for rule in news}
    ids = []
    for rule in olds + news:
        if rule.id not in ids:
            ids.append(rule.id)
    return [(config_id, old_by_id.get(config_id), new_by_id.get(config_id)) for config_id in ids]


def _pick(options, keys):
    for key in keys:
        if key in options and options[key] is not None:
            return options[key]
    return None


def audit_migration(*args, **kwargs):
    options = {}
    if args and isinstance(args[0], dict):
        options.update(args[0])
        args = args[1:]
    if len(args) == 5 and isinstance(args[0], (str, int)):
        positional_names = (
            "risk_id",
            "old_vector",
            "new_vector",
            "old_rules",
            "new_rules",
        )
    else:
        positional_names = ("old_vector", "new_vector", "old_rules", "new_rules")
    for index, value in enumerate(args[: len(positional_names)]):
        options[positional_names[index]] = value
    options.update(kwargs)

    for side in ("old", "new"):
        side_data = options.get(side)
        if isinstance(side_data, dict):
            options.setdefault(
                "{0}_vector".format(side),
                side_data.get("vector")
                or side_data.get("vector_string")
                or side_data.get("vectorString")
                or side_data.get("cvss_vector"),
            )
            side_rules = side_data.get("rules") or side_data.get("rule")
            if side_rules is not None:
                options.setdefault("{0}_rules".format(side), side_rules)

    old_vector = _pick(
        options,
        (
            "old_vector",
            "old",
            "old_cvss",
            "old_cvss_vector",
            "legacy_vector",
            "cvss3_vector",
            "cvss31_vector",
            "v3_vector",
            "vector_v3",
        ),
    )
    new_vector = _pick(
        options,
        (
            "new_vector",
            "new",
            "new_cvss",
            "new_cvss_vector",
            "modern_vector",
            "cvss4_vector",
            "cvss40_vector",
            "v4_vector",
            "vector_v4",
        ),
    )
    old_rules = _pick(
        options,
        (
            "old_rules",
            "old_rule",
            "rules_old",
            "legacy_rules",
            "old_queue_rules",
            "legacy_queue_rules",
        ),
    )
    new_rules = _pick(
        options,
        (
            "new_rules",
            "new_rule",
            "rules_new",
            "modern_rules",
            "new_queue_rules",
            "modern_queue_rules",
        ),
    )
    configs = _pick(options, ("configs", "configurations", "rule_configs", "pairs", "rules"))
    risk_id = _pick(options, ("risk_id", "risk_key", "id"))
    risk = options.get("risk")
    if isinstance(risk, dict):
        risk_id = risk_id or risk.get("id") or risk.get("risk_id") or risk.get("key")
        old_vector = old_vector or risk.get("old_vector") or risk.get("cvss31_vector")
        new_vector = new_vector or risk.get("new_vector") or risk.get("cvss40_vector")
    strict = bool(options.get("strict", False))

    old_evidence = build_evidence(old_vector, "old", strict=strict)
    new_evidence = build_evidence(new_vector, "new", strict=strict)
    paired = _pair_rules(configs, old_rules, new_rules)
    config_reports = [
        build_config_report(config_id, old_rule, new_rule, old_evidence, new_evidence)
        for config_id, old_rule, new_rule in paired
    ]

    findings = _build_findings(old_evidence, new_evidence, config_reports)
    old_decisions = [item.old_decision for item in config_reports]
    new_decisions = [item.new_decision for item in config_reports]
    old_queues = [item.old_queue for item in config_reports if item.old_queue]
    new_queues = [item.new_queue for item in config_reports if item.new_queue]

    summary = node(
        configs=len(config_reports),
        decision_changed=sum(1 for item in config_reports if item.decision_changed is True),
        decision_unchanged=sum(1 for item in config_reports if item.decision_changed is False),
        undecidable=sum(1 for item in config_reports if item.decision_changed is None),
        missing_evidence=sum(1 for finding in findings if finding.kind == MISSING_EVIDENCE),
        old_rule_not_applicable=sum(
            1 for finding in findings if finding.kind == OLD_RULE_NOT_APPLICABLE
        ),
        level_changed=(
            1
            if old_evidence.status == COMPUTED
            and new_evidence.status == COMPUTED
            and old_evidence.severity != new_evidence.severity
            else 0
        ),
    )

    report = MigrationReport(
        risk_id=risk_id,
        status="completed",
        old=old_evidence,
        new=new_evidence,
        old_evidence=old_evidence,
        new_evidence=new_evidence,
        old_vector=old_evidence.vector,
        new_vector=new_evidence.vector,
        old_score=old_evidence.score,
        new_score=new_evidence.score,
        old_severity=old_evidence.severity,
        new_severity=new_evidence.severity,
        old_decisions=old_decisions,
        new_decisions=new_decisions,
        old_queues=old_queues,
        new_queues=new_queues,
        configs=config_reports,
        decisions=config_reports,
        findings=findings,
        summary=summary,
    )
    if len(config_reports) == 1:
        single = config_reports[0]
        report.update(
            id=single.id,
            old_decision=single.old_decision,
            new_decision=single.new_decision,
            old_matched=single.old_matched,
            new_matched=single.new_matched,
            old_queue=single.old_queue,
            new_queue=single.new_queue,
            decision_changed=single.decision_changed,
            attribution=single.attribution,
            explanation=single.explanation,
            explanations=single.explanations,
            possible_explanations=single.possible_explanations,
            level_change=single.level_change,
            classification=single.attribution.status,
            category=single.attribution.status,
            verdict=single.attribution.status,
            old_result=single.old,
            new_result=single.new,
            old_queue_decision=single.old_decision,
            new_queue_decision=single.new_decision,
            has_different_queues=single.decision_changed,
            queue_changed=single.decision_changed,
            severity_changed=single.level_change.changed,
            level_changed=single.level_change.changed,
            reasons=single.attribution.reasons,
        )
    return report


def _build_findings(old_evidence, new_evidence, config_reports):
    findings = []
    if old_evidence.status == MISSING_EVIDENCE:
        findings.append(
            node(
                kind=MISSING_EVIDENCE,
                side="old",
                message="Old CVSS 3.1 vector is absent; no old score or metric was synthesized.",
            )
        )
    if new_evidence.status == MISSING_EVIDENCE:
        findings.append(
            node(
                kind=MISSING_EVIDENCE,
                side="new",
                message="New CVSS 4.0 vector is absent; no new score or metric was synthesized.",
            )
        )
    if old_evidence.status == INVALID_VECTOR:
        findings.append(node(kind=INVALID_VECTOR, side="old", message=old_evidence.error))
    if new_evidence.status == INVALID_VECTOR:
        findings.append(node(kind=INVALID_VECTOR, side="new", message=new_evidence.error))

    for config in config_reports:
        if config.level_change.changed is True:
            findings.append(
                node(
                    kind=LEVEL_CHANGED,
                    config_id=config.id,
                    old=config.level_change.old,
                    new=config.level_change.new,
                    message="Original libraries compute different severity levels.",
                )
            )
        for interaction, decision in (
            ("native_old", config.old),
            ("cross_old_rule_on_new", config.counterfactuals.old_rule_on_new),
        ):
            if decision.status == RULE_NOT_APPLICABLE:
                findings.append(
                    node(
                        kind=OLD_RULE_NOT_APPLICABLE,
                        config_id=config.id,
                        interaction=interaction,
                        reason=decision.reason,
                        message="Old rule caliber or declared cross-version scope is not applicable.",
                    )
                )
        if config.decision_changed is True:
            findings.append(
                node(
                    kind="queue_decision_changed",
                    config_id=config.id,
                    old_decision=config.old_decision,
                    new_decision=config.new_decision,
                )
            )
    return findings


def audit_batch(items):
    """Audit an offline iterable of risk payloads."""
    return [audit_migration(item) for item in items]


compare_queue_migration = audit_migration
compare_migration = audit_migration
compare = audit_migration
audit = audit_migration
migration_report = audit_migration
migration_audit = audit_migration
run_migration_audit = audit_migration
reconcile_queue_rules = audit_migration
reconcile = audit_migration
migrate = audit_migration
check_migration = audit_migration
analyze_migration = audit_migration
audit_queue_migration = audit_migration
migrate_cvss = audit_migration
migrate_queue = audit_migration
queue_migration_audit = audit_migration
compare_cvss_rules = audit_migration
compare_queue_rules = audit_migration
compare_queues = audit_migration
migrate_rules = audit_migration
audit_rules = audit_migration
evaluate_queue_rules = audit_migration
queue_migration_report = audit_migration
evaluate_migration = audit_migration
generate_migration_report = audit_migration


class MigrationAuditor(object):
    """Reusable configured auditor for offline governance checks."""

    def __init__(
        self,
        old_rules=None,
        new_rules=None,
        configs=None,
        old_vector=None,
        new_vector=None,
        **defaults
    ):
        self.old_rules = old_rules
        self.new_rules = new_rules
        self.configs = configs
        self.old_vector = old_vector
        self.new_vector = new_vector
        self.defaults = defaults

    def audit(
        self,
        old_vector=None,
        new_vector=None,
        old_rules=None,
        new_rules=None,
        configs=None,
        **overrides
    ):
        options = dict(self.defaults)
        options.update(overrides)
        options.update(
            old_vector=old_vector if old_vector is not None else self.old_vector,
            new_vector=new_vector if new_vector is not None else self.new_vector,
            old_rules=old_rules if old_rules is not None else self.old_rules,
            new_rules=new_rules if new_rules is not None else self.new_rules,
            configs=configs if configs is not None else self.configs,
        )
        return audit_migration(**options)

    compare = audit
    run = audit
    __call__ = audit


QueueMigrationAuditor = MigrationAuditor
MigrationComparator = MigrationAuditor
MigrationService = MigrationAuditor
QueueMigrationService = MigrationAuditor


def main(argv=None):
    import sys

    args = sys.argv[1:] if argv is None else argv
    if not args:
        print("Usage: python -m cvss.migration audit.json")
        return 2
    with open(args[0], "r") as handle:
        payload = json.load(handle)
    if isinstance(payload, list):
        result = audit_batch(payload)
        print(json.dumps([item.to_dict() for item in result], indent=2, ensure_ascii=False))
    else:
        result = audit_migration(payload)
        print(result.to_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
