# -*- coding: utf-8 -*-
"""Time-aware CPE applicability evaluation for deployment records."""

from collections import defaultdict
from datetime import datetime
import re
from xml.dom import minidom

from .cpe import CPE
from .comp.cpecomp import CPEComponent


AFFECTED = "affected"
NOT_AFFECTED = "not_affected"
UNKNOWN = "unknown"

_TRUE = "true"
_FALSE = "false"
_UNKNOWN = "unknown"


class DeploymentRecord(object):
    """A CPE observed while a deployment was active."""

    def __init__(self, deployment_id, cpe, effective, retired=None,
                 environment_known=True, complete_environment=False):
        self.deployment_id = deployment_id
        self.cpe = cpe
        self.effective = effective
        self.retired = retired
        self.environment_known = environment_known
        self.complete_environment = complete_environment

    @classmethod
    def from_mapping(cls, record):
        return cls(
            record["deployment_id"],
            record["cpe"],
            record["effective"],
            record.get("retired"),
            record.get("environment_known", True),
            record.get("complete_environment", False)
        )


class ApplicabilitySegment(object):
    """Result for a maximal interval with a stable applicability status."""

    def __init__(self, start, end, status, deployments=None,
                 missing_facts=None, unresolved_facts=None):
        self.start = start
        self.end = end
        self.status = status
        self.deployments = sorted(deployments or [])
        self.missing_facts = sorted(set(missing_facts or []))
        self.unresolved_facts = sorted(set(unresolved_facts or []))

    def as_dict(self):
        return {
            "start": self.start,
            "end": self.end,
            "status": self.status,
            "deployments": self.deployments,
            "missing_facts": self.missing_facts,
            "unresolved_facts": self.unresolved_facts,
        }


class _Fact(object):
    def __init__(self, name):
        self.name = name
        self.values = _normalize_cpe(name)


class _LogicalTest(object):
    def __init__(self, operator="AND", negate=False, children=None):
        self.operator = operator.upper()
        self.negate = negate
        self.children = children or []


class _Expression(object):
    def __init__(self, root):
        self.root = root
        self.facts = []
        self._collect_facts(root)

    def _collect_facts(self, node):
        if isinstance(node, _Fact):
            self.facts.append(node)
            return
        for child in node.children:
            self._collect_facts(child)


def _coerce_datetime(value):
    if value is None or isinstance(value, datetime):
        return value
    if isinstance(value, str):
        return datetime.strptime(value, "%Y-%m-%d")
    raise TypeError("dates must be datetime instances or YYYY-MM-DD strings")


def _normalize_cpe(cpe_name):
    cpe = CPE(cpe_name)
    wfn = cpe.as_wfn()
    content = wfn[len("wfn:["):-1]
    values = {}
    for pair in content.split(", "):
        attribute, raw_value = pair.split("=", 1)
        values[attribute] = _decode_wfn_value(raw_value)
    for attribute in CPEComponent.CPE_COMP_KEYS_EXTENDED:
        values.setdefault(attribute, "ANY")
    return values


def _decode_wfn_value(value):
    if value in ("ANY", "NA"):
        return value
    value = value[1:-1]
    decoded = []
    index = 0
    while index < len(value):
        if value[index] == "\\" and index + 1 < len(value):
            index += 1
        decoded.append(value[index])
        index += 1
    return "".join(decoded)


def _value_matches(pattern, value):
    if pattern == "ANY":
        return True
    if pattern == "NA":
        return value == "NA"
    if value in ("ANY", "NA"):
        return False

    regex_parts = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\" and index + 1 < len(pattern):
            index += 1
            regex_parts.append(re.escape(pattern[index]))
        elif char == "*":
            regex_parts.append(".*")
        elif char == "?":
            regex_parts.append(".")
        else:
            regex_parts.append(re.escape(char))
        index += 1
    return re.match("".join(regex_parts) + r"\Z", value) is not None


def _cpe_matches(fact, observed):
    observed_values = _normalize_cpe(observed)
    for attribute, pattern in fact.values.items():
        if not _value_matches(pattern, observed_values[attribute]):
            return False
    return True


def _element_nodes(node):
    return [child for child in node.childNodes if child.nodeType == node.ELEMENT_NODE]


def _parse_xml(expression):
    document = minidom.parseString(expression)
    root = document.documentElement
    if root.nodeName == "cpe:platform-specification":
        for node in _element_nodes(root):
            if node.nodeName == "cpe:platform":
                root = node
                break
    for node in _element_nodes(root):
        if node.nodeName == "cpe:logical-test":
            return _Expression(_parse_xml_node(node))
    raise ValueError("CPE language expression has no logical test")


def _parse_xml_node(node):
    if node.nodeName == "cpe:fact-ref":
        return _Fact(node.getAttribute("name"))

    children = [_parse_xml_node(child) for child in _element_nodes(node)]
    return _LogicalTest(
        node.getAttribute("operator") or "AND",
        (node.getAttribute("negate") or "FALSE").upper() == "TRUE",
        children
    )


def _parse_fact_list(facts):
    children = [_Fact(fact) for fact in facts]
    return _Expression(_LogicalTest("AND", False, children))


def parse_expression(expression):
    """Parse a CPE language XML document or a list of fact CPE names."""
    if isinstance(expression, _Expression):
        return expression
    if isinstance(expression, (list, tuple)):
        return _parse_fact_list(expression)
    return _parse_xml(expression)


def _not(value):
    if value == _UNKNOWN:
        return _UNKNOWN
    return _FALSE if value == _TRUE else _TRUE


def _evaluate_node(node, active_records):
    if isinstance(node, _Fact):
        matched_known = False
        has_unknown_environment = False
        has_matching_record = False

        for record in active_records:
            if not _cpe_matches(node, record.cpe):
                continue
            has_matching_record = True
            if record.environment_known:
                matched_known = True
            else:
                has_unknown_environment = True

        if matched_known:
            return _TRUE
        complete_environment = any(
            record.environment_known and record.complete_environment
            for record in active_records)
        if has_unknown_environment or (not has_matching_record and
                                       not complete_environment):
            return _UNKNOWN
        return _FALSE

    values = [_evaluate_node(child, active_records) for child in node.children]
    if node.operator == "AND":
        result = _TRUE
        if _FALSE in values:
            result = _FALSE
        elif _UNKNOWN in values:
            result = _UNKNOWN
    else:
        result = _FALSE
        if _TRUE in values:
            result = _TRUE
        elif _UNKNOWN in values:
            result = _UNKNOWN

    return _not(result) if node.negate else result


def _unknown_facts(node, active_records):
    if isinstance(node, _Fact):
        for record in active_records:
            if _cpe_matches(node, record.cpe) and not record.environment_known:
                return set([node.name])
        return set()

    unknown = set()
    if node.operator == "OR":
        child_values = [_evaluate_node(child, active_records)
                        for child in node.children]
        if _TRUE in child_values:
            return unknown
    for child in node.children:
        unknown.update(_unknown_facts(child, active_records))
    return unknown


def _unmatched_facts(node, active_records):
    if isinstance(node, _Fact):
        for record in active_records:
            if _cpe_matches(node, record.cpe):
                return set()
        return set([node.name])

    unmatched = set()
    if node.operator == "OR":
        child_values = [_evaluate_node(child, active_records)
                        for child in node.children]
        if _TRUE in child_values:
            return unmatched
    for child in node.children:
        unmatched.update(_unmatched_facts(child, active_records))
    return unmatched


def _status_from_value(value):
    if value == _TRUE:
        return AFFECTED
    if value == _FALSE:
        return NOT_AFFECTED
    return UNKNOWN


def _overlaps(active_start, active_end, segment_start, segment_end):
    active_end = active_end if active_end is not None else segment_end
    return active_start < segment_end and active_end > segment_start


def _is_active(record, segment_start, segment_end):
    if record.retired is not None and record.retired <= segment_start:
        return False
    return _overlaps(record.effective, record.retired,
                     segment_start, segment_end)


def evaluate_deployments(expression, records, start=None, end=None):
    """Return merged applicability segments for deployment CPE records.

    Records are grouped by ``deployment_id`` before CPE evaluation, so CPEs
    from different deployments can never satisfy one expression together.
    Intervals are half-open: ``[effective, retired)``. A record with no
    retired date remains active until ``end``.
    """
    parsed_expression = parse_expression(expression)
    normalized = []
    for record in records:
        if not isinstance(record, DeploymentRecord):
            record = DeploymentRecord.from_mapping(record)
        record.effective = _coerce_datetime(record.effective)
        record.retired = _coerce_datetime(record.retired)
        normalized.append(record)

    start = _coerce_datetime(start)
    end = _coerce_datetime(end)
    if start is None:
        starts = [record.effective for record in normalized]
        if not starts:
            return []
        start = min(starts)
    if end is None:
        ends = [record.retired for record in normalized if record.retired is not None]
        end = max(ends) if ends else max(record.effective for record in normalized)

    if start >= end:
        raise ValueError("evaluation start must be earlier than end")

    boundaries = set([start, end])
    for record in normalized:
        if start < record.effective < end:
            boundaries.add(record.effective)
        if record.retired is not None and start < record.retired < end:
            boundaries.add(record.retired)
    boundaries = sorted(boundaries)

    grouped = defaultdict(list)
    for record in normalized:
        grouped[record.deployment_id].append(record)

    raw_segments = []
    for boundary_start, boundary_end in zip(boundaries, boundaries[1:]):
        segment_status = NOT_AFFECTED
        segment_deployments = set()
        segment_missing = set()
        segment_unresolved = set()

        for deployment_id, deployment_records in grouped.items():
            active_records = [
                record for record in deployment_records
                if _is_active(record, boundary_start, boundary_end)
            ]
            if not active_records:
                continue

            value = _evaluate_node(parsed_expression.root, active_records)
            status = _status_from_value(value)
            if status == NOT_AFFECTED:
                continue

            segment_status = _combine_status(segment_status, status)
            segment_deployments.add(deployment_id)
            if status == UNKNOWN:
                segment_missing.update(
                    _unknown_facts(parsed_expression.root, active_records))
                segment_unresolved.update(
                    _unmatched_facts(parsed_expression.root, active_records))

        raw_segments.append(ApplicabilitySegment(
            boundary_start, boundary_end, segment_status,
            segment_deployments, segment_missing, segment_unresolved))

    return _merge_segments(raw_segments)


def _combine_status(current, candidate):
    if current == UNKNOWN or candidate == UNKNOWN:
        return UNKNOWN
    if current == AFFECTED or candidate == AFFECTED:
        return AFFECTED
    return NOT_AFFECTED


def _merge_segments(segments):
    if not segments:
        return []

    merged = [segments[0]]
    for segment in segments[1:]:
        previous = merged[-1]
        same_result = (
            previous.status == segment.status and
            previous.deployments == segment.deployments and
            previous.missing_facts == segment.missing_facts and
            previous.unresolved_facts == segment.unresolved_facts
        )
        if same_result and previous.end == segment.start:
            previous.end = segment.end
        else:
            merged.append(segment)
    return merged
