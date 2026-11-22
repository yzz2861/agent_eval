#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Offline differential analysis of CPE 2.3 language expressions.

This module compares two CPE applicability expressions against a finite,
review-supplied attribute domain.  It deliberately does not search the
network or inspect live instances.  Matching is performed with the relation
primitives already used by :class:`cpe.cpeset2_3.CPESet2_3`, but the result is
lifted to a three-valued logic so that unknown values and incomparable
attributes are reported as pending instead of being silently treated as a
non-match.

The command-line entry point is available with::

    python -m cpe.cpediff2_3 --old old.xml --new new.xml --review review.json

"""

from __future__ import absolute_import, print_function, unicode_literals

import argparse
import hashlib
import io
import itertools
import json
import sys
from collections import OrderedDict
from xml.dom import Node
from xml.dom import minidom

from .comp.cpecomp import CPEComponent
from .cpe2_3_wfn import CPE2_3_WFN
from .cpelang2_3 import CPELanguage2_3
from .cpeset2_3 import CPESet2_3


STATE_TRUE = "TRUE"
STATE_FALSE = "FALSE"
STATE_UNKNOWN = "UNKNOWN"

TRANSITION_NEW_EXCLUSION = "new_exclusion"
TRANSITION_REMOVED_EXCLUSION = "removed_exclusion"
TRANSITION_STILL_EXCLUDED = "still_excluded"
TRANSITION_STILL_INCLUDED = "still_included"

STATUS_CONCLUSIVE = "conclusive"
STATUS_PENDING = "pending"

_ATTRIBUTES = tuple(CPEComponent.CPE_COMP_KEYS_EXTENDED)
_ATTRIBUTE_ORDER = dict((att, idx) for idx, att in enumerate(_ATTRIBUTES))

_REL_NAMES = {
    CPESet2_3.LOGICAL_VALUE_SUPERSET: "superset",
    CPESet2_3.LOGICAL_VALUE_SUBSET: "subset",
    CPESet2_3.LOGICAL_VALUE_EQUAL: "equal",
    CPESet2_3.LOGICAL_VALUE_DISJOINT: "disjoint",
    CPESet2_3.LOGICAL_VALUE_UNDEFINED: "undefined",
}


class CPEDiffError(ValueError):
    """Raised when the expressions or review input are not usable."""


class _PendingDevice(Exception):
    """Internal signal that a device cannot be expanded decisively."""

    def __init__(self, code, detail=None):
        super(_PendingDevice, self).__init__(code)
        self.code = code
        self.detail = detail

    def as_dict(self):
        result = {"code": self.code}
        if self.detail is not None:
            result["detail"] = self.detail
        return result


def _local_name(node):
    return node.nodeName.split(":")[-1]


def _element_children(node):
    return [child for child in node.childNodes
            if child.nodeType == Node.ELEMENT_NODE]


def _load_text(value, is_file):
    if is_file:
        with io.open(value, "r", encoding="utf-8") as stream:
            return stream.read()
    return value


def _sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _coerce_scalar(value):
    if isinstance(value, bool) or isinstance(value, (dict, list, tuple)):
        raise CPEDiffError("attribute values must be strings or numbers")
    return str(value)


def _normalize_domain(raw_domain):
    """
    Normalize a review-supplied domain into an ordered mapping.

    A value of ``None``, ``"?"``, an empty list, or a list containing either
    marker means that attribute has no finite domain and cannot be enumerated.
    """

    if raw_domain is None:
        return OrderedDict()
    if not isinstance(raw_domain, dict):
        raise CPEDiffError("review.domain must be an object")

    unknown = set(raw_domain) - set(_ATTRIBUTES)
    if unknown:
        raise CPEDiffError(
            "review.domain contains invalid attribute(s): {0}".format(
                ", ".join(sorted(unknown))))

    domain = OrderedDict()
    for att in _ATTRIBUTES:
        if att not in raw_domain:
            continue
        raw_values = raw_domain[att]
        if raw_values is None or raw_values == "?":
            domain[att] = None
            continue
        if isinstance(raw_values, (str, int, float)):
            raw_values = [raw_values]
        if not isinstance(raw_values, (list, tuple)):
            raise CPEDiffError(
                "domain value for '{0}' must be a scalar or list".format(att))
        if len(raw_values) == 0:
            domain[att] = None
            continue
        values = []
        unbounded = False
        for value in raw_values:
            if value is None or value == "?":
                unbounded = True
                break
            values.append(_coerce_scalar(value))
        domain[att] = None if unbounded else tuple(values)

    return domain


def _normalize_confirmed(confirmed):
    if confirmed is None:
        return None, {}
    if isinstance(confirmed, dict):
        overlay = OrderedDict()
        for att, value in confirmed.items():
            if att not in _ATTRIBUTES:
                raise CPEDiffError(
                    "invalid confirmed attribute '{0}'".format(att))
            overlay[att] = value
        return None, overlay
    if isinstance(confirmed, (list, tuple, set)):
        names = set()
        for att in confirmed:
            if att not in _ATTRIBUTES:
                raise CPEDiffError(
                    "invalid confirmed attribute '{0}'".format(att))
            names.add(att)
        return names, {}
    raise CPEDiffError("'confirmed' must be a list or an object")


def _normalize_name_set(value, label):
    if value is None:
        return set()
    if not isinstance(value, (list, tuple, set)):
        raise CPEDiffError("'{0}' must be a list".format(label))
    result = set()
    for att in value:
        if att not in _ATTRIBUTES:
            raise CPEDiffError(
                "'{0}' contains invalid attribute '{1}'".format(label, att))
        result.add(att)
    return result


def _wfn_escape(value):
    """
    Escape a literal value for use in a WFN quoted string.

    ``*`` and ``?`` are intentionally left unescaped so reviewers can use a
    wildcard in a finite domain; such a device value is later reported as
    incomparable rather than guessed.  ``=`` is rejected because this version
    of the cpe parser splits attribute pairs without honouring quotes.
    """

    text = _coerce_scalar(value)
    if any(ch.isspace() for ch in text):
        raise CPEDiffError(
            "WFN values cannot contain whitespace: {0!r}".format(text))
    if "=" in text:
        raise CPEDiffError(
            "WFN values cannot contain '=': {0!r}".format(text))

    escaped = []
    for ch in text:
        if (("a" <= ch <= "z") or ("A" <= ch <= "Z") or
                ("0" <= ch <= "9") or ch in "_-*?"):
            escaped.append(ch)
        elif ch == "\\":
            escaped.append("\\\\")
        else:
            escaped.append("\\" + ch)
    return "".join(escaped)


def build_wfn(attributes):
    """
    Build a single-element CPE 2.3 WFN from an attribute mapping.

    Values ``ANY`` and ``NA`` (case-insensitive) become CPE logical values.
    Every other value is treated as a literal, except that ``*`` and ``?``
    retain their WFN wildcard meaning.
    """

    if not isinstance(attributes, dict):
        raise CPEDiffError("component attributes must be an object")

    invalid = set(attributes) - set(_ATTRIBUTES)
    if invalid:
        raise CPEDiffError(
            "invalid attribute(s): {0}".format(", ".join(sorted(invalid))))

    pairs = []
    for att in _ATTRIBUTES:
        if att not in attributes:
            continue
        value = attributes[att]
        if value is None or value == "?":
            raise CPEDiffError(
                "attribute '{0}' has no value".format(att))
        text = _coerce_scalar(value)
        if text.upper() in ("ANY", "NA"):
            pairs.append("{0}={1}".format(att, text.upper()))
        else:
            pairs.append('{0}="{1}"'.format(att, _wfn_escape(text)))

    if not pairs:
        raise CPEDiffError("a component must define at least one attribute")

    return CPE2_3_WFN("wfn:[{0}]".format(", ".join(pairs)))


def _wfn_attributes(wfn):
    result = OrderedDict()
    for att in _ATTRIBUTES:
        values = wfn.get_attribute_values(att)
        if len(values) != 1:
            raise _PendingDevice(
                "multi_element_cpe_not_supported",
                {"attribute": att, "values": values})
        result[att] = _decode_wfn_value(values[0])
    return result


def _parse_device_cpe(cpe_text):
    try:
        wfn = CPELanguage2_3._unbind(cpe_text)
    except Exception as exc:
        raise _PendingDevice(
            "invalid_cpe", {"cpe": cpe_text, "error": str(exc)})
    if not isinstance(wfn, CPE2_3_WFN):
        raise _PendingDevice(
            "invalid_cpe", {"cpe": cpe_text, "error": "not a CPE 2.3 WFN"})
    return wfn


def _decode_wfn_value(value):
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
    decoded = []
    index = 0
    while index < len(value):
        if value[index] == "\\" and index + 1 < len(value):
            decoded.append(value[index + 1])
            index += 2
        else:
            decoded.append(value[index])
            index += 1
    return "".join(decoded)


class DeviceCandidate(object):
    """One fully expanded device: a set of one or more CPE components."""

    def __init__(self, components, attributes):
        self.components = components
        self.attributes = attributes

    def to_dict(self):
        return {
            "components": [wfn.as_wfn() for wfn in self.components],
            "attributes": [dict(attrs) for attrs in self.attributes],
        }


def _normalize_component(component, device_confirmed, device_unknown,
                         domain):
    if not isinstance(component, dict):
        raise CPEDiffError("each component must be an object")

    meta_keys = {"confirmed", "unknown"}
    present = OrderedDict()
    for att, value in component.items():
        if att in meta_keys:
            continue
        if att not in _ATTRIBUTES:
            raise CPEDiffError(
                "invalid component attribute '{0}'".format(att))
        present[att] = value

    confirmed = component.get("confirmed", device_confirmed)
    confirmed_names, overlay = _normalize_confirmed(confirmed)
    if overlay:
        present.update(overlay)

    unknown = set(_normalize_name_set(component.get("unknown"), "unknown"))
    unknown.update(device_unknown)
    if confirmed_names is not None:
        unknown.update(set(present) - confirmed_names)
        unknown.update(
            att for att in domain
            if att not in confirmed_names and att not in present)
    unknown.update(
        att for att, value in present.items()
        if value is None or value == "?")

    if confirmed_names is not None:
        missing = confirmed_names - set(present)
        if missing:
            raise _PendingDevice(
                "missing_confirmed_value",
                {"attributes": sorted(missing)})

    for att in unknown:
        present.pop(att, None)

    if not present and not unknown:
        raise CPEDiffError("a component must define at least one attribute")

    return present, unknown


def _ordered_unknown(unknown):
    return sorted(unknown, key=lambda att: _ATTRIBUTE_ORDER[att])


def _expand_component(component, domain, device_confirmed, device_unknown,
                      max_candidates):
    base, unknown = _normalize_component(
        component, device_confirmed, device_unknown, domain)
    unknown = _ordered_unknown(unknown)

    if unknown:
        value_lists = []
        for att in unknown:
            values = domain.get(att)
            if values is None:
                raise _PendingDevice(
                    "no_finite_domain", {"attribute": att})
            value_lists.append(values)

        count = 1
        for values in value_lists:
            count *= len(values)
        if count > max_candidates:
            raise _PendingDevice(
                "domain_too_large",
                {"candidate_count": count, "limit": max_candidates})

        candidates = []
        for values in itertools.product(*value_lists):
            attributes = OrderedDict(base)
            for att, value in zip(unknown, values):
                attributes[att] = value
            candidates.append(
                (attributes, build_wfn(attributes)))
        return candidates

    attributes = OrderedDict(base)
    return [(attributes, build_wfn(attributes))]


def _expand_device(device, domain, max_candidates):
    if "cpes" in device and "components" in device:
        raise CPEDiffError(
            "a device must use either 'cpes' or 'components', not both")

    if "cpes" in device:
        raw_cpes = device["cpes"]
        if (not isinstance(raw_cpes, (list, tuple)) or not raw_cpes):
            raise CPEDiffError("'cpes' must be a non-empty list")
        components = [_parse_device_cpe(cpe) for cpe in raw_cpes]
        attributes = [_wfn_attributes(wfn) for wfn in components]
        return [DeviceCandidate(components, attributes)]

    raw_components = device.get("components")
    if (not isinstance(raw_components, (list, tuple)) or
            not raw_components):
        raise CPEDiffError("'components' must be a non-empty list")

    device_confirmed = device.get("confirmed")
    device_unknown = _normalize_name_set(device.get("unknown"), "unknown")

    per_component = [
        _expand_component(component, domain, device_confirmed, device_unknown,
                          max_candidates)
        for component in raw_components
    ]

    total = 1
    for candidates in per_component:
        total *= len(candidates)
    if total > max_candidates:
        raise _PendingDevice(
            "domain_too_large",
            {"candidate_count": total, "limit": max_candidates})

    result = []
    for combination in itertools.product(*per_component):
        result.append(DeviceCandidate(
            [item[1] for item in combination],
            [_wfn_attributes(item[1]) for item in combination]))
    return result


class ExpressionNode(object):
    """Parsed node of a CPE applicability expression."""

    def __init__(self, kind, path, operator=None, negate=False,
                 children=None, name=None, wfn=None, reason=None):
        self.kind = kind
        self.path = path
        self.operator = operator
        self.negate = negate
        self.children = children or []
        self.name = name
        self.wfn = wfn
        self.reason = reason


def _parse_logical_node(node, path):
    operator = node.getAttribute("operator").upper()
    negate = node.getAttribute("negate").upper() == "TRUE"
    children = []
    for index, child in enumerate(_element_children(node)):
        child_path = "{0}/{1}[{2}]".format(
            path, _local_name(child), index)
        children.append(_parse_expression_node(child, child_path))
    if operator not in ("AND", "OR"):
        return ExpressionNode(
            "logical", path, operator=operator, negate=negate,
            children=children, reason="invalid_operator")
    return ExpressionNode(
        "logical", path, operator=operator, negate=negate,
        children=children)


def _single_element_wfn(wfn):
    for att in _ATTRIBUTES:
        if len(wfn.get_attribute_values(att)) != 1:
            return False
    return True


def _parse_expression_node(node, path):
    local = _local_name(node)
    if local == "logical-test":
        return _parse_logical_node(node, path)
    if local == "fact-ref":
        name = node.getAttribute("name")
        try:
            wfn = CPELanguage2_3._unbind(name)
        except Exception as exc:
            return ExpressionNode(
                "fact", path, name=name,
                reason="invalid_fact_ref: {0}".format(exc))
        if not isinstance(wfn, CPE2_3_WFN):
            return ExpressionNode(
                "fact", path, name=name,
                reason="invalid_fact_ref: not a CPE 2.3 WFN")
        if not _single_element_wfn(wfn):
            return ExpressionNode(
                "fact", path, name=name,
                reason="multi_element_fact_ref_not_supported")
        return ExpressionNode("fact", path, name=name, wfn=wfn)
    if local == "check-fact-ref":
        return ExpressionNode(
            "unsupported", path, reason="check_fact_ref_not_supported")
    return ExpressionNode(
        "unsupported", path, reason="unsupported_element:{0}".format(local))


def parse_expression(expression, is_file=False):
    """Parse a CPE applicability expression into an ``ExpressionNode`` tree."""

    text = _load_text(expression, is_file)
    try:
        document = minidom.parseString(text)
    except Exception as exc:
        raise CPEDiffError("invalid expression XML: {0}".format(exc))

    root = document.documentElement
    local = _local_name(root)
    if local == "platform-specification":
        platforms = [child for child in _element_children(root)
                     if _local_name(child) == "platform"]
        if len(platforms) != 1:
            raise CPEDiffError(
                "expected exactly one cpe:platform, found {0}".format(
                    len(platforms)))
        platform = platforms[0]
    elif local == "platform":
        platform = root
    elif local == "logical-test":
        return _parse_logical_node(root, "logical-test[0]")
    else:
        raise CPEDiffError(
            "unsupported root element '{0}'".format(root.nodeName))

    logical_tests = [child for child in _element_children(platform)
                     if _local_name(child) == "logical-test"]
    if len(logical_tests) != 1:
        raise CPEDiffError(
            "expected exactly one cpe:logical-test in platform '{0}', "
            "found {1}".format(
                platform.getAttribute("id"), len(logical_tests)))
    return _parse_logical_node(logical_tests[0], "platform[0]/logical-test[0]")


def _walk(node):
    yield node
    for child in node.children:
        for item in _walk(child):
            yield item


def _fact_refs(node):
    return sorted(set(item.name for item in _walk(node)
                      if item.kind == "fact" and item.name))


def _negated_branches(node):
    result = []
    for item in _walk(node):
        if item.kind == "logical" and item.negate:
            result.append({
                "path": item.path,
                "operator": item.operator,
                "facts": _fact_refs(item),
            })
    return result


def expression_info(node, text):
    return {
        "sha256": _sha256(text),
        "fact_refs": _fact_refs(node),
        "negated_branches": _negated_branches(node),
    }


def expression_delta(old_node, new_node):
    old_facts = set(_fact_refs(old_node))
    new_facts = set(_fact_refs(new_node))
    return {
        "fact_refs_added": sorted(new_facts - old_facts),
        "fact_refs_removed": sorted(old_facts - new_facts),
    }


def _combine_and(states):
    if STATE_FALSE in states:
        return STATE_FALSE
    if STATE_UNKNOWN in states:
        return STATE_UNKNOWN
    return STATE_TRUE


def _combine_or(states):
    if STATE_TRUE in states:
        return STATE_TRUE
    if STATE_UNKNOWN in states:
        return STATE_UNKNOWN
    return STATE_FALSE


def _negate_state(state):
    if state == STATE_TRUE:
        return STATE_FALSE
    if state == STATE_FALSE:
        return STATE_TRUE
    return STATE_UNKNOWN


def _component_relation(fact_wfn, device_wfn):
    buckets = {
        CPESet2_3.LOGICAL_VALUE_SUPERSET: [],
        CPESet2_3.LOGICAL_VALUE_SUBSET: [],
        CPESet2_3.LOGICAL_VALUE_EQUAL: [],
        CPESet2_3.LOGICAL_VALUE_DISJOINT: [],
        CPESet2_3.LOGICAL_VALUE_UNDEFINED: [],
    }
    for att, relation in CPESet2_3.compare_wfns(fact_wfn, device_wfn):
        buckets[relation].append(att)

    if buckets[CPESet2_3.LOGICAL_VALUE_DISJOINT]:
        state = STATE_FALSE
        relation_name = "disjoint"
    elif (buckets[CPESet2_3.LOGICAL_VALUE_SUBSET] or
          buckets[CPESet2_3.LOGICAL_VALUE_UNDEFINED]):
        state = STATE_UNKNOWN
        relation_name = "incomparable"
    else:
        state = STATE_TRUE
        relation_name = "superset"

    detail = OrderedDict()
    detail["cpe"] = device_wfn.as_wfn()
    detail["relation"] = relation_name
    for relation in (
            CPESet2_3.LOGICAL_VALUE_EQUAL,
            CPESet2_3.LOGICAL_VALUE_SUPERSET,
            CPESet2_3.LOGICAL_VALUE_SUBSET,
            CPESet2_3.LOGICAL_VALUE_DISJOINT,
            CPESet2_3.LOGICAL_VALUE_UNDEFINED):
        if buckets[relation]:
            detail[_REL_NAMES[relation]] = buckets[relation]

    return state, detail


def _fact_state(fact_wfn, components):
    states = []
    traces = []
    for component in components:
        state, detail = _component_relation(fact_wfn, component)
        states.append(state)
        traces.append(detail)

    if STATE_TRUE in states:
        state = STATE_TRUE
    elif STATE_UNKNOWN in states:
        state = STATE_UNKNOWN
    else:
        state = STATE_FALSE

    return state, {"components": traces}


def _evaluate_node(node, components):
    if node.kind == "logical":
        child_results = [_evaluate_node(child, components)
                         for child in node.children]
        child_states = [result[0] for result in child_results]
        if node.operator == "AND":
            state = _combine_and(child_states)
        elif node.operator == "OR":
            state = _combine_or(child_states)
        else:
            state = STATE_UNKNOWN
        if node.negate:
            state = _negate_state(state)
        trace = OrderedDict()
        trace["path"] = node.path
        trace["kind"] = "logical-test"
        trace["operator"] = node.operator
        trace["negate"] = node.negate
        trace["state"] = state
        if node.reason:
            trace["reason"] = node.reason
        trace["children"] = [result[1] for result in child_results]
        return state, trace

    if node.kind == "fact":
        if node.reason:
            trace = OrderedDict()
            trace["path"] = node.path
            trace["kind"] = "fact-ref"
            trace["name"] = node.name
            trace["state"] = STATE_UNKNOWN
            trace["reason"] = node.reason
            return STATE_UNKNOWN, trace

        state, detail = _fact_state(node.wfn, components)
        trace = OrderedDict()
        trace["path"] = node.path
        trace["kind"] = "fact-ref"
        trace["name"] = node.name
        trace["state"] = state
        trace.update(detail)
        return state, trace

    trace = OrderedDict()
    trace["path"] = node.path
    trace["kind"] = node.kind
    trace["state"] = STATE_UNKNOWN
    trace["reason"] = node.reason or "unsupported_node"
    return STATE_UNKNOWN, trace


def _collect_unknown(trace):
    result = []
    if trace.get("kind") == "fact-ref" and trace.get("state") == STATE_UNKNOWN:
        item = {
            "path": trace.get("path"),
            "name": trace.get("name"),
            "reason": trace.get("reason", "incomparable"),
        }
        components = trace.get("components", [])
        incomparable = []
        for component in components:
            if component.get("relation") == "incomparable":
                incomparable.append({
                    "cpe": component.get("cpe"),
                    "undefined": component.get("undefined", []),
                    "subset": component.get("subset", []),
                })
        if incomparable:
            item["components"] = incomparable
        result.append(item)
    for child in trace.get("children", []):
        result.extend(_collect_unknown(child))
    return result


def _transition(old_state, new_state):
    if old_state == STATE_TRUE and new_state == STATE_FALSE:
        return TRANSITION_NEW_EXCLUSION
    if old_state == STATE_FALSE and new_state == STATE_TRUE:
        return TRANSITION_REMOVED_EXCLUSION
    if old_state == STATE_FALSE and new_state == STATE_FALSE:
        return TRANSITION_STILL_EXCLUDED
    if old_state == STATE_TRUE and new_state == STATE_TRUE:
        return TRANSITION_STILL_INCLUDED
    return None


def _covers(state):
    if state == STATE_TRUE:
        return True
    if state == STATE_FALSE:
        return False
    return None


def _device_pending(device_id, reason, candidate_count=0):
    return {
        "id": device_id,
        "status": STATUS_PENDING,
        "transition": None,
        "old_covered": None,
        "new_covered": None,
        "candidate_count": candidate_count,
        "pending_reasons": [reason],
    }


def _group_variants(records):
    grouped = OrderedDict()
    for record in records:
        key = (record["old_state"], record["new_state"])
        if key not in grouped:
            grouped[key] = []
        grouped[key].append(record)

    variants = []
    for (old_state, new_state), items in grouped.items():
        witness = items[0]
        variants.append({
            "old_state": old_state,
            "new_state": new_state,
            "transition": _transition(old_state, new_state),
            "candidate_count": len(items),
            "witness": witness["candidate"].to_dict(),
            "old_trace": witness["old_trace"],
            "new_trace": witness["new_trace"],
        })
    return variants


def _diff_device(device, old_node, new_node, domain, max_candidates):
    device_id = device["id"]
    try:
        candidates = _expand_device(device, domain, max_candidates)
    except _PendingDevice as pending:
        return _device_pending(device_id, pending.as_dict())

    records = []
    for candidate in candidates:
        old_state, old_trace = _evaluate_node(old_node, candidate.components)
        new_state, new_trace = _evaluate_node(new_node, candidate.components)
        records.append({
            "candidate": candidate,
            "old_state": old_state,
            "new_state": new_state,
            "old_trace": old_trace,
            "new_trace": new_trace,
        })

    unknown_reasons = []
    for record in records:
        if record["old_state"] == STATE_UNKNOWN:
            unknown_reasons.extend(_collect_unknown(record["old_trace"]))
        if record["new_state"] == STATE_UNKNOWN:
            unknown_reasons.extend(_collect_unknown(record["new_trace"]))

    outcomes = set(
        (record["old_state"], record["new_state"]) for record in records)
    if unknown_reasons:
        result = _device_pending(
            device_id,
            {"code": "unknown_or_incomparable", "facts": unknown_reasons},
            candidate_count=len(candidates))
        if len(outcomes) > 1:
            result["variants"] = _group_variants(records)
        return result

    if len(outcomes) > 1:
        result = _device_pending(
            device_id,
            {"code": "ambiguous_over_domain"},
            candidate_count=len(candidates))
        result["variants"] = _group_variants(records)
        return result

    record = records[0]
    transition = _transition(record["old_state"], record["new_state"])
    return {
        "id": device_id,
        "status": STATUS_CONCLUSIVE,
        "transition": transition,
        "old_covered": _covers(record["old_state"]),
        "new_covered": _covers(record["new_state"]),
        "old_state": record["old_state"],
        "new_state": record["new_state"],
        "candidate_count": len(candidates),
        "witness": record["candidate"].to_dict(),
        "old_trace": record["old_trace"],
        "new_trace": record["new_trace"],
        "pending_reasons": [],
    }


def diff_expressions(old_expression, new_expression, review,
                     old_is_file=False, new_is_file=False,
                     review_is_file=False, max_candidates=2000):
    """
    Compare two CPE 2.3 applicability expressions offline.

    ``review`` is either a mapping or, with ``review_is_file=True``, a path to
    a JSON file.  See :func:`normalize_review` for the accepted schema.

    The expression result is interpreted as follows:

    - ``TRUE``  : the device is covered by the announcement;
    - ``FALSE`` : the device is excluded;
    - ``UNKNOWN``: an attribute is unknown or incomparable, so the device is
      retained for review.
    """

    old_text = _load_text(old_expression, old_is_file)
    new_text = _load_text(new_expression, new_is_file)
    old_node = parse_expression(old_text)
    new_node = parse_expression(new_text)

    if review_is_file:
        with io.open(review, "r", encoding="utf-8") as stream:
            review = json.load(stream)
    review = normalize_review(review)

    domain = review["domain"]
    if max_candidates is None:
        max_candidates = review.get("max_candidates", 2000)
    try:
        max_candidates = int(max_candidates)
    except (TypeError, ValueError):
        raise CPEDiffError("max_candidates must be a positive integer")
    if max_candidates < 1:
        raise CPEDiffError("max_candidates must be a positive integer")

    devices = []
    for device in review["devices"]:
        devices.append(_diff_device(
            device, old_node, new_node, domain, max_candidates))

    new_exclusions = [
        item["id"] for item in devices
        if item.get("transition") == TRANSITION_NEW_EXCLUSION]
    removed_exclusions = [
        item["id"] for item in devices
        if item.get("transition") == TRANSITION_REMOVED_EXCLUSION]
    still_excluded = [
        item["id"] for item in devices
        if item.get("transition") == TRANSITION_STILL_EXCLUDED]
    still_included = [
        item["id"] for item in devices
        if item.get("transition") == TRANSITION_STILL_INCLUDED]
    pending = [item["id"] for item in devices
               if item["status"] == STATUS_PENDING]

    if new_exclusions and not removed_exclusions:
        exclusion_scope = "expanded"
    elif removed_exclusions and not new_exclusions:
        exclusion_scope = "shrunk"
    elif new_exclusions and removed_exclusions:
        exclusion_scope = "mixed"
    elif pending:
        exclusion_scope = "undetermined"
    else:
        exclusion_scope = "unchanged"

    summary = {
        "exclusion_scope": exclusion_scope,
        "scope_conclusive": len(pending) == 0,
        "new_exclusions": new_exclusions,
        "removed_exclusions": removed_exclusions,
        "still_excluded": still_excluded,
        "still_included": still_included,
        "pending": pending,
        "counts": {
            "new_exclusions": len(new_exclusions),
            "removed_exclusions": len(removed_exclusions),
            "still_excluded": len(still_excluded),
            "still_included": len(still_included),
            "pending": len(pending),
            "old_excluded": (len(removed_exclusions) +
                             len(still_excluded)),
            "new_excluded": len(new_exclusions) + len(still_excluded),
        },
    }

    changed_witnesses = {
        "new_exclusions": _changed_witnesses(
            devices, TRANSITION_NEW_EXCLUSION),
        "removed_exclusions": _changed_witnesses(
            devices, TRANSITION_REMOVED_EXCLUSION),
    }

    return {
        "tool": "cpediff2_3",
        "spec": "CPE 2.3",
        "semantics": {
            "covered": "expression evaluates TRUE",
            "excluded": "expression evaluates FALSE",
            "new_exclusion": "old covered -> new excluded",
            "removed_exclusion": "old excluded -> new covered",
        },
        "old_expression": expression_info(old_node, old_text),
        "new_expression": expression_info(new_node, new_text),
        "expression_delta": expression_delta(old_node, new_node),
        "review": {
            "domain": dict(
                (att, list(values) if values is not None else None)
                for att, values in domain.items()),
            "max_candidates": max_candidates,
            "device_count": len(devices),
        },
        "devices": devices,
        "witnesses": changed_witnesses,
        "summary": summary,
    }


def _changed_witnesses(devices, transition):
    result = []
    for device in devices:
        if device.get("transition") != transition:
            continue
        result.append({
            "id": device["id"],
            "witness": device["witness"],
            "old_covered": device["old_covered"],
            "new_covered": device["new_covered"],
            "old_state": device["old_state"],
            "new_state": device["new_state"],
            "old_trace": device["old_trace"],
            "new_trace": device["new_trace"],
        })
    return result


def normalize_review(review):
    """Validate and normalize a review input mapping."""

    if not isinstance(review, dict):
        raise CPEDiffError("review input must be an object")

    raw_devices = review.get("devices")
    if (not isinstance(raw_devices, (list, tuple)) or not raw_devices):
        raise CPEDiffError("review.devices must be a non-empty list")

    domain = _normalize_domain(review.get("domain"))
    devices = []
    for index, raw_device in enumerate(raw_devices):
        if not isinstance(raw_device, dict):
            raise CPEDiffError("each review device must be an object")
        device = dict(raw_device)
        device_id = device.get("id") or "device-{0}".format(index + 1)
        device["id"] = str(device_id)
        devices.append(device)

    return {
        "domain": domain,
        "devices": devices,
        "max_candidates": review.get("max_candidates"),
    }


def _short_cpe(name):
    try:
        wfn = CPELanguage2_3._unbind(name)
        attrs = _wfn_attributes(wfn)
    except Exception:
        return name
    return "{0}:{1}:{2}:{3}".format(
        attrs.get("part", "?"),
        attrs.get("vendor", "?"),
        attrs.get("product", "?"),
        attrs.get("version", "?"))


def _trace_expression(trace):
    kind = trace.get("kind")
    if kind == "fact-ref":
        return "fact({0})={1}".format(
            _short_cpe(trace.get("name", "?")), trace.get("state"))
    if kind == "logical-test":
        children = [_trace_expression(child)
                    for child in trace.get("children", [])]
        text = "{0}({1})".format(
            trace.get("operator", "?"), ", ".join(children))
        if trace.get("negate"):
            text = "NOT({0})".format(text)
        return text
    return "{0}={1}".format(kind, trace.get("state"))


def _format_witness(witness):
    return ", ".join(witness.get("components", []))


def format_text_report(report):
    """Render a concise human-readable report."""

    summary = report["summary"]
    counts = summary["counts"]
    by_id = dict((device["id"], device) for device in report["devices"])

    lines = []
    lines.append("CPE exclusion diff (offline, CPE 2.3)")
    lines.append("old expression: {0}".format(
        report["old_expression"]["sha256"][:16]))
    lines.append("new expression: {0}".format(
        report["new_expression"]["sha256"][:16]))

    delta = report["expression_delta"]
    lines.append("expression delta: +{0} fact-ref(s), -{1} fact-ref(s)".format(
        len(delta["fact_refs_added"]),
        len(delta["fact_refs_removed"])))
    for name in delta["fact_refs_added"]:
        lines.append("  added:   {0}".format(name))
    for name in delta["fact_refs_removed"]:
        lines.append("  removed: {0}".format(name))

    lines.append("exclusion scope: {0}".format(
        summary["exclusion_scope"].upper()))
    if not summary.get("scope_conclusive", True):
        lines.append(
            "  partial: {0} pending device(s) may still change the "
            "conclusion".format(counts["pending"]))
    lines.append("  old excluded: {0}  new excluded: {1}  pending: {2}".format(
        counts["old_excluded"], counts["new_excluded"], counts["pending"]))
    lines.append("")

    sections = (
        ("New exclusions (old covered -> new excluded)",
         summary["new_exclusions"]),
        ("Removed exclusions (old excluded -> new covered)",
         summary["removed_exclusions"]),
        ("Still excluded", summary["still_excluded"]),
        ("Still covered", summary["still_included"]),
    )
    for title, ids in sections:
        lines.append("{0}: {1}".format(title, len(ids)))
        for device_id in ids:
            device = by_id[device_id]
            lines.append("  - {0}".format(device_id))
            lines.append("      witness: {0}".format(
                _format_witness(device["witness"])))
            lines.append(
                "      old: covered={0} excluded={1}  {2}".format(
                    device["old_covered"], not device["old_covered"],
                    _trace_expression(device["old_trace"])))
            lines.append(
                "      new: covered={0} excluded={1}  {2}".format(
                    device["new_covered"], not device["new_covered"],
                    _trace_expression(device["new_trace"])))
        lines.append("")

    lines.append("Pending review: {0}".format(len(summary["pending"])))
    for device_id in summary["pending"]:
        device = by_id[device_id]
        reason_codes = [reason.get("code")
                        for reason in device.get("pending_reasons", [])]
        lines.append("  - {0} [{1}]".format(
            device_id, ", ".join(reason_codes)))
        for reason in device.get("pending_reasons", []):
            facts = reason.get("facts", [])
            for fact in facts:
                lines.append(
                    "      {0}: {1} ({2})".format(
                        fact.get("path"), fact.get("name"),
                        fact.get("reason")))
            if reason.get("detail") is not None:
                lines.append("      detail: {0}".format(reason["detail"]))
        for variant in device.get("variants", []):
            lines.append(
                "      variant old={0} new={1}: witness {2}".format(
                    variant["old_state"], variant["new_state"],
                    _format_witness(variant["witness"])))
            lines.append(
                "        old: {0}".format(
                    _trace_expression(variant["old_trace"])))
            lines.append(
                "        new: {0}".format(
                    _trace_expression(variant["new_trace"])))

    return "\n".join(lines)


def _build_arg_parser():
    parser = argparse.ArgumentParser(
        description="Offline differential analysis of CPE 2.3 expressions.")
    parser.add_argument(
        "--old", required=True,
        help="path to the old CPE applicability XML expression")
    parser.add_argument(
        "--new", required=True,
        help="path to the new CPE applicability XML expression")
    parser.add_argument(
        "--review", required=True,
        help="path to the review JSON file (finite domain and devices)")
    parser.add_argument(
        "--format", choices=("text", "json"), default="text",
        help="output format (default: text)")
    parser.add_argument(
        "--output",
        help="write the report to this path instead of stdout")
    parser.add_argument(
        "--max-candidates", type=int, default=2000,
        help="maximum expanded candidates per device (default: 2000)")
    return parser


def main(argv=None):
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    try:
        report = diff_expressions(
            args.old, args.new, args.review,
            old_is_file=True, new_is_file=True, review_is_file=True,
            max_candidates=args.max_candidates)
    except CPEDiffError as exc:
        parser.error(str(exc))
    except (IOError, OSError) as exc:
        parser.error(str(exc))
    except ValueError as exc:
        parser.error("invalid review input: {0}".format(exc))

    if args.format == "json":
        output = json.dumps(report, indent=2, sort_keys=False)
    else:
        output = format_text_report(report)

    if args.output:
        with io.open(args.output, "w", encoding="utf-8") as stream:
            stream.write(output)
            if not output.endswith("\n"):
                stream.write("\n")
    else:
        print(output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
