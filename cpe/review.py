#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""Rollback review built on the two CPE matching entry points.

The module intentionally does not invent a third matching algorithm.  Name
advisories are evaluated with ``CPESet2_3.name_match`` and platform
expressions with ``CPELanguage2_3.language_match``.  The extra traversal in
this module only records *why* a boolean answer was produced: the logical
branch that was satisfied, and any attribute whose comparison is undefined
because the installed inventory is under-specified.

The public entry point is :func:`analyze` (also exported as
:func:`review_rollback`).  It accepts a normalised scenario dictionary or the
individual ``approved``/``before``/``after``/``advisories`` arguments.
"""

from __future__ import unicode_literals

import argparse
import json
import sys
from xml.dom import Node, getDOMImplementation, minidom

from .cpe import CPE
from .cpe2_2 import CPE2_2
from .cpe2_3_wfn import CPE2_3_WFN
from .cpelang2_2 import CPELanguage2_2
from .cpelang2_3 import CPELanguage2_3
from .cpeset2_2 import CPESet2_2
from .cpeset2_3 import CPESet2_3


try:  # pragma: no cover - Python 2 compatibility
    string_types = (basestring,)  # noqa: F821
except NameError:  # pragma: no cover
    string_types = (str,)


# Match states.  "unknown" is deliberately distinct from "not_matched" so a
# wildcarded inventory entry is not mistaken for a definite non-match.
STATUS_MATCHED = "matched"
STATUS_NOT_MATCHED = "not_matched"
STATUS_UNKNOWN = "unknown"

# Device change classes.
CHANGE_UNCHANGED = "unchanged"
CHANGE_REPRESENTATION_ONLY = "representation_only"
CHANGE_COMPONENTS = "components_changed"

# Ticket actions.
ACTION_NO_REVIEW = "no_review"
ACTION_RE_REVIEW = "re_review"
ACTION_REOPEN_ADVISORY = "reopen_advisory_review"
ACTION_HOLD_UNKNOWN = "hold_for_unknown_dependency"


def _text(value):
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return value


def _extract_cpe(value):
    """Extract a CPE string/object from a loose inventory item."""

    if value is None:
        return None
    if isinstance(value, string_types):
        return _text(value).strip()
    if isinstance(value, CPE):
        return value
    if isinstance(value, dict):
        for key in ("cpe23Uri", "cpe", "criteria", "uri", "fs", "wfn"):
            if value.get(key):
                return _extract_cpe(value[key])
        name = value.get("name")
        if name and isinstance(name, string_types) and \
                name.strip().lower().startswith(("cpe:", "wfn:")):
            return name.strip()
        # NVD cpe_name is a list of alternative names.  The first one is the
        # canonical spelling for this match criterion.
        if value.get("cpe_name"):
            names = value["cpe_name"]
            if isinstance(names, (list, tuple)) and names:
                return _extract_cpe(names[0])
        return None
    return None


def _cpe_list(value):
    """Return a flat list of CPE strings/objects from loose input."""

    if value is None:
        return []
    if isinstance(value, string_types) or isinstance(value, CPE):
        item = _extract_cpe(value)
        return [] if item is None else [item]
    if isinstance(value, dict):
        item = _extract_cpe(value)
        if item is not None:
            return [item]
        return []
    if isinstance(value, (list, tuple, set)):
        result = []
        for entry in value:
            result.extend(_cpe_list(entry))
        return result
    return []


def _as_wfn(value):
    """Unbind any CPE representation to a 2.3 WFN."""

    if isinstance(value, CPE2_3_WFN):
        return value
    if isinstance(value, CPE):
        return CPE2_3_WFN(value.as_wfn())
    value = _extract_cpe(value)
    if isinstance(value, CPE):
        return CPE2_3_WFN(value.as_wfn())
    if isinstance(value, string_types):
        value = value.strip()
        if value.startswith("wfn:"):
            return CPE2_3_WFN(value)
        return CPE2_3_WFN(CPE(value).as_wfn())
    raise TypeError("Cannot convert {0!r} to a CPE WFN".format(value))


def _cpe_label(value):
    if isinstance(value, string_types):
        return value
    if isinstance(value, CPE):
        return str(value)
    return str(_extract_cpe(value))


def _device_records(raw, prefix="asset"):
    """Normalise a device inventory into records with stable ids."""

    if raw is None:
        return []

    if isinstance(raw, dict):
        for key in ("devices", "assets", "machines", "inventory",
                    "before", "after"):
            if key in raw:
                return _device_records(raw[key], prefix)

        # Mapping of device id -> CPE list.
        records = []
        for device_id, value in raw.items():
            if isinstance(value, dict) and any(
                    key in value for key in ("before", "after", "cpe", "cpes")):
                record = dict(value)
                record.setdefault("id", device_id)
                records.extend(_device_records([record], prefix))
            else:
                records.append({
                    "id": str(device_id),
                    "label": None,
                    "cpes": _cpe_list(value),
                })
        return records

    if not isinstance(raw, (list, tuple)):
        raw = [raw]

    records = []
    for index, item in enumerate(raw):
        if isinstance(item, dict):
            device_id = (item.get("id") or item.get("device_id") or
                         item.get("host") or item.get("asset") or
                         item.get("machine") or "{0}-{1}".format(prefix, index + 1))
            cpes = []
            for key in ("cpes", "inventory", "installed", "components", "cpe"):
                if key in item and item[key] is not None:
                    cpes = _cpe_list(item[key])
                    break
            record = {
                "id": str(device_id),
                "label": item.get("label") or item.get("description"),
                "cpes": cpes,
            }
            if "before" in item:
                record["before"] = _cpe_list(item["before"])
            if "after" in item:
                record["after"] = _cpe_list(item["after"])
            records.append(record)
        else:
            cpes = _cpe_list(item)
            records.append({
                "id": "{0}-{1}".format(prefix, index + 1),
                "label": None,
                "cpes": cpes,
            })
    return records


def _merge_devices(devices=None, before=None, after=None):
    """Merge combined records and separate before/after inventories by id."""

    combined = _device_records(devices, "asset")
    before_records = _device_records(before, "asset")
    after_records = _device_records(after, "asset")

    ordered = []
    by_id = {}

    def ensure(device_id, label=None):
        if device_id not in by_id:
            record = {
                "id": device_id,
                "label": label,
                "before": [],
                "after": [],
                "has_before": False,
                "has_after": False,
            }
            by_id[device_id] = record
            ordered.append(record)
        elif label and not by_id[device_id].get("label"):
            by_id[device_id]["label"] = label
        return by_id[device_id]

    for record in combined:
        target = ensure(record["id"], record.get("label"))
        if "before" in record or "after" in record:
            if "before" in record:
                target["before"] = record["before"]
                target["has_before"] = True
            if "after" in record:
                target["after"] = record["after"]
                target["has_after"] = True
        elif record.get("cpes"):
            target["before"] = record["cpes"]
            target["after"] = record["cpes"]
            target["has_before"] = True
            target["has_after"] = True

    for record in before_records:
        target = ensure(record["id"], record.get("label"))
        target["before"] = record.get("cpes") or record.get("before") or []
        target["has_before"] = True

    for record in after_records:
        target = ensure(record["id"], record.get("label"))
        target["after"] = record.get("cpes") or record.get("after") or []
        target["has_after"] = True

    # If only one side was supplied, there is no rollback information for the
    # missing side.  Keep the list empty rather than pretending it is unknown
    # inventory content.
    return ordered


def _approved_cpes(raw):
    if isinstance(raw, dict):
        for key in ("approved", "approved_devices", "allowlist", "devices", "cpes"):
            if key in raw:
                return _approved_cpes(raw[key])
        values = []
        for value in raw.values():
            values.extend(_cpe_list(value))
        return values
    return _cpe_list(raw)


def _relation_detail(candidate, inventory, inventory_label=None):
    """Return the tri-state relation of an advisory criterion to an asset."""

    candidate = _as_wfn(candidate)
    inventory = _as_wfn(inventory)

    results = list(CPESet2_3.compare_wfns(candidate, inventory))
    unknown = []
    disjoint = []
    unmatched = []

    for attribute, result in results:
        if result == CPESet2_3.LOGICAL_VALUE_UNDEFINED:
            unknown.append(attribute)
        elif result == CPESet2_3.LOGICAL_VALUE_DISJOINT:
            disjoint.append(attribute)
        elif result == CPESet2_3.LOGICAL_VALUE_SUBSET:
            # The inventory is the known instance.  If it says ANY for an
            # attribute, the installed value is not actually known; a specific
            # advisory criterion cannot be disproved with that inventory.
            source = candidate.get_attribute_values(attribute)[0]
            target = inventory.get_attribute_values(attribute)[0]
            if source.startswith('"'):
                source = source[1:-1]
            if target.startswith('"'):
                target = target[1:-1]
            if target == "ANY" and source != "ANY":
                unknown.append(attribute)
            else:
                unmatched.append(attribute)
        elif result not in (CPESet2_3.LOGICAL_VALUE_SUPERSET,
                            CPESet2_3.LOGICAL_VALUE_EQUAL):
            unmatched.append(attribute)

    if disjoint or unmatched:
        status = STATUS_NOT_MATCHED
        relation = "disjoint" if disjoint else "subset"
    elif unknown:
        status = STATUS_UNKNOWN
        relation = "undefined"
    else:
        status = STATUS_MATCHED
        relation = "superset_or_equal"

    return {
        "status": status,
        "relation": relation,
        "unknown_attributes": unknown,
        "disjoint_attributes": disjoint,
        "unmatched_attributes": unmatched,
        "candidate": str(candidate),
        "inventory": inventory_label if inventory_label is not None else str(inventory),
        "inventory_wfn": str(inventory),
    }


def _as_cpe22(value):
    if isinstance(value, CPE2_2):
        return value
    if isinstance(value, CPE) and value.VERSION == CPE.VERSION_2_2:
        return value
    if isinstance(value, CPE):
        # CPE 2.2 is a URI binding.  Re-parse through its URI spelling when
        # possible; otherwise the caller should provide a 2.2 name directly.
        value = value.as_uri_2_3()
    return CPE2_2(_text(value).strip())


def _match_name_candidate(candidate, inventory_cpes, version="2.3"):
    """Evaluate a name advisory with CPE_Name_Match."""

    candidate = _extract_cpe(candidate)
    inventory_cpes = _cpe_list(inventory_cpes)

    entry_match = None
    if str(version).startswith("2.2"):
        try:
            name_set = CPESet2_2()
            for inventory in inventory_cpes:
                name_set.append(_as_cpe22(inventory))
            entry_match = name_set.name_match(_as_cpe22(candidate))
        except Exception:
            entry_match = None
    else:
        name_set = CPESet2_3()
        for inventory in inventory_cpes:
            name_set.append(_as_wfn(inventory))
        entry_match = name_set.name_match(_as_wfn(candidate))

    details = [_relation_detail(candidate, inventory,
                                inventory_label=_cpe_label(inventory))
               for inventory in inventory_cpes]
    matched_inventory = [detail["inventory"] for detail in details
                         if detail["status"] == STATUS_MATCHED]
    unknown_inventory = [detail["inventory"] for detail in details
                         if detail["status"] == STATUS_UNKNOWN]
    unknown_attributes = []
    for detail in details:
        for attribute in detail["unknown_attributes"]:
            if attribute not in unknown_attributes:
                unknown_attributes.append(attribute)

    if any(detail["status"] == STATUS_MATCHED for detail in details):
        status = STATUS_MATCHED
    elif any(detail["status"] == STATUS_UNKNOWN for detail in details):
        status = STATUS_UNKNOWN
    else:
        status = STATUS_NOT_MATCHED

    # The actual entry point is authoritative for a definite answer.  The
    # detail traversal is only allowed to surface an undefined result that the
    # boolean algorithm cannot express.
    if entry_match is True:
        status = STATUS_MATCHED
    elif entry_match is False and status == STATUS_UNKNOWN:
        status = STATUS_UNKNOWN

    return {
        "status": status,
        "entry_match": entry_match,
        "matched_inventory": matched_inventory,
        "unknown_inventory": unknown_inventory,
        "unknown_attributes": unknown_attributes,
        "details": details,
    }


def _tag(node):
    name = node.nodeName or ""
    if ":" in name:
        name = name.split(":", 1)[1]
    return name.lower()


def _element_children(node):
    return [child for child in node.childNodes
            if child.nodeType == Node.ELEMENT_NODE]


class _Eval(object):
    """Tri-state evaluation result with branch provenance."""

    def __init__(self, status, branches=None, unknown=None, leaves=None,
                 note=None):
        self.status = status
        self.branches = branches or []
        self.unknown = unknown or []
        self.leaves = leaves or []
        self.note = note


def _invert(status):
    if status == STATUS_MATCHED:
        return STATUS_NOT_MATCHED
    if status == STATUS_NOT_MATCHED:
        return STATUS_MATCHED
    return STATUS_UNKNOWN


def _combine(operator, results):
    operator = (operator or "AND").upper()
    statuses = [result.status for result in results]

    if operator == "OR":
        if STATUS_MATCHED in statuses:
            status = STATUS_MATCHED
        elif STATUS_UNKNOWN in statuses:
            status = STATUS_UNKNOWN
        else:
            status = STATUS_NOT_MATCHED
    elif operator == "AND":
        if STATUS_NOT_MATCHED in statuses:
            status = STATUS_NOT_MATCHED
        elif STATUS_UNKNOWN in statuses:
            status = STATUS_UNKNOWN
        else:
            status = STATUS_MATCHED
    else:
        status = STATUS_UNKNOWN

    branches = []
    unknown = []
    leaves = []
    for result in results:
        unknown.extend(result.unknown)
        leaves.extend(result.leaves)
        if result.status == STATUS_MATCHED:
            branches.extend(result.branches)

    if status == STATUS_NOT_MATCHED:
        branches = []

    return _Eval(status, branches=branches, unknown=unknown, leaves=leaves)


def _bool_attribute(element, name):
    if not element.hasAttribute(name):
        return None
    value = (element.getAttribute(name) or "").strip().lower()
    if value in ("true", "1", "yes"):
        return True
    if value in ("false", "0", "no"):
        return False
    return None


def _eval_element(element, inventory_cpes, path="platform", version="2.3"):
    tag = _tag(element)

    if tag == "platform-specification":
        platforms = [child for child in _element_children(element)
                     if _tag(child) == "platform"]
        if not platforms:
            return _Eval(STATUS_UNKNOWN, unknown=[{
                "path": path,
                "reason": "platform-specification contains no platform",
            }])
        return _eval_element(platforms[0], inventory_cpes,
                             path + "/platform[0]", version)

    if tag == "platform":
        tests = [child for child in _element_children(element)
                 if _tag(child) == "logical-test"]
        if not tests:
            return _Eval(STATUS_UNKNOWN, unknown=[{
                "path": path,
                "reason": "platform contains no logical-test",
            }])
        return _eval_element(tests[0], inventory_cpes,
                             path + "/logical-test[0]", version)

    if tag == "logical-test":
        children = _element_children(element)
        results = []
        for index, child in enumerate(children):
            child_path = "{0}/{1}[{2}]".format(path, _tag(child), index)
            results.append(_eval_element(child, inventory_cpes,
                                         child_path, version))

        operator = (element.getAttribute("operator") or "AND").upper()
        result = _combine(operator, results)
        negated = _bool_attribute(element, "negate") is True
        if negated:
            result.status = _invert(result.status)
            if result.status == STATUS_MATCHED:
                result.branches = [{
                    "path": path,
                    "operator": operator,
                    "negated": True,
                    "reason": "satisfied through a negated logical-test",
                }]
            elif result.status == STATUS_NOT_MATCHED:
                result.branches = []
        result.branches = [dict(branch, operator=operator) for branch in result.branches]
        return result

    if tag in ("fact-ref", "check-fact-ref"):
        if tag == "check-fact-ref":
            return _Eval(STATUS_UNKNOWN, unknown=[{
                "path": path,
                "cpe": None,
                "reason": "external check-fact-ref cannot be evaluated locally",
            }])

        cpe_name = (element.getAttribute("name") or
                    element.getAttribute("cpe23Uri") or
                    element.getAttribute("cpe") or "").strip()
        range_attributes = [attribute for attribute in (
            "versionStartIncluding", "versionStartExcluding",
            "versionEndIncluding", "versionEndExcluding")
            if element.hasAttribute(attribute)]
        vulnerable = _bool_attribute(element, "vulnerable")
        if not cpe_name:
            return _Eval(STATUS_UNKNOWN, unknown=[{
                "path": path,
                "cpe": None,
                "reason": "fact-ref has no CPE name",
            }])

        detail = _match_name_candidate(cpe_name, inventory_cpes, version)
        leaf = {
            "path": path,
            "cpe": cpe_name,
            "vulnerable": vulnerable,
            "status": detail["status"],
        }

        if detail["status"] == STATUS_MATCHED and not range_attributes:
            branch = {
                "path": path,
                "cpe": cpe_name,
                "vulnerable": vulnerable,
                "matched_inventory": detail["matched_inventory"],
            }
            return _Eval(STATUS_MATCHED, branches=[branch], leaves=[leaf])

        if detail["status"] == STATUS_UNKNOWN or range_attributes:
            attributes = list(detail["unknown_attributes"])
            for attribute in range_attributes:
                if attribute not in attributes:
                    attributes.append(attribute)
            unknown = {
                "path": path,
                "cpe": cpe_name,
                "attributes": attributes,
                "inventory": detail["unknown_inventory"],
                "reason": ("NVD version range cannot be decided by exact CPE "
                           "name matching" if range_attributes else
                           "installed CPE contains wildcard values; match is undefined"),
            }
            return _Eval(STATUS_UNKNOWN, unknown=[unknown], leaves=[leaf])

        return _Eval(STATUS_NOT_MATCHED, leaves=[leaf])

    return _Eval(STATUS_UNKNOWN, unknown=[{
        "path": path,
        "reason": "unsupported CPE language element: {0}".format(tag),
    }])


def _json_node_element(document, node):
    element = document.createElement("cpe:logical-test")
    element.setAttribute("operator", (node.get("operator") or "OR").upper())
    element.setAttribute("negate", "TRUE" if node.get("negate") else "FALSE")

    for child in node.get("children") or []:
        element.appendChild(_json_node_element(document, child))

    matches = node.get("cpe_match") or node.get("cpeMatch") or []
    if matches:
        for match in matches:
            fact_ref = document.createElement("cpe:fact-ref")
            cpe_name = _extract_cpe(match)
            if cpe_name is None:
                continue
            fact_ref.setAttribute("name", _cpe_label(cpe_name))
            if "vulnerable" in match:
                vulnerable = match.get("vulnerable")
                if isinstance(vulnerable, string_types):
                    vulnerable = vulnerable.strip().lower() in (
                        "true", "1", "yes")
                fact_ref.setAttribute("vulnerable",
                                      "true" if vulnerable else "false")
            if match.get("matchCriteriaId"):
                fact_ref.setAttribute("matchCriteriaId",
                                      str(match["matchCriteriaId"]))
            for attribute in ("versionStartIncluding", "versionStartExcluding",
                              "versionEndIncluding", "versionEndExcluding"):
                if match.get(attribute) is not None:
                    fact_ref.setAttribute(attribute, str(match[attribute]))
            element.appendChild(fact_ref)
    elif _extract_cpe(node) is not None and not node.get("children"):
        fact_ref = document.createElement("cpe:fact-ref")
        fact_ref.setAttribute("name", _cpe_label(_extract_cpe(node)))
        element.appendChild(fact_ref)

    return element


def _json_to_xml(value):
    """Convert NVD-style nodes to a CPE language specification."""

    if isinstance(value, dict) and "configurations" in value:
        nodes = []
        for configuration in value["configurations"] or []:
            nodes.extend(configuration.get("nodes") or [])
    elif isinstance(value, dict) and "nodes" in value:
        nodes = value["nodes"] or []
    elif isinstance(value, dict) and any(
            key in value for key in ("operator", "children", "cpe_match")):
        nodes = [value]
    elif isinstance(value, list):
        nodes = value
    elif isinstance(value, string_types):
        nodes = json.loads(value)
        return _json_to_xml(nodes)
    else:
        raise ValueError("Unsupported JSON advisory: {0!r}".format(value))

    document = getDOMImplementation().createDocument(
        "http://cpe.mitre.org/language/2.0", "cpe:platform-specification", None)
    document.documentElement.setAttribute(
        "xmlns:cpe", "http://cpe.mitre.org/language/2.0")
    platform = document.createElement("cpe:platform")
    document.documentElement.appendChild(platform)
    root = document.createElement("cpe:logical-test")
    root.setAttribute("operator", "OR")
    root.setAttribute("negate", "FALSE")
    platform.appendChild(root)

    for node in nodes:
        root.appendChild(_json_node_element(document, node))

    return document.toxml()


def _normalise_advisory(item, index):
    if isinstance(item, string_types):
        text = _text(item).strip()
        if text.startswith("\ufeff"):
            text = text[1:].strip()
        if text.startswith("<"):
            return {
                "id": "ADV-{0}".format(index + 1),
                "entry_point": "language",
                "expression": text,
            }
        if text.startswith("[") or text.startswith("{"):
            return {
                "id": "ADV-{0}".format(index + 1),
                "entry_point": "language",
                "expression": json.loads(text),
                "is_json": True,
            }
        return {
            "id": "ADV-{0}".format(index + 1),
            "entry_point": "name",
            "cpe": text,
        }

    if not isinstance(item, dict):
        raise ValueError("Invalid advisory: {0!r}".format(item))

    advisory = dict(item)
    advisory.setdefault("id", "ADV-{0}".format(index + 1))
    advisory.setdefault("title", item.get("description") or item.get("title"))
    advisory.setdefault("version", str(item.get("cpe_version") or "2.3"))

    kind = (item.get("type") or item.get("entry_point") or
            item.get("kind") or "").strip().lower()
    if kind in ("name", "cpe", "name_match", "name-match"):
        advisory["entry_point"] = "name"
    elif kind in ("language", "lang", "platform", "xml", "json", "nvd"):
        advisory["entry_point"] = "language"
    else:
        if ("expression" in item or "xml" in item or "platform" in item or
                "json" in item or "nodes" in item or "configurations" in item or
                ("cpe_match" in item and "cpe" not in item)):
            advisory["entry_point"] = "language"
        else:
            advisory["entry_point"] = "name"

    if advisory["entry_point"] == "name":
        advisory["cpe"] = _extract_cpe(item) or item.get("cpe")
        if advisory["cpe"] is None:
            raise ValueError("Name advisory {0} has no CPE".format(advisory["id"]))
    else:
        expression = item.get("expression")
        if expression is None:
            expression = item.get("xml")
        if expression is None:
            expression = item.get("platform")
        if expression is None:
            expression = item.get("json")
        if expression is None and ("nodes" in item or "configurations" in item or
                                   "cpe_match" in item):
            expression = item
        if expression is None:
            raise ValueError("Language advisory {0} has no expression".format(
                advisory["id"]))
        advisory["expression"] = expression

        if isinstance(expression, string_types):
            text = _text(expression).strip()
            if text.startswith("\ufeff"):
                text = text[1:].strip()
            if text.startswith("[") or text.startswith("{"):
                advisory["expression"] = json.loads(text)
                advisory["is_json"] = True
            elif text.startswith("<"):
                advisory["is_json"] = False
            else:
                # Best effort: an unadorned JSON fragment is common in tests.
                advisory["expression"] = json.loads(text)
                advisory["is_json"] = True
        else:
            advisory["is_json"] = True

    return advisory


def _normalise_advisories(raw):
    if raw is None:
        return []
    if isinstance(raw, dict) and "advisories" in raw:
        raw = raw["advisories"]
    if isinstance(raw, dict) and "announcements" in raw:
        raw = raw["announcements"]
    if isinstance(raw, dict):
        if any(key in raw for key in (
                "id", "type", "entry_point", "kind", "cpe", "expression",
                "xml", "nodes", "configurations", "cpe_match", "operator")):
            raw = [raw]
        else:
            items = []
            for advisory_id, value in raw.items():
                if isinstance(value, dict):
                    record = dict(value)
                    record.setdefault("id", advisory_id)
                elif isinstance(value, string_types):
                    text = _text(value).strip()
                    if text.startswith("\ufeff"):
                        text = text[1:].strip()
                    if text.startswith("<") or text.startswith("[") or text.startswith("{"):
                        record = {"id": advisory_id, "expression": value}
                    else:
                        record = {"id": advisory_id, "cpe": value}
                else:
                    record = {"id": advisory_id, "expression": value}
                items.append(record)
            raw = items
    return [_normalise_advisory(item, index) for index, item in enumerate(raw)]


def _prepare_language_advisory(advisory):
    expression = advisory["expression"]
    is_json = advisory.get("is_json") or isinstance(expression, (list, dict))

    if is_json:
        xml = _json_to_xml(expression)
    elif isinstance(expression, string_types):
        xml = _text(expression)
    else:
        xml = str(expression)

    if xml.startswith("\ufeff"):
        xml = xml[1:]
    document = minidom.parseString(xml.encode("utf-8"))
    return xml, document


def _language_entry_match(advisory, inventory_cpes, xml, document):
    version = str(advisory.get("version") or "2.3")
    try:
        if version.startswith("2.2"):
            name_set = CPESet2_2()
            for inventory in inventory_cpes:
                name_set.append(_as_cpe22(inventory))
            return CPELanguage2_2(xml).language_match(name_set)

        name_set = CPESet2_3()
        for inventory in inventory_cpes:
            name_set.append(_as_wfn(inventory))
        return CPELanguage2_3(xml).language_match(name_set)
    except Exception:
        return None


def _eval_advisory(advisory, inventory_cpes):
    """Evaluate one advisory against one device inventory."""

    version = str(advisory.get("version") or "2.3")
    entry_point = advisory["entry_point"]

    if entry_point == "name":
        detail = _match_name_candidate(advisory["cpe"], inventory_cpes, version)
        branches = []
        if detail["status"] == STATUS_MATCHED:
            branches = [{
                "path": "advisory/cpe",
                "cpe": _cpe_label(advisory["cpe"]),
                "vulnerable": True,
                "matched_inventory": detail["matched_inventory"],
            }]
        unknown = []
        if detail["status"] == STATUS_UNKNOWN:
            unknown = [{
                "path": "advisory/cpe",
                "cpe": _cpe_label(advisory["cpe"]),
                "attributes": detail["unknown_attributes"],
                "inventory": detail["unknown_inventory"],
                "reason": "installed CPE contains wildcard values; match is undefined",
            }]
        leaves = [{
            "path": "advisory/cpe",
            "cpe": _cpe_label(advisory["cpe"]),
            "vulnerable": True,
            "status": detail["status"],
        }]
        evaluation = _Eval(detail["status"], branches=branches,
                           unknown=unknown, leaves=leaves)
        entry_match = detail["entry_match"]
        xml = None
    else:
        xml, document = _prepare_language_advisory(advisory)
        evaluation = _eval_element(document.documentElement, inventory_cpes,
                                   "platform", version)
        entry_match = _language_entry_match(advisory, inventory_cpes, xml, document)

    has_vulnerable_flags = any(leaf.get("vulnerable") is not None
                               for leaf in evaluation.leaves)

    vulnerable_matched = None
    if evaluation.status == STATUS_NOT_MATCHED:
        vulnerable_matched = False
    elif evaluation.status == STATUS_UNKNOWN:
        vulnerable_matched = None
    elif not has_vulnerable_flags:
        # A plain CPE language expression has no role metadata.  Every
        # satisfied fact-ref is an applicability condition.
        vulnerable_matched = True
    else:
        matched_leaves = [leaf for leaf in evaluation.leaves
                          if leaf["status"] == STATUS_MATCHED]
        if any(leaf.get("vulnerable") is True for leaf in matched_leaves):
            vulnerable_matched = True
        elif any(leaf.get("vulnerable") is None for leaf in matched_leaves):
            vulnerable_matched = None
        elif evaluation.status == STATUS_MATCHED and not matched_leaves:
            # A negated logical-test can be satisfied without a positive
            # fact-ref match.
            vulnerable_matched = True
        else:
            vulnerable_matched = False

    branches = list(evaluation.branches)
    if has_vulnerable_flags and vulnerable_matched is True:
        branches = [branch for branch in branches
                    if branch.get("vulnerable") is True]

    unknown = list(evaluation.unknown)
    if vulnerable_matched is None and evaluation.status == STATUS_MATCHED:
        unknown.append({
            "path": "advisory/role",
            "cpe": None,
            "attributes": ["vulnerable"],
            "inventory": [],
            "reason": "matched fact-ref has no known vulnerable role",
        })

    return {
        "status": evaluation.status,
        "vulnerable_matched": vulnerable_matched,
        "has_vulnerable_flags": has_vulnerable_flags,
        "entry_match": entry_match,
        "branches": branches,
        "unknown": unknown,
        "leaves": evaluation.leaves,
        "xml": xml,
    }


def _same_inventory(before, after):
    """Semantic inventory equality across CPE representations."""

    if len(before) != len(after):
        return False
    remaining = list(after)
    for left in before:
        found = None
        for index, right in enumerate(remaining):
            try:
                left_wfn = _as_wfn(left)
                right_wfn = _as_wfn(right)
                if (left_wfn._str == right_wfn._str or
                        CPESet2_3.cpe_equal(left_wfn, right_wfn)):
                    found = index
                    break
            except Exception:
                continue
        if found is None:
            return False
        del remaining[found]
    return True


def _changed_attributes(before, after):
    changes = []

    def compare_pair(left, right):
        try:
            left_wfn = _as_wfn(left)
            right_wfn = _as_wfn(right)
        except Exception:
            return False
        same_product = all(
            CPESet2_3._compare(left_wfn.get_attribute_values(att)[0],
                               right_wfn.get_attribute_values(att)[0]) ==
            CPESet2_3.LOGICAL_VALUE_EQUAL
            for att in ("part", "vendor", "product"))
        if not same_product:
            return False
        for attribute, result in CPESet2_3.compare_wfns(left_wfn, right_wfn):
            if (result != CPESet2_3.LOGICAL_VALUE_EQUAL and
                    attribute not in changes):
                changes.append(attribute)
        return True

    paired_after = set()
    for left in before:
        for index, right in enumerate(after):
            if index in paired_after:
                continue
            if compare_pair(left, right):
                paired_after.add(index)
                break

    if (len(before) != len(after) or
            (before and len(paired_after) != len(after)) or
            (after and len(paired_after) != len(before))):
        if "inventory" not in changes:
            changes.append("inventory")

    return changes or ["inventory"]


def _raw_same(before, after):
    return [_cpe_label(item) for item in before] == [_cpe_label(item) for item in after]


def _approval_relation(cpe, approved_names):
    """Compare an installed CPE with the pre-approved filters."""

    try:
        installed = _as_wfn(cpe)
    except Exception:
        return "unknown"

    unknown = False
    for approved_name in approved_names:
        try:
            approved = _as_wfn(approved_name)
        except Exception:
            unknown = True
            continue
        if (CPESet2_3.cpe_superset(approved, installed) or
                CPESet2_3.cpe_equal(approved, installed)):
            return "approved"
        if CPESet2_3.cpe_superset(installed, approved):
            # The installed name is broader than the approval entry; it may
            # cover other versions too, so it is not automatically approved.
            unknown = True
    return "unknown" if unknown else "not_approved"


def _classify_device(device, approved_names):
    before = device["before"]
    after = device["after"]

    semantic_same = _same_inventory(before, after)
    raw_same = _raw_same(before, after)
    if raw_same:
        change = CHANGE_UNCHANGED
    elif semantic_same:
        change = CHANGE_REPRESENTATION_ONLY
    else:
        change = CHANGE_COMPONENTS

    if before:
        before_relations = [_approval_relation(cpe, approved_names) for cpe in before]
        if "approved" in before_relations:
            approval_before = "approved"
        elif "unknown" in before_relations:
            approval_before = "unknown"
        else:
            approval_before = "not_approved"
    else:
        approval_before = "not_approved"

    if after:
        after_relations = [_approval_relation(cpe, approved_names) for cpe in after]
        if "approved" in after_relations:
            approval_after = "approved"
        elif "unknown" in after_relations:
            approval_after = "unknown"
        else:
            approval_after = "not_approved"
    else:
        approval_after = "not_approved"

    approved_before = approval_before == "approved"
    approved_after = approval_after == "approved"

    if change in (CHANGE_UNCHANGED, CHANGE_REPRESENTATION_ONLY):
        recommendation = ACTION_NO_REVIEW
        reason = ("CPE names are semantically identical after normalisation; "
                  "only the binding/representation changed")
    else:
        recommendation = ACTION_RE_REVIEW
        if approval_after == "unknown":
            reason = "installed components changed; approval cannot be decided from the pre-approved list"
        elif not approved_after:
            reason = "installed components changed and the result is not covered by the pre-approved list"
        else:
            reason = "installed components changed from the pre-approved baseline"

    return {
        "id": device["id"],
        "label": device.get("label"),
        "before": [_cpe_label(item) for item in before],
        "after": [_cpe_label(item) for item in after],
        "change": change,
        "changed_attributes": _changed_attributes(before, after) if change == CHANGE_COMPONENTS else [],
        "approved_before": approved_before,
        "approved_after": approved_after,
        "approval_before": approval_before,
        "approval_after": approval_after,
        "approved": approved_after,
        "approval_lost": bool(approved_before and not approved_after),
        "changed": change != CHANGE_UNCHANGED,
        "recommendation": recommendation,
        "reason": reason,
    }


def _approved_report(approved_names, device_records):
    report = []
    for approved_name in approved_names:
        before_ids = []
        after_ids = []
        for device in device_records:
            if any(_approval_relation(cpe, [approved_name]) == "approved"
                   for cpe in device["before"]):
                before_ids.append(device["id"])
            if any(_approval_relation(cpe, [approved_name]) == "approved"
                   for cpe in device["after"]):
                after_ids.append(device["id"])
        report.append({
            "cpe": _cpe_label(approved_name),
            "matched_before": before_ids,
            "matched_after": after_ids,
            "missing_after": [device_id for device_id in before_ids
                              if device_id not in after_ids],
        })
    return report


def _dedupe_unknown(entries):
    result = []
    seen = set()
    for entry in entries:
        key = (entry.get("stage"), entry.get("path"), entry.get("cpe"),
               tuple(entry.get("attributes") or []))
        if key in seen:
            continue
        seen.add(key)
        result.append(entry)
    return result


def _advisory_report(advisory, devices):
    reentered = []
    unknown_dependencies = []
    branch_sources = {}
    device_status = {}

    for device in devices:
        before = _eval_advisory(advisory, device["before"])
        after = _eval_advisory(advisory, device["after"])

        before_active = before["vulnerable_matched"] is True
        after_active = after["vulnerable_matched"] is True
        dependency_only = (after["status"] == STATUS_MATCHED and not after_active)

        device_status[device["id"]] = {
            "before": before["status"],
            "after": after["status"],
            "before_vulnerable_matched": before["vulnerable_matched"],
            "after_vulnerable_matched": after["vulnerable_matched"],
            "dependency_only_after": dependency_only,
        }

        if after_active and not before_active:
            reentered.append({
                "device_id": device["id"],
                "device": device["id"],
                "before": before["status"],
                "after": after["status"],
                "before_unknown": before["status"] == STATUS_UNKNOWN,
                "branch_sources": after["branches"],
                "branches": after["branches"],
            })

        if after["branches"]:
            branch_sources[device["id"]] = after["branches"]

        blocking_after = (after["status"] == STATUS_UNKNOWN or
                          after["vulnerable_matched"] is None)
        for stage, evaluation in (("before", before), ("after", after)):
            for entry in evaluation["unknown"]:
                item = dict(entry)
                item["stage"] = stage
                item["device_id"] = device["id"]
                item["unknown_attributes"] = list(item.get("attributes") or [])
                item["blocking"] = bool(stage == "after" and blocking_after)
                unknown_dependencies.append(item)

    report = {
        "id": advisory["id"],
        "title": advisory.get("title"),
        "entry_point": advisory["entry_point"],
        "version": advisory.get("version") or "2.3",
        "reentered_devices": reentered,
        "unknown_dependencies": _dedupe_unknown(unknown_dependencies),
        "branch_sources": branch_sources,
        "devices": device_status,
    }
    report["reentered"] = report["reentered_devices"]
    report["reentered_device_ids"] = [entry["device_id"]
                                      for entry in report["reentered_devices"]]
    report["unknown"] = report["unknown_dependencies"]
    report["branches"] = report["branch_sources"]
    return report


def _tickets(device_reports, advisory_reports):
    tickets = []

    for device in device_reports:
        tickets.append({
            "device_id": device["id"],
            "advisory_id": None,
            "action": device["recommendation"],
            "review_required": device["recommendation"] != ACTION_NO_REVIEW,
            "reason": device["reason"],
            "branch_sources": [],
            "unknown_dependencies": [],
        })

    for advisory in advisory_reports:
        for entry in advisory["reentered_devices"]:
            tickets.append({
                "device_id": entry["device_id"],
                "advisory_id": advisory["id"],
                "action": ACTION_REOPEN_ADVISORY,
                "review_required": True,
                "reason": "advisory condition is re-established after rollback",
                "branch_sources": entry["branch_sources"],
                "unknown_dependencies": [],
            })

        for unknown in advisory["unknown_dependencies"]:
            if not unknown.get("blocking"):
                continue
            tickets.append({
                "device_id": unknown["device_id"],
                "advisory_id": advisory["id"],
                "action": ACTION_HOLD_UNKNOWN,
                "review_required": True,
                "reason": unknown.get("reason"),
                "branch_sources": [],
                "unknown_dependencies": [unknown],
            })

    return tickets


def analyze(data=None, approved=None, before=None, after=None,
            advisories=None, devices=None, **kwargs):
    """Build a rollback-review report.

    :param dict data: optional scenario dictionary.  Recognised keys include
        ``approved``, ``before``, ``after``, ``devices`` and ``advisories``.
    :param approved: pre-approved CPE names (allowlist).
    :param before: inventory before rollback.
    :param after: inventory after rollback.
    :param advisories: name or language advisory expressions.
    :param devices: combined device records with optional before/after fields.
    :returns: JSON-serialisable report dictionary.
    """

    if approved is None:
        approved = (kwargs.pop("approved_devices", None) or
                    kwargs.pop("allowlist", None))
    if before is None:
        before = (kwargs.pop("before_inventory", None) or
                  kwargs.pop("inventory_before", None))
    if after is None:
        after = (kwargs.pop("after_inventory", None) or
                 kwargs.pop("inventory_after", None))
    if advisories is None:
        advisories = kwargs.pop("announcements", None)

    if data:
        if approved is None:
            approved = (data.get("approved") or data.get("approved_devices") or
                        data.get("allowlist"))
        if before is None:
            before = data.get("before") or data.get("before_inventory")
        if after is None:
            after = data.get("after") or data.get("after_inventory")
        if advisories is None:
            advisories = (data.get("advisories") or data.get("announcements"))
        if devices is None:
            devices = data.get("devices") or data.get("assets")

    device_records = _merge_devices(devices=devices, before=before, after=after)
    approved_names = _approved_cpes(approved)

    advisory_records = _normalise_advisories(advisories)

    device_reports = [_classify_device(device, approved_names)
                      for device in device_records]
    advisory_reports = [_advisory_report(advisory, device_records)
                        for advisory in advisory_records]
    tickets = _tickets(device_reports, advisory_reports)
    approved_report = _approved_report(approved_names, device_records)

    summary = {
        "devices": len(device_reports),
        "unchanged": sum(1 for device in device_reports
                         if device["change"] == CHANGE_UNCHANGED),
        "representation_only": sum(1 for device in device_reports
                                   if device["change"] == CHANGE_REPRESENTATION_ONLY),
        "components_changed": sum(1 for device in device_reports
                                  if device["change"] == CHANGE_COMPONENTS),
        "approval_lost": sum(1 for device in device_reports
                             if device["approval_lost"]),
        "approved_missing_after": sum(len(entry["missing_after"])
                                      for entry in approved_report),
        "advisories": len(advisory_reports),
        "reentered_pairs": sum(len(advisory["reentered_devices"])
                               for advisory in advisory_reports),
        "unknown_dependencies": sum(
            len(advisory["unknown_dependencies"]) for advisory in advisory_reports),
        "tickets": len(tickets),
    }

    return {
        "summary": summary,
        "approved_devices": approved_report,
        "devices": device_reports,
        "advisories": advisory_reports,
        "tickets": tickets,
        "ticket_suggestions": tickets,
    }


# Intuitive aliases for callers that describe the operation rather than the
# report.
review_rollback = analyze
analyze_inventory = analyze
build_report = analyze
reconcile = analyze


def _load_json(path):
    with open(path, "r") as stream:
        return json.load(stream)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Reconcile approved devices and before/after inventories "
                    "against CPE name and language advisories.")
    parser.add_argument("--input", "-i", help="scenario JSON file")
    parser.add_argument("--approved", help="pre-approved CPE JSON file")
    parser.add_argument("--before", help="inventory-before JSON file")
    parser.add_argument("--after", help="inventory-after JSON file")
    parser.add_argument("--advisories", help="advisory expression JSON file")
    parser.add_argument("--devices", help="combined device JSON file")
    parser.add_argument("--output", "-o", help="write report JSON to this path")
    parser.add_argument("--indent", type=int, default=2,
                        help="JSON indentation (default: 2)")
    args = parser.parse_args(argv)

    data = _load_json(args.input) if args.input else None
    report = analyze(
        data=data,
        approved=_load_json(args.approved) if args.approved else None,
        before=_load_json(args.before) if args.before else None,
        after=_load_json(args.after) if args.after else None,
        advisories=_load_json(args.advisories) if args.advisories else None,
        devices=_load_json(args.devices) if args.devices else None,
    )

    output = json.dumps(report, indent=args.indent, ensure_ascii=False)
    if args.output:
        with open(args.output, "w") as stream:
            stream.write(output)
            stream.write("\n")
    else:
        sys.stdout.write(output)
        sys.stdout.write("\n")
    return report


if __name__ == "__main__":
    main()
