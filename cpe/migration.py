#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""
Device exemption migration preview built on CPE 2.3 set matching.

CPE names describe product classes, not individual devices.  This module keeps
that distinction explicit:

* a device rule can only approve the asset IDs listed on the rule;
* a product rule may approve any matching device in the new inventories;
* a device approval may move to another asset only through an explicit
  inheritance edge whose evidence is present.

The command line interface accepts a JSON document containing ``rules``,
``inheritances`` and one or more ``inventories``.
"""

from __future__ import print_function, unicode_literals

import argparse
import io
import json
import sys

from .cpe import CPE
from .cpe2_3_wfn import CPE2_3_WFN
from .cpeset2_3 import CPESet2_3


try:
    string_types = (basestring,)
except NameError:
    string_types = (str,)


BASIS_DEVICE = "device"
BASIS_PRODUCT = "product"

DECISION_APPROVED_DEVICE = "approved_device"
DECISION_APPROVED_INHERITANCE = "approved_inheritance"
DECISION_APPROVED_PRODUCT = "approved_product_scope"
DECISION_PENDING = "pending_review"

REASON_APPROVED_DEVICE = "device_id_explicitly_approved"
REASON_APPROVED_INHERITANCE = "inherited_with_evidence"
REASON_APPROVED_PRODUCT = "product_scope_match"
REASON_CPE_MATCH_WITHOUT_DEVICE_APPROVAL = "cpe_match_without_device_approval"
REASON_INHERITANCE_EVIDENCE_MISSING = "inheritance_evidence_missing"
REASON_INHERITANCE_PARENT_NOT_APPROVED = "inheritance_parent_not_approved"
REASON_INHERITANCE_CPE_MISMATCH = "inheritance_cpe_mismatch"
REASON_INHERITANCE_CYCLE = "inheritance_cycle"
REASON_DEVICE_APPROVAL_CPE_MISMATCH = "device_approval_cpe_mismatch"
REASON_NO_APPROVAL = "no_device_or_product_approval"


class MigrationInputError(ValueError):
    """Raised when a migration preview input document is inconsistent."""


def _mapping(value, label):
    if not isinstance(value, dict):
        raise MigrationInputError("{0} must be an object".format(label))
    return value


def _required_text(mapping, key, label):
    value = mapping.get(key)
    if not isinstance(value, string_types):
        raise MigrationInputError("{0}.{1} must be a string".format(label, key))
    value = value.strip()
    if not value:
        raise MigrationInputError("{0}.{1} must not be empty".format(label, key))
    return value


def _optional_text(mapping, key, label):
    value = mapping.get(key, "")
    if value is None:
        return ""
    if not isinstance(value, string_types):
        raise MigrationInputError("{0}.{1} must be a string".format(label, key))
    return value.strip()


def _text_list(mapping, key, label, required=False):
    value = mapping.get(key, [])
    if isinstance(value, string_types):
        value = [value]
    if not isinstance(value, list):
        raise MigrationInputError("{0}.{1} must be a list".format(label, key))

    result = []
    for index, item in enumerate(value):
        if not isinstance(item, string_types):
            raise MigrationInputError(
                "{0}.{1}[{2}] must be a string".format(label, key, index))
        item = item.strip()
        if not item:
            raise MigrationInputError(
                "{0}.{1}[{2}] must not be empty".format(label, key, index))
        if item not in result:
            result.append(item)

    if required and not result:
        raise MigrationInputError(
            "{0}.{1} must contain at least one item".format(label, key))
    return result


def _parse_cpe(cpe_string, label):
    try:
        cpe = CPE(cpe_string)
    except (NotImplementedError, ValueError) as exc:
        raise MigrationInputError(
            "{0} is not a valid CPE name: {1}".format(label, exc))

    if cpe.VERSION != CPE.VERSION_2_3:
        raise MigrationInputError(
            "{0} must use CPE 2.3, got version {1}".format(label, cpe.VERSION))
    return CPE2_3_WFN(cpe.as_wfn())


class ApprovalRule(object):
    """An original exemption rule and the basis on which it was granted."""

    def __init__(self, rule_id, basis, cpe_strings, device_ids=None,
                 description=""):
        if basis not in (BASIS_DEVICE, BASIS_PRODUCT):
            raise MigrationInputError(
                "rule {0} has unsupported basis {1}".format(rule_id, basis))

        self.id = rule_id
        self.basis = basis
        self.cpe_strings = list(cpe_strings)
        self.device_ids = list(device_ids or [])
        self.description = description
        self._wfns = [
            _parse_cpe(cpe_string, "rule {0} CPE".format(rule_id))
            for cpe_string in self.cpe_strings
        ]

        if basis == BASIS_DEVICE and not self.device_ids:
            raise MigrationInputError(
                "device rule {0} must list device_ids".format(rule_id))

    @classmethod
    def from_dict(cls, value, index):
        label = "rules[{0}]".format(index)
        value = _mapping(value, label)
        rule_id = _required_text(value, "id", label)
        basis = _required_text(value, "basis", label)
        cpe_strings = _text_list(value, "cpes", label, required=True)
        device_ids = _text_list(value, "device_ids", label)
        description = _optional_text(value, "description", label)
        return cls(rule_id, basis, cpe_strings, device_ids, description)

    def covers(self, device_wfn):
        """Return True when at least one CPE in the rule covers the device."""
        for rule_wfn in self._wfns:
            if CPESet2_3.cpe_superset(rule_wfn, device_wfn):
                return True
        return False

    def to_dict(self):
        return {
            "id": self.id,
            "basis": self.basis,
            "cpes": list(self.cpe_strings),
            "device_ids": list(self.device_ids),
            "description": self.description,
        }


class Device(object):
    """A device in one of the post-migration inventories."""

    def __init__(self, asset_id, cpe_string, inventory):
        self.asset_id = asset_id
        self.cpe_string = cpe_string
        self.inventory = inventory
        self.wfn = _parse_cpe(
            cpe_string, "device {0} CPE".format(asset_id))


class Inheritance(object):
    """An explicit, evidenced transfer of a device approval."""

    def __init__(self, child_asset_id, parent_asset_id, evidence):
        self.child_asset_id = child_asset_id
        self.parent_asset_id = parent_asset_id
        self.evidence = list(evidence)

    @classmethod
    def from_dict(cls, value, index):
        label = "inheritances[{0}]".format(index)
        value = _mapping(value, label)
        child = _required_text(value, "child_asset_id", label)
        parent = _required_text(value, "parent_asset_id", label)
        if child == parent:
            raise MigrationInputError(
                "{0} cannot inherit from itself".format(label))
        evidence = _text_list(value, "evidence", label)
        return cls(child, parent, evidence)

    def to_dict(self):
        return {
            "child_asset_id": self.child_asset_id,
            "parent_asset_id": self.parent_asset_id,
            "evidence": list(self.evidence),
        }


class MigrationPreview(object):
    """Evaluate original exemptions against post-migration inventories."""

    def __init__(self, rules, inheritances, inventories):
        self.rules = list(rules)
        self.inheritances = list(inheritances)
        self.inventories = inventories

        self._rules_by_id = {}
        for rule in self.rules:
            if rule.id in self._rules_by_id:
                raise MigrationInputError(
                    "duplicate rule id {0}".format(rule.id))
            self._rules_by_id[rule.id] = rule

        self._devices_by_id = {}
        for inventory_name, devices in self.inventories:
            for device in devices:
                if device.asset_id in self._devices_by_id:
                    raise MigrationInputError(
                        "duplicate asset id {0}".format(device.asset_id))
                self._devices_by_id[device.asset_id] = device

        self._inheritances_by_child = {}
        for relation in self.inheritances:
            self._inheritances_by_child.setdefault(
                relation.child_asset_id, []).append(relation)

        self._results = self._evaluate()
        self._result_by_asset = {}
        for inventory_name, devices in self._results:
            for result in devices:
                self._result_by_asset[result["asset_id"]] = result

    @classmethod
    def from_dict(cls, document):
        document = _mapping(document, "input")

        raw_rules = document.get("rules")
        if not isinstance(raw_rules, list) or not raw_rules:
            raise MigrationInputError("input.rules must be a non-empty list")
        rules = [
            ApprovalRule.from_dict(value, index)
            for index, value in enumerate(raw_rules)
        ]

        raw_inheritances = document.get("inheritances", [])
        if not isinstance(raw_inheritances, list):
            raise MigrationInputError("input.inheritances must be a list")
        inheritances = [
            Inheritance.from_dict(value, index)
            for index, value in enumerate(raw_inheritances)
        ]

        raw_inventories = document.get("inventories")
        if not isinstance(raw_inventories, list) or not raw_inventories:
            raise MigrationInputError(
                "input.inventories must be a non-empty list")

        inventories = []
        inventory_names = set()
        for inventory_index, raw_inventory in enumerate(raw_inventories):
            label = "inventories[{0}]".format(inventory_index)
            raw_inventory = _mapping(raw_inventory, label)
            name = _required_text(raw_inventory, "name", label)
            if name in inventory_names:
                raise MigrationInputError(
                    "duplicate inventory name {0}".format(name))
            inventory_names.add(name)

            raw_devices = raw_inventory.get("devices")
            if not isinstance(raw_devices, list) or not raw_devices:
                raise MigrationInputError(
                    "{0}.devices must be a non-empty list".format(label))

            devices = []
            for device_index, raw_device in enumerate(raw_devices):
                device_label = "{0}.devices[{1}]".format(
                    label, device_index)
                raw_device = _mapping(raw_device, device_label)
                asset_id = _required_text(
                    raw_device, "asset_id", device_label)
                cpe_string = _required_text(
                    raw_device, "cpe", device_label)
                devices.append(Device(asset_id, cpe_string, name))
            inventories.append((name, devices))

        return cls(rules, inheritances, inventories)

    def _cpe_matches(self, device):
        matches = []
        for rule in self.rules:
            if not rule.covers(device.wfn):
                continue
            device_approved = (
                rule.basis == BASIS_DEVICE and
                device.asset_id in rule.device_ids
            )
            product_approved = rule.basis == BASIS_PRODUCT
            matches.append({
                "rule_id": rule.id,
                "basis": rule.basis,
                "authorized": device_approved or product_approved,
                "device_ids": list(rule.device_ids),
            })
        return matches

    def _direct_device_rule(self, asset_id, device_wfn):
        for rule in self.rules:
            if (rule.basis == BASIS_DEVICE and
                    asset_id in rule.device_ids and
                    rule.covers(device_wfn)):
                return rule
        return None

    def _device_rules_for_asset(self, asset_id):
        return [
            rule for rule in self.rules
            if rule.basis == BASIS_DEVICE and asset_id in rule.device_ids
        ]

    def _product_rule(self, device_wfn):
        for rule in self.rules:
            if rule.basis == BASIS_PRODUCT and rule.covers(device_wfn):
                return rule
        return None

    def _relations(self, asset_id):
        return self._inheritances_by_child.get(asset_id, [])

    def _inherited_approval(self, asset_id, device_wfn, visiting=None,
                            chain=None):
        """
        Find an evidenced inheritance path ending at a device approval.

        Returns ``(approval, failure)``.  Each relation is considered only
        when its own evidence list is non-empty.
        """
        if visiting is None:
            visiting = []
        if chain is None:
            chain = []

        relations = self._relations(asset_id)
        if not relations:
            return None, {
                "reason_code": REASON_INHERITANCE_PARENT_NOT_APPROVED,
                "relations": [],
            }

        evidenced = [relation for relation in relations if relation.evidence]
        missing = [relation for relation in relations if not relation.evidence]
        failures = []

        for relation in evidenced:
            if relation.parent_asset_id in visiting:
                failures.append({
                    "reason_code": REASON_INHERITANCE_CYCLE,
                    "parent_asset_id": relation.parent_asset_id,
                })
                continue

            parent_rule = self._direct_device_rule(
                relation.parent_asset_id, device_wfn)
            if parent_rule is not None:
                return {
                    "rule": parent_rule,
                    "relations": chain + [relation],
                    "evidence": (
                        relation.evidence +
                        self._flatten_evidence(chain)
                    ),
                }, None

            parent_rules = self._device_rules_for_asset(
                relation.parent_asset_id)
            if parent_rules:
                failures.append({
                    "reason_code": REASON_INHERITANCE_CPE_MISMATCH,
                    "relations": self._inheritance_dict([relation]),
                })
                continue

            parent_approval, failure = self._inherited_approval(
                relation.parent_asset_id,
                device_wfn,
                visiting + [asset_id],
                chain + [relation],
            )
            if parent_approval is not None:
                return parent_approval, None
            if failure is not None:
                failures.append(failure)

        if not evidenced:
            return None, {
                "reason_code": REASON_INHERITANCE_EVIDENCE_MISSING,
                "relations": [
                    {
                        "parent_asset_id": relation.parent_asset_id,
                        "evidence": [],
                    }
                    for relation in missing
                ],
            }

        if missing:
            failures.append({
                "reason_code": REASON_INHERITANCE_EVIDENCE_MISSING,
                "relations": [
                    {
                        "parent_asset_id": relation.parent_asset_id,
                        "evidence": [],
                    }
                    for relation in missing
                ],
            })

        if failures:
            failure = failures[0]
            failure["all_failures"] = failures
            return None, failure

        return None, {
            "reason_code": REASON_INHERITANCE_PARENT_NOT_APPROVED,
            "relations": [],
        }

    @staticmethod
    def _flatten_evidence(relations):
        evidence = []
        for relation in relations:
            evidence.extend(relation.evidence)
        return evidence

    @staticmethod
    def _inheritance_dict(relations):
        return [
            {
                "parent_asset_id": relation.parent_asset_id,
                "evidence": list(relation.evidence),
            }
            for relation in relations
        ]

    def _base_result(self, device, cpe_matches):
        return {
            "inventory": device.inventory,
            "asset_id": device.asset_id,
            "cpe": device.cpe_string,
            "decision": None,
            "reason_code": None,
            "reason": "",
            "basis": None,
            "approved_by": None,
            "evidence": [],
            "inheritance": [],
            "cpe_matches": cpe_matches,
        }

    def _evaluate_device(self, device):
        cpe_matches = self._cpe_matches(device)
        result = self._base_result(device, cpe_matches)

        direct_rule = self._direct_device_rule(device.asset_id, device.wfn)
        if direct_rule is not None:
            result.update({
                "decision": DECISION_APPROVED_DEVICE,
                "reason_code": REASON_APPROVED_DEVICE,
                "reason": "资产 ID 由设备型规则显式列出，且 CPE 匹配。",
                "basis": BASIS_DEVICE,
                "approved_by": direct_rule.id,
            })
            return result

        product_rule = self._product_rule(device.wfn)
        if product_rule is not None:
            result.update({
                "decision": DECISION_APPROVED_PRODUCT,
                "reason_code": REASON_APPROVED_PRODUCT,
                "reason": "CPE 落在产品范围规则内，不依赖具体资产 ID。",
                "basis": BASIS_PRODUCT,
                "approved_by": product_rule.id,
            })
            return result

        inherited_approval, failure = self._inherited_approval(
            device.asset_id, device.wfn, visiting=[device.asset_id]) \
            if self._relations(device.asset_id) else (None, None)
        if inherited_approval is not None:
            rule = inherited_approval["rule"]
            relations = inherited_approval["relations"]
            if rule.covers(device.wfn):
                result.update({
                    "decision": DECISION_APPROVED_INHERITANCE,
                    "reason_code": REASON_APPROVED_INHERITANCE,
                    "reason": "通过有证据的资产继承关系继承设备批准。",
                    "basis": BASIS_DEVICE,
                    "approved_by": rule.id,
                    "evidence": inherited_approval["evidence"],
                    "inheritance": self._inheritance_dict(relations),
                })
                return result
            failure = {
                "reason_code": REASON_INHERITANCE_CPE_MISMATCH,
                "relations": self._inheritance_dict(relations),
            }

        result["decision"] = DECISION_PENDING
        if failure is not None:
            reason_code = failure["reason_code"]
            result["reason_code"] = reason_code
            if reason_code == REASON_INHERITANCE_EVIDENCE_MISSING:
                parents = ", ".join([
                    relation["parent_asset_id"]
                    for relation in failure.get("relations", [])
                ])
                result["reason"] = (
                    "继承关系存在，但证据缺失；应回到待审（来源资产：{0}）。"
                    .format(parents)
                )
                result["inheritance"] = failure.get("relations", [])
            elif reason_code == REASON_INHERITANCE_CPE_MISMATCH:
                result["reason"] = (
                    "继承来源的设备批准 CPE 不覆盖当前设备。")
                result["inheritance"] = failure.get("relations", [])
            elif reason_code == REASON_INHERITANCE_CYCLE:
                result["reason"] = "资产继承关系形成环，不能自动批准。"
            else:
                result["reason"] = "继承来源没有有效的设备批准。"
                result["inheritance"] = failure.get("relations", [])
            return result

        bound_rules = self._device_rules_for_asset(device.asset_id)
        if bound_rules:
            result["reason_code"] = REASON_DEVICE_APPROVAL_CPE_MISMATCH
            result["reason"] = (
                "资产 ID 出现在设备型规则 {0} 中，但设备 CPE 不被该规则覆盖；"
                "原批准已失效，应回到待审。"
                .format(", ".join([rule.id for rule in bound_rules]))
            )
            return result

        approved_device_matches = [
            match for match in cpe_matches
            if match["basis"] == BASIS_DEVICE
        ]
        if approved_device_matches:
            rule_ids = ", ".join([
                match["rule_id"] for match in approved_device_matches
            ])
            result["reason_code"] = (
                REASON_CPE_MATCH_WITHOUT_DEVICE_APPROVAL)
            result["reason"] = (
                "CPE 与设备型规则 {0} 同型号，但该资产 ID 未被批准，"
                "也没有产品范围规则或带证据的继承关系。"
                .format(rule_ids)
            )
        else:
            result["reason_code"] = REASON_NO_APPROVAL
            result["reason"] = "没有匹配的设备批准或产品范围规则。"
        return result

    def _evaluate(self):
        results = []
        for inventory_name, devices in self.inventories:
            inventory_results = []
            for device in devices:
                inventory_results.append(self._evaluate_device(device))
            results.append((inventory_name, inventory_results))
        return results

    def to_dict(self):
        summary = {
            "rules": len(self.rules),
            "device_rules": len([
                rule for rule in self.rules if rule.basis == BASIS_DEVICE
            ]),
            "product_rules": len([
                rule for rule in self.rules if rule.basis == BASIS_PRODUCT
            ]),
            "inventories": len(self._results),
            "devices": len(self._result_by_asset),
            "approved": 0,
            "approved_device": 0,
            "approved_inheritance": 0,
            "approved_product_scope": 0,
            "pending_review": 0,
        }

        inventories = []
        pending_review = []
        attention = []
        for inventory_name, devices in self._results:
            inventories.append({
                "name": inventory_name,
                "devices": devices,
            })
            for result in devices:
                if result["decision"] == DECISION_PENDING:
                    summary["pending_review"] += 1
                    pending_review.append({
                        "inventory": inventory_name,
                        "asset_id": result["asset_id"],
                        "reason_code": result["reason_code"],
                        "reason": result["reason"],
                    })
                    if (result["reason_code"] ==
                            REASON_CPE_MATCH_WITHOUT_DEVICE_APPROVAL):
                        attention.append({
                            "inventory": inventory_name,
                            "asset_id": result["asset_id"],
                            "reason": result["reason"],
                        })
                else:
                    summary["approved"] += 1
                    summary[result["decision"]] += 1

        return {
            "summary": summary,
            "rules": [rule.to_dict() for rule in self.rules],
            "inheritances": [
                relation.to_dict() for relation in self.inheritances
            ],
            "inventories": inventories,
            "pending_review": pending_review,
            "attention": attention,
        }

    def has_asset(self, asset_id):
        return asset_id in self._result_by_asset

    def asset_result(self, asset_id):
        return self._result_by_asset.get(asset_id)

    def pending_review(self):
        return self.to_dict()["pending_review"]

    def render_text(self, focus_asset_id=None):
        document = self.to_dict()
        summary = document["summary"]
        lines = [
            "设备豁免迁移预览",
            "规则: {rules} (device={device_rules}, "
            "product={product_rules})".format(**summary),
            "清单: {inventories}; 设备: {devices}".format(**summary),
            "批准: {approved} (device={approved_device}, "
            "inheritance={approved_inheritance}, "
            "product={approved_product_scope})".format(**summary),
            "待审: {pending_review}".format(**summary),
        ]

        if document["attention"]:
            lines.append("")
            lines.append("重点核对（CPE 同型号但资产未获批）:")
            for item in document["attention"]:
                lines.append("  - {0}/{1}".format(
                    item["inventory"], item["asset_id"]))

        asset_width = max(
            [len("ASSET_ID")] +
            [len(device["asset_id"]) for inventory in document["inventories"]
             for device in inventory["devices"]]
        )
        decision_width = max(
            [len("DECISION")] +
            [len(device["decision"]) for inventory in document["inventories"]
             for device in inventory["devices"]]
        )

        for inventory in document["inventories"]:
            lines.append("")
            lines.append("{0} ({1})".format(
                inventory["name"].upper(), len(inventory["devices"])))
            lines.append("{0}  {1}  {2}  {3}".format(
                "ASSET_ID".ljust(asset_width),
                "DECISION".ljust(decision_width),
                "BASIS".ljust(8),
                "DETAIL",
            ))
            for device in inventory["devices"]:
                detail = device["approved_by"] or device["reason"]
                if device["asset_id"] == focus_asset_id:
                    detail = "{0}  <-- FOCUS".format(detail)
                lines.append("{0}  {1}  {2}  {3}".format(
                    device["asset_id"].ljust(asset_width),
                    device["decision"].ljust(decision_width),
                    (device["basis"] or "-").ljust(8),
                    detail,
                ))

        if document["pending_review"]:
            lines.append("")
            lines.append("待审清单:")
            for item in document["pending_review"]:
                lines.append("  - {0}/{1}: {2} [{3}]".format(
                    item["inventory"],
                    item["asset_id"],
                    item["reason"],
                    item["reason_code"],
                ))

        if focus_asset_id is not None:
            result = self.asset_result(focus_asset_id)
            if result is None:
                lines.append("")
                lines.append("未找到设备: {0}".format(focus_asset_id))
            else:
                lines.append("")
                lines.append("关注设备: {0}/{1}".format(
                    result["inventory"], result["asset_id"]))
                lines.append("  CPE: {0}".format(result["cpe"]))
                lines.append("  结论: {0}".format(result["decision"]))
                lines.append("  原因: {0}".format(result["reason"]))
                if result["approved_by"]:
                    lines.append("  批准规则: {0} ({1})".format(
                        result["approved_by"], result["basis"]))
                if result["evidence"]:
                    lines.append("  证据: {0}".format(
                        ", ".join(result["evidence"])))
                if result["inheritance"]:
                    lines.append("  继承关系:")
                    for relation in result["inheritance"]:
                        evidence = relation["evidence"] or ["<missing>"]
                        lines.append("    - 来源 {0}; 证据 {1}".format(
                            relation["parent_asset_id"],
                            ", ".join(evidence)))
                lines.append("  CPE 命中:")
                if not result["cpe_matches"]:
                    lines.append("    - 无")
                for match in result["cpe_matches"]:
                    if match["basis"] == BASIS_DEVICE:
                        authorization = "型号匹配"
                        if match["authorized"]:
                            authorization = "设备批准"
                        device_ids = ", ".join(match["device_ids"])
                        lines.append(
                            "    - {0} [device] {1}; 批准资产: {2}".format(
                                match["rule_id"], authorization, device_ids))
                    else:
                        lines.append("    - {0} [product] 产品范围批准".format(
                            match["rule_id"]))

        return "\n".join(lines)


def build_preview(document):
    """Build a preview from a decoded JSON-compatible document."""
    return MigrationPreview.from_dict(document)


def _read_json(path):
    with io.open(path, "r", encoding="utf-8") as input_file:
        return json.load(input_file)


def _write_text(path, text):
    with io.open(path, "w", encoding="utf-8") as output_file:
        output_file.write(text)
        output_file.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Preview device exemption migration using CPE matching.")
    parser.add_argument(
        "input", help="JSON file containing rules, inheritances and inventories")
    parser.add_argument(
        "--device", dest="focus_asset_id",
        help="highlight and explain one asset ID")
    parser.add_argument(
        "--json", dest="as_json", action="store_true",
        help="write the full preview as JSON")
    parser.add_argument(
        "--output", help="write the preview to a file instead of stdout")
    args = parser.parse_args(argv)

    try:
        preview = build_preview(_read_json(args.input))
    except (IOError, OSError, ValueError) as exc:
        print("error: {0}".format(exc), file=sys.stderr)
        return 2

    if args.focus_asset_id is not None and not preview.has_asset(
            args.focus_asset_id):
        print("error: asset id not found: {0}".format(
            args.focus_asset_id), file=sys.stderr)
        return 2

    if args.as_json:
        text = json.dumps(
            preview.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
    else:
        text = preview.render_text(args.focus_asset_id)

    if args.output:
        _write_text(args.output, text)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
