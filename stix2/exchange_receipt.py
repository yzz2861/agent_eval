"""Offline field-level receipts for desensitized STIX exchange samples."""

from __future__ import annotations

import argparse
import copy
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any


PRESERVED = "identity_preserved"
PRESERVED_UNORDERED = "identity_preserved_order_insensitive"
TRANSFORMED = "explicitly_transformed"
UNVERIFIABLE = "unverifiable"
REAL_UPDATE = "real_update"
FIELD_ADDED = "field_added"
FIELD_REMOVED = "field_removed"
REVISION_CHANGED = "revision_metadata_changed"
REVISION_PRESERVED = "revision_metadata_preserved"
IDENTITY_MISMATCH = "identity_mismatch"
UNORDERED_COLLECTION_CHANGED = "unordered_collection_changed"

_MISSING = object()

_DEFAULT_IDENTITY_FIELDS = {
    "id", "type", "spec_version", "created", "created_by_ref",
}
_DEFAULT_REVISION_FIELDS = {"modified", "revoked"}
_DEFAULT_UNORDERED = {
    "external_references": {"key": ["source_name", "external_id"]},
    "aliases": {},
}


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return copy.deepcopy(value)


def _load_json(path: str | Path | Mapping[str, Any]) -> Any:
    if isinstance(path, Mapping):
        return _plain(path)
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _selector_matches(selector: str, path: str) -> bool:
    return selector == path or path.startswith(selector + ".") or path.startswith(selector + "[")


def _normalized_rules(disclosure: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    disclosure = disclosure or {}
    rules: list[dict[str, Any]] = []
    for rule in disclosure.get("rules", []):
        for selector in rule.get("selectors", []):
            item = dict(rule)
            item["selector"] = selector
            rules.append(item)
    for key in ("explicit_transforms", "transforms"):
        for rule in disclosure.get(key, []):
            rule = dict(rule)
            rule.setdefault("classification", TRANSFORMED)
            for selector in rule.get("selectors", []):
                item = dict(rule)
                item["selector"] = selector
                rules.append(item)
    for key in ("proof_blocked", "unverifiable_fields"):
        for rule in disclosure.get(key, []):
            rule = dict(rule)
            rule.setdefault("classification", UNVERIFIABLE)
            for selector in rule.get("selectors", []):
                item = dict(rule)
                item["selector"] = selector
                rules.append(item)
    rules.sort(key=lambda rule: len(rule["selector"]), reverse=True)
    return rules


def _rule_for_path(path: str, rules: list[dict[str, Any]]) -> dict[str, Any] | None:
    for rule in rules:
        if _selector_matches(rule["selector"], path):
            return rule
    return None


def _marking_map(obj: Mapping[str, Any]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for marking in obj.get("granular_markings", []) or []:
        for selector in marking.get("selectors", []) or []:
            result.setdefault(selector, set()).add(marking.get("marking_ref"))
    return result


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _key_for_item(item: Any, key_fields: list[str]) -> tuple[Any, ...]:
    if isinstance(item, Mapping):
        values = []
        for field in key_fields:
            value = item.get(field, _MISSING)
            values.append("\x00missing" if value is _MISSING else _canonical(value))
        return tuple(values)
    return (_canonical(item),)


def _key_selector(path: str, item: Any, config: Mapping[str, Any]) -> str:
    key_fields = config.get("key", [])
    if key_fields and isinstance(item, Mapping):
        parts = []
        for field in key_fields:
            if field in item:
                value = item[field]
                if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.-]+", value):
                    parts.append(f"{field}={value}")
                else:
                    parts.append(f"{field}={json.dumps(value, ensure_ascii=False)}")
        return f"{path}[{', '.join(parts)}]"
    return path


class _ReceiptBuilder:
    def __init__(
        self,
        before: Mapping[str, Any],
        after: Mapping[str, Any],
        disclosure: Mapping[str, Any] | None,
    ) -> None:
        self.before = _plain(before)
        self.after = _plain(after)
        self.disclosure = _plain(disclosure or {})
        self.rules = _normalized_rules(self.disclosure)
        self.fields: list[dict[str, Any]] = []
        self.issues: list[str] = []
        self.before_markings = _marking_map(self.before)
        self.after_markings = _marking_map(self.after)
        self.unordered = dict(_DEFAULT_UNORDERED)
        self.unordered.update(self.disclosure.get("unordered_collections", {}))
        self.identity_fields = set(_DEFAULT_IDENTITY_FIELDS)
        self.identity_fields.update(self.disclosure.get("identity_fields", []))
        self.revision_fields = set(_DEFAULT_REVISION_FIELDS)
        self.revision_fields.update(self.disclosure.get("revision_fields", []))

    def build(self) -> dict[str, Any]:
        same_id = self.before.get("id") == self.after.get("id")
        same_type = self.before.get("type") == self.after.get("type")
        if not same_id:
            self.issues.append("object IDs differ; comparison is not an ID-preserving revision pair")
        if not same_type:
            self.issues.append("object types differ")
        self._compare("$", self.before, self.after)
        self._verify_rule_bindings()

        groups = {
            "identity_preserved": [],
            "explicitly_transformed": [],
            "unverifiable": [],
            "real_updates": [],
            "revision_metadata_changes": [],
            "order_normalized": [],
            "identity_mismatches": [],
        }
        for field in self.fields:
            selector = field["selector"]
            status = field["status"]
            if status in (PRESERVED, PRESERVED_UNORDERED, REVISION_PRESERVED):
                groups["identity_preserved"].append(selector)
            if status == PRESERVED_UNORDERED:
                groups["order_normalized"].append(selector)
            if status == TRANSFORMED:
                groups["explicitly_transformed"].append(selector)
            if status in (UNVERIFIABLE, "transformed_drift_unproven"):
                groups["unverifiable"].append(selector)
            if status in (REAL_UPDATE, FIELD_ADDED, FIELD_REMOVED):
                groups["real_updates"].append(selector)
            if status == REVISION_CHANGED:
                groups["revision_metadata_changes"].append(selector)
            if status == IDENTITY_MISMATCH:
                groups["identity_mismatches"].append(selector)

        real_updates = groups["real_updates"]
        receipt = {
            "schema": "stix2.exchange-receipt/v1",
            "object_id": self.after.get("id") or self.before.get("id"),
            "same_id": same_id,
            "same_type": same_type,
            "summary": {
                **groups,
                "real_update_count": len(real_updates),
                "only_real_update": real_updates[0] if len(real_updates) == 1 else None,
                "issues": self.issues,
            },
            "fields": self.fields,
        }
        return receipt

    def _append(self, selector: str, status: str, **details: Any) -> None:
        record = {"selector": selector, "status": status}
        record.update(details)
        self.fields.append(record)

    def _verify_rule_bindings(self) -> None:
        for rule in self.rules:
            marking_ref = rule.get("marking_ref")
            selector = rule["selector"]
            if not marking_ref:
                continue
            refs = self.before_markings.get(selector, set()) | self.after_markings.get(selector, set())
            if marking_ref not in refs:
                self.issues.append(
                    f"rule for {selector} is not bound by granular marking {marking_ref}",
                )

    def _transform_details(
        self,
        selector: str,
        before: Any,
        after: Any,
        rule: Mapping[str, Any],
    ) -> dict[str, Any]:
        details: dict[str, Any] = {
            "transform": rule.get("transform", rule.get("kind", "declared-transform")),
            "wire_equal": before is not _MISSING and after is not _MISSING and before == after,
        }
        pattern = rule.get("pattern")
        prefix = rule.get("token_prefix")
        value = after if after is not _MISSING else before
        format_verified = True
        if isinstance(value, str):
            if pattern:
                format_verified = re.fullmatch(pattern, value) is not None
            elif prefix:
                format_verified = value.startswith(prefix)
        details["format_verified"] = format_verified
        if not format_verified:
            self.issues.append(f"transformed value at {selector} does not match declared format")
        if rule.get("stable"):
            details["stable"] = True
            details["pseudonym_continuity_proven"] = details["wire_equal"] and format_verified
        return details

    def _compare(self, path: str, before: Any, after: Any) -> None:
        rule = _rule_for_path(path, self.rules)
        if rule is not None and rule.get("classification") == UNVERIFIABLE:
            self._append(
                path,
                UNVERIFIABLE,
                reason=rule.get("reason", "marking rule does not permit offline proof"),
                marking_ref=rule.get("marking_ref"),
                wire_equal=before is not _MISSING and after is not _MISSING and before == after,
                before=before if before is not _MISSING else None,
                after=after if after is not _MISSING else None,
                present_before=before is not _MISSING,
                present_after=after is not _MISSING,
            )
            return

        if rule is not None and rule.get("classification") == TRANSFORMED:
            details = self._transform_details(path, before, after, rule)
            if before is _MISSING or after is _MISSING:
                status = UNVERIFIABLE
                details["reason"] = "declared transform field is absent on one side"
            elif rule.get("stable") and not details["wire_equal"]:
                status = "transformed_drift_unproven"
                details["reason"] = "stable transform output changed without a continuity receipt"
                self.issues.append(f"transformed field {path} changed and cannot be silently treated as redaction")
            else:
                status = TRANSFORMED
            self._append(
                path,
                status,
                marking_ref=rule.get("marking_ref"),
                before=before if before is not _MISSING else None,
                after=after if after is not _MISSING else None,
                **details,
            )
            return

        if before is _MISSING or after is _MISSING:
            status = FIELD_REMOVED if after is _MISSING else FIELD_ADDED
            self._append(
                path,
                IDENTITY_MISMATCH if path in self.identity_fields else status,
                before=None if before is _MISSING else before,
                after=None if after is _MISSING else after,
            )
            return

        unordered_config = self._unordered_config(path)
        if unordered_config is not None and isinstance(before, list) and isinstance(after, list):
            self._compare_unordered(path, before, after, unordered_config)
            return

        if isinstance(before, Mapping) and isinstance(after, Mapping):
            for key in sorted(set(before) | set(after)):
                self._compare(
                    f"{path}.{key}" if path != "$" else key,
                    before.get(key, _MISSING),
                    after.get(key, _MISSING),
                )
            return

        if isinstance(before, list) and isinstance(after, list):
            if len(before) != len(after):
                self._append(
                    path,
                    REAL_UPDATE,
                    change="list_length",
                    before_length=len(before),
                    after_length=len(after),
                )
            for index, (item_before, item_after) in enumerate(zip(before, after)):
                self._compare(f"{path}[{index}]", item_before, item_after)
            return

        if before == after:
            if path in self.revision_fields:
                status = REVISION_PRESERVED
            elif path in self.identity_fields:
                status = PRESERVED
            else:
                status = PRESERVED
            self._append(path, status, value=after)
            return

        if path in self.identity_fields:
            status = IDENTITY_MISMATCH
        elif path in self.revision_fields:
            status = REVISION_CHANGED
        else:
            status = REAL_UPDATE
        self._append(path, status, before=before, after=after)

    def _unordered_config(self, path: str) -> Mapping[str, Any] | None:
        config = self.unordered.get(path)
        if config is None:
            leaf = path.rsplit(".", 1)[-1]
            config = self.unordered.get(leaf)
        return config

    def _compare_unordered(
        self,
        path: str,
        before: list[Any],
        after: list[Any],
        config: Mapping[str, Any],
    ) -> None:
        key_fields = list(config.get("key", []))
        if not key_fields:
            if sorted(map(_canonical, before)) == sorted(map(_canonical, after)):
                self._append(path, PRESERVED_UNORDERED, item_count=len(after))
                return
            self._append(path, UNORDERED_COLLECTION_CHANGED)
            before_sorted = sorted(before, key=_canonical)
            after_sorted = sorted(after, key=_canonical)
            for index, (item_before, item_after) in enumerate(zip(before_sorted, after_sorted)):
                self._compare(f"{path}[unordered-{index}]", item_before, item_after)
            return

        if sorted(map(_canonical, before)) == sorted(map(_canonical, after)):
            self._append(
                path,
                PRESERVED_UNORDERED,
                item_count=len(after),
                key_fields=key_fields,
            )
            return

        before_map: dict[tuple[Any, ...], list[Any]] = {}
        after_map: dict[tuple[Any, ...], list[Any]] = {}
        for item in before:
            before_map.setdefault(_key_for_item(item, key_fields), []).append(item)
        for item in after:
            after_map.setdefault(_key_for_item(item, key_fields), []).append(item)

        before_keys = set(before_map)
        after_keys = set(after_map)
        for key in sorted(before_keys - after_keys, key=_canonical):
            selector = _key_selector(path, before_map[key][0], config)
            self._append(selector, FIELD_REMOVED, before=before_map[key][0], after=None)
        for key in sorted(after_keys - before_keys, key=_canonical):
            selector = _key_selector(path, after_map[key][0], config)
            self._append(selector, FIELD_ADDED, before=None, after=after_map[key][0])
        for key in sorted(before_keys & after_keys, key=_canonical):
            before_items = before_map[key]
            after_items = after_map[key]
            selector = _key_selector(path, before_items[0], config)
            if len(before_items) == 1 and len(after_items) == 1:
                self._compare(selector, before_items[0], after_items[0])
            else:
                self._append(
                    selector,
                    UNORDERED_COLLECTION_CHANGED,
                    duplicate_counts=[len(before_items), len(after_items)],
                )


def build_exchange_receipt(
    before: str | Path | Mapping[str, Any],
    after: str | Path | Mapping[str, Any],
    disclosure: str | Path | Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a field-classified offline receipt for an ID-preserving pair."""
    before_obj = _load_json(before)
    after_obj = _load_json(after)
    disclosure_obj = _load_json(disclosure) if disclosure is not None else {}
    return _ReceiptBuilder(before_obj, after_obj, disclosure_obj).build()


build_offline_receipt = build_exchange_receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path, help="earlier exchange sample")
    parser.add_argument("after", type=Path, help="later exchange sample")
    parser.add_argument("--disclosure", type=Path, help="gateway transform and marking disclosure")
    parser.add_argument("--write", type=Path, help="write receipt JSON to this path")
    args = parser.parse_args(argv)

    receipt = build_exchange_receipt(args.before, args.after, args.disclosure)
    rendered = json.dumps(receipt, ensure_ascii=False, indent=2) + "\n"
    if args.write:
        args.write.write_text(rendered, encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
