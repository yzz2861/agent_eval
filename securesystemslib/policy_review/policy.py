"""Parsing and normalization of DSSE signing-policy documents.

Three rule shapes are accepted and all expand to the same normalized form
(one concrete set of required key ids per rule):

* ``threshold``: any ``threshold`` distinct key ids chosen from ``keyids``;
* ``slots``: one key id per slot, where a slot may list alternates;
* ``combination``: one explicit list of required key ids.

The same key id may appear in any number of rules. Two rules that expand to
the same set of key ids are merged, and the report keeps every originating
rule id so the combination can be traced back by hand.
"""

from __future__ import annotations

import json
from itertools import combinations
from pathlib import Path
from typing import Any

from securesystemslib.policy_review.models import Policy, PolicyReviewError, Rule

_RULE_TYPES = frozenset({"threshold", "slots", "combination"})


def load_policy(path: str | Path) -> Policy:
    """Load a policy document from a JSON file."""
    try:
        with open(path, "rb") as file:
            data = json.load(file)
    except OSError as error:
        raise PolicyReviewError(f"cannot read policy file {path!s}: {error}") from error
    except json.JSONDecodeError as error:
        raise PolicyReviewError(f"invalid JSON in policy file: {error}") from error
    return parse_policy(data)


def parse_policy(data: Any) -> Policy:
    """Parse and normalize a policy document given as a decoded JSON object."""
    if not isinstance(data, dict):
        raise PolicyReviewError("policy document must be a JSON object")

    policy_id = _as_identifier(data.get("policy_id"), "policy_id", required=True)
    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise PolicyReviewError("policy must contain a non-empty rules list")

    rules: list[Rule] = []
    rule_index: dict[frozenset[str], list[str]] = {}
    for position, raw_rule in enumerate(raw_rules):
        if not isinstance(raw_rule, dict):
            raise PolicyReviewError(f"rule at position {position} must be an object")
        rule_type = raw_rule.get("type")
        if rule_type not in _RULE_TYPES:
            raise PolicyReviewError(
                f"rule at position {position} has unknown type {rule_type!r}; "
                f"expected one of {sorted(_RULE_TYPES)}"
            )
        rule_id = _as_identifier(
            raw_rule.get("rule_id"),
            f"rule_id of rule at position {position}",
            required=False,
        ) or f"{rule_type}-{position + 1}"

        if rule_type == "threshold":
            expansions = _expand_threshold(rule_id, raw_rule)
        elif rule_type == "slots":
            expansions = _expand_slots(rule_id, raw_rule)
        else:
            expansions = _expand_combination(rule_id, raw_rule)

        source = _source_label(rule_type, raw_rule)
        for keyids in expansions:
            rule_index.setdefault(keyids, [])
            if rule_id not in rule_index[keyids]:
                rule_index[keyids].append(rule_id)
            rules.append(Rule(rule_id=rule_id, keyids=keyids, source=source))

    all_keyids = frozenset(keyid for rule in rules for keyid in rule.keyids)
    if not all_keyids:
        raise PolicyReviewError("policy does not require any key id")

    index = {keyids: tuple(ids) for keyids, ids in rule_index.items()}
    return Policy(
        policy_id=policy_id,
        rules=tuple(rules),
        keyids=all_keyids,
        rule_index=index,
    )


def _as_identifier(value: Any, what: str, required: bool) -> str | None:
    if value is None:
        if required:
            raise PolicyReviewError(f"missing required field {what!r}")
        return None
    if not isinstance(value, str) or not value.strip():
        raise PolicyReviewError(f"field {what!r} must be a non-empty string")
    return value


def _as_keyid_list(value: Any, field_name: str, rule_id: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise PolicyReviewError(
            f"rule {rule_id!r}: field {field_name!r} must be a non-empty list"
        )
    keyids: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise PolicyReviewError(
                f"rule {rule_id!r}: entries of {field_name!r} must be key id strings"
            )
        if item not in keyids:
            keyids.append(item)
    return keyids


def _expand_threshold(rule_id: str, raw_rule: dict[str, Any]) -> list[frozenset[str]]:
    keyids = _as_keyid_list(raw_rule.get("keyids"), "keyids", rule_id)
    threshold = raw_rule.get("threshold")
    if not isinstance(threshold, int) or isinstance(threshold, bool):
        raise PolicyReviewError(f"rule {rule_id!r}: threshold must be an integer")
    if threshold < 1 or threshold > len(keyids):
        raise PolicyReviewError(
            f"rule {rule_id!r}: threshold {threshold} must be between 1 and "
            f"the number of key ids ({len(keyids)})"
        )
    return [frozenset(combo) for combo in combinations(sorted(keyids), threshold)]


def _expand_slots(rule_id: str, raw_rule: dict[str, Any]) -> list[frozenset[str]]:
    raw_slots = raw_rule.get("slots")
    if not isinstance(raw_slots, list) or not raw_slots:
        raise PolicyReviewError(f"rule {rule_id!r}: slots must be a non-empty list")

    slot_choices: list[list[str]] = []
    for position, raw_slot in enumerate(raw_slots):
        if isinstance(raw_slot, str) and raw_slot:
            choices = [raw_slot]
        elif isinstance(raw_slot, list):
            choices = _as_keyid_list(raw_slot, f"slots[{position}]", rule_id)
        else:
            raise PolicyReviewError(
                f"rule {rule_id!r}: slot {position} must be a key id or a list"
            )
        slot_choices.append(choices)

    expansions: list[frozenset[str]] = []

    def expand(index: int, chosen: set[str]) -> None:
        if index == len(slot_choices):
            expansions.append(frozenset(chosen))
            return
        for keyid in slot_choices[index]:
            if keyid in chosen:
                # One key cannot fill two slots of the same envelope.
                continue
            chosen.add(keyid)
            expand(index + 1, chosen)
            chosen.remove(keyid)

    expand(0, set())
    if not expansions:
        raise PolicyReviewError(
            f"rule {rule_id!r}: slots cannot be filled without reusing a key id"
        )
    return expansions


def _expand_combination(
    rule_id: str, raw_rule: dict[str, Any]
) -> list[frozenset[str]]:
    keyids = _as_keyid_list(raw_rule.get("keyids"), "keyids", rule_id)
    return [frozenset(keyids)]


def _source_label(rule_type: str, raw_rule: dict[str, Any]) -> str:
    if rule_type == "threshold":
        threshold = raw_rule.get("threshold")
        count = len(raw_rule.get("keyids", []))
        return f"threshold({threshold} of {count})"
    if rule_type == "slots":
        return f"slots({len(raw_rule.get('slots', []))})"
    return "combination"
