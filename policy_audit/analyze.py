"""Shadowing analysis over the finite policy domain.

The analysis language is deliberately small so the audit stays decidable:

- ``id``:           string, required
- ``action``:       ``allow`` or ``deny``, required
- ``priority``:     integer, required (higher wins; ties break by definition
                    order, earlier files first)
- ``environments``: optional list of strings; absent means "all environments"
- ``tags``:         optional mapping of tag key -> value or list of values;
                    every listed key must match (equality)

Anything outside this language is reported as ``unsupported_condition`` and
left out of the shadowing analysis rather than guessed at.

The domain is finite: environments come from the policy's declared
``environments`` list (or the union of rule lists), and each tag key ranges
over the values mentioned in the policy plus an ``<other>`` sentinel that
stands for every unlisted value. That is sound for equality-only conditions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import product
from typing import Any, Optional

from .loader import Issue, LoadedPolicy, RuleEntry

OTHER = "<other>"

KNOWN_KEYS = {"id", "action", "priority", "environments", "tags", "description"}
ACTIONS = {"allow", "deny"}


@dataclass(frozen=True)
class Context:
    """One point in the finite deployment domain."""

    environment: Any
    tags: tuple  # tuple[tuple[str, Any], ...] sorted by key

    def as_dict(self) -> dict:
        return {"environment": self.environment, "tags": dict(self.tags)}


@dataclass
class RuleVerdict:
    """Audit verdict for one rule of the effective policy."""

    entry: RuleEntry
    verdict: str  # effective | partially_shadowed | fully_shadowed | vacuous
    matched_points: int
    winning_points: int
    winning_example: Optional[Context] = None
    shadowed_example: Optional[Context] = None
    shadowed_by: list = field(default_factory=list)  # list of rule ids

    @property
    def rule_id(self) -> str:
        return self.entry.rule_id or "<no id>"


def _validate_rule(entry: RuleEntry) -> Optional[str]:
    """Return None if the rule is inside the analysis language, else a reason."""
    data = entry.data
    unknown = sorted(set(data) - KNOWN_KEYS)
    if unknown:
        return "unknown condition key(s) %s are outside the analysis language" % (
            ", ".join(repr(k) for k in unknown)
        )
    if not isinstance(data.get("id"), str):
        return "rule 'id' must be a string"
    if data.get("action") not in ACTIONS:
        return "rule 'action' must be one of %s" % sorted(ACTIONS)
    priority = data.get("priority")
    if not isinstance(priority, int) or isinstance(priority, bool):
        return "rule 'priority' must be an integer"
    envs = data.get("environments")
    if envs is not None and (
        not isinstance(envs, list)
        or any(not isinstance(e, str) for e in envs)
    ):
        return "rule 'environments' must be a list of strings"
    tags = data.get("tags")
    if tags is not None:
        if not isinstance(tags, dict):
            return "rule 'tags' must be a mapping"
        for key, value in tags.items():
            values = value if isinstance(value, list) else [value]
            if not isinstance(key, str) or any(
                not isinstance(v, (str, int, float, bool)) for v in values
            ):
                return "rule 'tags' must map strings to scalars or lists of scalars"
    return None


def _tag_values(rule_data: dict, key: str) -> Optional[frozenset]:
    tags = rule_data.get("tags") or {}
    if key not in tags:
        return None  # unconstrained
    value = tags[key]
    values = value if isinstance(value, list) else [value]
    return frozenset(values)


def rule_matches(rule_data: dict, context: Context) -> bool:
    """Check a context against a rule; used by the audit and verifiable by hand."""
    envs = rule_data.get("environments")
    if envs is not None and context.environment not in envs:
        return False
    tags = dict(context.tags)
    for key in (rule_data.get("tags") or {}):
        allowed = _tag_values(rule_data, key)
        if tags.get(key, OTHER) not in allowed:
            return False
    return True


def _sort_key(value: Any) -> str:
    return repr(value)


def build_domain(rules_data: list, declared_envs: Optional[list]) -> list:
    """Enumerate every point of the finite deployment domain."""
    envs = set(declared_envs or [])
    for data in rules_data:
        envs.update(data.get("environments") or [])
    if not envs:
        envs = {"<unspecified>"}

    tag_keys = set()
    for data in rules_data:
        tag_keys.update((data.get("tags") or {}).keys())
    tag_values = {}
    for key in sorted(tag_keys):
        values = set()
        for data in rules_data:
            allowed = _tag_values(data, key)
            if allowed:
                values.update(allowed)
        tag_values[key] = sorted(values, key=_sort_key) + [OTHER]

    points = []
    keys = sorted(tag_values)
    for env in sorted(envs, key=_sort_key):
        for combo in product(*(tag_values[k] for k in keys)):
            points.append(Context(env, tuple(zip(keys, combo))))
    return points


def _winner(rules: list, context: Context) -> Optional[RuleEntry]:
    best = None
    best_key = None
    for entry in rules:
        if not rule_matches(entry.data, context):
            continue
        key = (entry.data["priority"], -entry.source_index)
        if best_key is None or key > best_key:
            best = entry
            best_key = key
    return best


def analyze_policy(policy: LoadedPolicy) -> tuple:
    """Return (verdicts, issues, domain) for the effective policy."""
    issues = list(policy.issues)
    analyzable = []
    for entry in policy.rules:
        reason = _validate_rule(entry)
        if reason is None:
            analyzable.append(entry)
        else:
            issues.append(Issue(
                "unsupported_condition",
                "%s; rule excluded from the shadowing analysis" % reason,
                entry.provenance,
                entry.rule_id,
            ))

    declared_envs = policy.data.get("environments")
    if not isinstance(declared_envs, list) or not all(
        isinstance(e, str) for e in declared_envs or []
    ):
        declared_envs = None
    domain = build_domain([e.data for e in analyzable], declared_envs)

    stats = {id(e): {"matched": 0, "won": 0, "win_ex": None,
                     "lose_ex": None, "by": set()} for e in analyzable}
    for context in domain:
        winner = _winner(analyzable, context)
        for entry in analyzable:
            if not rule_matches(entry.data, context):
                continue
            stat = stats[id(entry)]
            stat["matched"] += 1
            if winner is entry:
                stat["won"] += 1
                if stat["win_ex"] is None:
                    stat["win_ex"] = context
            else:
                if stat["lose_ex"] is None:
                    stat["lose_ex"] = context
                if winner is not None and winner.rule_id:
                    stat["by"].add(winner.rule_id)

    verdicts = []
    for entry in analyzable:
        stat = stats[id(entry)]
        matched, won = stat["matched"], stat["won"]
        if matched == 0:
            verdict = "vacuous"
        elif won == matched:
            verdict = "effective"
        elif won == 0:
            verdict = "fully_shadowed"
        else:
            verdict = "partially_shadowed"
        verdicts.append(RuleVerdict(
            entry=entry,
            verdict=verdict,
            matched_points=matched,
            winning_points=won,
            winning_example=stat["win_ex"],
            shadowed_example=stat["lose_ex"],
            shadowed_by=sorted(stat["by"]),
        ))
    return verdicts, issues, domain
