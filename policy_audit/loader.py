"""Load policy YAML files through PyYAML's safe path and merge them.

Loading uses ``yaml.SafeLoader`` end to end: documents are composed to a
node graph (which keeps source marks for provenance and lets us detect
recursive aliases before construction), then constructed with the real
``SafeConstructor`` so scalar resolution and ``<<`` merge keys behave
exactly as in production parsing.

Merge semantics ("真实合并"): mappings merge key-by-key recursively, the
``rules`` sequences of the inputs concatenate in file order, and for any
other scalar/sequence conflict the later file wins.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

RULES_KEY = "rules"


@dataclass(frozen=True)
class Provenance:
    """Where a policy fragment came from (line/column are 1-based)."""

    path: str
    line: int
    column: int

    def __str__(self) -> str:
        return "%s:%d:%d" % (self.path, self.line, self.column)


@dataclass
class Issue:
    """A finding that keeps a file or rule out of the effective policy.

    ``kind`` is one of: ``load_error``, ``circular_reference``,
    ``conflicting_definitions``, ``unsupported_condition``.
    """

    kind: str
    message: str
    provenance: Optional[Provenance] = None
    rule_id: Optional[str] = None


@dataclass
class RuleEntry:
    """A rule as constructed by SafeLoader, plus where it was defined."""

    data: dict
    provenance: Provenance
    source_index: int

    @property
    def rule_id(self) -> Optional[str]:
        rid = self.data.get("id")
        return rid if isinstance(rid, str) else None


@dataclass
class LoadedPolicy:
    """The effective policy after real loading and merging."""

    data: dict
    rules: list = field(default_factory=list)  # list[RuleEntry]
    issues: list = field(default_factory=list)  # list[Issue]
    files: list = field(default_factory=list)  # list[str]


def _find_cycle(root: Node) -> Optional[Node]:
    """Return a node that closes an anchor/alias cycle, or None."""
    seen = set()
    active = set()

    def visit(node: Node) -> Optional[Node]:
        node_id = id(node)
        if node_id in active:
            return node
        if node_id in seen:
            return None
        seen.add(node_id)
        active.add(node_id)
        children = []
        if isinstance(node, MappingNode):
            for key_node, value_node in node.value:
                children.append(key_node)
                children.append(value_node)
        elif isinstance(node, SequenceNode):
            children.extend(node.value)
        for child in children:
            hit = visit(child)
            if hit is not None:
                return hit
        active.discard(node_id)
        return None

    return visit(root)


def _provenance(path: str, node: Node) -> Provenance:
    mark = node.start_mark
    return Provenance(path=path, line=mark.line + 1, column=mark.column + 1)


def _rules_node(root: Node) -> Optional[SequenceNode]:
    if not isinstance(root, MappingNode):
        return None
    for key_node, value_node in root.value:
        if (
            isinstance(key_node, ScalarNode)
            and key_node.value == RULES_KEY
            and isinstance(value_node, SequenceNode)
        ):
            return value_node
    return None


def _load_one(path: str) -> tuple:
    """Load one file; return (data, rule_entries, issues)."""
    try:
        with open(path, "r", encoding="utf-8") as stream:
            text = stream.read()
    except OSError as exc:
        return None, [], [Issue("load_error", "cannot read file: %s" % exc,
                                Provenance(path, 1, 1))]

    loader = yaml.SafeLoader(text)
    try:
        root = loader.get_single_node()
    except yaml.YAMLError as exc:
        loader.dispose()
        return None, [], [Issue("load_error", "YAML parse error: %s" % exc,
                                Provenance(path, 1, 1))]

    if root is None:
        loader.dispose()
        return {}, [], []

    cycle = _find_cycle(root)
    if cycle is not None:
        loader.dispose()
        return None, [], [Issue(
            "circular_reference",
            "anchor/alias cycle detected; document excluded from the merge",
            _provenance(path, cycle),
        )]

    try:
        data = loader.construct_document(root)
    except yaml.YAMLError as exc:
        loader.dispose()
        return None, [], [Issue("load_error", "YAML construct error: %s" % exc,
                                Provenance(path, 1, 1))]
    finally:
        loader.dispose()

    if data is None:
        data = {}
    if not isinstance(data, dict):
        return None, [], [Issue(
            "load_error",
            "top-level document must be a mapping, got %s" % type(data).__name__,
            _provenance(path, root),
        )]

    entries = []
    issues = []
    rules_node = _rules_node(root)
    raw_rules = data.get(RULES_KEY)
    if RULES_KEY in data and not isinstance(raw_rules, list):
        issues.append(Issue(
            "unsupported_condition",
            "top-level %r must be a sequence of rule mappings, got %s; "
            "file's rules excluded from the analysis"
            % (RULES_KEY, type(raw_rules).__name__),
            _provenance(path, root),
        ))
    elif rules_node is not None and isinstance(raw_rules, list):
        for index, item_node in enumerate(rules_node.value):
            if index < len(raw_rules) and isinstance(raw_rules[index], dict):
                entries.append(RuleEntry(
                    data=raw_rules[index],
                    provenance=_provenance(path, item_node),
                    source_index=-1,  # assigned after the merge
                ))
            else:
                issues.append(Issue(
                    "unsupported_condition",
                    "rule entry #%d is not a mapping; excluded from the "
                    "analysis" % (index + 1),
                    _provenance(path, item_node),
                ))
    return data, entries, issues


def _deep_merge(base: Any, override: Any, key_path: tuple = ()) -> Any:
    if (
        isinstance(base, dict)
        and isinstance(override, dict)
    ):
        merged = dict(base)
        for key, value in override.items():
            if key in merged:
                merged[key] = _deep_merge(merged[key], value, key_path + (key,))
            else:
                merged[key] = value
        return merged
    if (
        key_path == (RULES_KEY,)
        and isinstance(base, list)
        and isinstance(override, list)
    ):
        return list(base) + list(override)
    return override


def _rule_signature(data: dict) -> Any:
    def freeze(value: Any) -> Any:
        if isinstance(value, dict):
            return tuple(sorted((k, freeze(v)) for k, v in value.items()))
        if isinstance(value, list):
            return tuple(freeze(v) for v in value)
        return value

    return freeze(data)


def _resolve_conflicts(entries: list) -> tuple:
    """Split entries into (effective, issues) by rule id."""
    by_id = {}
    excluded = set()
    issues = []
    for entry in entries:
        rid = entry.rule_id
        if rid is None:
            continue
        by_id.setdefault(rid, []).append(entry)
    for rid, group in by_id.items():
        signatures = {_rule_signature(e.data) for e in group}
        if len(group) > 1 and len(signatures) > 1:
            where = ", ".join(str(e.provenance) for e in group)
            issues.append(Issue(
                "conflicting_definitions",
                "rule id %r defined %d times with different content (%s); "
                "all copies excluded from the effective policy"
                % (rid, len(group), where),
                group[0].provenance,
                rid,
            ))
            excluded.update(id(e) for e in group)
    # Keep first occurrence of each id, in original merge order.
    seen_ids = set()
    effective = []
    for entry in entries:
        if id(entry) in excluded:
            continue
        rid = entry.rule_id
        if rid is not None:
            if rid in seen_ids:
                continue  # identical re-definition is harmless
            seen_ids.add(rid)
        effective.append(entry)
    return effective, issues


def load_policy(paths) -> LoadedPolicy:
    """Load and merge policy files in order; later files win conflicts."""
    merged: Any = {}
    all_entries = []
    issues = []
    files = []
    for path in paths:
        files.append(path)
        data, entries, file_issues = _load_one(path)
        issues.extend(file_issues)
        if data is None:
            continue
        merged = _deep_merge(merged, data)
        all_entries.extend(entries)

    effective, conflict_issues = _resolve_conflicts(all_entries)
    issues.extend(conflict_issues)
    for index, entry in enumerate(effective):
        entry.source_index = index

    return LoadedPolicy(
        data=merged if isinstance(merged, dict) else {},
        rules=effective,
        issues=issues,
        files=files,
    )
