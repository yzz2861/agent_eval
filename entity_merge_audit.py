#!/usr/bin/env python3
"""Audit purpose-scoped STIX entity merge and separation constraints.

Input JSON may contain ``positive``, ``negative``, ``evidence``,
``constraints``, ``objects``, and ``purposes``. Edge records accept
``a``/``b`` or STIX ``source_ref``/``target_ref`` endpoints and optional
``purposes``, ``source``, and ``mandatory`` fields. STIX Bundle relationship
objects are also accepted as constraint records.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict, deque
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path


POSITIVE_RELATIONS = {
    "same", "same_as", "equivalent", "equivalence", "must_link",
    "positive", "merge", "merged_into",
}
NEGATIVE_RELATIONS = {
    "different", "different_from", "distinct", "not_same",
    "cannot_merge", "do_not_merge", "negative", "separate",
}
PURPOSE_WILDCARDS = {"*", "all", "any"}


@dataclass(frozen=True)
class Edge:
    a: str
    b: str
    relation: str
    source: str = ""
    purposes: tuple[str, ...] = ()
    mandatory: bool = True


class DSU:
    def __init__(self, nodes):
        self.parent = {node: node for node in nodes}
        self.rank = {node: 0 for node in nodes}

    def add(self, node):
        if node not in self.parent:
            self.parent[node] = node
            self.rank[node] = 0

    def find(self, node):
        self.add(node)
        while self.parent[node] != node:
            self.parent[node] = self.parent[self.parent[node]]
            node = self.parent[node]
        return node

    def union(self, left, right):
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return
        if self.rank[left_root] < self.rank[right_root]:
            left_root, right_root = right_root, left_root
        self.parent[right_root] = left_root
        if self.rank[left_root] == self.rank[right_root]:
            self.rank[left_root] += 1

    def groups(self):
        result = defaultdict(list)
        for node in self.parent:
            result[self.find(node)].append(node)
        return sorted((sorted(members) for members in result.values()), key=lambda item: item[0])


def normalize_relation(relation):
    return str(relation or "").strip().lower().replace("-", "_").replace(" ", "_")


def is_negative_relation(relation):
    normalized = normalize_relation(relation)
    return (
        normalized in NEGATIVE_RELATIONS
        or "cannot" in normalized
        or "do_not" in normalized
        or "different" in normalized
        or "distinct" in normalized
        or "separat" in normalized
        or "not_same" in normalized
    )


def is_positive_relation(relation):
    normalized = normalize_relation(relation)
    if is_negative_relation(normalized):
        return False
    return (
        normalized in POSITIVE_RELATIONS
        or "same_as" in normalized
        or "equival" in normalized
        or "must_link" in normalized
        or "merge" in normalized
    )


def first_value(record, names):
    for name in names:
        value = record.get(name)
        if value is not None:
            return value
    return None


def as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value]
    return [str(value)]


def parse_edge(record, default_relation, default_mandatory):
    left = first_value(record, ("a", "left", "object_a", "id_a", "source_ref", "source", "from"))
    right = first_value(record, ("b", "right", "object_b", "id_b", "target_ref", "target", "to"))
    if left is None or right is None:
        return None
    relation = first_value(
        record,
        ("relation", "relationship", "relationship_type", "constraint", "constraint_type", "type"),
    ) or default_relation
    source = first_value(record, ("source", "provenance", "evidence_id", "id", "ref")) or ""
    purposes = tuple(as_list(first_value(record, ("purposes", "purpose", "use_cases", "scopes"))))
    mandatory = bool(record.get("mandatory", default_mandatory))
    return Edge(str(left), str(right), str(relation), str(source), purposes, mandatory)


def dataset_from_json(value):
    if isinstance(value, list):
        if value and all(isinstance(item, dict) for item in value):
            if any("source_ref" in item or "target_ref" in item for item in value):
                return {"constraints": value}
        return {"objects": value}
    if not isinstance(value, dict):
        return {}
    if value.get("type") == "bundle" and isinstance(value.get("objects"), list):
        return {
            "objects": [item for item in value["objects"] if isinstance(item, dict) and "id" in item],
            "constraints": [
                item for item in value["objects"]
                if isinstance(item, dict) and item.get("type") == "relationship"
            ],
        }
    return value


def merge_datasets(datasets):
    merged = {"objects": [], "constraints": [], "positive": [], "negative": [], "evidence": []}
    purposes = []
    for dataset in datasets:
        dataset = dataset_from_json(dataset)
        for key in merged:
            value = dataset.get(key, [])
            if isinstance(value, list):
                merged[key].extend(value)
        purposes.extend(as_list(dataset.get("purposes")))
    if purposes:
        merged["purposes"] = purposes
    return merged


def load_dataset(paths):
    datasets = []
    for path in paths:
        with Path(path).open("r", encoding="utf-8") as handle:
            datasets.append(json.load(handle))
    return merge_datasets(datasets)


def collect_nodes(dataset, edges):
    nodes = set()
    for obj in dataset.get("objects", []):
        if isinstance(obj, str):
            nodes.add(obj)
        elif isinstance(obj, dict) and obj.get("id"):
            nodes.add(str(obj["id"]))
    for key in ("nodes", "entities"):
        for obj in dataset.get(key, []):
            if isinstance(obj, str):
                nodes.add(obj)
            elif isinstance(obj, dict) and obj.get("id"):
                nodes.add(str(obj["id"]))
    for edge in edges:
        nodes.add(edge.a)
        nodes.add(edge.b)
    return nodes


def collect_edges(dataset):
    edges = []
    specs = [
        ("constraints", None, True),
        ("positive", "positive", True),
        ("must_link", "must_link", True),
        ("same_as", "same_as", True),
        ("negative", "negative", True),
        ("cannot_merge", "cannot_merge", True),
        ("different_from", "different_from", True),
        ("evidence", "equivalence_evidence", False),
        ("equivalence_evidence", "equivalence_evidence", False),
    ]
    for key, default_relation, mandatory in specs:
        for record in dataset.get(key, []):
            if not isinstance(record, dict):
                continue
            edge = parse_edge(record, default_relation or "constraint", mandatory)
            if edge is not None:
                edges.append(edge)
    return edges


def edge_applies(edge, purpose):
    if purpose is None:
        return True
    if not edge.purposes:
        return True
    normalized = {normalize_relation(item) for item in edge.purposes}
    return bool(normalized & {normalize_relation(purpose), "*", "all", "any"})


def edge_reference(edge, index=None):
    label = f"{edge.a} ~ {edge.b} [{edge.relation}]"
    if edge.source:
        label += f" ({edge.source})"
    if index is not None:
        return {"index": index, "edge": label}
    return label


def shortest_path(adjacency, start, target):
    if start == target:
        return []
    queue = deque([start])
    parent = {start: (None, None)}
    while queue:
        node = queue.popleft()
        for neighbor, edge_index in adjacency.get(node, []):
            if neighbor in parent:
                continue
            parent[neighbor] = (node, edge_index)
            if neighbor == target:
                path = []
                current = target
                while parent[current][0] is not None:
                    previous, edge_index = parent[current]
                    path.append(edge_index)
                    current = previous
                path.reverse()
                return path
            queue.append(neighbor)
    return None


def build_dsu(nodes, positive_edges, excluded=frozenset()):
    dsu = DSU(nodes)
    for index, edge in positive_edges:
        if index not in excluded:
            dsu.union(edge.a, edge.b)
    return dsu


def negative_violations(dsu, negative_edges):
    return [
        (index, edge)
        for index, edge in negative_edges
        if dsu.find(edge.a) == dsu.find(edge.b)
    ]


def groups_after_removals(nodes, positive_edges, excluded):
    return build_dsu(nodes, positive_edges, excluded).groups()


def diagnostic_repairs(nodes, positive_edges, negative_edges, conflicts):
    if not conflicts or len(positive_edges) > 16:
        return []
    indices = [index for index, _ in positive_edges]
    max_removals = min(4, len(indices))
    for removal_count in range(1, max_removals + 1):
        options = []
        for removed in combinations(indices, removal_count):
            excluded = frozenset(removed)
            dsu = build_dsu(nodes, positive_edges, excluded)
            if not negative_violations(dsu, negative_edges):
                options.append({
                    "remove_edges": [edge_reference(dict(positive_edges)[index], index) for index in removed],
                    "groups": groups_after_removals(nodes, positive_edges, excluded),
                })
        if options:
            return options[:20]
    return []


def component_pair_prohibited(root_left, root_right, prohibited_pairs):
    left = (min(root_left, root_right), max(root_left, root_right))
    return left in prohibited_pairs


def audit_purpose(nodes, all_edges, purpose):
    edges = [(index, edge) for index, edge in enumerate(all_edges) if edge_applies(edge, purpose)]
    positive_edges = []
    negative_edges = []
    advisory_edges = []
    unknown_edges = []
    for index, edge in edges:
        if is_negative_relation(edge.relation):
            negative_edges.append((index, edge))
        elif is_positive_relation(edge.relation):
            if edge.mandatory:
                positive_edges.append((index, edge))
            else:
                advisory_edges.append((index, edge))
        else:
            unknown_edges.append(edge_reference(edge, index))

    scoped_nodes = set(nodes)
    for _, edge in edges:
        scoped_nodes.update((edge.a, edge.b))

    adjacency = defaultdict(list)
    for index, edge in positive_edges:
        adjacency[edge.a].append((edge.b, index))
        adjacency[edge.b].append((edge.a, index))

    dsu = build_dsu(scoped_nodes, positive_edges)
    conflicts = []
    for neg_index, negative in negative_edges:
        if dsu.find(negative.a) != dsu.find(negative.b):
            continue
        path_indices = shortest_path(adjacency, negative.a, negative.b) or []
        conflicts.append({
            "negative_constraint": edge_reference(negative, neg_index),
            "positive_path": [
                edge_reference(next(edge for idx, edge in edges if idx == path_index), path_index)
                for path_index in path_indices
            ],
            "minimal_conflict_set": [
                edge_reference(next(edge for idx, edge in edges if idx == path_index), path_index)
                for path_index in path_indices
            ] + [edge_reference(negative, neg_index)],
        })

    result = {
        "purpose": purpose or "default",
        "applicable_edge_count": len(edges),
        "unknown_relations": unknown_edges,
    }

    if conflicts:
        result.update({
            "status": "incompatible_hard_constraints",
            "compatible_grouping": None,
            "forced_positive_closure": dsu.groups(),
            "minimal_conflicts": conflicts,
            "minimum_retraction_alternatives": diagnostic_repairs(
                scoped_nodes, positive_edges, negative_edges, conflicts
            ),
        })
        return result

    forced_groups = dsu.groups()
    prohibited_pairs = set()
    for _, edge in negative_edges:
        left_root = dsu.find(edge.a)
        right_root = dsu.find(edge.b)
        if left_root != right_root:
            prohibited_pairs.add((min(left_root, right_root), max(left_root, right_root)))

    class_count = len(forced_groups)
    partition_determined = class_count <= 1 or len(prohibited_pairs) == class_count * (class_count - 1) // 2

    advisory_by_root = []
    advisory_adjacency = defaultdict(list)
    for index, edge in advisory_edges:
        left_root = dsu.find(edge.a)
        right_root = dsu.find(edge.b)
        if left_root == right_root:
            continue
        advisory_by_root.append((index, edge, left_root, right_root))
        advisory_adjacency[left_root].append((right_root, index))
        advisory_adjacency[right_root].append((left_root, index))

    seen_roots = set()
    safe_optional_groups = []
    evidence_conflicts = []
    for start_root in advisory_adjacency:
        if start_root in seen_roots:
            continue
        queue = deque([start_root])
        component = set()
        while queue:
            root = queue.popleft()
            if root in seen_roots:
                continue
            seen_roots.add(root)
            component.add(root)
            for neighbor, _ in advisory_adjacency.get(root, []):
                if neighbor not in seen_roots:
                    queue.append(neighbor)
        forbidden_inside = []
        for left_root, right_root in combinations(sorted(component), 2):
            if component_pair_prohibited(left_root, right_root, prohibited_pairs):
                forbidden_inside.append([left_root, right_root])
        member_group = []
        root_to_members = {dsu.find(node): group for group in forced_groups for node in group}
        for root in component:
            member_group.extend(root_to_members.get(root, [root]))
        if forbidden_inside:
            evidence_conflicts.append({
                "evidence_component": sorted(member_group),
                "forbidden_class_pairs": forbidden_inside,
                "advice": "Do not merge this evidence component wholesale; multiple evidence-aligned cuts are possible.",
            })
        else:
            safe_optional_groups.append(sorted(member_group))

    no_evidence = not positive_edges and not advisory_edges
    result.update({
        "status": "insufficient_evidence" if no_evidence else (
            "review_required" if evidence_conflicts else "compatible"
        ),
        "partition_logically_determined": partition_determined,
        "conservative_grouping": forced_groups,
        "safe_optional_evidence_groups": safe_optional_groups,
        "evidence_conflicts": evidence_conflicts,
        "prohibited_class_pairs": sorted([list(pair) for pair in prohibited_pairs]),
    })
    if not partition_determined:
        result["underdetermination"] = (
            "Must-link closure is consistent, but some classes are neither required to merge nor required to separate."
        )
    return result


def audit_dataset(dataset, purposes=None):
    edges = collect_edges(dataset)
    nodes = collect_nodes(dataset, edges)
    if purposes is None:
        purposes = dataset.get("purposes")
    if purposes is None:
        scoped_purposes = sorted({
            purpose
            for edge in edges
            for purpose in edge.purposes
            if normalize_relation(purpose) not in PURPOSE_WILDCARDS
        })
        purposes = scoped_purposes or [None]
    return {
        "purpose_reports": [audit_purpose(nodes, edges, purpose) for purpose in purposes],
    }


def selftest():
    dataset = {
        "positive": [
            {"a": "A", "b": "B", "source": "evidence-AB"},
            {"a": "B", "b": "C", "source": "evidence-BC"},
        ],
        "negative": [{"a": "A", "b": "C", "source": "legal-AC"}],
    }
    report = audit_dataset(dataset, purposes=[None])["purpose_reports"][0]
    assert report["status"] == "incompatible_hard_constraints"
    conflict = report["minimal_conflicts"][0]["minimal_conflict_set"]
    assert [item["edge"] for item in conflict] == [
        "A ~ B [positive] (evidence-AB)",
        "B ~ C [positive] (evidence-BC)",
        "A ~ C [negative] (legal-AC)",
    ]
    groups = {tuple(tuple(group) for group in option["groups"]) for option in report["minimum_retraction_alternatives"]}
    assert groups == {
        (("A", "B"), ("C",)),
        (("A",), ("B", "C")),
    }, groups

    advisory = {
        "evidence": [
            {"a": "A", "b": "B"},
            {"a": "B", "b": "C"},
        ],
        "negative": [{"a": "A", "b": "C"}],
    }
    advisory_report = audit_dataset(advisory, purposes=[None])["purpose_reports"][0]
    assert advisory_report["status"] == "review_required"
    assert advisory_report["evidence_conflicts"]
    print(json.dumps({"hard": report, "advisory": advisory_report}, ensure_ascii=False, indent=2))


def main():
    parser = argparse.ArgumentParser(description="Audit STIX entity merge evidence and constraints.")
    parser.add_argument("inputs", nargs="*", help="JSON constraint/evidence files or STIX bundles")
    parser.add_argument("--purpose", action="append", help="purpose to evaluate; repeat for multiple purposes")
    parser.add_argument("--selftest", action="store_true", help="run the built-in A/B/C consistency check")
    args = parser.parse_args()

    if args.selftest:
        selftest()
        return 0
    if not args.inputs:
        parser.error("provide input JSON file(s), or use --selftest")
    report = audit_dataset(load_dataset(args.inputs), purposes=args.purpose)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
