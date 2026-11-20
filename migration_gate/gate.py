"""Core migration-gate logic.

The gate loads two YAML documents (before/after a rewrite) through PyYAML's
safe loading path, resolves a list of protected key paths in both, and
compares the reachable object graphs for:

* effective values (merge keys already resolved by the safe constructor),
* exact Python types,
* object-sharing relationships (which paths point at the same object).

Anchor names are deliberately ignored: only the sharing topology matters.
Documents that the safe path cannot handle, or that exceed configured
bounds, produce a REVIEW verdict with explicit reasons instead of a
pass/fail decision.
"""

import math
from dataclasses import dataclass, field

import yaml

DEFAULT_MAX_NODES = 10000
DEFAULT_MAX_DEPTH = 100

VERDICT_PASS = "PASS"
VERDICT_FAIL = "FAIL"
VERDICT_REVIEW = "REVIEW"

_MERGE_TAG = "tag:yaml.org,2002:merge"


@dataclass
class Finding:
    kind: str
    paths: list
    detail: str

    def to_dict(self):
        return {"kind": self.kind, "paths": list(self.paths), "detail": self.detail}


@dataclass
class DocumentEvidence:
    label: str
    node_count: int = 0
    max_depth: int = 0
    merge_keys: list = field(default_factory=list)
    shared_groups: list = field(default_factory=list)
    cycles: list = field(default_factory=list)

    def to_dict(self):
        return {
            "node_count": self.node_count,
            "max_depth": self.max_depth,
            "merge_keys": list(self.merge_keys),
            "shared_groups": [list(group) for group in self.shared_groups],
            "cycles": list(self.cycles),
        }


@dataclass
class GateReport:
    verdict: str
    protected_paths: list
    findings: list = field(default_factory=list)
    review_reasons: list = field(default_factory=list)
    evidence: dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "verdict": self.verdict,
            "protected_paths": list(self.protected_paths),
            "findings": [finding.to_dict() for finding in self.findings],
            "review_reasons": list(self.review_reasons),
            "evidence": {
                label: evidence.to_dict()
                for label, evidence in self.evidence.items()
            },
        }

    def to_yaml(self):
        return yaml.safe_dump(
            self.to_dict(), allow_unicode=True, sort_keys=False, default_flow_style=False
        )


class _BoundsExceeded(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _node_key_name(key_node):
    if isinstance(key_node, yaml.ScalarNode):
        return str(key_node.value)
    return "<complex-key>"


def _inspect_node_graph(root, evidence, max_nodes, max_depth):
    """Walk the composed node graph (cycle-safe) to enforce bounds and
    collect merge-key evidence."""
    visited = set()
    in_progress = {}

    def visit(node, path, depth):
        if node is None:
            return
        node_id = id(node)
        if node_id in visited:
            return
        if node_id in in_progress:
            evidence.cycles.append("%s -> %s" % (path, in_progress[node_id]))
            return
        evidence.node_count += 1
        if evidence.node_count > max_nodes:
            raise _BoundsExceeded(
                "节点数超过上限 %d（越界）" % max_nodes
            )
        if depth > max_depth:
            raise _BoundsExceeded(
                "嵌套深度超过上限 %d（越界）" % max_depth
            )
        evidence.max_depth = max(evidence.max_depth, depth)
        in_progress[node_id] = path
        if isinstance(node, yaml.MappingNode):
            for key_node, value_node in node.value:
                if getattr(key_node, "tag", None) == _MERGE_TAG:
                    evidence.merge_keys.append(path)
                visit(value_node, "%s.%s" % (path, _node_key_name(key_node)), depth + 1)
        elif isinstance(node, yaml.SequenceNode):
            for index, item in enumerate(node.value):
                visit(item, "%s[%d]" % (path, index), depth + 1)
        in_progress.pop(node_id, None)
        visited.add(node_id)

    visit(root, "$", 1)


def _collect_object_evidence(root, evidence):
    """Walk the constructed object graph (cycle-safe) to record shared
    reference groups and cycles."""
    first_seen = {}
    state = {}

    def visit(obj, path):
        if isinstance(obj, dict):
            children = [("%s.%s" % (path, key), value) for key, value in obj.items()]
        elif isinstance(obj, list):
            children = [
                ("%s[%d]" % (path, index), value) for index, value in enumerate(obj)
            ]
        else:
            return
        obj_id = id(obj)
        if obj_id in first_seen:
            evidence.shared_groups.append([first_seen[obj_id], path])
            if state.get(obj_id) == "open":
                evidence.cycles.append("%s -> %s" % (path, first_seen[obj_id]))
            return
        first_seen[obj_id] = path
        state[obj_id] = "open"
        for child_path, value in children:
            visit(value, child_path)
        state[obj_id] = "done"

    visit(root, "$")


def _load_document(text, label, max_nodes, max_depth):
    """Returns (obj, evidence, review_reasons)."""
    evidence = DocumentEvidence(label=label)
    reasons = []
    try:
        nodes = list(yaml.compose_all(text, Loader=yaml.SafeLoader))
    except yaml.YAMLError as exc:
        reasons.append("%s: 安全解析器拒绝该文档: %s" % (label, exc))
        return None, evidence, reasons
    if len(nodes) != 1:
        reasons.append(
            "%s: 期望 1 个文档，实际 %d 个（越界）" % (label, len(nodes))
        )
        return None, evidence, reasons
    try:
        _inspect_node_graph(nodes[0], evidence, max_nodes, max_depth)
    except _BoundsExceeded as exc:
        reasons.append("%s: %s" % (label, exc.reason))
        return None, evidence, reasons
    try:
        obj = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        reasons.append("%s: 安全构造器拒绝该文档: %s" % (label, exc))
        return None, evidence, reasons
    _collect_object_evidence(obj, evidence)
    return obj, evidence, reasons


def _parse_path(spec):
    segments = []
    for part in spec.split("."):
        if part == "":
            raise ValueError("无效的键路径: %r" % spec)
        segments.append(part)
    return segments


def _resolve(obj, segments):
    """Resolve a parsed protected path. Returns (found, value)."""
    current = obj
    for segment in segments:
        if isinstance(current, dict):
            if segment in current:
                current = current[segment]
            elif segment.isdigit() and int(segment) in current:
                current = current[int(segment)]
            else:
                return False, None
        elif isinstance(current, list):
            if not segment.isdigit():
                return False, None
            index = int(segment)
            if index >= len(current):
                return False, None
            current = current[index]
        else:
            return False, None
    return True, current


def _child_path(path, key):
    return "%s.%s" % (path, key)


def _index_path(path, index):
    return "%s[%d]" % (path, index)


def _scalar_equal(before, after):
    if before == after:
        return True
    if isinstance(before, float) and isinstance(after, float):
        return math.isnan(before) and math.isnan(after)
    return False


class _GraphComparator:
    """Parallel walk of the before/after object graphs.

    Maintains a bijection between before-objects and after-objects. A
    consistent bijection means identical sharing topology regardless of
    anchor names; any conflict is reported as a sharing change with the
    two involved paths.
    """

    def __init__(self):
        self.findings = []
        self._seen = set()
        self._before_pairs = {}
        self._after_pairs = {}

    def _add(self, kind, paths, detail):
        key = (kind, tuple(paths), detail)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(Finding(kind=kind, paths=list(paths), detail=detail))

    def compare(self, before, after, path):
        before_container = isinstance(before, (dict, list))
        after_container = isinstance(after, (dict, list))
        if before_container and after_container:
            if isinstance(before, dict) != isinstance(after, dict):
                self._add(
                    "type_mismatch",
                    [path],
                    "容器类型不同: %s -> %s"
                    % (type(before).__name__, type(after).__name__),
                )
                return
            if not self._pair(before, after, path):
                return
            if isinstance(before, dict):
                self._compare_dicts(before, after, path)
            else:
                self._compare_lists(before, after, path)
            return
        if before_container or after_container:
            self._add(
                "type_mismatch",
                [path],
                "一侧为容器另一侧为标量: %s -> %s"
                % (type(before).__name__, type(after).__name__),
            )
            return
        if type(before) is not type(after):
            self._add(
                "type_mismatch",
                [path],
                "标量类型不同: %s(%r) -> %s(%r)"
                % (
                    type(before).__name__,
                    before,
                    type(after).__name__,
                    after,
                ),
            )
            return
        if not _scalar_equal(before, after):
            self._add(
                "value_mismatch",
                [path],
                "值不同: %r -> %r" % (before, after),
            )

    def _pair(self, before, after, path):
        before_id = id(before)
        after_id = id(after)
        known_before = self._before_pairs.get(before_id)
        known_after = self._after_pairs.get(after_id)
        if known_before is None and known_after is None:
            self._before_pairs[before_id] = (after_id, path)
            self._after_pairs[after_id] = (before_id, path)
            return True
        if (
            known_before is not None
            and known_after is not None
            and known_before[0] == after_id
            and known_after[0] == before_id
        ):
            return False
        first_path = known_before[1] if known_before is not None else known_after[1]
        self._add(
            "sharing_changed",
            [first_path, path],
            "共享关系变化: 路径 %s 与 %s 的对象共享关系在改写前后不一致"
            % (first_path, path),
        )
        return False

    def _compare_dicts(self, before, after, path):
        before_keys = set(before)
        after_keys = set(after)
        for key in sorted(before_keys - after_keys, key=repr):
            self._add(
                "structure_mismatch",
                [_child_path(path, key)],
                "改写后缺少键: %r" % (key,),
            )
        for key in sorted(after_keys - before_keys, key=repr):
            self._add(
                "structure_mismatch",
                [_child_path(path, key)],
                "改写后新增键: %r" % (key,),
            )
        for key in sorted(before_keys & after_keys, key=repr):
            self.compare(before[key], after[key], _child_path(path, key))

    def _compare_lists(self, before, after, path):
        if len(before) != len(after):
            self._add(
                "structure_mismatch",
                [path],
                "序列长度不同: %d -> %d" % (len(before), len(after)),
            )
        for index in range(min(len(before), len(after))):
            self.compare(before[index], after[index], _index_path(path, index))


def run_gate(before_text, after_text, protected_paths,
             max_nodes=DEFAULT_MAX_NODES, max_depth=DEFAULT_MAX_DEPTH):
    """Run the migration gate.

    ``before_text`` / ``after_text`` are YAML documents (strings);
    ``protected_paths`` is a list of dot-separated key paths (integer
    segments index into sequences). Returns a GateReport.
    """
    protected_paths = list(protected_paths)
    findings = []
    review_reasons = []
    evidence = {}

    before_obj, before_evidence, before_reasons = _load_document(
        before_text, "before", max_nodes, max_depth
    )
    after_obj, after_evidence, after_reasons = _load_document(
        after_text, "after", max_nodes, max_depth
    )
    evidence["before"] = before_evidence
    evidence["after"] = after_evidence
    review_reasons.extend(before_reasons)
    review_reasons.extend(after_reasons)

    if review_reasons:
        return GateReport(
            verdict=VERDICT_REVIEW,
            protected_paths=protected_paths,
            findings=findings,
            review_reasons=review_reasons,
            evidence=evidence,
        )

    comparator = _GraphComparator()
    for spec in protected_paths:
        try:
            segments = _parse_path(spec)
        except ValueError as exc:
            review_reasons.append(str(exc))
            continue
        found_before, before_value = _resolve(before_obj, segments)
        found_after, after_value = _resolve(after_obj, segments)
        if not found_before or not found_after:
            missing_in = []
            if not found_before:
                missing_in.append("before")
            if not found_after:
                missing_in.append("after")
            findings.append(
                Finding(
                    kind="path_missing",
                    paths=[spec],
                    detail="受保护路径在 %s 文档中不存在" % "/".join(missing_in),
                )
            )
            continue
        comparator.compare(before_value, after_value, spec)

    findings.extend(comparator.findings)

    if review_reasons:
        verdict = VERDICT_REVIEW
    elif findings:
        verdict = VERDICT_FAIL
    else:
        verdict = VERDICT_PASS
    return GateReport(
        verdict=verdict,
        protected_paths=protected_paths,
        findings=findings,
        review_reasons=review_reasons,
        evidence=evidence,
    )
