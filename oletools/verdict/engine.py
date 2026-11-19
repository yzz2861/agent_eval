"""Composite verdict engine.

Combines a container tree (model.ContainerNode + model.ContainerEdge) with
per-node detector results (model.DetectorResult) and produces a single,
order-independent security verdict plus the smallest evidence set that
justifies it.

Four node states are distinguished (model.NodeStatus):

* RISK        - at least one detector confirmed a risk;
* CLEAN       - every required capability applicable to the node ran and
                reported no findings;
* UNCOVERED   - the node was parsed but a required capability was not run /
                was skipped (encryption, unknown embedded format, ...);
* UNPARSEABLE - the node or one of its required sub-documents could not be
                parsed (corruption, unreadable stream, cycle, ...).

Rules (full logic in VerdictEngine.evaluate):

1. A confirmed detector finding always blocks. Making a capability optional
   only relaxes coverage requirements; it can never erase a finding.
2. Encryption / unknown format / corruption are structural coverage
   failures, not clean. They produce structural evidence and downgrade the
   node to UNCOVERED / UNPARSEABLE.
3. States propagate child -> parent. A parent is never safer than its worst
   reachable child. Unexamined edges carry the worst state of their target,
   so no unchecked branch can disappear.
4. Nodes referenced from several edges are counted once (deduplicated by
   node id and evidence key).
5. Submitting a new result for the same (node, capability, detector,
   signature) replaces only that evidence (retry); every other finding is
   retained.
"""

import json

from .model import (
    Capability,
    ContainerEdge,
    ContainerNode,
    DetectorResult,
    Evidence,
    EvidenceReason,
    NodeKind,
    NodeStatus,
    Outcome,
    Policy,
    Severity,
    Verdict,
)

_STATUS_ORDER = (
    NodeStatus.CLEAN,
    NodeStatus.UNCOVERED,
    NodeStatus.UNPARSEABLE,
    NodeStatus.RISK,
)
_STATUS_RANK = {status: index for index, status in enumerate(_STATUS_ORDER)}

# Structural reason -> forced node state.
_STRUCTURAL_STATE = {
    EvidenceReason.ENCRYPTED: NodeStatus.UNCOVERED,
    EvidenceReason.UNKNOWN_FORMAT: NodeStatus.UNCOVERED,
    EvidenceReason.CORRUPT: NodeStatus.UNPARSEABLE,
    EvidenceReason.CYCLE: NodeStatus.UNPARSEABLE,
}
# Structural reasons that always downgrade a node and always justify blocking,
# independent of whether their capability is marked required in the policy.
_ALWAYS_BLOCKING_REASONS = frozenset((
    EvidenceReason.ENCRYPTED,
    EvidenceReason.CORRUPT,
    EvidenceReason.CYCLE,
    EvidenceReason.UNKNOWN_FORMAT,
    EvidenceReason.UNEXAMINED_EDGE,
    EvidenceReason.UNKNOWN_EDGE,
))



def worst_status(*statuses):
    """Return the most severe of the given states (CLEAN if empty)."""
    result = NodeStatus.CLEAN
    for status in statuses:
        if status is None:
            continue
        if _STATUS_RANK[status] > _STATUS_RANK[result]:
            result = status
    return result




class VerdictReport(object):
    """Result of VerdictEngine.evaluate (verdict, states and evidence)."""

    def __init__(self, verdict, node_states, evidence, blocking_evidence,
                 node_paths, counts):
        self.verdict = verdict
        self.node_states = dict(node_states)
        self.evidence = list(evidence)
        self.blocking_evidence = list(blocking_evidence)
        self.node_paths = dict(node_paths)
        self.counts = dict(counts)

    @property
    def is_allowed(self):
        return self.verdict == Verdict.ALLOW

    def to_dict(self):
        """Return a canonical JSON-serialisable representation."""
        return {
            'verdict': self.verdict.value,
            'counts': {status.value: self.counts.get(status, 0)
                       for status in _STATUS_ORDER},
            'node_states': {node_id: status.value
                            for node_id, status
                            in sorted(self.node_states.items())},
            'blocking_evidence': [item.to_dict()
                                  for item in self.blocking_evidence],
            'evidence': [item.to_dict() for item in self.evidence],
            'node_paths': {node_id: [list(path) for path in paths]
                           for node_id, paths
                           in sorted(self.node_paths.items())},
        }

    def to_json(self, indent=2):
        """Return canonical JSON; identical trees yield identical text."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True,
                          ensure_ascii=False)

    def __repr__(self):
        return 'VerdictReport(verdict={0}, nodes={1}, evidence={2})'.format(
            self.verdict.value, len(self.node_states), len(self.evidence))


class VerdictEngine(object):
    """Accumulate detector results over a container tree and decide."""

    def __init__(self, roots, edges=(), policy=None, nodes=()):
        if isinstance(roots, ContainerNode):
            roots = [roots]
        roots = list(roots)
        if not roots:
            raise ValueError('at least one root node is required')
        self._roots = []
        self._nodes = {}
        for root in roots:
            if not isinstance(root, ContainerNode):
                raise TypeError('roots must be ContainerNode instances')
            self._roots.append(root)
            self._index_node(root)
        self._edges = []
        for node in nodes:
            self.add_node(node)
        for edge in edges:
            self.add_edge(edge)
        self.policy = policy if policy is not None else Policy()
        # node_id -> {(cap_key, detector, signature): DetectorResult}
        self._results = dict((node_id, {}) for node_id in self._nodes)
        self._attempts = dict((node_id, {}) for node_id in self._nodes)
        # node_id -> list[Evidence] structural evidence
        self._structural = dict((node_id, []) for node_id in self._nodes)
        self._seed_structural_evidence()

    def _index_node(self, node):
        if not isinstance(node, ContainerNode):
            raise TypeError('tree entries must be ContainerNode instances')
        if node.node_id in self._nodes:
            if self._nodes[node.node_id] is not node:
                raise ValueError(
                    'duplicate node_id %r used by different node objects'
                    % node.node_id)
            return
        self._nodes[node.node_id] = node

    def add_node(self, node):
        """Register an extra node (e.g. discovered during traversal)."""
        self._index_node(node)
        if hasattr(self, '_results'):
            self._results.setdefault(node.node_id, {})
            self._attempts.setdefault(node.node_id, {})
            self._structural.setdefault(node.node_id, [])
        return node

    def add_edge(self, edge):
        """Register a parent -> child ContainerEdge, validating endpoints."""
        if not isinstance(edge, ContainerEdge):
            raise TypeError('edges must be ContainerEdge instances')
        if edge.parent_id not in self._nodes:
            raise KeyError('unknown parent node_id: %r' % edge.parent_id)
        if edge.child_id not in self._nodes:
            raise KeyError('unknown child node_id: %r' % edge.child_id)
        self._edges.append(edge)
        return edge

    def _children(self, node_id):
        out = [edge for edge in self._edges if edge.parent_id == node_id]
        return sorted(out, key=lambda item: (item.label, item.child_id))

    @property
    def node_ids(self):
        return frozenset(self._nodes)

    @property
    def roots(self):
        return tuple(self._roots)

    def get_node(self, node_id):
        return self._nodes[node_id]

    def _seed_structural_evidence(self):
        # Materialise node-level parser/format limitations up front so they
        # survive even when no detector ever visits the node.
        for node_id, node in self._nodes.items():
            bucket = self._structural[node_id]
            if node.encrypted:
                bucket.append(Evidence(
                    node_id=node_id,
                    capability=Capability.ENCRYPTION.value,
                    reason=EvidenceReason.ENCRYPTED,
                    severity=Severity.MEDIUM,
                    detail='node content is encrypted and cannot be scanned',
                ))
            if node.kind == NodeKind.UNKNOWN:
                bucket.append(Evidence(
                    node_id=node_id,
                    capability=Capability.UNKNOWN_EMBED.value,
                    reason=EvidenceReason.UNKNOWN_FORMAT,
                    severity=Severity.MEDIUM,
                    detail='embedded object format is not recognised',
                ))
            if node.corrupt or node.parse_error is not None:
                bucket.append(Evidence(
                    node_id=node_id,
                    capability=Capability.PARSER.value,
                    reason=EvidenceReason.CORRUPT,
                    severity=Severity.HIGH,
                    detail=node.parse_error or 'node is corrupt / unreadable',
                ))

    def mark_corrupt(self, node_id, detail=None):
        """Record that a node/sub-document could not be parsed."""
        if node_id not in self._nodes:
            raise KeyError('unknown node_id: %r' % node_id)
        node = self._nodes[node_id]
        node.corrupt = True
        node.parse_error = detail or node.parse_error
        self._structural[node_id].append(Evidence(
            node_id=node_id,
            capability=Capability.PARSER.value,
            reason=EvidenceReason.CORRUPT,
            severity=Severity.HIGH,
            detail=detail or 'node is corrupt / unreadable',
        ))

    def mark_unknown_format(self, node_id, detail=None):
        """Record an unrecognised embedded format (coverage gap)."""
        if node_id not in self._nodes:
            raise KeyError('unknown node_id: %r' % node_id)
        node = self._nodes[node_id]
        node.kind = NodeKind.UNKNOWN
        node.format_hint = detail or node.format_hint
        self._structural[node_id].append(Evidence(
            node_id=node_id,
            capability=Capability.UNKNOWN_EMBED.value,
            reason=EvidenceReason.UNKNOWN_FORMAT,
            severity=Severity.MEDIUM,
            detail=detail or 'embedded object format is not recognised',
        ))

    # ------------------------------------------------------------- inputs
    def submit_result(self, result):
        """Submit one DetectorResult; a retry replaces only that evidence."""
        if not isinstance(result, DetectorResult):
            raise TypeError('expected a DetectorResult instance')
        if result.node_id not in self._nodes:
            raise KeyError('unknown node_id: %r' % result.node_id)
        key = (result.capability_key, result.detector, result.signature)
        bucket = self._results[result.node_id]
        self._attempts.setdefault(result.node_id, {})
        counter = self._attempts[result.node_id]
        counter[key] = counter.get(key, 0) + 1
        bucket[key] = result
        return result

    def submit_results(self, results):
        """Submit many results; submission order never affects output."""
        ordered = sorted(results, key=lambda item: item.dedupe_key())
        for result in ordered:
            self.submit_result(result)

    # ------------------------------------------------------------ graph
    def _reachable(self):
        seen = set()
        stack = [root.node_id for root in sorted(self._roots, key=lambda r: r.node_id)]
        while stack:
            node_id = stack.pop()
            if node_id in seen:
                continue
            seen.add(node_id)
            for edge in reversed(self._children(node_id)):
                if edge.child_id not in seen:
                    stack.append(edge.child_id)
        return seen

    def _find_cycles(self, reachable):
        # Nodes that are part of a reference cycle cannot be fully expanded;
        # they are unparseable rather than silently skipped.
        color = {}
        cyclic = set()

        def visit(node_id, trail):
            color[node_id] = 1
            for edge in self._children(node_id):
                child_id = edge.child_id
                if child_id not in reachable:
                    continue
                if color.get(child_id) == 1 or child_id in trail:
                    cyclic.add(node_id)
                    cyclic.add(child_id)
                elif color.get(child_id, 0) == 0:
                    visit(child_id, trail + (child_id,))
            color[node_id] = 2

        for root in sorted(node.node_id for node in self._roots):
            if color.get(root, 0) == 0:
                visit(root, (root,))
        return cyclic

    def _all_paths(self, reachable):
        # Every root-to-node path: a shared node reached through several
        # branches exposes all paths while the node itself is counted once.
        paths = dict((node_id, set()) for node_id in reachable)

        def walk(node_id, path):
            paths[node_id].add(path)
            for edge in self._children(node_id):
                child_id = edge.child_id
                if child_id not in reachable:
                    continue
                if child_id in path:
                    paths[child_id].add(path + (child_id,))
                    continue
                walk(child_id, path + (child_id,))

        for root in sorted(node.node_id for node in self._roots):
            walk(root, (root,))
        return dict((node_id, sorted(path_set))
                    for node_id, path_set in sorted(paths.items()))

    def _detector_evidence(self, node_id):
        # Translate DetectorResult into Evidence, one per (cap, detector,
        # signature). Retry attempts are carried over for auditability.
        node = self._nodes[node_id]
        out = []
        for key, result in sorted(self._results[node_id].items(),
                                  key=lambda item: item[0]):
            attempts = self._attempts[node_id].get(key, 1)
            cap = result.capability_key
            if result.outcome == Outcome.RISK:
                reason = EvidenceReason.DETECTOR_FINDING
            elif result.outcome == Outcome.ERROR:
                reason = EvidenceReason.DETECTOR_ERROR
            else:
                reason = EvidenceReason.DETECTOR_CLEAN
            out.append(Evidence(
                node_id=node_id,
                capability=cap,
                reason=reason,
                severity=result.severity,
                detector=result.detector,
                detail=result.detail,
                signature=result.signature,
                attempts=attempts,
            ))
        return out

    def _node_own_status(self, node, detector_evidence):
        # Own state of one node, ignoring children.
        node_id = node.node_id
        status = NodeStatus.CLEAN
        gap_evidence = []
        # Structural limitations.
        for evidence in self._structural[node_id]:
            if (evidence.reason in _ALWAYS_BLOCKING_REASONS or
                    self._is_required_evidence(evidence, node)):
                status = worst_status(status,
                                      _STRUCTURAL_STATE[evidence.reason])
        # Detector outcomes. A finding blocks even for optional capabilities.
        for evidence in detector_evidence:
            if evidence.reason == EvidenceReason.DETECTOR_FINDING:
                status = worst_status(status, NodeStatus.RISK)
            elif evidence.reason == EvidenceReason.DETECTOR_ERROR:
                if self._is_required_evidence(evidence, node):
                    status = worst_status(status, NodeStatus.UNPARSEABLE)
        # Coverage: every required capability applicable to this kind must
        # have at least one terminal (CLEAN/RISK) result or structural note.
        terminal_caps = set()
        for evidence in detector_evidence:
            if evidence.reason in (EvidenceReason.DETECTOR_FINDING,
                                   EvidenceReason.DETECTOR_CLEAN):
                terminal_caps.add(evidence.capability)
        for evidence in self._structural[node_id]:
            if (evidence.reason in _ALWAYS_BLOCKING_REASONS or
                    self._is_required_evidence(evidence, node)):
                terminal_caps.add(evidence.capability)
        required_caps = self.policy.required_for(node.kind)
        for cap in sorted(required_caps - terminal_caps):
            gap_evidence.append(Evidence(
                node_id=node_id,
                capability=cap,
                reason=EvidenceReason.CAPABILITY_GAP,
                severity=Severity.MEDIUM,
                detail='required capability was not run on this node',
            ))
            status = worst_status(status, NodeStatus.UNCOVERED)
        return status, gap_evidence

    def _is_required_evidence(self, evidence, node):
        cap = evidence.capability
        return (self.policy.is_required(cap) and
                self.policy.applies_to(cap, node.kind))

    # ---------------------------------------------------------- evaluate
    def evaluate(self):
        """Compute the composite verdict and minimal evidence set."""
        reachable = self._reachable()
        cyclic = self._find_cycles(reachable)
        node_paths = self._all_paths(reachable)

        own_status = {}
        all_evidence = []
        seen_keys = set()

        def add_evidence(evidence):
            key = evidence.dedupe_key()
            if key in seen_keys:
                return None
            seen_keys.add(key)
            all_evidence.append(evidence)
            return evidence

        # 1) own state of every node + structural / cycle evidence
        for node_id in sorted(reachable):
            node = self._nodes[node_id]
            detector_evidence = self._detector_evidence(node_id)
            for evidence in self._structural[node_id]:
                add_evidence(evidence)
            for evidence in detector_evidence:
                add_evidence(evidence)
            if node_id in cyclic:
                add_evidence(Evidence(
                    node_id=node_id,
                    capability=Capability.PARSER.value,
                    reason=EvidenceReason.CYCLE,
                    severity=Severity.HIGH,
                    detail='reference cycle prevents full expansion',
                ))
            status, gap_evidence = self._node_own_status(node,
                                                     detector_evidence)
            for evidence in gap_evidence:
                add_evidence(evidence)
            if node_id in cyclic:
                status = worst_status(status, NodeStatus.UNPARSEABLE)
            own_status[node_id] = status

        # 2) child -> parent propagation: a parent is never safer than its
        # worst reachable child; shared nodes are evaluated once and reused.
        node_states = dict(own_status)
        depth = {}

        def measure(node_id, trail):
            depth[node_id] = max(depth.get(node_id, 0), len(trail))
            for edge in self._children(node_id):
                child_id = edge.child_id
                if child_id in trail or child_id not in reachable:
                    continue
                measure(child_id, trail + (child_id,))

        for root in sorted(node.node_id for node in self._roots):
            measure(root, (root,))
        for node_id in sorted(reachable, key=lambda item: (-depth[item], item)):
            for edge in self._children(node_id):
                child_id = edge.child_id
                if child_id not in reachable:
                    continue
                node_states[node_id] = worst_status(
                    node_states[node_id], node_states[child_id])

        # 3) branch coverage. An unexamined or unknown-format edge carries
        # the worst state of its target, so no unchecked branch can vanish.
        for node_id in sorted(reachable):
            for edge in self._children(node_id):
                child_id = edge.child_id
                if child_id not in reachable:
                    add_evidence(Evidence(
                        node_id=child_id,
                        capability=Capability.PARSER.value,
                        reason=EvidenceReason.UNEXAMINED_EDGE,
                        severity=Severity.MEDIUM,
                        detail='branch target is not reachable from a root',
                        edge=(node_id, child_id)))
                    node_states[node_id] = worst_status(
                        node_states[node_id], NodeStatus.UNCOVERED)
                    continue
                if not edge.examined or not edge.known_format:
                    reason = (EvidenceReason.UNKNOWN_EDGE
                              if not edge.known_format
                              else EvidenceReason.UNEXAMINED_EDGE)
                    add_evidence(Evidence(
                        node_id=child_id,
                        capability=Capability.PARSER.value,
                        reason=reason,
                        severity=Severity.MEDIUM,
                        detail='edge %r was not fully traversed' % edge.label,
                        edge=(node_id, child_id)))
                    node_states[node_id] = worst_status(
                        node_states[node_id], node_states[child_id])

        # 4) final verdict driven by the worst root state.
        root_status = worst_status(*[node_states[root.node_id]
                                     for root in self._roots])
        if root_status == NodeStatus.RISK:
            verdict = Verdict.BLOCK_RISK
        elif root_status == NodeStatus.UNPARSEABLE:
            verdict = Verdict.BLOCK_UNPARSEABLE
        elif root_status == NodeStatus.UNCOVERED:
            verdict = Verdict.BLOCK_UNCOVERED
        else:
            verdict = Verdict.ALLOW

        # 5) minimal blocking evidence. Only evidence that actually justifies
        # the verdict is kept, deduplicated by Evidence.dedupe_key(). Risk
        # blocks alone; otherwise only structural/gap evidence at the
        # blocking severity (or worse) is retained.
        blocking = self._select_blocking(verdict, all_evidence)
        all_evidence = sorted(all_evidence, key=lambda item: item.sort_key())
        blocking = sorted(blocking, key=lambda item: item.sort_key())

        counts = {}
        for status in _STATUS_ORDER:
            counts[status] = sum(1 for value in node_states.values()
                                  if value == status)
        return VerdictReport(
            verdict=verdict,
            node_states=dict(sorted(node_states.items())),
            evidence=all_evidence,
            blocking_evidence=blocking,
            node_paths=node_paths,
            counts=counts)

    def _select_blocking(self, verdict, evidence):
        # Only evidence whose reason can actually produce the verdict is
        # retained, so clean/info records never pollute the minimal set.
        blocking_reasons = {
            Verdict.BLOCK_RISK: (EvidenceReason.DETECTOR_FINDING,),
            Verdict.BLOCK_UNPARSEABLE: (
                EvidenceReason.DETECTOR_FINDING,
                EvidenceReason.DETECTOR_ERROR,
                EvidenceReason.CORRUPT,
                EvidenceReason.CYCLE,
                EvidenceReason.ENCRYPTED,
                EvidenceReason.UNKNOWN_FORMAT,
                EvidenceReason.CAPABILITY_GAP,
                EvidenceReason.UNEXAMINED_EDGE,
                EvidenceReason.UNKNOWN_EDGE,
            ),
            Verdict.BLOCK_UNCOVERED: (
                EvidenceReason.DETECTOR_FINDING,
                EvidenceReason.ENCRYPTED,
                EvidenceReason.UNKNOWN_FORMAT,
                EvidenceReason.CAPABILITY_GAP,
                EvidenceReason.UNEXAMINED_EDGE,
                EvidenceReason.UNKNOWN_EDGE,
                EvidenceReason.CORRUPT,
                EvidenceReason.CYCLE,
            ),
        }.get(verdict, ())
        out = []
        for item in evidence:
            if item.reason not in blocking_reasons:
                continue
            node = self._nodes[item.node_id]
            if item.reason == EvidenceReason.DETECTOR_FINDING:
                # A confirmed finding blocks even if the capability is optional.
                out.append(item)
            elif item.reason in _ALWAYS_BLOCKING_REASONS:
                # Structural parse/coverage failures block regardless of policy.
                out.append(item)
            elif self._is_required_evidence(item, node):
                out.append(item)
        return out

def evaluate(roots, edges=(), results=(), policy=None, nodes=()):
    """Convenience wrapper: build engine, submit results, evaluate once."""
    engine = VerdictEngine(roots, edges=edges, policy=policy, nodes=nodes)
    engine.submit_results(results)
    return engine.evaluate()
