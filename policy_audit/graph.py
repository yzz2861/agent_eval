"""
One-independent-fact adjacency graph and the band-crossing audit.

An *independent fact* is exactly one base metric changing value (for example C:N -> C:H). Two
legal vectors are adjacent when they differ in precisely one metric. We enumerate every legal
adjacency through the scoring kernel, then derive:

* the connected components of the policy-covered subgraph,
* which components touch more than one band ("cross-band connected regions"),
* every single-fact edge whose endpoints land in different bands,
* band-skipping edges (one fact jumps over an intermediate band), and
* a reproducible shortest-change witness (BFS) between any two vectors.

Nothing here fabricates vectors: both endpoints of every edge already exist in the kernel-proven
universe.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from .policy import Policy, VersionPolicy
from .universe import LegalVector, VERSIONS


@dataclass(frozen=True)
class Edge:
    """A legal single-fact change between two scored vectors."""

    metric: str
    old_value: str
    new_value: str
    source: LegalVector
    target: LegalVector

    @property
    def fact(self) -> str:
        return f"{self.metric}:{self.old_value}->{self.new_value}"

    def oriented(self, from_vector: str) -> Tuple[str, str, str, LegalVector, LegalVector]:
        """Return (metric, old, new, source, target) guaranteed to leave from_vector."""
        if self.source.vector == from_vector:
            return self.metric, self.old_value, self.new_value, self.source, self.target
        return self.metric, self.new_value, self.old_value, self.target, self.source

    def as_dict(self) -> Dict:
        return {
            "fact": self.fact,
            "metric": self.metric,
            "change": [self.old_value, self.new_value],
            "source_vector": self.source.vector,
            "source_score": self.source.score,
            "source_band": None,
            "target_vector": self.target.vector,
            "target_score": self.target.score,
            "target_band": None,
        }


@dataclass
class Component:
    """A connected component of the policy-covered adjacency graph."""

    component_id: int
    vectors: List[LegalVector]
    bands: List[str]
    cross_band: bool


@dataclass
class Witness:
    """A reproducible shortest chain of single-fact changes."""

    start: LegalVector
    goal: LegalVector
    edges: List[Edge]
    distance: int

    def as_dict(self) -> Dict:
        chain = [
            {"vector": self.start.vector, "score": self.start.score, "fact": None}
        ]
        current = self.start
        for edge in self.edges:
            current = edge.target if edge.source.vector == current.vector else edge.source
            chain.append(
                {"vector": current.vector, "score": current.score, "fact": edge.fact}
            )
        return {
            "start": self.start.vector,
            "goal": self.goal.vector,
            "distance": self.distance,
            "chain": chain,
        }


class BandGraph:
    """Holds the covered vectors, their bands and all legal adjacencies."""

    def __init__(self, version: str, policy: Policy, covered: Sequence[LegalVector]):
        self.version = version
        self.policy = policy
        self.version_policy: VersionPolicy = policy.version_policy(version)
        self.vectors: List[LegalVector] = list(covered)
        self._index: Dict[Tuple[Tuple[str, str], ...], LegalVector] = {
            lv.values: lv for lv in self.vectors
        }
        self.band_of_vector: Dict[str, str] = {
            lv.vector: self.version_policy.band_of(lv.score).name for lv in self.vectors
        }
        self.metrics: Tuple[str, ...] = VERSIONS[version].mandatory
        self.edges: List[Edge] = []
        self.cross_band_edges: List[Edge] = []
        self.band_skipping_edges: List[Edge] = []
        self.components: List[Component] = []
        self._adjacency: Dict[str, List[Edge]] = {lv.vector: [] for lv in self.vectors}
        self._build_edges()
        self._build_components()

    def _neighbour_key(
        self, lv: LegalVector, metric: str, new_value: str
    ) -> Tuple[Tuple[str, str], ...]:
        values = dict(lv.values)
        values[metric] = new_value
        return tuple((name, values[name]) for name in self.metrics)

    def _build_edges(self) -> None:
        domains = VERSIONS[self.version].domains
        seen: set = set()
        for lv in self.vectors:
            for metric in self.metrics:
                current = lv.value_map[metric]
                for candidate in domains[metric]:
                    if candidate == current:
                        continue
                    neighbour = self._index.get(self._neighbour_key(lv, metric, candidate))
                    if neighbour is None:
                        # Legal kernel vector but excluded by policy: no edge inside the
                        # covered subgraph; recorded separately as a blocked adjacency.
                        continue
                    key = tuple(sorted((lv.vector, neighbour.vector)))
                    if key in seen:
                        continue
                    seen.add(key)
                    edge = Edge(
                        metric=metric,
                        old_value=current,
                        new_value=candidate,
                        source=lv,
                        target=neighbour,
                    )
                    self.edges.append(edge)
                    self._adjacency[lv.vector].append(edge)
                    self._adjacency[neighbour.vector].append(edge)
                    source_band = self.band_of_vector[lv.vector]
                    target_band = self.band_of_vector[neighbour.vector]
                    if source_band != target_band:
                        self.cross_band_edges.append(edge)
                        if self._skips_band(source_band, target_band):
                            self.band_skipping_edges.append(edge)

    def _band_order(self) -> List[str]:
        return [band.name for band in self.version_policy.bands]

    def _skips_band(self, source_band: str, target_band: str) -> bool:
        order = self._band_order()
        gap = abs(order.index(source_band) - order.index(target_band))
        return gap > 1

    def _build_components(self) -> None:
        visited: set = set()
        component_id = 0
        for lv in self.vectors:
            if lv.vector in visited:
                continue
            queue = deque([lv])
            visited.add(lv.vector)
            members: List[LegalVector] = []
            while queue:
                node = queue.popleft()
                members.append(node)
                for edge in self._adjacency[node.vector]:
                    neighbour = (
                        edge.target if edge.source.vector == node.vector else edge.source
                    )
                    if neighbour.vector not in visited:
                        visited.add(neighbour.vector)
                        queue.append(neighbour)
            bands = sorted({self.band_of_vector[node.vector] for node in members})
            self.components.append(
                Component(
                    component_id=component_id,
                    vectors=members,
                    bands=bands,
                    cross_band=len(bands) > 1,
                )
            )
            component_id += 1

    def shortest_witness(
        self, start: LegalVector, goal: LegalVector
    ) -> Optional[Witness]:
        """BFS shortest path of single-fact edges inside the covered subgraph."""
        if start.vector not in self._adjacency or goal.vector not in self._adjacency:
            return None
        if start.vector == goal.vector:
            return Witness(start=start, goal=goal, edges=[], distance=0)
        visited = {start.vector}
        prev: Dict[str, Tuple[str, Edge]] = {}
        queue = deque([start])
        while queue:
            node = queue.popleft()
            if node.vector == goal.vector:
                break
            for edge in self._adjacency[node.vector]:
                neighbour = (
                    edge.target if edge.source.vector == node.vector else edge.source
                )
                if neighbour.vector in visited:
                    continue
                visited.add(neighbour.vector)
                prev[neighbour.vector] = (node.vector, edge)
                queue.append(neighbour)
        if goal.vector not in prev:
            return None
        backwards: List[Tuple[str, Edge]] = []
        cursor = goal.vector
        while cursor != start.vector:
            previous_vector, edge = prev[cursor]
            backwards.append((previous_vector, edge))
            cursor = previous_vector
        backwards.reverse()
        edges: List[Edge] = []
        cursor = start.vector
        for previous_vector, edge in backwards:
            metric, old_value, new_value, source, target = edge.oriented(cursor)
            edges.append(
                Edge(metric, old_value, new_value, source, target)
            )
            cursor = target.vector
        return Witness(start=start, goal=goal, edges=edges, distance=len(edges))

    def cross_band_components(self) -> List[Component]:
        return [component for component in self.components if component.cross_band]

    def blocked_adjacencies(
        self, covered: Sequence[LegalVector], full_universe: Sequence[LegalVector]
    ) -> List[Dict[str, str]]:
        """
        Legal single-fact neighbours that exist in the kernel universe but were excluded by the
        policy allow-list. These are the concrete shape of the missing-candidate rule.
        """
        full_index = {lv.values: lv for lv in full_universe}
        covered_keys = {lv.values for lv in covered}
        domains = VERSIONS[self.version].domains
        blocked: List[Dict[str, str]] = []
        for lv in covered:
            for metric in self.metrics:
                current = lv.value_map[metric]
                for candidate in domains[metric]:
                    if candidate == current:
                        continue
                    key = self._neighbour_key(lv, metric, candidate)
                    if key in full_index and key not in covered_keys:
                        blocked.append(
                            {
                                "from_vector": lv.vector,
                                "fact": f"{metric}:{current}->{candidate}",
                                "missing_neighbour": full_index[key].vector,
                            }
                        )
        return blocked


def build_band_graph(
    version: str, policy: Policy, covered: Sequence[LegalVector]
) -> BandGraph:
    return BandGraph(version=version, policy=policy, covered=covered)
