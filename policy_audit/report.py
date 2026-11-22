"""
Audit report assembly.

A report is fully reproducible from the same policy document and the same scoring kernel: it
records every legal universe size, how many vectors the board actually covered, which legal
candidates were left unvoted, the cross-band connected regions, the band-skipping single-fact
edges and a shortest-change witness for each band boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .graph import BandGraph
from .policy import Policy
from .universe import LegalVector, VERSIONS, build_universe


@dataclass
class VersionAudit:
    version: str
    universe_size: int
    covered_size: int
    uncovered_size: int
    graph: BandGraph
    covered: List[LegalVector]
    uncovered: List[LegalVector]
    witnesses: List[Dict[str, Any]]
    blocked: List[Dict[str, str]]

    def as_dict(self) -> Dict[str, Any]:
        band_names = [band.name for band in self.graph.version_policy.bands]
        band_population = {name: 0 for name in band_names}
        for lv in self.covered:
            band_population[self.graph.band_of_vector[lv.vector]] += 1
        return {
            "version": self.version,
            "metric_universe": {
                metric: list(VERSIONS[self.version].domains[metric])
                for metric in VERSIONS[self.version].mandatory
            },
            "legal_universe_size": self.universe_size,
            "policy_covered_size": self.covered_size,
            "policy_uncovered_size": self.uncovered_size,
            "coverage_ratio": round(self.covered_size / self.universe_size, 6)
            if self.universe_size
            else 0.0,
            "bands": [
                {
                    "name": band.name,
                    "lower": band.lower,
                    "upper": band.upper,
                    "disposition": band.disposition,
                    "vectors": band_population[band.name],
                }
                for band in self.graph.version_policy.bands
            ],
            "adjacency": {
                "single_fact_edges": len(self.graph.edges),
                "cross_band_edges": len(self.graph.cross_band_edges),
                "band_skipping_edges": len(self.graph.band_skipping_edges),
                "connected_components": len(self.graph.components),
                "cross_band_components": len(self.graph.cross_band_components()),
            },
            "cross_band_components": [
                {
                    "component_id": component.component_id,
                    "vectors": len(component.vectors),
                    "bands": component.bands,
                }
                for component in self.graph.cross_band_components()
            ],
            "band_skipping_witnesses": [
                self._edge_witness(edge) for edge in self.graph.band_skipping_edges
            ],
            "boundary_witnesses": self.witnesses,
            "blocked_adjacencies": self.blocked,
            "uncovered_examples": [lv.vector for lv in self.uncovered[:20]],
        }

    def _edge_witness(self, edge) -> Dict[str, Any]:
        return {
            "fact": edge.fact,
            "from": {
                "vector": edge.source.vector,
                "score": edge.source.score,
                "band": self.graph.band_of_vector[edge.source.vector],
            },
            "to": {
                "vector": edge.target.vector,
                "score": edge.target.score,
                "band": self.graph.band_of_vector[edge.target.vector],
            },
        }


def _boundary_witnesses(graph: BandGraph) -> List[Dict[str, Any]]:
    """One shortest reproducible witness for each ordered pair of distinct bands."""
    band_names = [band.name for band in graph.version_policy.bands]
    representatives: Dict[str, LegalVector] = {}
    for lv in graph.vectors:
        representatives.setdefault(graph.band_of_vector[lv.vector], lv)
    witnesses: List[Dict[str, Any]] = []
    for source_band in band_names:
        for target_band in band_names:
            if source_band == target_band:
                continue
            if source_band not in representatives or target_band not in representatives:
                continue
            witness = graph.shortest_witness(
                representatives[source_band], representatives[target_band]
            )
            if witness is None:
                witnesses.append(
                    {
                        "from_band": source_band,
                        "to_band": target_band,
                        "reachable": False,
                    }
                )
                continue
            record = witness.as_dict()
            record["from_band"] = source_band
            record["to_band"] = target_band
            record["reachable"] = True
            witnesses.append(record)
    return witnesses


def audit_version(version: str, policy: Policy) -> VersionAudit:
    universe = build_universe(version)
    covered, uncovered = policy.partition_universe(universe)
    graph = BandGraph(version=version, policy=policy, covered=covered)
    witnesses = _boundary_witnesses(graph)
    blocked = graph.blocked_adjacencies(covered, universe)
    return VersionAudit(
        version=version,
        universe_size=len(universe),
        covered_size=len(covered),
        uncovered_size=len(uncovered),
        graph=graph,
        covered=covered,
        uncovered=uncovered,
        witnesses=witnesses,
        blocked=blocked,
    )


def build_report(policy: Policy, versions: Optional[List[str]] = None) -> Dict[str, Any]:
    chosen = versions or list(policy.version_policies)
    audits = [audit_version(version, policy) for version in chosen]
    return {
        "policy": policy.name,
        "description": policy.description,
        "versions": [audit.as_dict() for audit in audits],
        "verdicts": [_verdict(audit) for audit in audits],
    }


def _verdict(audit: VersionAudit) -> Dict[str, Any]:
    blocking: List[str] = []
    if audit.uncovered_size:
        blocking.append(
            f"{audit.uncovered_size} legal vectors are not covered by an allow-listed choice"
        )
    if audit.blocked:
        blocking.append(
            f"{len(audit.blocked)} single-fact neighbours exist only outside the allow-list"
        )
    if audit.graph.band_skipping_edges:
        blocking.append(
            f"{len(audit.graph.band_skipping_edges)} single-fact edges skip over a band"
        )
    unreachable = [w for w in audit.witnesses if not w.get("reachable", True)]
    if unreachable:
        blocking.append(
            f"{len(unreachable)} band pairs are disconnected inside the covered subgraph"
        )
    return {
        "version": audit.version,
        "status": "needs-review" if blocking else "pass",
        "findings": blocking,
    }
