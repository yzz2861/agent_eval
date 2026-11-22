"""
Cross-version review on a shared metric mapping.

CVSS versions do not share a metric set. To review one band configuration across versions without
synthesising vectors, a policy supplies an explicit, metric-by-metric mapping. We only compare
vectors whose every mapped metric has a legal value in both versions; anything that cannot be
mapped is reported as unavailable in that version rather than cast as a vote.

For every legal single-fact change in the shared space we compute the band transition in each
version. A transition that stays smooth in one version but lands in a different disposition in the
other is exactly the "surprise jump" the review board wants surfaced.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .policy import Policy
from .universe import VERSIONS, LegalVector, find_vector


@dataclass(frozen=True)
class SharedEdge:
    """A single-fact change evaluated in two CVSS versions."""

    fact: str
    metric: str
    values_before: Dict[str, str]
    values_after: Dict[str, str]
    vectors: Dict[str, str]
    scores: Dict[str, List[float]]
    bands: Dict[str, List[str]]
    dispositions: Dict[str, List[str]]

    @property
    def band_changed(self) -> Dict[str, bool]:
        """Per version: did this single fact move the vector to a different band?"""
        return {
            version: before != after for version, (before, after) in self.bands.items()
        }

    @property
    def is_surprise(self) -> bool:
        """True when the versions disagree on whether the same fact crosses a band."""
        changed = set(self.band_changed.values())
        return len(changed) > 1


@dataclass
class ComparisonReport:
    versions: Tuple[str, ...]
    mapping: Dict[str, Dict[str, str]]
    shared_vectors: List[Dict[str, Any]]
    edges: List[SharedEdge]
    unavailable: List[Dict[str, Any]]

    def surprise_edges(self) -> List[SharedEdge]:
        return [edge for edge in self.edges if edge.is_surprise]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "versions": list(self.versions),
            "mapping": self.mapping,
            "shared_vector_count": len(self.shared_vectors),
            "edge_count": len(self.edges),
            "surprise_edge_count": len(self.surprise_edges()),
            "unavailable_count": len(self.unavailable),
            "surprise_edges": [_edge_to_dict(edge) for edge in self.surprise_edges()],
            "edges": [_edge_to_dict(edge) for edge in self.edges],
            "unavailable": self.unavailable,
        }


def _edge_to_dict(edge: SharedEdge) -> Dict[str, Any]:
    return {
        "fact": edge.fact,
        "metric": edge.metric,
        "values_before": edge.values_before,
        "values_after": edge.values_after,
        "vectors": edge.vectors,
        "scores": edge.scores,
        "bands": edge.bands,
        "dispositions": edge.dispositions,
    }


def _project(
    values: Dict[str, str],
    version: str,
    metric_mapping: Dict[str, Dict[str, str]],
    value_mapping: Dict[str, Dict[str, str]],
):
    """
    Translate canonical metric/value choices into a version-local vector.

    value_mapping maps a canonical value (per canonical metric) to the value used in this
    version. If a canonical choice has no legal local value, the candidate is unavailable in this
    version (never a vote).
    """
    projected: Dict[str, str] = {}
    for canonical, per_version_metric in metric_mapping.items():
        if version not in per_version_metric:
            return None
        metric = per_version_metric[version]
        domain = VERSIONS[version].domains[metric]
        canonical_value = values[canonical]
        local_value = value_mapping[canonical][canonical_value].get(version)
        if local_value is None or local_value not in domain:
            return None
        projected[metric] = local_value
    return projected




def _complete_vector(version: str, projected: Dict[str, str], baseline: Dict[str, str]):
    """Fill every mandatory metric not covered by the shared mapping from a fixed baseline."""
    values = dict(baseline.get(version, {}))
    values.update(projected)
    mandatory = set(VERSIONS[version].mandatory)
    if set(values) != mandatory:
        missing = sorted(mandatory - set(values))
        raise ValueError(f"version {version} baseline misses mandatory metrics {missing}")
    return values


def compare_versions(
    versions: List[str],
    canonical_metrics: List[str],
    metric_mapping: Dict[str, Dict[str, str]],
    value_mapping: Dict[str, Dict[str, str]],
    canonical_domains: Dict[str, Tuple[str, ...]],
    policy: Policy,
    baseline: Dict[str, Dict[str, str]],
) -> ComparisonReport:
    """
    Build every shared vector and shared single-fact edge, scoring each side with its own kernel.

    ``mapping`` maps a canonical metric name to the version-specific metric abbreviation, e.g.
    ``{"C": {"2.0": "C", "3.1": "C"}}``. ``canonical_domains`` restricts each canonical metric to
    values that must be legal in *every* compared version.
    """
    from itertools import product

    for version in versions:
        missing = [
            canonical
            for canonical in canonical_metrics
            if version not in metric_mapping.get(canonical, {})
        ]
        if missing:
            raise ValueError(
                f"version {version} is missing mappings for canonical metrics {missing}"
            )

    domain_lists = [canonical_domains[metric] for metric in canonical_metrics]
    shared_records: List[Dict[str, Any]] = []
    shared_lookup: Dict[Tuple[Tuple[str, str], ...], Dict[str, LegalVector]] = {}
    unavailable: List[Dict[str, Any]] = []

    for combo in product(*domain_lists):
        canonical_values = dict(zip(canonical_metrics, combo))
        per_version_vectors: Dict[str, Optional[LegalVector]] = {}
        for version in versions:
            projected = _project(canonical_values, version, metric_mapping, value_mapping)
            if projected is None:
                per_version_vectors[version] = None
                continue
            full_values = _complete_vector(version, projected, baseline)
            per_version_vectors[version] = find_vector(version, full_values)
        available = {
            version: lv for version, lv in per_version_vectors.items() if lv is not None
        }
        if len(available) != len(versions):
            unavailable.append(
                {
                    "canonical_values": canonical_values,
                    "available_in": sorted(available),
                    "missing_in": sorted(
                        version
                        for version in versions
                        if per_version_vectors.get(version) is None
                    ),
                }
            )
            continue
        key = tuple(sorted(canonical_values.items()))
        shared_lookup[key] = available
        record = {"canonical_values": canonical_values, "per_version": {}}
        for version in versions:
            lv = available[version]
            band = policy.version_policy(version).band_of(lv.score)
            record["per_version"][version] = {
                "vector": lv.vector,
                "score": lv.score,
                "band": band.name,
                "disposition": band.disposition,
            }
        shared_records.append(record)

    edges: List[SharedEdge] = []
    shared_keys = list(shared_lookup.keys())
    for index, key in enumerate(shared_keys):
        values_before = dict(key)
        for metric in canonical_metrics:
            current = values_before[metric]
            for new_value in canonical_domains[metric]:
                if new_value == current:
                    continue
                values_after = dict(values_before)
                values_after[metric] = new_value
                neighbour_key = tuple(sorted(values_after.items()))
                if neighbour_key not in shared_lookup:
                    continue
                vectors: Dict[str, str] = {}
                scores: Dict[str, List[float]] = {}
                bands: Dict[str, List[str]] = {}
                dispositions: Dict[str, List[str]] = {}
                for version in versions:
                    before = shared_lookup[key][version]
                    after = shared_lookup[neighbour_key][version]
                    band_before = policy.version_policy(version).band_of(before.score)
                    band_after = policy.version_policy(version).band_of(after.score)
                    vectors[version] = f"{before.vector}  =>  {after.vector}"
                    scores[version] = [before.score, after.score]
                    bands[version] = [band_before.name, band_after.name]
                    dispositions[version] = [
                        band_before.disposition,
                        band_after.disposition,
                    ]
                edges.append(
                    SharedEdge(
                        fact=f"{metric}:{current}->{new_value}",
                        metric=metric,
                        values_before=values_before,
                        values_after=values_after,
                        vectors=vectors,
                        scores=scores,
                        bands=bands,
                        dispositions=dispositions,
                    )
                )

    return ComparisonReport(
        versions=tuple(versions),
        mapping=metric_mapping,
        shared_vectors=shared_records,
        edges=edges,
        unavailable=unavailable,
    )
