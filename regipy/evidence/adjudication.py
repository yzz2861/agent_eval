"""Explicit-rule adjudication of normalized execution evidence.

Facts are clustered by executable path and user identity, and each cluster is
combined under a fixed rule order into one of four verdicts:

1. ``execution_evidenced`` - at least one strong ``execution_occurred`` fact.
2. ``possibly_executed`` - no strong fact, but at least one weak
   ``execution_possible`` fact.
3. ``present`` - only ``file_present`` facts (e.g. AmCache on its own).
4. ``insufficient_evidence`` - queried subject has no aligned facts, or its
   facts could not be aligned and therefore could not be spliced.

Facts from different hives are only spliced when user identity, path spelling
and acquisition windows all align. Unalignable facts are kept as explicit
counter-evidence with the failing reason; conflicting facts are retained on
the conclusion instead of being merged away. Nothing is inferred from
absence: a source that was never collected is a coverage gap.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from regipy.evidence.models import (
    CollectionWindow,
    CounterEvidence,
    CounterEvidenceReason,
    EvidenceConclusion,
    Fact,
    FactStrength,
    Proposition,
    UserIdentity,
    VERDICT_LABELS_ZH,
    Verdict,
)
from regipy.evidence.normalizers import (
    NORMALIZERS,
    PLUGIN_NAME_TO_SOURCE,
    SourceContext,
)
from regipy.evidence.pathnorm import NormalizedPath, normalize_path


@dataclass(frozen=True)
class _ClusterKey:
    path: str
    identity_key: Optional[str]
    partition_id: int = 0


class EvidenceAdjudicator:
    """Accumulate facts from multiple hives and adjudicate per program/user."""

    def __init__(self, volume_mappings: Optional[dict[str, str]] = None) -> None:
        self.volume_mappings = dict(volume_mappings or {})
        self._facts: list[Fact] = []
        self._known_sources: set[str] = set()

    def add_facts(self, facts: list[Fact]) -> None:
        """Add already-normalized facts (e.g. produced by the normalizers)."""
        for fact in facts:
            self._facts.append(fact)
            self._known_sources.add(fact.source)

    def add_plugin_output(
        self,
        source: str,
        entries: list[dict[str, Any]],
        window: Optional[CollectionWindow] = None,
        identity: Optional[UserIdentity] = None,
        volume_mappings: Optional[dict[str, str]] = None,
    ) -> list[Fact]:
        """Normalize one plugin's ``entries`` and register the resulting facts.

        ``source`` is either a normalizer key or a plugin ``NAME``. Raises
        ``ValueError`` for unknown sources so callers cannot silently lose
        evidence by mistyping a plugin name.
        """
        source_key = PLUGIN_NAME_TO_SOURCE.get(source, source)
        normalizer = NORMALIZERS.get(source_key)
        if normalizer is None:
            known = sorted(set(NORMALIZERS) | set(PLUGIN_NAME_TO_SOURCE))
            raise ValueError(f"Unknown evidence source {source!r}; supported sources: {known}")

        context = SourceContext(
            source=source_key,
            window=window,
            identity=identity,
            volume_mappings=volume_mappings or self.volume_mappings,
        )
        facts = normalizer(entries, context)
        self.add_facts(facts)
        return facts

    @property
    def facts(self) -> list[Fact]:
        return list(self._facts)

    def adjudicate_all(self) -> list[EvidenceConclusion]:
        """Adjudicate every path/identity cluster observed in the facts."""
        clusters = self._build_clusters(self._facts)
        conclusions = [
            self._adjudicate_cluster(cluster_key, cluster_facts) for cluster_key, cluster_facts in clusters.items()
        ]
        conclusions.sort(key=lambda item: (item.path, item.identity_key or ""))
        return conclusions

    def adjudicate_path(self, path: str, identity: Optional[UserIdentity] = None) -> EvidenceConclusion:
        """Adjudicate a specific program, optionally constrained to a user."""
        target = normalize_path(path, self.volume_mappings)
        related: list[Fact] = []
        for fact in self._facts:
            fact_path = normalize_path(fact.path, self.volume_mappings)
            if not target.equivalent_to(fact_path):
                continue
            if identity is not None and not fact.machine_wide and not identity.aligns_with(fact.identity):
                continue
            related.append(fact)

        identity_key = identity.key if identity is not None else None
        if not related:
            return EvidenceConclusion(
                path=target.normalized,
                identity_key=identity_key,
                verdict=Verdict.INSUFFICIENT_EVIDENCE,
                verdict_label_zh=VERDICT_LABELS_ZH[Verdict.INSUFFICIENT_EVIDENCE],
                coverage_gaps=self._coverage_gaps(set()),
            )
        partitions = self._partition_alignable(related)
        if len(partitions) == 1:
            return self._adjudicate_cluster(_ClusterKey(target.normalized, identity_key), partitions[0])

        # Multiple unalignable partitions: adjudicate each, then keep the
        # strongest verdict while preserving every partition as counter-evidence.
        sub_conclusions = [
            self._adjudicate_cluster(
                _ClusterKey(target.normalized, identity_key, partition_id=index),
                partition,
            )
            for index, partition in enumerate(partitions)
        ]
        order = {
            Verdict.INSUFFICIENT_EVIDENCE: 0,
            Verdict.PRESENT: 1,
            Verdict.POSSIBLY_EXECUTED: 2,
            Verdict.EXECUTION_EVIDENCED: 3,
        }
        primary = max(sub_conclusions, key=lambda item: order[item.verdict])
        primary_fact_ids = set(primary.supporting_fact_ids)
        for conclusion in sub_conclusions:
            if conclusion is primary:
                continue
            # Only carry over counter-evidence about facts outside the primary
            # partition; sub-conclusions may flag primary facts merely because
            # those facts were not members of the sub-conclusion partition.
            primary.counter_evidence.extend(
                item for item in conclusion.counter_evidence if item.fact_id not in primary_fact_ids
            )
            primary.coverage_gaps.extend(
                gap for gap in conclusion.coverage_gaps if gap not in primary.coverage_gaps
            )
        seen = set()
        deduped = []
        for item in primary.counter_evidence:
            dedupe_key = (item.fact_id, item.reason)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            deduped.append(item)
        primary.counter_evidence = sorted(deduped, key=lambda item: item.fact_id)
        return primary

    def _build_clusters(self, facts: list[Fact]) -> dict[_ClusterKey, list[Fact]]:
        """Group facts, splitting unalignable identity/window/path variants.

        Facts are first grouped by normalized path, then partitioned on user
        identity. Within an identity group, a fact opens a new partition when
        it cannot align (window or path spelling) with every existing one.
        Partitions therefore only contain facts that may legally be spliced.
        """
        by_path: dict[str, list[Fact]] = {}
        for fact in facts:
            by_path.setdefault(fact.path, []).append(fact)

        clusters: dict[_ClusterKey, list[Fact]] = {}
        for path, path_facts in by_path.items():
            identity_groups: dict[Optional[str], list[Fact]] = {}
            machine_wide_facts: list[Fact] = []
            for fact in path_facts:
                if fact.machine_wide or fact.identity is None:
                    machine_wide_facts.append(fact)
                    continue
                identity_groups.setdefault(fact.identity.key, []).append(fact)

            # Machine-wide artifacts (AmCache, ShimCache) describe the host
            # rather than a user: they may support every user cluster, but
            # they also keep their own anonymous cluster for the host view.
            group_material = [(key, identity_groups[key]) for key in identity_groups]
            group_material.append((None, machine_wide_facts))
            for identity_key, group_facts in group_material:
                combined = list(group_facts)
                if identity_key is not None:
                    combined.extend(machine_wide_facts)
                for partition in self._partition_alignable(combined):
                    # Each partition is independently spliceable; unalignable
                    # partitions get distinct conclusions, never merged.
                    key = _ClusterKey(
                        path=path,
                        identity_key=identity_key,
                        partition_id=len(clusters),
                    )
                    clusters[key] = list(partition)
        return clusters

    def _partition_alignable(self, facts: list[Fact]) -> list[list[Fact]]:
        partitions: list[list[Fact]] = []
        for fact in sorted(facts, key=lambda item: item.fact_id):
            placed = False
            for partition in partitions:
                if all(self._facts_align(fact, existing) for existing in partition):
                    partition.append(fact)
                    placed = True
                    break
            if not placed:
                partitions.append([fact])
        return partitions

    def _facts_align(self, left: Fact, right: Fact) -> bool:
        """Identity, window and path alignment required to splice two facts."""
        if left.source == right.source:
            return True
        if not (left.machine_wide or right.machine_wide) and not _identities_align(
            left.identity, right.identity
        ):
            return False
        if not _windows_align(left.collection_window, right.collection_window):
            return False
        left_path = normalize_path(left.path, self.volume_mappings)
        right_path = normalize_path(right.path, self.volume_mappings)
        if not left_path.equivalent_to(right_path):
            return False
        return True

    def _adjudicate_cluster(self, key: _ClusterKey, facts: list[Fact]) -> EvidenceConclusion:
        ordered = sorted(facts, key=lambda item: (item.source, item.fact_id))
        sources = {fact.source for fact in ordered}

        strong = [
            fact
            for fact in ordered
            if fact.proposition == Proposition.EXECUTION_OCCURRED and fact.strength == FactStrength.STRONG
        ]
        weak_execution = [fact for fact in ordered if fact.proposition == Proposition.EXECUTION_POSSIBLE]
        file_present = [fact for fact in ordered if fact.proposition == Proposition.FILE_PRESENT]

        if strong:
            verdict = Verdict.EXECUTION_EVIDENCED
        elif weak_execution:
            verdict = Verdict.POSSIBLY_EXECUTED
        elif file_present:
            verdict = Verdict.PRESENT
        else:
            verdict = Verdict.INSUFFICIENT_EVIDENCE

        minimal_support = self._minimal_support(strong, weak_execution, file_present)
        counter_evidence = self._counter_evidence_for(key, ordered)
        conflicts = self._conflicts(ordered)

        return EvidenceConclusion(
            path=key.path,
            identity_key=key.identity_key,
            verdict=verdict,
            verdict_label_zh=VERDICT_LABELS_ZH[verdict],
            minimal_support=minimal_support,
            supporting_fact_ids=[fact.fact_id for fact in ordered],
            counter_evidence=counter_evidence,
            coverage_gaps=self._coverage_gaps(sources),
            conflicts=conflicts,
        )

    @staticmethod
    def _minimal_support(
        strong: list[Fact],
        weak_execution: list[Fact],
        file_present: list[Fact],
    ) -> list[str]:
        """Smallest fact set sufficient to justify the reached verdict.

        The verdict only needs one fact of the deciding strength; supporting
        facts remain available in full via ``supporting_fact_ids``.
        """
        deciding = strong or weak_execution or file_present
        if not deciding:
            return []
        return [sorted(deciding, key=lambda item: item.fact_id)[0].fact_id]

    def _counter_evidence_for(self, key: _ClusterKey, facts: list[Fact]) -> list[CounterEvidence]:
        """Facts sharing the path spelling but excluded from this cluster."""
        own_ids = {fact.fact_id for fact in facts}
        counter: list[CounterEvidence] = []
        cluster_identity = next((fact.identity for fact in facts if fact.identity is not None), None)

        for other in self._facts:
            if other.fact_id in own_ids or other.path != key.path:
                continue
            reason, detail = self._exclusion_reason(other, facts, cluster_identity)
            counter.append(
                CounterEvidence(fact_id=other.fact_id, source=other.source, reason=reason, detail=detail)
            )
        return sorted(counter, key=lambda item: item.fact_id)

    def _exclusion_reason(
        self,
        candidate: Fact,
        cluster_facts: list[Fact],
        cluster_identity: Optional[UserIdentity],
    ) -> tuple[CounterEvidenceReason, str]:
        if not candidate.machine_wide and not _identities_align(candidate.identity, cluster_identity):
            candidate_key = candidate.identity.key if candidate.identity is not None else "unknown"
            cluster_key = cluster_identity.key if cluster_identity is not None else "unknown"
            return (
                CounterEvidenceReason.IDENTITY_MISMATCH,
                f"identity {candidate_key} cannot be aligned with {cluster_key}",
            )

        blockers = [
            fact
            for fact in cluster_facts
            if not _windows_align(candidate.collection_window, fact.collection_window)
        ]
        if len(blockers) == len(cluster_facts):
            reference = cluster_facts[0]
            if not (candidate.collection_window.is_fully_known() and reference.collection_window.is_fully_known()):
                return (
                    CounterEvidenceReason.WINDOW_UNKNOWN,
                    "acquisition window is not fully recorded; cross-hive splicing cannot be proven",
                )
            return (
                CounterEvidenceReason.WINDOW_DISJOINT,
                "acquisition windows do not overlap; facts may describe different time periods",
            )

        candidate_path = normalize_path(candidate.path, self.volume_mappings)
        reference_path: NormalizedPath = normalize_path(cluster_facts[0].path, self.volume_mappings)
        return (
            CounterEvidenceReason.PATH_NOT_EQUIVALENT,
            f"path {candidate_path.normalized} cannot be proven equivalent to {reference_path.normalized}",
        )

    @staticmethod
    def _conflicts(facts: list[Fact]) -> list[str]:
        """Retain contradictions instead of collapsing them by timestamp."""
        conflicts: list[str] = []
        zero_counter = [
            fact
            for fact in facts
            if fact.source == "user_assist"
            and fact.proposition == Proposition.EXECUTION_POSSIBLE
            and (fact.raw or {}).get("run_counter") == 0
        ]
        strong = [
            fact
            for fact in facts
            if fact.proposition == Proposition.EXECUTION_OCCURRED and fact.strength == FactStrength.STRONG
        ]
        if zero_counter and strong:
            strong_ids = ", ".join(sorted(fact.fact_id for fact in strong))
            for fact in sorted(zero_counter, key=lambda item: item.fact_id):
                conflicts.append(
                    f"{fact.fact_id} records run_counter=0 while {strong_ids} records execution; "
                    "both observations retained without time-based merge"
                )
        return conflicts

    def _coverage_gaps(self, represented_sources: set[str]) -> list[str]:
        gaps = sorted(self._known_sources - represented_sources)
        if not self._known_sources:
            return ["no evidence sources were collected"]
        return [f"source {source} contributed no aligned fact for this subject" for source in gaps]


def _identities_align(left: Optional[UserIdentity], right: Optional[UserIdentity]) -> bool:
    if left is None and right is None:
        return True
    if left is None or right is None:
        return False
    return left.aligns_with(right)


def _windows_align(left: CollectionWindow, right: CollectionWindow) -> bool:
    """Align only on identical fully-known windows or proven overlap."""
    if left == right and left.is_fully_known():
        return True
    return left.overlaps(right)



def adjudicate(
    plugin_outputs: dict[str, list[dict[str, Any]]],
    windows: Optional[dict[str, CollectionWindow]] = None,
    identities: Optional[dict[str, UserIdentity]] = None,
    volume_mappings: Optional[dict[str, str]] = None,
) -> list[EvidenceConclusion]:
    """Convenience entry point: normalize plugin outputs and adjudicate at once.

    ``plugin_outputs`` maps a source/plugin name to its raw ``entries`` list.
    ``windows`` and ``identities`` optionally map the same source names to
    acquisition windows and user identities. Sources missing from either map
    are still processed; their conclusions simply carry explicit alignment
    limitations rather than guessing.
    """
    adjudicator = EvidenceAdjudicator(volume_mappings=volume_mappings)
    windows = windows or {}
    identities = identities or {}
    for source, entries in plugin_outputs.items():
        source_key = PLUGIN_NAME_TO_SOURCE.get(source, source)
        adjudicator.add_plugin_output(
            source,
            entries,
            window=windows.get(source) or windows.get(source_key),
            identity=identities.get(source) or identities.get(source_key),
        )
    return adjudicator.adjudicate_all()