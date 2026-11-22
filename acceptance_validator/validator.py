"""Offline acceptance gate for outbound STIX conclusions.

The case lead merges the conclusions of two review cells by object id:
one cell may only verify entity attributes, the other may derive
relationships.  Before any conclusion leaves the organization this module
verifies, fully offline, that each conclusion has:

1. an *original investigation authorization* (a STIX marking) that is
   approved, permits the release purpose, and covers the conclusion scope; and
2. *enough independent actual observations* backing it, where independent
   means produced by distinct observing sources and grounded in distinct
   raw material.

Multiple reports may reference the same material: such reuse is preserved
but never counts twice towards independence.
"""

from collections import Counter

from stix2 import Filter, MarkingDefinition, MemoryStore, parse

from .markings import (
    APPROVED_STATUS,
    AUTHORIZATION_MARKING_TYPE,
    RELEASE_PURPOSE,
    SCOPE_ENTITY_ATTRIBUTE,
    SCOPE_RELATIONSHIP,
)

MIN_INDEPENDENT_OBSERVATIONS = 2
CONCLUSION_TYPE = "report"
EVIDENCE_TYPE = "observed-data"
VALID_SCOPES = (SCOPE_ENTITY_ATTRIBUTE, SCOPE_RELATIONSHIP)


def load_store(source):
    """Build a MemoryStore from a bundle path, raw JSON string, or store."""
    if isinstance(source, MemoryStore):
        return source
    if isinstance(source, str):
        if source.lstrip().startswith("{"):
            raw = source
        else:
            with open(source, "r", encoding="utf-8") as handle:
                raw = handle.read()
        parsed = parse(raw, allow_custom=True)
        objects = parsed.objects if parsed.type == "bundle" else [parsed]
        return MemoryStore(stix_data=objects)
    return MemoryStore(stix_data=source)


class ConclusionVerdict:
    """Acceptance result for one outbound conclusion."""

    def __init__(self, conclusion):
        self.conclusion_id = conclusion.id
        self.name = conclusion.name
        self.scope = conclusion.get("x_conclusion_scope")
        self.evidence_refs = list(conclusion.object_refs)
        self.authorization_refs = list(conclusion.object_marking_refs)
        self.authorization_findings = []
        self.evidence_findings = []
        self.independent_sources = set()
        self.independent_material = set()
        self.material_reference_counts = Counter()
        self.reasons = []

    @property
    def releasable(self):
        return not self.reasons

    def as_dict(self):
        return {
            "conclusion_id": self.conclusion_id,
            "name": self.name,
            "scope": self.scope,
            "releasable": self.releasable,
            "reasons": list(self.reasons),
            "authorization_refs": self.authorization_refs,
            "authorization_findings": self.authorization_findings,
            "evidence_refs": self.evidence_refs,
            "evidence_findings": self.evidence_findings,
            "independent_source_count": len(self.independent_sources),
            "independent_material_count": len(self.independent_material),
            "material_reference_counts": dict(self.material_reference_counts),
            "required_independent_observations": MIN_INDEPENDENT_OBSERVATIONS,
        }


class ReleaseGate:
    """Runs the offline checks over a STIX MemoryStore."""

    def __init__(self, source):
        self.store = load_store(source)
        self._authorization_cache = {}

    def conclusions(self):
        """Object filtering: outbound conclusions are report objects."""
        return self.store.query(Filter("type", "=", CONCLUSION_TYPE))

    def _authorization_marking(self, marking_ref):
        if marking_ref in self._authorization_cache:
            return self._authorization_cache[marking_ref]
        marking = self.store.get(marking_ref)
        result = None
        if isinstance(marking, MarkingDefinition):
            if marking.definition_type == AUTHORIZATION_MARKING_TYPE:
                result = marking
        self._authorization_cache[marking_ref] = result
        return result

    def _check_authorization(self, verdict):
        scope = verdict.scope
        if scope not in VALID_SCOPES:
            verdict.reasons.append(
                "declared scope %r is not a valid review scope (%s)"
                % (scope, ", ".join(VALID_SCOPES))
            )
            return

        usable = []
        for ref in verdict.authorization_refs:
            marking = self._authorization_marking(ref)
            if marking is None:
                verdict.authorization_findings.append(
                    {"marking_ref": ref, "usable": False,
                     "detail": "not an investigation-authorization marking"}
                )
                continue
            definition = marking.definition
            problems = []
            if definition.x_status != APPROVED_STATUS:
                problems.append("status is %r, not %r"
                                % (definition.x_status, APPROVED_STATUS))
            if RELEASE_PURPOSE not in definition.x_permitted_purposes:
                problems.append("purpose %r not in permitted purposes %s"
                                % (RELEASE_PURPOSE, definition.x_permitted_purposes))
            if scope not in definition.x_scope:
                problems.append("scope %r not covered by authorization scope %s"
                                % (scope, definition.x_scope))
            verdict.authorization_findings.append({
                "marking_ref": ref,
                "authorization_id": definition.x_authorization_id,
                "usable": not problems,
                "detail": "covers this release" if not problems else "; ".join(problems),
            })
            if not problems:
                usable.append(definition.x_authorization_id)

        if not usable:
            verdict.reasons.append(
                "no approved investigation authorization permits %r for scope %r"
                % (RELEASE_PURPOSE, scope)
            )

    @staticmethod
    def _material_id(observed_data):
        return observed_data.get("x_raw_material_id") or observed_data.id

    @staticmethod
    def _source_id(observed_data):
        return observed_data.get("created_by_ref") or observed_data.get("x_observation_source")

    def _check_evidence(self, verdict):
        """Trace every evidence ref, then deduplicate by source/material."""
        eligible_observations = []

        for ref in verdict.evidence_refs:
            observed = self.store.get(ref)
            if observed is None or observed.type != EVIDENCE_TYPE:
                verdict.evidence_findings.append({
                    "evidence_ref": ref, "eligible": False,
                    "detail": "reference does not resolve to an observed-data object"
                })
                continue

            markings = set(observed.object_marking_refs)
            covered = self._covered_by_usable_authorization(markings, verdict.scope)
            material = self._material_id(observed)
            source = self._source_id(observed)
            verdict.material_reference_counts[material] += 1
            detail = []
            if not covered:
                detail.append("observation lacks an authorization covering this release")
            if not source:
                detail.append("observation has no attributed observing source")
            eligible = not detail
            verdict.evidence_findings.append({
                "evidence_ref": ref,
                "eligible": eligible,
                "material_id": material,
                "source_id": source,
                "detail": "; ".join(detail) if detail else "authorized actual observation",
            })
            if eligible:
                eligible_observations.append((source, material))

        # Deduplicate: reused material / repeated observations from one source
        # are preserved in material_reference_counts but counted only once.
        eligible_sources = {source for source, _ in eligible_observations}
        eligible_material = {material for _, material in eligible_observations}
        verdict.independent_sources = eligible_sources
        verdict.independent_material = eligible_material

        if not verdict.evidence_refs:
            verdict.reasons.append("conclusion cites no observed-data evidence")
            return

        if len(eligible_observations) < len(verdict.evidence_refs):
            verdict.reasons.append(
                "%d of %d cited references are not usable actual observations"
                % (len(verdict.evidence_refs) - len(eligible_observations),
                   len(verdict.evidence_refs))
            )

        distinct_pairs = set(eligible_observations)
        if len(distinct_pairs) < MIN_INDEPENDENT_OBSERVATIONS:
            verdict.reasons.append(
                "only %d distinct (source, material) observation(s); need %d independent"
                % (len(distinct_pairs), MIN_INDEPENDENT_OBSERVATIONS)
            )
        if len(eligible_sources) < MIN_INDEPENDENT_OBSERVATIONS:
            verdict.reasons.append(
                "only %d distinct observing source(s); need %d independent sources"
                % (len(eligible_sources), MIN_INDEPENDENT_OBSERVATIONS)
            )
        if len(eligible_material) < MIN_INDEPENDENT_OBSERVATIONS:
            verdict.reasons.append(
                "only %d distinct raw material item(s); need %d independent materials"
                % (len(eligible_material), MIN_INDEPENDENT_OBSERVATIONS)
            )

    def _covered_by_usable_authorization(self, marking_refs, scope):
        for ref in marking_refs:
            marking = self._authorization_marking(ref)
            if marking is not None and marking.definition.permits(RELEASE_PURPOSE, scope):
                return True
        return False

    def evaluate(self, conclusion):
        verdict = ConclusionVerdict(conclusion)
        self._check_authorization(verdict)
        self._check_evidence(verdict)
        return verdict

    def run(self):
        return [self.evaluate(conclusion) for conclusion in self.conclusions()]
