"""Binding record occurrences into exhibits with strict source-chain rules.

Two occurrences are bound into the same exhibit only when a provable,
layer-by-layer source chain demonstrates that they describe the same record
in the same origin hive.  Equal content fingerprints alone never justify a
merge; content-only excerpts therefore stay in separate exhibits.

The grouping works in two stages:

1. Primary hive occurrences are clustered into hive families.  A live hive and
   its in-memory recovered view are the same family when the view declares the
   live hive as its origin.  Inside a family, the cell offset identifies the
   record, so live and recovered occurrences of one cell form one exhibit.
2. Excerpts only join an exhibit when their full provenance claim resolves to
   the claimed source file and the claimed cell.  Content-only excerpts, and
   excerpts whose source file was not delivered, always open their own
   exhibit, even when their content matches another record.
"""

from .models import (
    ArtifactKind,
    BindingDecision,
    Exhibit,
    ProvenanceGrade,
    Reachability,
)


def _cell_identity(occurrence):
    """Identity of a cell within one hive family."""
    return (occurrence.record_kind, occurrence.absolute_offset)


def bind_occurrences(occurrences):
    """Group occurrences into exhibits under the source-chain rules."""
    primary = [o for o in occurrences if o.artifact_kind != ArtifactKind.EXCERPT]
    excerpts = [o for o in occurrences if o.artifact_kind == ArtifactKind.EXCERPT]

    family_index = _build_families(primary)
    exhibits = []
    cell_to_exhibit = {}

    for family_id, members in family_index.items():
        grouped = {}
        for occurrence in members:
            grouped.setdefault(_cell_identity(occurrence), []).append(occurrence)
        for _identity, cell_occurrences in grouped.items():
            exhibit = Exhibit(
                exhibit_id='EXH-%03d' % (len(exhibits) + 1),
                title=_title_for(cell_occurrences[0]),
                occurrences=cell_occurrences,
                decision=_primary_decision(cell_occurrences),
            )
            exhibits.append(exhibit)
            for occurrence in cell_occurrences:
                cell_to_exhibit[(_family_key(occurrence), _cell_identity(occurrence))] = exhibit

    delivered_artifacts = {o.artifact_path: o.artifact_sha256 for o in primary}

    for occurrence in excerpts:
        target = _resolve_excerpt(occurrence, family_index, cell_to_exhibit, delivered_artifacts)
        if target is not None:
            exhibit, reason = target
            exhibit.occurrences.append(occurrence)
            exhibit.decision = BindingDecision(
                bound=True,
                reason=reason,
                evidence=_evidence_for(exhibit.occurrences),
            )
            continue

        exhibit = Exhibit(
            exhibit_id='EXH-%03d' % (len(exhibits) + 1),
            title=_title_for(occurrence),
            occurrences=[occurrence],
            decision=BindingDecision(
                bound=False,
                reason=_standalone_reason(occurrence),
                evidence=_evidence_for(occurrence),
            ),
        )
        exhibits.append(exhibit)

    return exhibits


def _build_families(primary):
    """Cluster live hives and their recovered views into families."""
    families = []
    by_artifact = {}
    for occurrence in primary:
        by_artifact.setdefault(occurrence.artifact_path, []).append(occurrence)

    for artifact_path, members in by_artifact.items():
        placed = False
        derived_from = members[0].source_claim.get('derived_from') if members[0].source_claim else None
        for family in families:
            anchor_path = family[0].artifact_path
            if derived_from == anchor_path:
                family.extend(members)
                placed = True
                break
        if not placed:
            families.append(list(members))
    return dict(enumerate(families))


def _family_key(occurrence):
    """Best-effort family identifier carried on a primary occurrence."""
    derived = occurrence.source_claim.get('derived_from') if occurrence.source_claim else None
    return derived if derived else occurrence.artifact_path


def _resolve_excerpt(occurrence, family_index, cell_to_exhibit, delivered_artifacts):
    claim = occurrence.source_claim or {}
    if occurrence.provenance_grade != ProvenanceGrade.FULL:
        return None
    source_hash = claim.get('source_sha256')
    matching_artifact = next(
        (path for path, digest in delivered_artifacts.items() if digest == source_hash),
        None,
    )
    if matching_artifact is None:
        occurrence.binding_blockers.append(
            'claimed source file was not delivered in the bundle'
        )
        return None
    try:
        claimed_offset = int(str(claim.get('record_absolute_offset_hex')), 16)
    except (TypeError, ValueError):
        occurrence.binding_blockers.append('excerpt carries no usable record offset')
        return None
    if claim.get('record_kind') != occurrence.record_kind:
        occurrence.binding_blockers.append('excerpt record kind does not match its claim')
        return None

    for family_id, members in family_index.items():
        paths = {member.artifact_path for member in members}
        if matching_artifact not in paths:
            continue
        anchor = next(member for member in members if member.artifact_path == matching_artifact)
        key = (_family_key(anchor), (occurrence.record_kind, claimed_offset))
        exhibit = cell_to_exhibit.get(key)
        if exhibit is None:
            occurrence.binding_blockers.append(
                'claimed cell offset is not present in the source hive'
            )
            return None
        anchor_occurrence = exhibit.occurrences[0]
        if anchor_occurrence.content_fingerprint != occurrence.content_fingerprint:
            occurrence.binding_blockers.append(
                'content fingerprint differs at the claimed source cell'
            )
            return None
        return exhibit, 'full provenance resolves to the delivered source hive cell'
    return None


def _primary_decision(occurrences):
    if len(occurrences) == 1:
        only = occurrences[0]
        return BindingDecision(
            bound=False,
            reason=_standalone_reason(only),
            evidence=_evidence_for(occurrences),
        )
    artifacts = sorted({o.artifact_path for o in occurrences})
    return BindingDecision(
        bound=True,
        reason='same cell across linked live and in-memory recovered hive views',
        evidence=_evidence_for(occurrences) + ['family artifacts: %s' % ', '.join(artifacts)],
    )


def _evidence_for(occurrences):
    if not isinstance(occurrences, list):
        occurrences = [occurrences]
    return [
        '%s @ 0x%x (%s)' % (
            occurrence.artifact_path,
            occurrence.absolute_offset,
            occurrence.reachability.value,
        )
        for occurrence in occurrences
    ]


def _standalone_reason(occurrence):
    if occurrence.artifact_kind == ArtifactKind.EXCERPT:
        if occurrence.binding_blockers:
            return occurrence.binding_blockers[0]
        return 'excerpt provenance cannot be resolved against a delivered hive'
    if occurrence.reachability == Reachability.UNREACHABLE:
        return 'allocated cell not reachable from the live root key'
    return 'single occurrence with an independent source chain'


def _title_for(occurrence):
    if occurrence.record_kind == 'value':
        return '%s!%s' % (occurrence.registry_path, occurrence.value_name or '(default)')
    return occurrence.registry_path
