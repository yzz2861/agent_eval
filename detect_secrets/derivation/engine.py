"""Derived-relationship analysis backend.
"""
from collections import defaultdict
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Sequence
from typing import Set
from typing import Tuple

from .identity import compute_group_identity
from .identity import compute_relationship_identity
from .identity import compute_occurrence_identity
from .identity import compute_value_identity
from .identity import mask_secret
from .models import DerivationAnalysis
from .models import DerivationGroup
from .models import DerivationReport
from .models import GroupMember
from .models import Observation
from .models import TransformStep
from .models import UnverifiableRelationship
from .transforms import DecodeResult
from .transforms import MAX_CHAIN_DEPTH
from .transforms import decode_once

ObservationTuple = Tuple[str, str, str, int, str]

TRANSFORM_ORDER = (
    "url_decode",
    "json_unescape",
    "base64_decode",
    "hex_decode",
)

#: Cap on the unverifiable look-alike relationships reported per analysis.
MAX_UNVERIFIABLE = 100




def build_observation(
    tenant: str,
    secret_type: str,
    filename: str,
    line_number: int,
    raw_value: str,
) -> Observation:
    """Constructs an :class:`Observation` from a raw candidate value.

    The plaintext is retained in memory only (for the current scan); the
    persisted identity is already computed here, before any relationship
    analysis runs.
    """
    return Observation(
        occurrence_identity=compute_occurrence_identity(
            tenant,
            secret_type,
            filename,
            line_number,
            raw_value,
        ),
        tenant=tenant,
        secret_type=secret_type,
        filename=filename,
        line_number=line_number,
        raw_value=raw_value,
    )


def build_observations(
    candidates: Iterable[ObservationTuple],
) -> List[Observation]:
    """Convenience builder for ``(tenant, type, file, line, raw)`` tuples."""
    return [
        build_observation(tenant, secret_type, filename, line_number, raw_value)
        for tenant, secret_type, filename, line_number, raw_value in candidates
    ]


def _reachable_values(root: str) -> List[Tuple[str, List[DecodeResult]]]:
    """All values reachable from ``root`` through the allowed transforms.

    Returns ``(value, chain)`` pairs. The first pair is the root itself
    with an empty chain. Search is breadth-first, depth-bounded by
    :data:`MAX_CHAIN_DEPTH`, and never revisits a value, so every chain
    uses distinct transforms on distinct intermediate values.
    """
    reached: Dict[str, List[DecodeResult]] = {root: []}
    queue: List[Tuple[str, int]] = [(root, 0)]
    while queue:
        current, depth = queue.pop(0)
        if depth >= MAX_CHAIN_DEPTH:
            continue

        for name in TRANSFORM_ORDER:
            candidate = decode_once(name, current)
            if candidate is None:
                continue
            if candidate.decoded in reached:
                continue

            chain = [*reached[current], candidate]
            reached[candidate.decoded] = chain
            queue.append((candidate.decoded, depth + 1))

    return sorted(reached.items(), key=lambda item: (len(item[1]), item[0]))


def _clusters_from_shared_values(
    observations: Sequence[Observation],
    value_to_occurrences: Dict[str, Set[str]],
    by_identity: Dict[str, Observation],
    reachable: Dict[str, Dict[str, List[DecodeResult]]],
) -> Dict[str, List[Observation]]:
    """Forms groups whose members share at least one fully reachable value.

    Every shared value yields a candidate cluster of exactly the
    occurrences that decode to it within the bounded chain depth. A
    cluster is only emitted once (the largest such cluster wins for a set
    of members, deterministically), and clusters are never merged through
    transitive edges: each emitted group is directly backed by a value
    every member can reach, so an over-deep candidate cannot join a group
    merely by sharing intermediate encodings.
    """
    candidate_clusters: List[Set[str]] = []
    for occurrences in value_to_occurrences.values():
        if len(occurrences) < 2:
            continue
        cluster = set(occurrences)
        if cluster not in candidate_clusters:
            candidate_clusters.append(cluster)

    # Overlapping clusters describe the same equivalence family (every edge
    # is a verified shared value), so merge them; but only when the merge
    # itself still has a value every member can reach. A candidate that only
    # shares an intermediate encoding at a depth beyond another member's
    # reach stays in its own, separately verifiable group.
    groups: List[Set[str]] = []
    reachable_members = {
        identity: set(reachable[identity])
        for identity in (item.occurrence_identity for item in observations)
    }
    for candidate in sorted(candidate_clusters, key=lambda cluster: (-len(cluster), min(cluster))):
        if any(candidate <= group for group in groups):
            continue

        merged_into_existing_group = False
        for index, existing in enumerate(groups):
            if not (candidate & existing):
                continue
            merged = candidate | existing
            common = set.intersection(*(
                reachable_members[identity] for identity in merged
            ))
            if common:
                groups[index] = merged
                merged_into_existing_group = True
                break
            # Overlapping but without a value reachable by every member: this
            # candidate cannot join the existing group. Continue scanning the
            # other groups, and only append a brand-new group if none accept
            # it (its own shared value still makes it independently valid).

        if not merged_into_existing_group:
            groups.append(set(candidate))

    clusters: Dict[str, List[Observation]] = {}
    for index, group in enumerate(groups):
        # Key by index, not by a member identity: distinct verified groups
        # can legitimately share one member (e.g. an intermediate encoding),
        # and identity keys would silently overwrite each other.
        clusters[f"group-{index}"] = [by_identity[identity] for identity in group]
    return clusters


def analyze_observations(
    observations: Sequence[Observation],
    tenant: Optional[str] = None,
) -> DerivationAnalysis:
    """Groups observations through verifiable decoding relationships.

    Only candidates whose raw values can be *canonically* decoded to a
    shared value (through the allow-listed transforms, within
    :data:`MAX_CHAIN_DEPTH` steps) are merged into a group. Masking,
    shared prefixes/suffixes and string similarity alone never cause a
    merge; pairs that merely look alike are reported separately.

    :param tenant: if supplied, observations belonging to other tenants
        are ignored. Tenant labels are part of every occurrence identity,
        so cross-tenant merges are impossible by construction.
    """
    scoped = [
        observation
        for observation in observations
        if tenant is None or observation.tenant == tenant
    ]

    reachable: Dict[str, Dict[str, List[DecodeResult]]] = {}
    value_to_occurrences: Dict[str, Set[str]] = defaultdict(set)
    for observation in scoped:
        values = dict(_reachable_values(observation.raw_value))
        reachable[observation.occurrence_identity] = values
        for value in values:
            value_to_occurrences[value].add(observation.occurrence_identity)

    by_identity = {
        observation.occurrence_identity: observation
        for observation in scoped
    }
    clusters = _clusters_from_shared_values(
        scoped,
        value_to_occurrences,
        by_identity,
        reachable,
    )

    groups: List[DerivationGroup] = []
    for members in clusters.values():
        if len(members) < 2:
            continue
        groups.append(
            _build_group(members, reachable, by_identity),
        )

    grouped_identities = {
        member.occurrence_identity
        for group in groups
        for member in group.members
    }
    unverifiable = _find_unverifiable_relationships(scoped, grouped_identities)
    return DerivationAnalysis(
        tenant=tenant,
        observations=list(scoped),
        groups=sorted(groups, key=lambda group: group.group_identity),
        unverifiable_relationships=unverifiable,
    )


def _build_group(
    members: List[Observation],
    reachable: Dict[str, Dict[str, List[DecodeResult]]],
    by_identity: Dict[str, Observation],
) -> DerivationGroup:
    member_identities = sorted(
        member.occurrence_identity for member in members
    )

    # A group root is a value every member can decode to. We pick the
    # deepest such value, breaking ties deterministically.
    shared_values: Optional[Set[str]] = None
    for identity in member_identities:
        values = set(reachable[identity])
        shared_values = values if shared_values is None else shared_values & values

    assert shared_values is not None
    root_value = min(
        shared_values,
        key=lambda value: (
            -max(len(reachable[identity][value]) for identity in member_identities),
            value,
        ),
    )
    root_value_identity = compute_value_identity(root_value)
    group_identity = compute_group_identity(root_value_identity, member_identities)

    group_members: List[GroupMember] = []
    for identity in member_identities:
        observation = by_identity[identity]
        chain = reachable[identity][root_value]
        steps: List[TransformStep] = []
        current = observation.raw_value
        for result in chain:
            steps.append(
                TransformStep(
                    transform=result.transform,
                    source_location={
                        "filename": observation.filename,
                        "line_number": observation.line_number,
                    },
                    input_identity=compute_value_identity(current),
                    output_identity=compute_value_identity(result.decoded),
                ),
            )
            current = result.decoded

        group_members.append(
            GroupMember(
                occurrence_identity=identity,
                filename=observation.filename,
                line_number=observation.line_number,
                secret_type=observation.secret_type,
                tenant=observation.tenant,
                chain=steps,
                connects_via=root_value_identity,
                root_reachable=True,
            ),
        )

    return DerivationGroup(
        group_identity=group_identity,
        root_value_identity=root_value_identity,
        members=group_members,
    )


def _find_unverifiable_relationships(
    observations: Sequence[Observation],
    grouped_identities: Set[str],
) -> List[UnverifiableRelationship]:
    """Lists look-alike pairs that fail every verifiable decode test.

    A pair is only considered when it shares the same tenant and secret
    type, looks plausibly related (common prefix/suffix or close edit
    distance), but cannot be merged through an allowed transform chain.
    Both entirely-ungrouped candidates and an ungrouped candidate next to
    an already-grouped one are reported; two members of the same verified
    group are never reported. These relationships are for manual review
    and never cause a merge.
    """
    output: List[UnverifiableRelationship] = []
    for index, left in enumerate(observations):
        for right in observations[index + 1:]:
            if left.tenant != right.tenant or left.secret_type != right.secret_type:
                continue

            both_grouped = (
                left.occurrence_identity in grouped_identities
                and right.occurrence_identity in grouped_identities
            )
            if both_grouped:
                continue
            if not _looks_related(left.raw_value, right.raw_value):
                continue

            output.append(
                UnverifiableRelationship(
                    relationship_identity=compute_relationship_identity(
                        left.tenant,
                        left.occurrence_identity,
                        right.occurrence_identity,
                    ),
                    left_occurrence_identity=left.occurrence_identity,
                    right_occurrence_identity=right.occurrence_identity,
                    reason="no_verifiable_decode_chain",
                    masked_left=mask_secret(left.raw_value),
                    masked_right=mask_secret(right.raw_value),
                ),
            )
            if len(output) >= MAX_UNVERIFIABLE:
                return output

    return output


def _looks_related(left: str, right: str) -> bool:
    """Conservative appearance-only heuristic.

    This is used *solely* to populate the unverifiable list. It can never
    contribute to a merge decision.
    """
    if left == right:
        return True
    if not left or not right:
        return False

    prefix = _common_prefix_length(left, right)
    suffix = _common_suffix_length(left, right)
    shorter = min(len(left), len(right))
    if shorter and (prefix + suffix) >= max(4, shorter // 2):
        return True

    return _edit_distance(left, right) <= max(2, shorter // 4)


def _common_prefix_length(left: str, right: str) -> int:
    index = 0
    for index, (a, b) in enumerate(zip(left, right)):
        if a != b:
            return index
    return min(len(left), len(right))


def _common_suffix_length(left: str, right: str) -> int:
    index = 0
    for index, (a, b) in enumerate(zip(reversed(left), reversed(right))):
        if a != b:
            return index
    return min(len(left), len(right))


def _edit_distance(left: str, right: str) -> int:
    previous = list(range(len(right) + 1))
    for i, char_left in enumerate(left, start=1):
        current = [i]
        for j, char_right in enumerate(right, start=1):
            current.append(min(
                previous[j] + 1,
                current[j - 1] + 1,
                previous[j - 1] + (char_left != char_right),
            ))
        previous = current
    return previous[-1]


def build_derivation_report(
    candidates: Iterable[ObservationTuple],
    tenant: Optional[str] = None,
) -> DerivationReport:
    """One-shot entry point: tuples in, persistable report out."""
    return analyze_observations(build_observations(candidates), tenant).to_report()


def analyze_secrets_collection(
    collection: Any,
    tenant: str = "default",
) -> DerivationAnalysis:
    """Runs derivation analysis over a SecretsCollection scan result.

    The plugin interface is untouched: this only reads the
    ``PotentialSecret`` objects already produced by a normal scan, using
    their in-memory plaintext values for the current scan only.
    """
    observations: List[Observation] = []
    for filename, secret in collection:
        if secret.secret_value is None:
            # Loaded from a baseline: plaintext is intentionally absent.
            continue
        observations.append(
            build_observation(
                tenant=tenant,
                secret_type=secret.type,
                filename=filename,
                line_number=getattr(secret, "line_number", 0),
                raw_value=secret.secret_value,
            ),
        )

    return analyze_observations(observations, tenant=tenant)


def clear_plaintext(analysis: DerivationAnalysis) -> None:
    """Drops every in-memory plaintext value held by an analysis."""
    for observation in analysis.observations:
        observation.raw_value = ""
