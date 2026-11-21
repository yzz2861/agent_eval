"""Scoped diff review for updated TUF trusted targets.

The review compares two snapshots of ``Targets.targets`` and classifies every
change. Each change carries a visibility scope and its own evidence. A
notification consumer only receives a :class:`ScopedReviewView`, which is
built from changes in one scope: totals, deletion notes, and evidence are all
computed from that filtered set.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, ClassVar

from tuf.api.metadata import TargetFile, Targets
from tuf.maintenance._errors import ScopeNotVisibleError
from tuf.maintenance.policy import ScopePolicy  # noqa: TC001

_COMPONENT_ID_FIELD = "component_id"
_TargetMap = Mapping[str, TargetFile]


class ChangeKind(StrEnum):
    """Kind of change between two trusted target snapshots."""

    ADDED = "added"
    UPDATED = "updated"
    REMOVED = "removed"
    RENAMED = "renamed"


class EvidenceKind(StrEnum):
    """Reason a change was classified the way it was."""

    COMPONENT_IDENTITY = "component-identity"
    SHARED_DIGEST = "shared-digest"
    DELIVERY_CHANNEL = "delivery-channel"


class IdentitySource(StrEnum):
    """Source of the independent evidence for a rename."""

    TARGET_CUSTOM = "target-custom"
    SECURITY_OPERATIONS = "security-operations"


@dataclass(frozen=True)
class _RenamePair:
    old_path: str
    new_path: str
    component_id: str
    source: IdentitySource


@dataclass(frozen=True)
class ComponentIdentity:
    """Stable component identity proving that a path change is a rename."""

    component_id: str
    old_path: str
    new_path: str
    source: IdentitySource = IdentitySource.TARGET_CUSTOM
    kind: ClassVar[EvidenceKind] = EvidenceKind.COMPONENT_IDENTITY

    def as_dict(self) -> dict[str, str]:
        """Return a serializable representation."""
        return {
            "kind": self.kind.value,
            "component_id": self.component_id,
            "old_path": self.old_path,
            "new_path": self.new_path,
            "source": self.source.value,
        }


@dataclass(frozen=True)
class SharedDigest:
    """Evidence that distinct components happen to share a digest.

    ``peers`` only contains paths in the same visibility scope. Digest
    sharing does not prove that two targets are the same component, so it
    must never be treated as rename evidence.
    """

    digest: str
    peers: tuple[str, ...]
    kind: ClassVar[EvidenceKind] = EvidenceKind.SHARED_DIGEST

    def as_dict(self) -> dict[str, Any]:
        """Return a serializable representation."""
        return {
            "kind": self.kind.value,
            "digest": self.digest,
            "peers": list(self.peers),
        }


@dataclass(frozen=True)
class DeliveryChannel:
    """Evidence that this path is one delivery channel of an artifact.

    The evidence deliberately names only this path. Other channels are
    separate changes with their own evidence, so one channel never has to be
    disclosed in order to explain another.
    """

    path: str
    component_id: str
    digest: str
    kind: ClassVar[EvidenceKind] = EvidenceKind.DELIVERY_CHANNEL

    def as_dict(self) -> dict[str, str]:
        """Return a serializable representation."""
        return {
            "kind": self.kind.value,
            "path": self.path,
            "component_id": self.component_id,
            "digest": self.digest,
        }


Evidence = ComponentIdentity | SharedDigest | DeliveryChannel


@dataclass(frozen=True)
class TargetChange:
    """One scoped change with independent classification evidence."""

    kind: ChangeKind
    scope: str
    path: str
    old_path: str | None = None
    old: TargetFile | None = None
    new: TargetFile | None = None
    evidence: tuple[Evidence, ...] = ()

    def __post_init__(self) -> None:
        if self.kind is ChangeKind.ADDED and self.new is None:
            raise ValueError("added change requires a new target")
        if self.kind is ChangeKind.REMOVED and self.old is None:
            raise ValueError("removed change requires an old target")
        if self.kind is ChangeKind.UPDATED and (
            self.old is None or self.new is None
        ):
            raise ValueError("updated change requires old and new targets")
        if self.kind is ChangeKind.RENAMED and (
            self.old is None or self.new is None or not self.old_path
        ):
            raise ValueError(
                "renamed change requires old path and both targets"
            )

    @property
    def evidence_kinds(self) -> tuple[EvidenceKind, ...]:
        """Return the evidence kinds attached to this change."""
        return tuple(item.kind for item in self.evidence)

    @property
    def old_artifact(self) -> ArtifactRef | None:
        """Return the old artifact that a maintenance group may replace."""
        if self.kind is ChangeKind.ADDED or self.old is None:
            return None
        if self.kind is ChangeKind.RENAMED and self.old_path is not None:
            return ArtifactRef(self.old_path, digest_label(self.old))
        return ArtifactRef(self.path, digest_label(self.old))

    def as_dict(self) -> dict[str, Any]:
        """Return a serializable representation."""
        return {
            "kind": self.kind.value,
            "scope": self.scope,
            "path": self.path,
            "old_path": self.old_path,
            "old_digest": digest_label(self.old) if self.old else None,
            "new_digest": digest_label(self.new) if self.new else None,
            "evidence": [item.as_dict() for item in self.evidence],
        }


@dataclass(frozen=True)
class ArtifactRef:
    """Reference to a target artifact that a group may need to replace."""

    path: str
    digest: str

    def as_dict(self) -> dict[str, str]:
        """Return a serializable representation."""
        return {"path": self.path, "digest": self.digest}


@dataclass(frozen=True)
class ReviewTotals:
    """Change counts for the changes visible to one scope."""

    added: int = 0
    updated: int = 0
    removed: int = 0
    renamed: int = 0

    @property
    def total(self) -> int:
        """Return the number of visible changes."""
        return self.added + self.updated + self.removed + self.renamed

    def as_dict(self) -> dict[str, int]:
        """Return a serializable representation."""
        return {
            "added": self.added,
            "updated": self.updated,
            "removed": self.removed,
            "renamed": self.renamed,
            "total": self.total,
        }


@dataclass(frozen=True)
class ScopedReviewView:
    """The complete review as seen by exactly one visibility scope.

    This object never stores global totals or unfiltered changes. Everything
    that can be serialized or rendered is derived from ``changes``, which
    already belongs to one scope. Even the review digest is scope-local, so
    it cannot be used as a confirmation oracle for another group's changes.
    """

    scope: str
    policy_version: int
    changes: tuple[TargetChange, ...]
    view_id: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "view_id", self._compute_view_id())

    def _compute_view_id(self) -> str:
        canonical = json.dumps(
            {
                "scope": self.scope,
                "policy_version": self.policy_version,
                "changes": [change.as_dict() for change in self.changes],
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @property
    def totals(self) -> ReviewTotals:
        """Return totals computed only from visible changes."""
        counts: dict[ChangeKind, int] = dict.fromkeys(ChangeKind, 0)
        for change in self.changes:
            counts[change.kind] += 1
        return ReviewTotals(
            added=counts[ChangeKind.ADDED],
            updated=counts[ChangeKind.UPDATED],
            removed=counts[ChangeKind.REMOVED],
            renamed=counts[ChangeKind.RENAMED],
        )

    @property
    def deletions(self) -> tuple[TargetChange, ...]:
        """Return only the visible removals."""
        return tuple(
            change
            for change in self.changes
            if change.kind is ChangeKind.REMOVED
        )

    @property
    def deletion_notes(self) -> tuple[str, ...]:
        """Return human-readable notes for visible removals only."""
        return tuple(
            f"remove {change.path} ({digest_label(change.old)})"
            for change in self.deletions
            if change.old is not None
        )

    @property
    def old_artifacts(self) -> tuple[ArtifactRef, ...]:
        """Return old artifacts this scope may need to replace."""
        artifacts: list[ArtifactRef] = []
        for change in self.changes:
            artifact = change.old_artifact
            if artifact is not None:
                artifacts.append(artifact)
        return tuple(artifacts)

    def as_dict(self) -> dict[str, Any]:
        """Return a serializable representation of this scoped view."""
        return {
            "scope": self.scope,
            "policy_version": self.policy_version,
            "view_id": self.view_id,
            "changes": [change.as_dict() for change in self.changes],
            "totals": self.totals.as_dict(),
            "deletion_notes": list(self.deletion_notes),
            "old_artifacts": [
                artifact.as_dict() for artifact in self.old_artifacts
            ],
        }

    def render_text(self) -> str:
        """Render a plain-text maintenance notice from visible data only."""
        lines = [f"maintenance scope: {self.scope}"]
        for change in self.changes:
            if change.kind is ChangeKind.RENAMED:
                lines.append(f"rename {change.old_path} -> {change.path}")
            elif change.kind is ChangeKind.ADDED:
                lines.append(f"add {change.path}")
            elif change.kind is ChangeKind.REMOVED:
                lines.append(f"remove {change.path}")
            else:
                lines.append(f"update {change.path}")
            artifact = change.old_artifact
            if artifact is not None:
                lines.append(f"  replace {artifact.path} {artifact.digest}")
        if self.deletion_notes:
            lines.append("deletions:")
            for note in self.deletion_notes:
                lines.append(f"  {note}")
        totals = self.totals
        lines.append(
            "totals: "
            f"added={totals.added} updated={totals.updated} "
            f"removed={totals.removed} renamed={totals.renamed}"
        )
        return "\n".join(lines)


@dataclass(frozen=True)
class ScopedDiffReview:
    """Immutable, sealed review of two trusted target snapshots.

    Build reviews with :meth:`build`. A review is accepted by the
    notification generator only while its policy version and fingerprint are
    still current.
    """

    policy: ScopePolicy
    previous_version: int | None
    updated_version: int | None
    changes: tuple[TargetChange, ...]
    review_id: str = field(init=False)
    policy_fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        normalized = tuple(
            sorted(self.changes, key=lambda change: (change.scope, change.path))
        )
        object.__setattr__(self, "changes", normalized)
        object.__setattr__(self, "policy_fingerprint", self.policy.fingerprint)
        object.__setattr__(self, "review_id", self._compute_review_id())

    def _compute_review_id(self) -> str:
        canonical = json.dumps(
            {
                "policy": self.policy_fingerprint,
                "previous_version": self.previous_version,
                "updated_version": self.updated_version,
                "changes": [change.as_dict() for change in self.changes],
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @classmethod
    def build(
        cls,
        previous: Targets | _TargetMap,
        updated: Targets | _TargetMap,
        policy: ScopePolicy,
        *,
        rename_evidence: Mapping[str, str] | None = None,
    ) -> ScopedDiffReview:
        """Build a sealed review of ``updated`` relative to ``previous``.

        Args:
            previous: Previous trusted targets metadata or target mapping.
            updated: Updated trusted targets metadata or target mapping.
            policy: Visibility policy assigning target paths to scopes.
            rename_evidence: Optional explicit mapping of old path to new
                path supplied by security operations. This is independent
                evidence and takes precedence over target custom metadata.

        Returns:
            The sealed review.
        """
        old_targets, old_version = _coerce_targets(previous)
        new_targets, new_version = _coerce_targets(updated)

        changes = _classify_changes(
            old_targets,
            new_targets,
            policy,
            rename_evidence or {},
        )
        return cls(
            policy=policy,
            previous_version=old_version,
            updated_version=new_version,
            changes=changes,
        )

    def for_scope(self, scope: str) -> ScopedReviewView:
        """Return the review filtered to ``scope``.

        The reviewer scope receives every change. Any other scope receives
        only changes whose owning scope matches exactly. Unknown maintenance
        scopes raise instead of silently producing an empty notice.

        Raises:
            ScopeNotVisibleError: If ``scope`` is not a maintenance scope in
                the review policy and is not the reviewer scope.
        """
        if self.policy.is_reviewer(scope):
            visible = self.changes
        elif scope not in self.policy.maintenance_scopes():
            raise ScopeNotVisibleError(
                f"scope {scope!r} is not part of policy version "
                f"{self.policy.version}"
            )
        else:
            visible = tuple(
                change for change in self.changes if change.scope == scope
            )
        return ScopedReviewView(
            scope=scope,
            policy_version=self.policy.version,
            changes=visible,
        )

    @property
    def reviewer_view(self) -> ScopedReviewView:
        """Return the unfiltered security operations view."""
        return self.for_scope(self.policy.reviewer_scope)


def _coerce_targets(
    targets: Targets | _TargetMap,
) -> tuple[_TargetMap, int | None]:
    if isinstance(targets, Targets):
        return targets.targets, targets.version
    if isinstance(targets, Mapping):
        return targets, None
    raise TypeError("targets must be Targets metadata or a target mapping")


def _classify_changes(
    old_targets: _TargetMap,
    new_targets: _TargetMap,
    policy: ScopePolicy,
    rename_evidence: Mapping[str, str],
) -> tuple[TargetChange, ...]:
    old_paths = set(old_targets)
    new_paths = set(new_targets)
    removed_paths = old_paths - new_paths
    added_paths = new_paths - old_paths

    renames = _rename_pairs(
        old_targets,
        new_targets,
        removed_paths,
        added_paths,
        rename_evidence,
    )
    renamed_old = {pair.old_path for pair in renames}
    renamed_new = {pair.new_path for pair in renames}

    changes: list[TargetChange] = []

    for pair in renames:
        old_target = old_targets[pair.old_path]
        new_target = new_targets[pair.new_path]
        old_scope = policy.scope_of(pair.old_path)
        new_scope = policy.scope_of(pair.new_path)
        if old_scope != new_scope:
            # A cross-scope move must not become a rename: exposing the pair
            # would tell one group which path the other group now owns.
            changes.append(
                _make_change(
                    ChangeKind.REMOVED,
                    old_scope,
                    pair.old_path,
                    old_target,
                    None,
                    old_targets,
                    new_targets,
                    policy,
                )
            )
            changes.append(
                _make_change(
                    ChangeKind.ADDED,
                    new_scope,
                    pair.new_path,
                    None,
                    new_target,
                    old_targets,
                    new_targets,
                    policy,
                )
            )
            continue

        evidence = _evidence_for(
            old_scope,
            pair.new_path,
            old_target,
            new_target,
            old_targets,
            new_targets,
            policy,
        )
        changes.append(
            TargetChange(
                kind=ChangeKind.RENAMED,
                scope=old_scope,
                path=pair.new_path,
                old_path=pair.old_path,
                old=old_target,
                new=new_target,
                evidence=(
                    ComponentIdentity(
                        component_id=pair.component_id,
                        old_path=pair.old_path,
                        new_path=pair.new_path,
                        source=pair.source,
                    ),
                    *evidence,
                ),
            )
        )

    for path in sorted(removed_paths - renamed_old):
        changes.append(
            _make_change(
                ChangeKind.REMOVED,
                policy.scope_of(path),
                path,
                old_targets[path],
                None,
                old_targets,
                new_targets,
                policy,
            )
        )

    for path in sorted(added_paths - renamed_new):
        changes.append(
            _make_change(
                ChangeKind.ADDED,
                policy.scope_of(path),
                path,
                None,
                new_targets[path],
                old_targets,
                new_targets,
                policy,
            )
        )

    for path in sorted(old_paths & new_paths):
        old_target = old_targets[path]
        new_target = new_targets[path]
        if not _same_content(old_target, new_target):
            changes.append(
                _make_change(
                    ChangeKind.UPDATED,
                    policy.scope_of(path),
                    path,
                    old_target,
                    new_target,
                    old_targets,
                    new_targets,
                    policy,
                )
            )

    return tuple(changes)


def _rename_pairs(
    old_targets: _TargetMap,
    new_targets: _TargetMap,
    removed_paths: set[str],
    added_paths: set[str],
    explicit_evidence: Mapping[str, str],
) -> list[_RenamePair]:
    pairs, claimed_old, claimed_new = _explicit_rename_pairs(
        old_targets,
        new_targets,
        removed_paths,
        added_paths,
        explicit_evidence,
    )
    pairs.extend(
        _identity_rename_pairs(
            old_targets,
            new_targets,
            removed_paths,
            added_paths,
            claimed_old,
            claimed_new,
        )
    )
    return pairs


def _explicit_rename_pairs(
    old_targets: _TargetMap,
    new_targets: _TargetMap,
    removed_paths: set[str],
    added_paths: set[str],
    explicit_evidence: Mapping[str, str],
) -> tuple[list[_RenamePair], set[str], set[str]]:
    pairs: list[_RenamePair] = []
    claimed_old: set[str] = set()
    claimed_new: set[str] = set()

    for old_path, new_path in explicit_evidence.items():
        if old_path not in removed_paths:
            raise ValueError(
                f"rename source is not a removed target: {old_path}"
            )
        if new_path not in added_paths:
            raise ValueError(
                f"rename destination is not an added target: {new_path}"
            )
        if old_path in claimed_old or new_path in claimed_new:
            raise ValueError("rename evidence must be one-to-one")
        claimed_old.add(old_path)
        claimed_new.add(new_path)
        old_component = _component_id(old_targets[old_path])
        new_component = _component_id(new_targets[new_path])
        component_id = ""
        if old_component and old_component == new_component:
            component_id = old_component
        pairs.append(
            _RenamePair(
                old_path=old_path,
                new_path=new_path,
                component_id=component_id,
                source=IdentitySource.SECURITY_OPERATIONS,
            )
        )

    return pairs, claimed_old, claimed_new


def _identity_rename_pairs(
    old_targets: _TargetMap,
    new_targets: _TargetMap,
    removed_paths: set[str],
    added_paths: set[str],
    claimed_old: set[str],
    claimed_new: set[str],
) -> list[_RenamePair]:
    old_by_component: dict[str, list[str]] = defaultdict(list)
    new_by_component: dict[str, list[str]] = defaultdict(list)
    for path in removed_paths - claimed_old:
        component = _component_id(old_targets[path])
        if component:
            old_by_component[component].append(path)
    for path in added_paths - claimed_new:
        component = _component_id(new_targets[path])
        if component:
            new_by_component[component].append(path)

    pairs: list[_RenamePair] = []
    for component in sorted(set(old_by_component) & set(new_by_component)):
        old_candidates = old_by_component[component]
        new_candidates = new_by_component[component]
        if len(old_candidates) != 1 or len(new_candidates) != 1:
            continue
        pairs.append(
            _RenamePair(
                old_path=old_candidates[0],
                new_path=new_candidates[0],
                component_id=component,
                source=IdentitySource.TARGET_CUSTOM,
            )
        )
    return pairs


def _make_change(
    kind: ChangeKind,
    scope: str,
    path: str,
    old: TargetFile | None,
    new: TargetFile | None,
    old_targets: _TargetMap,
    new_targets: _TargetMap,
    policy: ScopePolicy,
) -> TargetChange:
    evidence = _evidence_for(
        scope,
        path,
        old,
        new,
        old_targets,
        new_targets,
        policy,
    )
    return TargetChange(
        kind=kind,
        scope=scope,
        path=path,
        old=old,
        new=new,
        evidence=evidence,
    )


def _evidence_for(
    scope: str,
    path: str,
    old: TargetFile | None,
    new: TargetFile | None,
    old_targets: _TargetMap,
    new_targets: _TargetMap,
    policy: ScopePolicy,
) -> tuple[Evidence, ...]:
    evidence: list[Evidence] = []
    component_id = _component_id(new) or _component_id(old)
    baseline = new_targets if new is not None else old_targets
    subject = new if new is not None else old
    if subject is None:
        return ()
    digest = digest_label(subject)

    if component_id:
        channels = tuple(
            sorted(
                candidate
                for candidate, target in baseline.items()
                if candidate != path
                and _component_id(target) == component_id
                and digest_label(target) == digest
                and target.length == subject.length
                and policy.scope_of(candidate) == scope
            )
        )
        if channels:
            evidence.append(
                DeliveryChannel(
                    path=path,
                    component_id=component_id,
                    digest=digest,
                )
            )

    shared_peers = tuple(
        sorted(
            candidate
            for candidate, target in baseline.items()
            if candidate != path
            and digest_label(target) == digest
            and _different_component(component_id, _component_id(target))
            and policy.scope_of(candidate) == scope
        )
    )
    if shared_peers:
        evidence.append(SharedDigest(digest=digest, peers=shared_peers))

    return tuple(evidence)


def _different_component(
    left: str | None,
    right: str | None,
) -> bool:
    return left is not None and right is not None and left != right


def _component_id(target: TargetFile | None) -> str | None:
    if target is None:
        return None
    custom = target.custom
    if not isinstance(custom, Mapping):
        return None
    component = custom.get(_COMPONENT_ID_FIELD)
    if isinstance(component, str) and component:
        return component
    return None


def _same_content(left: TargetFile, right: TargetFile) -> bool:
    if left.length != right.length:
        return False
    common = set(left.hashes) & set(right.hashes)
    if not common:
        return False
    return all(
        left.hashes[algorithm] == right.hashes[algorithm]
        for algorithm in common
    )


def digest_label(target: TargetFile) -> str:
    """Return a stable ``algorithm:hex`` digest label for ``target``."""
    if "sha256" in target.hashes:
        algorithm = "sha256"
    else:
        algorithm = sorted(target.hashes)[0]
    return f"{algorithm}:{target.hashes[algorithm]}"
