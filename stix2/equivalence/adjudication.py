"""Explicit review adjudication for STIX object similarity.

The semantic equivalence APIs answer the question "how similar are these two
objects?"  They intentionally do not answer the operational question "are
these two objects the same thing, according to the people reviewing the
import?"  This module adds that missing layer.

An adjudication is built from three inputs:

* the current objects held by a data store,
* pairwise similarity scores produced by :mod:`stix2.equivalence`, and
* a :class:`ReviewLedger` containing analyst opinions.

A review opinion applies to a particular version of each object.  Opinions are
append-only: retracting one adds a :class:`Retraction` record instead of
deleting the original opinion.  Confirmations are counted by *collection
source*, not by reviewer, comment, or opinion.  Two opinions derived from the
same source therefore provide only one independent confirmation.

Clustering deliberately is not a plain connected-components operation.  A
chain of above-threshold pairwise similarities may be split by an explicit
rejection, and objects which have active reviews are pinned: a newly imported
bridge object cannot silently merge their groups.  A change caused by an
explicit review or by a retraction is still allowed, and is reported in an
:class:`AdjudicationDelta`.

The :class:`AdjudicationLayer` class wires the model to an existing
``DataStoreMixin`` instance.  It reads current object versions from the store,
delegates pairwise scoring to the equivalence code, and keeps the review
ledger alongside the stored STIX content.
"""

from __future__ import annotations

import datetime as dt
import itertools
import uuid
from collections import OrderedDict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Optional

from ..datastore import DataStoreMixin

__all__ = [
    "AdjudicationDelta",
    "AdjudicationLayer",
    "AdjudicationResult",
    "AdjudicationStore",
    "Adjudicator",
    "BlockedEdge",
    "EquivalenceAdjudicator",
    "Group",
    "GroupChange",
    "MatchReview",
    "ObjectMove",
    "Opinion",
    "PairDecision",
    "PairState",
    "Retraction",
    "Review",
    "ReviewLedger",
    "ReviewOpinion",
    "ReviewRecord",
    "ReviewVerdict",
    "SimilarityEdge",
    "adjudicate",
]


Pair = tuple[str, str]
VersionMap = Mapping[str, Optional[str]]


def _utcnow_string() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _canonical_pair(left: str, right: str) -> Pair:
    if left is None or right is None:
        raise ValueError("both object IDs are required")

    left = str(left)
    right = str(right)
    if left == right:
        raise ValueError("a match review requires two different object IDs")

    return (left, right) if left <= right else (right, left)


def _version_string(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value

    try:
        from ..utils import format_datetime

        return format_datetime(value)
    except (AttributeError, TypeError, ValueError):
        return str(value)


def _versions_equal(expected: str, actual: Any) -> bool:
    """Compare version tokens, treating equivalent timestamps as the same."""

    actual = _version_string(actual)
    if expected == actual:
        return True

    try:
        from ..utils import parse_into_datetime

        return parse_into_datetime(expected) == parse_into_datetime(actual)
    except (AttributeError, TypeError, ValueError):
        return False


def _object_version(obj: Any) -> Optional[str]:
    if obj is None:
        return None
    if isinstance(obj, Mapping):
        version = obj.get("modified") or obj.get("created")
    else:
        version = getattr(obj, "modified", None) or getattr(obj, "created", None)
    return _version_string(version)


def _object_id(obj: Any) -> Optional[str]:
    if isinstance(obj, Mapping):
        return obj.get("id")
    return getattr(obj, "id", None)


def _normalise_objects(
    objects: Iterable[Any] | Mapping[str, Any],
    versions: Optional[VersionMap] = None,
) -> tuple[dict[str, Any], dict[str, Optional[str]]]:
    """Return an id-to-object mapping and the current version of each object."""

    objects_by_id: dict[str, Any] = {}
    current_versions: dict[str, Optional[str]] = {
        str(object_id): _version_string(version)
        for object_id, version in (versions or {}).items()
    }

    if isinstance(objects, Mapping):
        values = objects.items()
    else:
        values = ((None, value) for value in objects)

    for key, value in values:
        object_id = _object_id(value)
        if object_id is None and isinstance(key, str):
            object_id = key

        if object_id is None:
            raise TypeError(
                "objects must be STIX objects/dicts with an 'id', or a "
                "mapping of object IDs",
            )

        object_id = str(object_id)
        objects_by_id[object_id] = value
        current_versions.setdefault(object_id, _object_version(value))

    return objects_by_id, current_versions


def _normalise_edges(
    edges: Optional[
        Iterable[Any] | Mapping[Any, Any]
    ],
) -> list["SimilarityEdge"]:
    if not edges:
        return []

    if isinstance(edges, Mapping):
        raw_edges = []
        for pair, score in edges.items():
            if isinstance(score, Mapping):
                item = dict(score)
                item.setdefault("pair", pair)
                raw_edges.append(item)
            else:
                left, right = pair
                raw_edges.append((left, right, score))
    else:
        raw_edges = list(edges)

    by_pair: dict[Pair, SimilarityEdge] = {}
    for raw in raw_edges:
        edge = SimilarityEdge.from_any(raw)
        old = by_pair.get(edge.pair)
        if old is None or edge.score > old.score:
            by_pair[edge.pair] = edge

    return [by_pair[pair] for pair in sorted(by_pair)]


class ReviewVerdict(str, Enum):
    """The two fundamental review outcomes."""

    CONFIRM = "confirm"
    REJECT = "reject"

    @classmethod
    def coerce(cls, value: Any) -> "ReviewVerdict":
        if isinstance(value, cls):
            return value

        normalised = str(value).strip().lower()
        aliases = {
            "confirm": cls.CONFIRM,
            "confirmed": cls.CONFIRM,
            "merge": cls.CONFIRM,
            "match": cls.CONFIRM,
            "positive": cls.CONFIRM,
            "reject": cls.REJECT,
            "rejected": cls.REJECT,
            "split": cls.REJECT,
            "different": cls.REJECT,
            "negative": cls.REJECT,
        }
        try:
            return aliases[normalised]
        except KeyError:
            raise ValueError(
                "review verdict must be one of: confirm, reject",
            ) from None


CONFIRM = ReviewVerdict.CONFIRM
REJECT = ReviewVerdict.REJECT


@dataclass(frozen=True)
class ReviewOpinion:
    """One analyst's opinion about a pair of STIX objects.

    Args:
        left: One object ID in the pair.
        right: The other object ID in the pair.
        verdict: ``"confirm"``/``"reject"`` (or an alias such as
            ``"merge"``/``"split"``).
        reviewer: The analyst or system which recorded the opinion.
        source: The collection source from which the judgment was derived.
            This is the unit of independence.  If omitted, ``reviewer`` is
            used as the source.
        versions: Mapping of object ID to the STIX version the opinion applies
            to (normally the ``modified`` or ``created`` timestamp).  An
            object ID omitted from the mapping is treated as version
            agnostic.
        review_id: Stable identifier for the opinion.  Generated when omitted.
        created_at: Timestamp at which the opinion became applicable.
        reason: Optional analyst note.
        metadata: Optional caller-defined data.
    """

    left: str
    right: str
    verdict: str
    reviewer: str
    source: Optional[str] = None
    versions: Mapping[str, str] = field(default_factory=dict)
    review_id: str = field(default_factory=lambda: "review--" + str(uuid.uuid4()))
    created_at: str = field(default_factory=_utcnow_string)
    reason: Optional[str] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        left, right = _canonical_pair(self.left, self.right)
        reviewer = str(self.reviewer).strip()
        if not reviewer:
            raise ValueError("reviewer must not be empty")

        source = str(self.source).strip() if self.source else reviewer
        if not source:
            raise ValueError("source must not be empty")

        review_id = str(self.review_id).strip()
        if not review_id:
            raise ValueError("review_id must not be empty")

        created_at = str(self.created_at).strip()
        if not created_at:
            raise ValueError("created_at must not be empty")

        versions = {
            str(object_id): _version_string(version)
            for object_id, version in (self.versions or {}).items()
            if version is not None
        }

        object.__setattr__(self, "left", left)
        object.__setattr__(self, "right", right)
        object.__setattr__(
            self,
            "verdict",
            ReviewVerdict.coerce(self.verdict).value,
        )
        object.__setattr__(self, "reviewer", reviewer)
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "versions", MappingProxyType(versions))
        object.__setattr__(self, "review_id", review_id)
        object.__setattr__(self, "created_at", created_at)
        object.__setattr__(
            self,
            "metadata",
            MappingProxyType(dict(self.metadata or {})),
        )

    @property
    def pair(self) -> Pair:
        return (self.left, self.right)

    @property
    def verdict_enum(self) -> ReviewVerdict:
        return ReviewVerdict(self.verdict)

    @property
    def is_confirmation(self) -> bool:
        return self.verdict_enum is ReviewVerdict.CONFIRM

    @property
    def is_rejection(self) -> bool:
        return self.verdict_enum is ReviewVerdict.REJECT

    def applies_to(self, current_versions: VersionMap) -> bool:
        """Whether this opinion applies to the supplied object versions."""

        for object_id in self.pair:
            expected = self.versions.get(object_id)
            if expected is None or expected == "*":
                continue

            actual = current_versions.get(object_id)
            if actual is None:
                continue
            if not _versions_equal(expected, actual):
                return False

        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "review_id": self.review_id,
            "left": self.left,
            "right": self.right,
            "verdict": self.verdict,
            "reviewer": self.reviewer,
            "source": self.source,
            "versions": dict(self.versions),
            "created_at": self.created_at,
            "reason": self.reason,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ReviewOpinion":
        return cls(**dict(data))


@dataclass(frozen=True)
class Retraction:
    """An immutable record that a review opinion was withdrawn."""

    review_id: str
    retracted_at: str = field(default_factory=_utcnow_string)
    actor: Optional[str] = None
    reason: Optional[str] = None

    def __post_init__(self) -> None:
        review_id = str(self.review_id).strip()
        if not review_id:
            raise ValueError("review_id must not be empty")
        object.__setattr__(self, "review_id", review_id)
        object.__setattr__(self, "retracted_at", str(self.retracted_at))

    def to_dict(self) -> dict[str, Any]:
        return {
            "review_id": self.review_id,
            "retracted_at": self.retracted_at,
            "actor": self.actor,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Retraction":
        return cls(**dict(data))


@dataclass(frozen=True)
class ReviewRecord:
    """An opinion together with its (optional) retraction record."""

    opinion: ReviewOpinion
    retraction: Optional[Retraction] = None

    @property
    def active(self) -> bool:
        return self.retraction is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "opinion": self.opinion.to_dict(),
            "retraction": (
                None if self.retraction is None else self.retraction.to_dict()
            ),
        }


class ReviewLedger:
    """Append-only storage for review opinions and retraction records.

    Adding an opinion never overwrites an earlier opinion, even when both
    concern the same object pair.  Retracting an opinion keeps the original
    opinion in :meth:`history` and records who/when/why it was withdrawn.
    """

    def __init__(
        self,
        opinions: Optional[Iterable[ReviewOpinion]] = None,
        retractions: Optional[Iterable[Retraction]] = None,
    ) -> None:
        self._opinions: "OrderedDict[str, ReviewOpinion]" = OrderedDict()
        self._retractions: "OrderedDict[str, Retraction]" = OrderedDict()

        for opinion in opinions or ():
            self.add(opinion)
        for retraction in retractions or ():
            self._add_retraction(retraction)

    def __len__(self) -> int:
        return len(self._opinions)

    def __iter__(self):
        return iter(self._opinions.values())

    def add(self, opinion: ReviewOpinion | Mapping[str, Any]) -> ReviewOpinion:
        if isinstance(opinion, Mapping):
            opinion = ReviewOpinion.from_dict(opinion)
        if not isinstance(opinion, ReviewOpinion):
            raise TypeError("opinion must be a ReviewOpinion or a mapping")
        if opinion.review_id in self._opinions:
            raise ValueError(
                "review_id already exists: {}".format(opinion.review_id),
            )
        self._opinions[opinion.review_id] = opinion
        return opinion

    add_opinion = add

    def record(
        self,
        left: str,
        right: str,
        verdict: str,
        reviewer: str,
        source: Optional[str] = None,
        versions: Optional[VersionMap] = None,
        review_id: Optional[str] = None,
        created_at: Optional[str] = None,
        reason: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> ReviewOpinion:
        """Create and append a review opinion."""

        kwargs: dict[str, Any] = {
            "left": left,
            "right": right,
            "verdict": verdict,
            "reviewer": reviewer,
            "source": source,
            "versions": versions or {},
            "reason": reason,
            "metadata": metadata or {},
        }
        if review_id is not None:
            kwargs["review_id"] = review_id
        if created_at is not None:
            kwargs["created_at"] = created_at
        return self.add(ReviewOpinion(**kwargs))

    def retract(
        self,
        review_id: str,
        at: Optional[str] = None,
        actor: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> Retraction:
        """Withdraw an opinion while retaining the original record."""

        if review_id not in self._opinions:
            raise KeyError("unknown review_id: {}".format(review_id))
        if review_id in self._retractions:
            raise ValueError(
                "review_id is already retracted: {}".format(review_id),
            )

        kwargs: dict[str, Any] = {
            "review_id": review_id,
            "actor": actor,
            "reason": reason,
        }
        if at is not None:
            kwargs["retracted_at"] = at
        return self._add_retraction(Retraction(**kwargs))

    def _add_retraction(self, retraction: Retraction) -> Retraction:
        if retraction.review_id not in self._opinions:
            raise KeyError(
                "unknown review_id: {}".format(retraction.review_id),
            )
        if retraction.review_id in self._retractions:
            raise ValueError(
                "review_id is already retracted: {}".format(
                    retraction.review_id,
                ),
            )
        self._retractions[retraction.review_id] = retraction
        return retraction

    def get(self, review_id: str) -> ReviewOpinion:
        return self._opinions[review_id]

    def retraction_for(self, review_id: str) -> Optional[Retraction]:
        return self._retractions.get(review_id)

    def opinions(
        self,
        pair: Optional[Pair] = None,
        include_retracted: bool = True,
    ) -> list[ReviewOpinion]:
        canonical = _canonical_pair(*pair) if pair else None
        result = []
        for opinion in self._opinions.values():
            if canonical is not None and opinion.pair != canonical:
                continue
            if not include_retracted and opinion.review_id in self._retractions:
                continue
            result.append(opinion)
        return result

    def active_opinions(
        self,
        pair: Optional[Pair] = None,
        versions: Optional[VersionMap] = None,
    ) -> list[ReviewOpinion]:
        result = []
        for opinion in self.opinions(pair=pair, include_retracted=False):
            if versions is None or opinion.applies_to(versions):
                result.append(opinion)
        return result

    def history(self, pair: Optional[Pair] = None) -> list[ReviewRecord]:
        return [
            ReviewRecord(
                opinion=opinion,
                retraction=self._retractions.get(opinion.review_id),
            )
            for opinion in self.opinions(pair=pair)
        ]

    def confirmation_sources(
        self,
        pair: Pair,
        versions: Optional[VersionMap] = None,
    ) -> set[str]:
        return {
            opinion.source
            for opinion in self.active_opinions(pair, versions)
            if opinion.is_confirmation
        }

    def rejection_sources(
        self,
        pair: Pair,
        versions: Optional[VersionMap] = None,
    ) -> set[str]:
        return {
            opinion.source
            for opinion in self.active_opinions(pair, versions)
            if opinion.is_rejection
        }

    def is_reviewed(
        self,
        object_id: str,
        versions: Optional[VersionMap] = None,
    ) -> bool:
        return any(
            object_id in opinion.pair
            for opinion in self.active_opinions(versions=versions)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "opinions": [opinion.to_dict() for opinion in self._opinions.values()],
            "retractions": [
                retraction.to_dict()
                for retraction in self._retractions.values()
            ],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ReviewLedger":
        return cls(
            opinions=[
                ReviewOpinion.from_dict(item)
                for item in data.get("opinions", [])
            ],
            retractions=[
                Retraction.from_dict(item)
                for item in data.get("retractions", [])
            ],
        )

    def __repr__(self) -> str:
        return "ReviewLedger(opinions={}, retractions={})".format(
            len(self._opinions),
            len(self._retractions),
        )


class PairState(str, Enum):
    """Adjudicated state of one object pair."""

    UNREVIEWED = "unreviewed"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INSUFFICIENT = "insufficient"
    CONFLICTED = "conflicted"


@dataclass(frozen=True)
class PairDecision:
    """The result of adjudicating one object pair."""

    pair: Pair
    state: str
    score: Optional[float] = None
    confirmations: int = 0
    rejections: int = 0
    confirm_sources: tuple[str, ...] = ()
    reject_sources: tuple[str, ...] = ()
    opinions: tuple[ReviewOpinion, ...] = ()
    conflicted: bool = False
    reason: str = ""

    @property
    def state_enum(self) -> PairState:
        return PairState(self.state)

    @property
    def reviewed(self) -> bool:
        return bool(self.opinions)

    @property
    def merge_allowed(self) -> bool:
        return self.state_enum is PairState.CONFIRMED

    @property
    def auto_merge_allowed(self) -> bool:
        return self.state_enum is PairState.UNREVIEWED

    def to_dict(self) -> dict[str, Any]:
        return {
            "pair": list(self.pair),
            "state": self.state,
            "score": self.score,
            "confirmations": self.confirmations,
            "rejections": self.rejections,
            "confirm_sources": list(self.confirm_sources),
            "reject_sources": list(self.reject_sources),
            "conflicted": self.conflicted,
            "reason": self.reason,
            "review_ids": [opinion.review_id for opinion in self.opinions],
        }


@dataclass(frozen=True)
class SimilarityEdge:
    """A pairwise similarity score between two object versions."""

    left: str
    right: str
    score: float
    versions: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        left, right = _canonical_pair(self.left, self.right)
        object.__setattr__(self, "left", left)
        object.__setattr__(self, "right", right)
        object.__setattr__(self, "score", float(self.score))
        object.__setattr__(
            self,
            "versions",
            MappingProxyType(
                {
                    str(object_id): _version_string(version)
                    for object_id, version in (self.versions or {}).items()
                    if version is not None
                },
            ),
        )

    @property
    def pair(self) -> Pair:
        return (self.left, self.right)

    @classmethod
    def from_any(cls, value: Any) -> "SimilarityEdge":
        if isinstance(value, cls):
            return value

        if isinstance(value, Mapping):
            if "pair" in value:
                pair = value["pair"]
                left, right = pair
                return cls(
                    left=left,
                    right=right,
                    score=value["score"],
                    versions=value.get("versions", {}),
                )

            left = value.get("left", value.get("object1"))
            right = value.get("right", value.get("object2"))
            return cls(
                left=left,
                right=right,
                score=value["score"],
                versions=value.get("versions", {}),
            )

        if isinstance(value, (tuple, list)):
            if len(value) < 3:
                raise ValueError(
                    "similarity edge tuples need at least (left, right, score)",
                )
            versions = value[3] if len(value) > 3 else {}
            return cls(value[0], value[1], value[2], versions)

        try:
            return cls(value.left, value.right, value.score, value.versions)
        except AttributeError:
            raise TypeError(
                "unsupported similarity edge: {!r}".format(value),
            ) from None

    def to_dict(self) -> dict[str, Any]:
        return {
            "left": self.left,
            "right": self.right,
            "score": self.score,
            "versions": dict(self.versions),
        }


@dataclass(frozen=True)
class BlockedEdge:
    """A candidate merge which was not applied."""

    pair: Pair
    reason: str
    score: Optional[float] = None
    left_group: tuple[str, ...] = ()
    right_group: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "pair": list(self.pair),
            "reason": self.reason,
            "score": self.score,
            "left_group": list(self.left_group),
            "right_group": list(self.right_group),
        }


@dataclass(frozen=True)
class Group:
    """An adjudicated group of STIX object IDs."""

    group_id: str
    members: tuple[str, ...]
    status: str
    pinned: bool = False
    confirmed_pairs: tuple[Pair, ...] = ()
    similarity_pairs: tuple[Pair, ...] = ()

    @property
    def anchor(self) -> str:
        return self.members[0]

    def __contains__(self, object_id: str) -> bool:
        return object_id in self.members

    def __len__(self) -> int:
        return len(self.members)

    def to_dict(self) -> dict[str, Any]:
        return {
            "group_id": self.group_id,
            "members": list(self.members),
            "status": self.status,
            "pinned": self.pinned,
            "confirmed_pairs": [list(pair) for pair in self.confirmed_pairs],
            "similarity_pairs": [
                list(pair) for pair in self.similarity_pairs
            ],
        }


@dataclass(frozen=True)
class AdjudicationResult:
    """A complete adjudication snapshot."""

    groups: tuple[Group, ...]
    pair_decisions: Mapping[Pair, PairDecision]
    blocked_edges: tuple[BlockedEdge, ...]
    versions: Mapping[str, Optional[str]]
    object_ids: tuple[str, ...]

    def group_for(self, object_id: str) -> Optional[Group]:
        for group in self.groups:
            if object_id in group:
                return group
        return None

    def group_id_for(self, object_id: str) -> Optional[str]:
        group = self.group_for(object_id)
        return group.group_id if group else None

    @property
    def groups_by_id(self) -> dict[str, Group]:
        return {group.group_id: group for group in self.groups}

    @property
    def signature(self) -> tuple[tuple[str, tuple[str, ...]], ...]:
        return tuple(
            (group.group_id, group.members)
            for group in self.groups
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "groups": [group.to_dict() for group in self.groups],
            "pair_decisions": [
                decision.to_dict()
                for _, decision in sorted(self.pair_decisions.items())
            ],
            "blocked_edges": [
                edge.to_dict() for edge in self.blocked_edges
            ],
            "versions": dict(self.versions),
        }

    def __str__(self) -> str:
        return "; ".join(
            "{}={} [{}]".format(
                group.group_id,
                _format_members(group.members),
                group.status,
            )
            for group in self.groups
        )


@dataclass(frozen=True)
class GroupChange:
    """A group whose membership or status changed between two snapshots."""

    group_id: str
    before_members: tuple[str, ...]
    after_members: tuple[str, ...]
    before_status: str
    after_status: str

    @property
    def members_added(self) -> tuple[str, ...]:
        return tuple(
            member for member in self.after_members
            if member not in self.before_members
        )

    @property
    def members_removed(self) -> tuple[str, ...]:
        return tuple(
            member for member in self.before_members
            if member not in self.after_members
        )

    @property
    def membership_changed(self) -> bool:
        return self.before_members != self.after_members

    @property
    def status_changed(self) -> bool:
        return self.before_status != self.after_status

    def to_dict(self) -> dict[str, Any]:
        return {
            "group_id": self.group_id,
            "before_members": list(self.before_members),
            "after_members": list(self.after_members),
            "members_added": list(self.members_added),
            "members_removed": list(self.members_removed),
            "before_status": self.before_status,
            "after_status": self.after_status,
        }


@dataclass(frozen=True)
class ObjectMove:
    """An object changing group between two snapshots."""

    object_id: str
    from_group: Optional[str]
    to_group: Optional[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "object_id": self.object_id,
            "from_group": self.from_group,
            "to_group": self.to_group,
        }


@dataclass(frozen=True)
class AdjudicationDelta:
    """The visible difference between two adjudication snapshots."""

    trigger: str
    before: Optional[AdjudicationResult]
    after: AdjudicationResult
    added_groups: tuple[Group, ...]
    removed_groups: tuple[Group, ...]
    changed_groups: tuple[GroupChange, ...]
    unchanged_groups: tuple[Group, ...]
    object_moves: tuple[ObjectMove, ...]
    new_blocked_edges: tuple[BlockedEdge, ...]

    @property
    def is_empty(self) -> bool:
        return not (
            self.added_groups
            or self.removed_groups
            or self.changed_groups
            or self.object_moves
            or self.new_blocked_edges
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "trigger": self.trigger,
            "added_groups": [group.to_dict() for group in self.added_groups],
            "removed_groups": [
                group.to_dict() for group in self.removed_groups
            ],
            "changed_groups": [
                change.to_dict() for change in self.changed_groups
            ],
            "unchanged_groups": [
                group.to_dict() for group in self.unchanged_groups
            ],
            "object_moves": [move.to_dict() for move in self.object_moves],
            "new_blocked_edges": [
                edge.to_dict() for edge in self.new_blocked_edges
            ],
        }

    def describe(self) -> str:
        lines = ["Adjudication delta ({}):".format(self.trigger)]

        if self.added_groups:
            lines.append(
                "  added: " + "; ".join(
                    "{}={} [{}]".format(
                        group.group_id,
                        _format_members(group.members),
                        group.status,
                    )
                    for group in self.added_groups
                ),
            )

        if self.removed_groups:
            lines.append(
                "  removed: " + "; ".join(
                    "{}={}".format(
                        group.group_id,
                        _format_members(group.members),
                    )
                    for group in self.removed_groups
                ),
            )

        if self.changed_groups:
            lines.append(
                "  changed: " + "; ".join(
                    _describe_group_change(change)
                    for change in self.changed_groups
                ),
            )

        if self.unchanged_groups:
            lines.append(
                "  unchanged: " + "; ".join(
                    "{}={}".format(
                        group.group_id,
                        _format_members(group.members),
                    )
                    for group in self.unchanged_groups
                ),
            )

        if self.object_moves:
            lines.append(
                "  object moves: " + "; ".join(
                    "{}: {} -> {}".format(
                        move.object_id,
                        move.from_group or "<none>",
                        move.to_group or "<none>",
                    )
                    for move in self.object_moves
                ),
            )

        if self.new_blocked_edges:
            lines.append(
                "  blocked: " + "; ".join(
                    "{}-{} ({})".format(
                        edge.pair[0],
                        edge.pair[1],
                        edge.reason,
                    )
                    for edge in self.new_blocked_edges
                ),
            )

        if self.is_empty:
            lines.append("  no changes")

        return "\n".join(lines)

    def __str__(self) -> str:
        return self.describe()


class _DisjointSet:
    def __init__(self, items: Iterable[str]) -> None:
        self.parent = {item: item for item in items}
        self.members = {item: {item} for item in items}

    def find(self, item: str) -> str:
        root = item
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[item] != item:
            parent = self.parent[item]
            self.parent[item] = root
            item = parent
        return root

    def group_members(self, item: str) -> set[str]:
        return self.members[self.find(item)]

    def union(self, left: str, right: str) -> str:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return left_root

        if left_root > right_root:
            left_root, right_root = right_root, left_root

        self.parent[right_root] = left_root
        self.members[left_root].update(self.members.pop(right_root))
        return left_root

    def groups(self) -> list[set[str]]:
        result = []
        seen = set()
        for item in self.parent:
            root = self.find(item)
            if root in seen:
                continue
            seen.add(root)
            result.append(self.members[root])
        return result


class Adjudicator:
    """Turn similarity scores plus reviews into versioned object groups.

    Args:
        ledger: Review ledger to consult.  A new ledger is created if omitted.
        threshold: Minimum similarity score (normally 0-100) for an unreviewed
            pair to be considered for automatic grouping.
        min_independent_confirmations: Number of distinct collection sources
            required to confirm a pair.  The default is 2.
        conflict_policy: How to resolve a pair with both confirmation and
            rejection opinions.  ``"reject_wins"`` (default) is conservative;
            ``"confirm_wins"`` prefers a sufficiently confirmed match;
            ``"latest_wins"`` follows the most recently recorded opinion.
        pin_reviewed: When true, similarity-only evidence cannot merge a group
            containing an actively reviewed object with another group.
    """

    _CONFLICT_POLICIES = {"reject_wins", "confirm_wins", "latest_wins"}

    def __init__(
        self,
        ledger: Optional[ReviewLedger] = None,
        threshold: float = 70.0,
        min_independent_confirmations: int = 2,
        conflict_policy: str = "reject_wins",
        pin_reviewed: bool = True,
    ) -> None:
        if min_independent_confirmations < 1:
            raise ValueError(
                "min_independent_confirmations must be at least 1",
            )
        if conflict_policy not in self._CONFLICT_POLICIES:
            raise ValueError(
                "conflict_policy must be one of: {}".format(
                    ", ".join(sorted(self._CONFLICT_POLICIES)),
                ),
            )

        self.ledger = ledger or ReviewLedger()
        self.threshold = float(threshold)
        self.min_independent_confirmations = min_independent_confirmations
        self.conflict_policy = conflict_policy
        self.pin_reviewed = pin_reviewed
        self.last_result: Optional[AdjudicationResult] = None
        self.last_delta: Optional[AdjudicationDelta] = None

    def review(self, *args, **kwargs) -> ReviewOpinion:
        return self.ledger.record(*args, **kwargs)

    def retract(self, *args, **kwargs) -> Retraction:
        return self.ledger.retract(*args, **kwargs)

    def adjudicate(
        self,
        objects: Iterable[Any] | Mapping[str, Any],
        edges: Optional[Iterable[Any] | Mapping[Any, Any]] = None,
        versions: Optional[VersionMap] = None,
        trigger: Optional[str] = None,
    ) -> AdjudicationResult:
        """Build a new snapshot and return it."""

        result, delta = self._run(objects, edges, versions, trigger)
        return result

    def update(
        self,
        objects: Iterable[Any] | Mapping[str, Any],
        edges: Optional[Iterable[Any] | Mapping[Any, Any]] = None,
        versions: Optional[VersionMap] = None,
        trigger: str = "update",
    ) -> AdjudicationDelta:
        """Build a new snapshot and return the visible delta."""

        _, delta = self._run(objects, edges, versions, trigger)
        return delta

    def _run(
        self,
        objects: Iterable[Any] | Mapping[str, Any],
        edges: Optional[Iterable[Any] | Mapping[Any, Any]],
        versions: Optional[VersionMap],
        trigger: Optional[str],
    ) -> tuple[AdjudicationResult, AdjudicationDelta]:
        objects_by_id, current_versions = _normalise_objects(objects, versions)
        normalised_edges = _normalise_edges(edges)

        for edge in normalised_edges:
            for object_id in edge.pair:
                objects_by_id.setdefault(object_id, object_id)
                current_versions.setdefault(object_id, None)

        result = self._build_result(
            objects_by_id,
            current_versions,
            normalised_edges,
        )
        if trigger is None:
            trigger = "initial" if self.last_result is None else "update"

        delta = _compare_results(self.last_result, result, trigger)
        self.last_result = result
        self.last_delta = delta
        return result, delta

    def _build_result(
        self,
        objects_by_id: Mapping[str, Any],
        current_versions: VersionMap,
        edges: list[SimilarityEdge],
    ) -> AdjudicationResult:
        object_ids = tuple(sorted(objects_by_id))
        object_id_set = set(object_ids)
        scores = {edge.pair: edge.score for edge in edges}

        applicable_opinions = [
            opinion
            for opinion in self.ledger.active_opinions(versions=current_versions)
            if opinion.left in object_id_set and opinion.right in object_id_set
        ]

        candidate_pairs = set(scores)
        candidate_pairs.update(opinion.pair for opinion in applicable_opinions)

        pair_decisions: dict[Pair, PairDecision] = {}
        for pair in sorted(candidate_pairs):
            pair_decisions[pair] = self._decide_pair(
                pair,
                scores.get(pair),
                current_versions,
            )

        reviewed_ids = {
            object_id
            for opinion in applicable_opinions
            for object_id in opinion.pair
        }
        cannot_links = {
            frozenset(pair)
            for pair, decision in pair_decisions.items()
            if decision.state_enum is PairState.REJECTED
        }

        disjoint_set = _DisjointSet(object_ids)
        blocked_edges: list[BlockedEdge] = []

        confirmed_pairs = sorted(
            (
                pair
                for pair, decision in pair_decisions.items()
                if decision.state_enum is PairState.CONFIRMED
            ),
            key=lambda pair: (
                -pair_decisions[pair].confirmations,
                -(pair_decisions[pair].score or 0.0),
                pair,
            ),
        )

        for pair in confirmed_pairs:
            self._try_union(
                disjoint_set,
                pair,
                scores.get(pair),
                reviewed_ids,
                cannot_links,
                blocked_edges,
                allow_pinned=True,
                pin_reviewed=False,
                reason_prefix="confirmation",
            )

        automatic_pairs = sorted(
            (
                pair
                for pair, decision in pair_decisions.items()
                if (
                    decision.state_enum is PairState.UNREVIEWED
                    and decision.score is not None
                    and decision.score >= self.threshold
                )
            ),
            key=lambda pair: (-pair_decisions[pair].score, pair),
        )

        for pair in automatic_pairs:
            self._try_union(
                disjoint_set,
                pair,
                scores.get(pair),
                reviewed_ids,
                cannot_links,
                blocked_edges,
                allow_pinned=not self.pin_reviewed,
                pin_reviewed=self.pin_reviewed,
                reason_prefix="similarity",
            )

        raw_groups = []
        for members in disjoint_set.groups():
            members = tuple(sorted(members))
            member_set = set(members)
            group_confirmed_pairs = tuple(
                pair
                for pair, decision in sorted(pair_decisions.items())
                if (
                    decision.state_enum is PairState.CONFIRMED
                    and pair[0] in member_set
                    and pair[1] in member_set
                )
            )
            group_similarity_pairs = tuple(
                pair
                for pair, decision in sorted(pair_decisions.items())
                if (
                    decision.score is not None
                    and decision.score >= self.threshold
                    and pair[0] in member_set
                    and pair[1] in member_set
                )
            )
            pinned = bool(member_set & reviewed_ids)

            if group_confirmed_pairs:
                status = "confirmed"
            elif pinned:
                status = "reviewed"
            else:
                status = "provisional"

            raw_groups.append(
                (
                    members,
                    status,
                    pinned,
                    group_confirmed_pairs,
                    group_similarity_pairs,
                ),
            )

        raw_groups.sort(key=lambda item: item[0])
        groups = self._assign_group_ids(raw_groups)

        return AdjudicationResult(
            groups=groups,
            pair_decisions=MappingProxyType(dict(pair_decisions)),
            blocked_edges=tuple(blocked_edges),
            versions=MappingProxyType(dict(current_versions)),
            object_ids=object_ids,
        )

    def _decide_pair(
        self,
        pair: Pair,
        score: Optional[float],
        current_versions: VersionMap,
    ) -> PairDecision:
        opinions = tuple(
            self.ledger.active_opinions(pair=pair, versions=current_versions),
        )
        confirmation_sources = {
            opinion.source
            for opinion in opinions
            if opinion.is_confirmation
        }
        rejection_sources = {
            opinion.source
            for opinion in opinions
            if opinion.is_rejection
        }

        confirmations = len(confirmation_sources)
        rejections = len(rejection_sources)
        conflicted = bool(confirmation_sources and rejection_sources)

        if not opinions:
            state = PairState.UNREVIEWED
            reason = (
                "no applicable review; using similarity"
                if score is not None
                else "no applicable review or similarity score"
            )

        elif self.conflict_policy == "reject_wins" and rejections:
            state = PairState.REJECTED
            reason = "active rejection source(s): {}".format(
                ", ".join(sorted(rejection_sources)),
            )
            if conflicted:
                reason += " (conflicts with confirmation source(s): {})".format(
                    ", ".join(sorted(confirmation_sources)),
                )

        elif (
            self.conflict_policy == "confirm_wins"
            and confirmations >= self.min_independent_confirmations
        ):
            state = PairState.CONFIRMED
            reason = "confirmed by independent source(s): {}".format(
                ", ".join(sorted(confirmation_sources)),
            )
            if conflicted:
                reason += " (conflicts with rejection source(s): {})".format(
                    ", ".join(sorted(rejection_sources)),
                )

        elif self.conflict_policy == "latest_wins" and conflicted:
            latest = max(
                opinions,
                key=lambda opinion: (opinion.created_at, opinion.review_id),
            )
            if latest.is_rejection:
                state = PairState.REJECTED
                reason = "latest opinion ({}) is a rejection".format(
                    latest.review_id,
                )
            elif confirmations >= self.min_independent_confirmations:
                state = PairState.CONFIRMED
                reason = "latest opinion ({}) is a confirmation".format(
                    latest.review_id,
                )
            else:
                state = PairState.INSUFFICIENT
                reason = (
                    "latest opinion is a confirmation, but only {} of {} "
                    "independent sources confirm"
                ).format(
                    confirmations,
                    self.min_independent_confirmations,
                )

        elif confirmations:
            if confirmations >= self.min_independent_confirmations:
                state = PairState.CONFIRMED
                reason = "confirmed by independent source(s): {}".format(
                    ", ".join(sorted(confirmation_sources)),
                )
            else:
                state = PairState.INSUFFICIENT
                reason = (
                    "only {} of {} required independent confirmation "
                    "source(s)"
                ).format(
                    confirmations,
                    self.min_independent_confirmations,
                )
                if conflicted:
                    reason += "; also rejected by: {}".format(
                        ", ".join(sorted(rejection_sources)),
                    )

        elif rejections:
            state = PairState.REJECTED
            reason = "rejected by source(s): {}".format(
                ", ".join(sorted(rejection_sources)),
            )

        else:  # pragma: no cover - defensive; opinions must have a verdict
            state = PairState.INSUFFICIENT
            reason = "review did not produce an adjudicable decision"

        return PairDecision(
            pair=pair,
            state=state.value,
            score=score,
            confirmations=confirmations,
            rejections=rejections,
            confirm_sources=tuple(sorted(confirmation_sources)),
            reject_sources=tuple(sorted(rejection_sources)),
            opinions=opinions,
            conflicted=conflicted,
            reason=reason,
        )

    def _try_union(
        self,
        disjoint_set: _DisjointSet,
        pair: Pair,
        score: Optional[float],
        reviewed_ids: set[str],
        cannot_links: set[frozenset[str]],
        blocked_edges: list[BlockedEdge],
        allow_pinned: bool,
        pin_reviewed: bool,
        reason_prefix: str,
    ) -> bool:
        left, right = pair
        left_root = disjoint_set.find(left)
        right_root = disjoint_set.find(right)
        if left_root == right_root:
            return True

        left_group = tuple(sorted(disjoint_set.group_members(left)))
        right_group = tuple(sorted(disjoint_set.group_members(right)))

        if pin_reviewed and not allow_pinned:
            if (
                set(left_group) & reviewed_ids
                or set(right_group) & reviewed_ids
            ):
                blocked_edges.append(
                    BlockedEdge(
                        pair=pair,
                        reason="reviewed-object-pinned",
                        score=score,
                        left_group=left_group,
                        right_group=right_group,
                    ),
                )
                return False

        conflicting_pair = _find_cannot_link(
            left_group,
            right_group,
            cannot_links,
        )
        if conflicting_pair is not None:
            blocked_edges.append(
                BlockedEdge(
                    pair=pair,
                    reason="{} blocked by rejected pair {}-{}".format(
                        reason_prefix,
                        conflicting_pair[0],
                        conflicting_pair[1],
                    ),
                    score=score,
                    left_group=left_group,
                    right_group=right_group,
                ),
            )
            return False

        disjoint_set.union(left_root, right_root)
        return True

    def _assign_group_ids(
        self,
        raw_groups: list[
            tuple[
                tuple[str, ...],
                str,
                bool,
                tuple[Pair, ...],
                tuple[Pair, ...],
            ]
        ],
    ) -> tuple[Group, ...]:
        previous_groups = list(self.last_result.groups) if self.last_result else []
        used_previous = set()

        numeric_ids = [
            int(group.group_id[1:])
            for group in previous_groups
            if (
                group.group_id.startswith("G")
                and group.group_id[1:].isdigit()
            )
        ]
        next_numeric_id = (max(numeric_ids) + 1) if numeric_ids else 1
        allocated_ids = {group.group_id for group in previous_groups}

        result = []
        for (
            members,
            status,
            pinned,
            confirmed_pairs,
            similarity_pairs,
        ) in raw_groups:
            member_set = set(members)
            candidates = [
                (group, len(member_set & set(group.members)))
                for group in previous_groups
                if (
                    group.group_id not in used_previous
                    and member_set & set(group.members)
                )
            ]

            if candidates:
                candidates.sort(
                    key=lambda item: (
                        -item[1],
                        _group_sort_key(item[0]),
                    ),
                )
                group_id = candidates[0][0].group_id
                used_previous.add(group_id)
            else:
                while "G{}".format(next_numeric_id) in allocated_ids:
                    next_numeric_id += 1
                group_id = "G{}".format(next_numeric_id)
                allocated_ids.add(group_id)
                next_numeric_id += 1

            result.append(
                Group(
                    group_id=group_id,
                    members=members,
                    status=status,
                    pinned=pinned,
                    confirmed_pairs=confirmed_pairs,
                    similarity_pairs=similarity_pairs,
                ),
            )

        result.sort(key=_group_sort_key)
        return tuple(result)


def _find_cannot_link(
    left_group: Iterable[str],
    right_group: Iterable[str],
    cannot_links: set[frozenset[str]],
) -> Optional[Pair]:
    for left in left_group:
        for right in right_group:
            if frozenset((left, right)) in cannot_links:
                return _canonical_pair(left, right)
    return None


def _group_sort_key(group: Group) -> tuple[int, str]:
    suffix = group.group_id[1:]
    if group.group_id.startswith("G") and suffix.isdigit():
        return (int(suffix), group.group_id)
    return (10**9, group.group_id)


def _format_members(members: Iterable[str]) -> str:
    return "{" + ", ".join(members) + "}"


def _describe_group_change(change: GroupChange) -> str:
    detail = "{} {} -> {}".format(
        change.group_id,
        _format_members(change.before_members),
        _format_members(change.after_members),
    )
    if change.status_changed:
        detail += " [{} -> {}]".format(
            change.before_status,
            change.after_status,
        )
    return detail


def _compare_results(
    before: Optional[AdjudicationResult],
    after: AdjudicationResult,
    trigger: str,
) -> AdjudicationDelta:
    before_groups = before.groups_by_id if before else {}
    after_groups = after.groups_by_id

    added_groups = tuple(
        group
        for group_id, group in after_groups.items()
        if group_id not in before_groups
    )
    removed_groups = tuple(
        group
        for group_id, group in before_groups.items()
        if group_id not in after_groups
    )

    changed_groups = []
    unchanged_groups = []
    for group_id in sorted(
        set(before_groups) & set(after_groups),
        key=lambda value: _group_sort_key(after_groups[value]),
    ):
        old_group = before_groups[group_id]
        new_group = after_groups[group_id]
        if (
            old_group.members != new_group.members
            or old_group.status != new_group.status
        ):
            changed_groups.append(
                GroupChange(
                    group_id=group_id,
                    before_members=old_group.members,
                    after_members=new_group.members,
                    before_status=old_group.status,
                    after_status=new_group.status,
                ),
            )
        else:
            unchanged_groups.append(new_group)

    object_moves = []
    if before is not None:
        before_membership = {
            object_id: group.group_id
            for group in before.groups
            for object_id in group.members
        }
    else:
        before_membership = {}

    after_membership = {
        object_id: group.group_id
        for group in after.groups
        for object_id in group.members
    }

    for object_id in sorted(set(before_membership) | set(after_membership)):
        old_group_id = before_membership.get(object_id)
        new_group_id = after_membership.get(object_id)
        if old_group_id != new_group_id:
            object_moves.append(
                ObjectMove(
                    object_id=object_id,
                    from_group=old_group_id,
                    to_group=new_group_id,
                ),
            )

    before_blocked = set()
    if before is not None:
        before_blocked = {
            (edge.pair, edge.reason)
            for edge in before.blocked_edges
        }
    new_blocked_edges = tuple(
        edge
        for edge in after.blocked_edges
        if (edge.pair, edge.reason) not in before_blocked
    )

    return AdjudicationDelta(
        trigger=trigger,
        before=before,
        after=after,
        added_groups=tuple(
            sorted(added_groups, key=_group_sort_key),
        ),
        removed_groups=tuple(
            sorted(removed_groups, key=_group_sort_key),
        ),
        changed_groups=tuple(changed_groups),
        unchanged_groups=tuple(
            sorted(unchanged_groups, key=_group_sort_key),
        ),
        object_moves=tuple(object_moves),
        new_blocked_edges=new_blocked_edges,
    )


def _default_object_similarity(left: Any, right: Any) -> float:
    from .object import object_similarity

    return object_similarity(left, right, {})


class AdjudicationLayer(DataStoreMixin):
    """A datastore-shaped facade which adds review adjudication.

    The wrapped store remains the source of truth for STIX objects.  This
    layer reads its current versions, computes pairwise similarity through the
    semantic equivalence API (or accepts explicit scores), and applies the
    review ledger before returning group deltas.

    Args:
        store: A ``DataStoreMixin`` instance (for example ``MemoryStore``).
        ledger: Optional existing review ledger.
        similarity: Optional callable ``(left, right) -> score``.  Defaults to
            :func:`stix2.equivalence.object.object_similarity`.
        threshold: Similarity threshold for automatic grouping.
        min_independent_confirmations: Distinct sources required to confirm.
        conflict_policy: One of ``"reject_wins"``, ``"confirm_wins"``, or
            ``"latest_wins"``.
        pin_reviewed: Prevent silent similarity-only merges of reviewed
            groups.
    """

    def __init__(
        self,
        store: DataStoreMixin,
        ledger: Optional[ReviewLedger] = None,
        similarity: Optional[Any] = None,
        threshold: float = 70.0,
        min_independent_confirmations: int = 2,
        conflict_policy: str = "reject_wins",
        pin_reviewed: bool = True,
    ) -> None:
        super().__init__(
            source=getattr(store, "source", None),
            sink=getattr(store, "sink", None),
        )
        self.store = store
        self.similarity = similarity
        self.adjudicator = Adjudicator(
            ledger=ledger,
            threshold=threshold,
            min_independent_confirmations=min_independent_confirmations,
            conflict_policy=conflict_policy,
            pin_reviewed=pin_reviewed,
        )

    @property
    def ledger(self) -> ReviewLedger:
        return self.adjudicator.ledger

    @property
    def result(self) -> Optional[AdjudicationResult]:
        return self.adjudicator.last_result

    def current_objects(self) -> dict[str, Any]:
        """Return the latest version of every object in the wrapped store."""

        latest: dict[str, Any] = {}
        latest_versions: dict[str, str] = {}

        for obj in self.store.query([]):
            object_id = _object_id(obj)
            if object_id is None:
                continue
            object_id = str(object_id)
            version = _object_version(obj)
            if (
                object_id not in latest
                or (
                    version is not None
                    and (
                        object_id not in latest_versions
                        or version > latest_versions[object_id]
                    )
                )
            ):
                latest[object_id] = obj
                if version is not None:
                    latest_versions[object_id] = version

        return latest

    def current_versions(self) -> dict[str, Optional[str]]:
        return {
            object_id: _object_version(obj)
            for object_id, obj in self.current_objects().items()
        }

    def review(
        self,
        left: str,
        right: str,
        verdict: str,
        reviewer: str,
        source: Optional[str] = None,
        versions: Optional[VersionMap] = None,
        review_id: Optional[str] = None,
        created_at: Optional[str] = None,
        reason: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> ReviewOpinion:
        """Record a review tied to the current stored object versions."""

        objects = self.current_objects()
        if versions is None:
            versions = {}
            for object_id in _canonical_pair(left, right):
                if object_id not in objects:
                    raise KeyError(
                        "object is not present in the store: {}".format(
                            object_id,
                        ),
                    )
                versions[object_id] = _object_version(objects[object_id])

        return self.ledger.record(
            left=left,
            right=right,
            verdict=verdict,
            reviewer=reviewer,
            source=source,
            versions=versions,
            review_id=review_id,
            created_at=created_at,
            reason=reason,
            metadata=metadata,
        )

    def retract(
        self,
        review_id: str,
        at: Optional[str] = None,
        actor: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> Retraction:
        return self.ledger.retract(
            review_id,
            at=at,
            actor=actor,
            reason=reason,
        )

    def refresh(
        self,
        edges: Optional[Iterable[Any] | Mapping[Any, Any]] = None,
        trigger: str = "refresh",
    ) -> AdjudicationDelta:
        """Re-adjudicate the current store contents and return the delta."""

        objects = self.current_objects()
        if edges is None:
            edges = self._similarity_edges(objects)
        return self.adjudicator.update(
            objects=objects,
            edges=edges,
            trigger=trigger,
        )

    def _similarity_edges(
        self,
        objects: Mapping[str, Any],
    ) -> list[SimilarityEdge]:
        similarity = self.similarity or _default_object_similarity
        edges = []

        for left_id, right_id in itertools.combinations(sorted(objects), 2):
            left = objects[left_id]
            right = objects[right_id]
            try:
                score = similarity(left, right)
            except (TypeError, ValueError):
                continue
            if score < self.adjudicator.threshold:
                continue

            edges.append(
                SimilarityEdge(
                    left=left_id,
                    right=right_id,
                    score=score,
                    versions={
                        left_id: _object_version(left),
                        right_id: _object_version(right),
                    },
                ),
            )

        return edges


def adjudicate(
    objects: Iterable[Any] | Mapping[str, Any],
    edges: Optional[Iterable[Any] | Mapping[Any, Any]] = None,
    ledger: Optional[ReviewLedger] = None,
    **kwargs,
) -> AdjudicationResult:
    """Convenience wrapper around :class:`Adjudicator`."""

    return Adjudicator(ledger=ledger, **kwargs).adjudicate(objects, edges)


AdjudicationStore = AdjudicationLayer
EquivalenceAdjudicator = Adjudicator
MatchReview = ReviewOpinion
Opinion = ReviewOpinion
Review = ReviewOpinion
