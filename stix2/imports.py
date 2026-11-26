"""Import-time identity resolution for merged STIX case files.

When case files are merged, a record often receives a new identifier while
older systems keep referring to its former ticket number.  Two source batches
may also use the same number for different records until the merge has been
reviewed.  This module keeps track of those candidates and of the identity
decisions that an analyst has explicitly confirmed, so that a reference can be
attached to one object without depending on the order in which batches were
received.

The moving parts are deliberately small:

* :class:`ImportedCandidate` is one version of one record from one batch.
* :class:`OccupancySlot` reports which candidates claim the same identifier.
* :class:`IdentityAnchor` is an auditable, human-confirmed mapping from a
  reference to one candidate.
* :class:`ImportService` ingests bundles and resolves references using the
  occupancy table, the active anchors, the review (``revoked``) flag, version
  visibility, and batch provenance.

Resolution never guesses.  If more than one candidate remains after the
documented rules have been applied, the result is ``ambiguous`` and all
surviving candidates are returned.
"""

import copy
import hashlib
import json
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


_EPOCH = datetime.min.replace(tzinfo=timezone.utc)
_ALIAS_PROPERTIES = (
    "x_original_id",
    "x_original_ids",
    "x_legacy_id",
    "x_legacy_ids",
    "x_ticket_id",
    "x_ticket_number",
)


class IdentityResolutionError(Exception):
    """Base class for import-time identity resolution errors."""


class AnchorError(IdentityResolutionError):
    """Raised when an identity anchor cannot be applied."""


class AmbiguousCandidateError(AnchorError):
    """Raised when a manual decision must name one of several candidates."""


def _as_datetime(value: Any) -> Optional[datetime]:
    """Return an aware UTC datetime, or ``None`` for an unusable value."""
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _version_token(value: Optional[datetime]) -> str:
    if value is None:
        return "unversioned"
    return value.strftime("%Y%m%dT%H%M%S.%fZ")


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=str,
    )


def _coerce_mapping(obj: Any) -> Mapping[str, Any]:
    """Accept both plain mappings and stix2 objects."""
    if isinstance(obj, Mapping) and hasattr(obj, "serialize"):
        serialized = obj.serialize()
        if isinstance(serialized, str):
            return json.loads(serialized)
    return obj


def fingerprint(obj: Mapping[str, Any]) -> str:
    """Return a stable SHA-256 fingerprint for a STIX object.

    The fingerprint covers every property, including the identifier and the
    version timestamp.  It is used to decide whether two imported records are
    the same candidate or merely occupy the same identifier.
    """
    return hashlib.sha256(
        _canonical_json(_coerce_mapping(obj)).encode("utf-8"),
    ).hexdigest()


def _iter_aliases(obj: Mapping[str, Any]) -> Tuple[str, ...]:
    aliases: Set[str] = set()

    stix_id = obj.get("id")
    if isinstance(stix_id, str):
        aliases.add(stix_id)

    for prop in _ALIAS_PROPERTIES:
        value = obj.get(prop)
        if isinstance(value, str):
            aliases.add(value)
        elif isinstance(value, (list, tuple, set)):
            aliases.update(v for v in value if isinstance(v, str))

    for ext_ref in obj.get("external_references", []) or []:
        if not isinstance(ext_ref, Mapping):
            continue
        external_id = ext_ref.get("external_id")
        if not isinstance(external_id, str):
            continue
        aliases.add(external_id)
        source_name = ext_ref.get("source_name")
        if isinstance(source_name, str):
            aliases.add("{}:{}".format(source_name, external_id))

    return tuple(sorted(aliases))


def _iter_stix_objects(data: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(data, str):
        data = json.loads(data)

    if isinstance(data, Mapping):
        if data.get("type") == "bundle":
            for obj in data.get("objects", []) or []:
                yield from _iter_stix_objects(obj)
        else:
            yield data
    elif isinstance(data, (list, tuple)):
        for item in data:
            yield from _iter_stix_objects(item)
    else:
        raise TypeError(
            "expected a STIX object, bundle, list, or JSON string; got {}".format(
                type(data).__name__,
            ),
        )


@dataclass(frozen=True)
class ImportedCandidate:
    """One version of one record received from one import batch.

    Attributes:
        object: The original STIX object, as a mapping.
        batch: Provenance label for the bundle or message that carried it.
        key: Stable key built from batch, identifier, version, and content.
        type: STIX object type.
        stix_id: The STIX identifier currently assigned to the record.
        version: ``modified`` (or ``created``) as an aware datetime.
        revoked: The review flag carried by the record.
        fingerprint: Content fingerprint including id and version.
        aliases: Every reference token that may address this record.
    """

    object: Mapping[str, Any] = field(compare=False, hash=False, repr=False)
    batch: str
    key: str
    type: str
    stix_id: str
    version: Optional[datetime]
    revoked: bool
    fingerprint: str
    aliases: Tuple[str, ...]

    @classmethod
    def from_object(
        cls,
        obj: Mapping[str, Any],
        batch: str,
    ) -> "ImportedCandidate":
        obj = _coerce_mapping(obj)
        if not isinstance(obj, Mapping):
            raise TypeError("candidate must be a mapping")
        stix_id = obj.get("id")
        obj_type = obj.get("type")
        if not isinstance(stix_id, str) or not stix_id:
            raise ValueError("candidate is missing a string 'id' property")
        if not isinstance(obj_type, str) or not obj_type:
            raise ValueError("candidate is missing a string 'type' property")

        version = _as_datetime(obj.get("modified") or obj.get("created"))
        digest = fingerprint(obj)
        key = "{}|{}|{}|{}".format(
            batch, stix_id, _version_token(version), digest[:16],
        )
        return cls(
            object=copy.deepcopy(dict(obj)),
            batch=batch,
            key=key,
            type=obj_type,
            stix_id=stix_id,
            version=version,
            revoked=bool(obj.get("revoked", False)),
            fingerprint=digest,
            aliases=_iter_aliases(obj),
        )

    @property
    def sort_key(self) -> Tuple[Any, ...]:
        return (
            self.type,
            self.stix_id,
            self.batch,
            self.version or _EPOCH,
            self.fingerprint,
        )

    def summary(self) -> Dict[str, Any]:
        """Return a small, JSON-friendly description of the candidate."""
        return {
            "key": self.key,
            "batch": self.batch,
            "type": self.type,
            "id": self.stix_id,
            "version": self.version.isoformat() if self.version else None,
            "revoked": self.revoked,
            "aliases": list(self.aliases),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-friendly representation including the object."""
        result = self.summary()
        result["object"] = copy.deepcopy(dict(self.object))
        result["fingerprint"] = self.fingerprint
        return result


@dataclass(frozen=True)
class OccupancySlot:
    """All candidates that claim one identifier."""

    reference: str
    candidates: Tuple[ImportedCandidate, ...]

    @property
    def conflicted(self) -> bool:
        """True when different content claims the same identifier and version."""
        by_version: Dict[str, Set[str]] = defaultdict(set)
        for candidate in self.candidates:
            by_version[_version_token(candidate.version)].add(candidate.fingerprint)
        return any(len(fingerprints) > 1 for fingerprints in by_version.values())

    @property
    def occupants(self) -> Tuple[str, ...]:
        return tuple(sorted(candidate.key for candidate in self.candidates))

    @property
    def versions(self) -> Tuple[Optional[datetime], ...]:
        return tuple(sorted(
            {candidate.version for candidate in self.candidates},
            key=lambda value: value or _EPOCH,
        ))


@dataclass(frozen=True)
class IdentityAnchor:
    """A human-confirmed decision that a reference names one candidate."""

    reference: str
    candidate_key: str
    confirmed_by: str
    confirmed_at: datetime
    note: str = ""
    revoked: bool = False
    revoked_by: Optional[str] = None
    revoked_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reference": self.reference,
            "candidate_key": self.candidate_key,
            "confirmed_by": self.confirmed_by,
            "confirmed_at": self.confirmed_at.isoformat(),
            "note": self.note,
            "revoked": self.revoked,
            "revoked_by": self.revoked_by,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
        }


class AnchorRegistry:
    """Auditable store of active and revoked identity anchors."""

    def __init__(self) -> None:
        self._anchors: List[IdentityAnchor] = []

    def __len__(self) -> int:
        return len(self._anchors)

    @property
    def anchors(self) -> Tuple[IdentityAnchor, ...]:
        return tuple(self._anchors)

    def confirm(
        self,
        reference: str,
        candidate_key: str,
        confirmed_by: str,
        note: str = "",
        confirmed_at: Optional[datetime] = None,
    ) -> IdentityAnchor:
        if not reference:
            raise ValueError("an anchor needs a non-empty reference")
        if not candidate_key:
            raise ValueError("an anchor needs a non-empty candidate key")
        if not confirmed_by:
            raise ValueError("an anchor needs the identity of the confirming analyst")

        for anchor in self._anchors:
            if (
                not anchor.revoked and
                anchor.reference == reference and
                anchor.candidate_key == candidate_key
            ):
                return anchor

        anchor = IdentityAnchor(
            reference=reference,
            candidate_key=candidate_key,
            confirmed_by=confirmed_by,
            confirmed_at=confirmed_at or datetime.now(timezone.utc),
            note=note,
        )
        self._anchors.append(anchor)
        return anchor

    def revoke(
        self,
        reference: str,
        candidate_key: Optional[str] = None,
        revoked_by: str = "",
        note: str = "",
        revoked_at: Optional[datetime] = None,
    ) -> Tuple[IdentityAnchor, ...]:
        changed: List[IdentityAnchor] = []
        updated: List[IdentityAnchor] = []
        timestamp = revoked_at or datetime.now(timezone.utc)

        for anchor in self._anchors:
            matches = (
                not anchor.revoked and anchor.reference == reference and
                (candidate_key is None or anchor.candidate_key == candidate_key)
            )
            if matches:
                anchor = replace(
                    anchor,
                    revoked=True,
                    revoked_by=revoked_by or None,
                    revoked_at=timestamp,
                    note="{} {}".format(anchor.note, note).strip(),
                )
                changed.append(anchor)
            updated.append(anchor)

        self._anchors = updated
        return tuple(changed)

    def active_for(self, reference: str) -> Tuple[IdentityAnchor, ...]:
        anchors = [
            anchor for anchor in self._anchors
            if not anchor.revoked and anchor.reference == reference
        ]
        return tuple(sorted(anchors, key=lambda anchor: (
            anchor.confirmed_at, anchor.candidate_key,
        )))

    def restore(self, anchor: IdentityAnchor) -> None:
        """Restore an anchor from a snapshot without changing its audit data."""
        self._anchors.append(anchor)


class ResolutionStatus(str, Enum):
    """Outcome of resolving one reference."""

    UNIQUE = "unique"
    AMBIGUOUS = "ambiguous"
    UNRESOLVED = "unresolved"
    REVOKED = "revoked"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class Resolution:
    """The attachment decision for one reference."""

    reference: str
    status: ResolutionStatus
    candidates: Tuple[ImportedCandidate, ...] = ()
    candidate: Optional[ImportedCandidate] = None
    reason: str = ""
    anchor: Optional[IdentityAnchor] = None
    referrer_batch: Optional[str] = None
    referrer_version: Optional[datetime] = None

    @property
    def is_unique(self) -> bool:
        return self.status is ResolutionStatus.UNIQUE

    @property
    def target(self) -> Optional[ImportedCandidate]:
        """Alias for :attr:`candidate`, matching attachment terminology."""
        return self.candidate

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reference": self.reference,
            "status": self.status.value,
            "reason": self.reason,
            "target": self.candidate.summary() if self.candidate else None,
            "candidates": [candidate.summary() for candidate in self.candidates],
            "anchor": self.anchor.to_dict() if self.anchor else None,
            "referrer_batch": self.referrer_batch,
            "referrer_version": (
                self.referrer_version.isoformat() if self.referrer_version else None
            ),
        }


@dataclass(frozen=True)
class Attachment:
    """Resolution of every reference carried by one importing object."""

    object_id: str
    status: ResolutionStatus
    references: Mapping[str, Resolution] = field(compare=False, hash=False)
    batch: Optional[str] = None
    version: Optional[datetime] = None

    @property
    def unique(self) -> bool:
        return self.status is ResolutionStatus.UNIQUE

    @property
    def targets(self) -> Dict[str, ImportedCandidate]:
        return {
            reference: resolution.candidate
            for reference, resolution in self.references.items()
            if resolution.candidate is not None
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "object_id": self.object_id,
            "status": self.status.value,
            "batch": self.batch,
            "version": self.version.isoformat() if self.version else None,
            "references": {
                reference: resolution.to_dict()
                for reference, resolution in sorted(self.references.items())
            },
        }


@dataclass(frozen=True)
class ReplayStep:
    """One action and the resolution that immediately followed it."""

    index: int
    action: str
    reference: str
    resolution: Resolution
    candidate: Optional[ImportedCandidate] = None
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "action": self.action,
            "reference": self.reference,
            "candidate": self.candidate.summary() if self.candidate else None,
            "detail": self.detail,
            "resolution": self.resolution.to_dict(),
        }


@dataclass
class _Identity:
    stix_id: str
    batch: str
    candidates: List[ImportedCandidate]
    collision: bool = False

    @property
    def revoked(self) -> bool:
        return all(candidate.revoked for candidate in self.candidates)

    def visible_at(self, moment: Optional[datetime]) -> bool:
        if moment is None:
            return True
        return any(
            candidate.version is None or candidate.version <= moment
            for candidate in self.candidates
        )

    def representative(
        self,
        moment: Optional[datetime] = None,
    ) -> ImportedCandidate:
        live = [candidate for candidate in self.candidates if not candidate.revoked]
        pool = live or self.candidates
        if moment is not None:
            visible = [
                candidate for candidate in pool
                if candidate.version is None or candidate.version <= moment
            ]
            if visible:
                pool = visible
        return max(pool, key=lambda candidate: (
            candidate.version or _EPOCH, candidate.fingerprint,
        ))


def _reference_values(obj: Mapping[str, Any]) -> Tuple[str, ...]:
    """Collect the references carried by an object, in canonical order."""
    references: Set[str] = set()

    if isinstance(obj.get("source_ref"), str):
        references.add(obj["source_ref"])
    if isinstance(obj.get("target_ref"), str):
        references.add(obj["target_ref"])

    if not references:
        for key, value in obj.items():
            if key in ("source_ref", "target_ref"):
                continue
            if key.endswith("_ref") and isinstance(value, str):
                references.add(value)
            elif key.endswith("_refs") and isinstance(value, (list, tuple)):
                references.update(v for v in value if isinstance(v, str))

    return tuple(sorted(references))


def _combined_status(resolutions: Sequence[Resolution]) -> ResolutionStatus:
    statuses = {resolution.status for resolution in resolutions}
    if ResolutionStatus.AMBIGUOUS in statuses:
        return ResolutionStatus.AMBIGUOUS
    if ResolutionStatus.UNRESOLVED in statuses:
        return ResolutionStatus.UNRESOLVED
    if ResolutionStatus.REVOKED in statuses:
        return ResolutionStatus.REVOKED
    return ResolutionStatus.UNIQUE


class ImportService:
    """Resolve references against duplicated candidates from merged batches.

    The service is intentionally storage agnostic: it accepts ordinary STIX
    mappings (or bundles, lists, and JSON strings) and keeps its own compact
    candidate index.  Use :meth:`ingest` in any order, confirm decisions with
    :meth:`confirm_anchor`, and ask :meth:`resolve` or :meth:`attach` for the
    current attachment.

    The same inputs, anchors, and archived batches always produce the same
    result; :meth:`snapshot` and :meth:`restore` make that state explicit.
    """

    def __init__(self) -> None:
        self._candidates: Dict[str, ImportedCandidate] = {}
        self._alias_index: Dict[str, Set[str]] = defaultdict(set)
        self._occupancy: Dict[str, Set[str]] = defaultdict(set)
        self._anchors = AnchorRegistry()
        self._batches: Set[str] = set()
        self._archived: Set[str] = set()
        self._events: List[Dict[str, Any]] = []

    def __len__(self) -> int:
        return len(self._candidates)

    def __repr__(self) -> str:
        return "<ImportService candidates={} batches={} anchors={}>".format(
            len(self._candidates), len(self._batches), len(self._anchors),
        )

    @property
    def anchors(self) -> AnchorRegistry:
        return self._anchors

    @property
    def batches(self) -> Tuple[str, ...]:
        return tuple(sorted(self._batches))

    @property
    def archived_batches(self) -> Tuple[str, ...]:
        return tuple(sorted(self._archived))

    @property
    def events(self) -> Tuple[Dict[str, Any], ...]:
        return tuple(copy.deepcopy(self._events))

    def ingest(self, data: Any, batch: Optional[str] = None) -> Tuple[ImportedCandidate, ...]:
        """Import STIX content and record its candidate occupancy.

        Args:
            data: A STIX object, bundle, list of either, or JSON string.
            batch: Provenance label.  When omitted, a bundle's ``id`` is used,
                otherwise ``"default"``.

        Returns:
            The candidates that were newly added.  Re-importing the same
            object from the same batch is idempotent.
        """
        decoded = json.loads(data) if isinstance(data, str) else data
        inferred_batch = batch
        if inferred_batch is None and isinstance(decoded, Mapping):
            if decoded.get("type") == "bundle":
                inferred_batch = decoded.get("id")
        inferred_batch = inferred_batch or "default"

        added: List[ImportedCandidate] = []
        for obj in _iter_stix_objects(decoded):
            candidate = ImportedCandidate.from_object(obj, inferred_batch)
            if candidate.key in self._candidates:
                continue

            self._candidates[candidate.key] = candidate
            self._batches.add(candidate.batch)
            for alias in candidate.aliases:
                self._alias_index[alias].add(candidate.key)
            self._occupancy[candidate.stix_id].add(candidate.key)
            self._events.append({
                "action": "ingest",
                "batch": candidate.batch,
                "id": candidate.stix_id,
                "candidate": candidate.key,
            })
            added.append(candidate)

        return tuple(added)

    add = ingest

    def candidates(self, reference: Optional[str] = None) -> Tuple[ImportedCandidate, ...]:
        """Return all candidates, or all candidates addressed by a reference."""
        if reference is None:
            selected = self._candidates.values()
        else:
            selected = (
                self._candidates[key]
                for key in self._alias_index.get(reference, ())
            )
        return tuple(sorted(selected, key=lambda candidate: candidate.sort_key))

    def references(self) -> Tuple[str, ...]:
        return tuple(sorted(self._alias_index))

    def get_candidate(
        self,
        key: Optional[str] = None,
        stix_id: Optional[str] = None,
        batch: Optional[str] = None,
    ) -> ImportedCandidate:
        """Look up one candidate, raising when the request is ambiguous."""
        if key is not None:
            try:
                return self._candidates[key]
            except KeyError:
                raise AnchorError("unknown candidate key: {}".format(key))

        matches = [
            candidate for candidate in self._candidates.values()
            if (stix_id is None or candidate.stix_id == stix_id) and
            (batch is None or candidate.batch == batch)
        ]
        if not matches:
            raise AnchorError("no candidate matches the requested identity")
        if len(matches) > 1:
            raise AmbiguousCandidateError(
                "more than one candidate matches; supply a candidate key",
            )
        return matches[0]

    def occupancy(self, reference: Optional[str] = None) -> Tuple[OccupancySlot, ...]:
        """Return candidate occupancy slots in canonical order."""
        slots: List[OccupancySlot] = []
        for stix_id, keys in self._occupancy.items():
            if reference is not None and stix_id != reference:
                continue
            candidates = tuple(sorted(
                (self._candidates[key] for key in keys),
                key=lambda candidate: candidate.sort_key,
            ))
            slots.append(OccupancySlot(stix_id, candidates))
        return tuple(sorted(slots, key=lambda slot: slot.reference))

    def collisions(self) -> Tuple[OccupancySlot, ...]:
        """Return only the slots claimed by differing candidate content."""
        return tuple(slot for slot in self.occupancy() if slot.conflicted)

    def archive(self, batch: str) -> None:
        """Exclude a branch from future attachment decisions."""
        if batch not in self._batches:
            raise AnchorError("unknown batch: {}".format(batch))
        self._archived.add(batch)
        self._events.append({"action": "archive", "batch": batch})

    def unarchive(self, batch: str) -> None:
        """Make an archived branch available again."""
        if batch in self._archived:
            self._archived.remove(batch)
            self._events.append({"action": "unarchive", "batch": batch})

    def confirm_anchor(
        self,
        reference: str,
        candidate: Any = None,
        candidate_key: Optional[str] = None,
        confirmed_by: Optional[str] = None,
        note: str = "",
        confirmed_at: Optional[datetime] = None,
    ) -> IdentityAnchor:
        """Confirm that ``reference`` names one candidate.

        ``candidate`` may be a candidate, a candidate key, or a STIX id.  If
        it is omitted, the reference must already have exactly one candidate.
        """
        if candidate_key is None:
            if isinstance(candidate, ImportedCandidate):
                candidate_key = candidate.key
            elif isinstance(candidate, str):
                if candidate in self._candidates:
                    candidate_key = candidate
                else:
                    candidate_key = self.get_candidate(stix_id=candidate).key

        if candidate_key is None:
            matches = self.candidates(reference)
            if not matches:
                raise AnchorError("no candidate is addressed by {!r}".format(reference))
            if len(matches) > 1:
                raise AmbiguousCandidateError(
                    "{} candidates claim {!r}; name the confirmed candidate".format(
                        len(matches), reference,
                    ),
                )
            candidate_key = matches[0].key

        if candidate_key not in self._candidates:
            raise AnchorError("unknown candidate key: {}".format(candidate_key))

        anchor = self._anchors.confirm(
            reference=reference,
            candidate_key=candidate_key,
            confirmed_by=confirmed_by or "",
            note=note,
            confirmed_at=confirmed_at,
        )
        self._events.append({
            "action": "confirm",
            "reference": reference,
            "candidate": candidate_key,
            "by": anchor.confirmed_by,
        })
        return anchor

    def revoke_anchor(
        self,
        reference: str,
        candidate_key: Optional[str] = None,
        revoked_by: str = "",
        note: str = "",
        revoked_at: Optional[datetime] = None,
    ) -> Tuple[IdentityAnchor, ...]:
        """Withdraw an anchor and immediately re-resolve from remaining state."""
        changed = self._anchors.revoke(
            reference=reference,
            candidate_key=candidate_key,
            revoked_by=revoked_by,
            note=note,
            revoked_at=revoked_at,
        )
        if not changed:
            raise AnchorError(
                "no active anchor on {!r} matched the request".format(reference),
            )
        for anchor in changed:
            self._events.append({
                "action": "revoke",
                "reference": reference,
                "candidate": anchor.candidate_key,
                "by": revoked_by or None,
            })
        return changed

    def _available_candidates(
        self,
        reference: str,
        include_archived: bool,
    ) -> Tuple[ImportedCandidate, ...]:
        candidates = self.candidates(reference)
        if not include_archived:
            candidates = tuple(
                candidate for candidate in candidates
                if candidate.batch not in self._archived
            )
        return candidates

    def _identities(
        self,
        candidates: Sequence[ImportedCandidate],
    ) -> Tuple[_Identity, ...]:
        grouped: Dict[Tuple[str, str], List[ImportedCandidate]] = defaultdict(list)
        for candidate in candidates:
            grouped[(candidate.stix_id, candidate.batch)].append(candidate)

        identities: List[_Identity] = []
        for (stix_id, batch), group in sorted(grouped.items()):
            by_version: Dict[str, List[ImportedCandidate]] = defaultdict(list)
            for candidate in group:
                by_version[_version_token(candidate.version)].append(candidate)

            if any(
                len({candidate.fingerprint for candidate in version_group}) > 1
                for version_group in by_version.values()
            ):
                fingerprints = sorted({candidate.fingerprint for candidate in group})
                for digest in fingerprints:
                    identities.append(_Identity(
                        stix_id=stix_id,
                        batch=batch,
                        candidates=sorted(
                            (c for c in group if c.fingerprint == digest),
                            key=lambda candidate: candidate.sort_key,
                        ),
                        collision=True,
                    ))
            else:
                identities.append(_Identity(
                    stix_id=stix_id,
                    batch=batch,
                    candidates=sorted(
                        group, key=lambda candidate: candidate.sort_key,
                    ),
                ))

        return tuple(sorted(
            identities,
            key=lambda identity: (
                identity.stix_id,
                identity.batch,
                identity.representative().sort_key,
            ),
        ))

    def resolve(
        self,
        reference: str,
        referrer: Any = None,
        batch: Optional[str] = None,
        version: Any = None,
        include_archived: bool = False,
    ) -> Resolution:
        """Resolve a reference to a unique candidate, or explain why not.

        Args:
            reference: STIX id, legacy id, or external id to resolve.
            referrer: Optional object/version that carries the reference.  Its
                batch and timestamp are used for provenance and visibility.
            batch: Explicit referrer batch (overrides ``referrer``).
            version: Explicit referrer timestamp (overrides ``referrer``).
            include_archived: Whether archived branches may still be attached.
        """
        referrer_batch = batch
        referrer_version = _as_datetime(version)

        if referrer is not None:
            if isinstance(referrer, ImportedCandidate):
                referrer_batch = referrer_batch or referrer.batch
                referrer_version = referrer_version or referrer.version
            elif isinstance(referrer, Mapping):
                referrer_batch = referrer_batch or self.batch_of(referrer)
                if referrer_version is None:
                    referrer_version = _as_datetime(
                        referrer.get("modified") or referrer.get("created"),
                    )

        all_candidates = self._available_candidates(reference, include_archived)
        anchor_tokens = {reference}
        for candidate in all_candidates:
            anchor_tokens.update(candidate.aliases)

        active_anchors: List[IdentityAnchor] = []
        seen_anchors: Set[Tuple[str, str, datetime]] = set()
        for token in sorted(anchor_tokens):
            for anchor in self._anchors.active_for(token):
                signature = (
                    anchor.reference, anchor.candidate_key, anchor.confirmed_at,
                )
                if signature not in seen_anchors:
                    seen_anchors.add(signature)
                    active_anchors.append(anchor)
        active_anchors.sort(key=lambda anchor: (
            anchor.confirmed_at, anchor.candidate_key, anchor.reference,
        ))

        if active_anchors:
            anchored_keys = [
                anchor.candidate_key for anchor in active_anchors
                if anchor.candidate_key in self._candidates
            ]
            anchored_candidates = tuple(
                self._candidates[key] for key in sorted(set(anchored_keys))
                if include_archived or self._candidates[key].batch not in self._archived
            )
            if anchored_candidates:
                anchored_identities = self._identities(anchored_candidates)
                if len(anchored_identities) == 1:
                    candidate = anchored_identities[0].representative(referrer_version)
                    return Resolution(
                        reference=reference,
                        status=ResolutionStatus.UNIQUE,
                        candidates=(candidate,),
                        candidate=candidate,
                        reason="anchor",
                        anchor=active_anchors[0],
                        referrer_batch=referrer_batch,
                        referrer_version=referrer_version,
                    )
                return Resolution(
                    reference=reference,
                    status=ResolutionStatus.AMBIGUOUS,
                    candidates=self._representatives(
                        anchored_identities, referrer_version,
                    ),
                    reason="conflicting-anchors",
                    anchor=active_anchors[0],
                    referrer_batch=referrer_batch,
                    referrer_version=referrer_version,
                )

            if anchored_keys and not include_archived and all(
                self._candidates[key].batch in self._archived for key in anchored_keys
            ):
                return Resolution(
                    reference=reference,
                    status=ResolutionStatus.UNRESOLVED,
                    reason="archived-anchor",
                    anchor=active_anchors[0],
                    referrer_batch=referrer_batch,
                    referrer_version=referrer_version,
                )

        if not all_candidates:
            return Resolution(
                reference=reference,
                status=ResolutionStatus.UNRESOLVED,
                reason="no-candidate",
                referrer_batch=referrer_batch,
                referrer_version=referrer_version,
            )

        identities = self._identities(all_candidates)
        if len(identities) == 1:
            candidate = identities[0].representative(referrer_version)
            return Resolution(
                reference=reference,
                status=ResolutionStatus.UNIQUE,
                candidates=(candidate,),
                candidate=candidate,
                reason="sole-candidate",
                referrer_batch=referrer_batch,
                referrer_version=referrer_version,
            )

        live_identities = tuple(
            identity for identity in identities if not identity.revoked
        )
        if not live_identities:
            return Resolution(
                reference=reference,
                status=ResolutionStatus.REVOKED,
                candidates=self._representatives(identities, referrer_version),
                reason="all-revoked",
                referrer_batch=referrer_batch,
                referrer_version=referrer_version,
            )

        reason = "multiple-candidates"
        if len(live_identities) < len(identities):
            reason = "review-flag"
        identities = live_identities

        if len(identities) == 1:
            candidate = identities[0].representative(referrer_version)
            return Resolution(
                reference=reference,
                status=ResolutionStatus.UNIQUE,
                candidates=(candidate,),
                candidate=candidate,
                reason=reason,
                referrer_batch=referrer_batch,
                referrer_version=referrer_version,
            )

        if referrer_version is not None:
            visible = tuple(
                identity for identity in identities
                if identity.visible_at(referrer_version)
            )
            if visible and len(visible) < len(identities):
                identities = visible
                reason = "version-window"
                if len(identities) == 1:
                    candidate = identities[0].representative(referrer_version)
                    return Resolution(
                        reference=reference,
                        status=ResolutionStatus.UNIQUE,
                        candidates=(candidate,),
                        candidate=candidate,
                        reason=reason,
                        referrer_batch=referrer_batch,
                        referrer_version=referrer_version,
                    )

        if referrer_batch is not None:
            same_batch = tuple(
                identity for identity in identities
                if identity.batch == referrer_batch
            )
            if len(same_batch) == 1:
                candidate = same_batch[0].representative(referrer_version)
                return Resolution(
                    reference=reference,
                    status=ResolutionStatus.UNIQUE,
                    candidates=(candidate,),
                    candidate=candidate,
                    reason="batch",
                    referrer_batch=referrer_batch,
                    referrer_version=referrer_version,
                )

        return Resolution(
            reference=reference,
            status=ResolutionStatus.AMBIGUOUS,
            candidates=self._representatives(identities, referrer_version),
            reason=reason,
            referrer_batch=referrer_batch,
            referrer_version=referrer_version,
        )

    def _representatives(
        self,
        identities: Sequence[_Identity],
        moment: Optional[datetime],
    ) -> Tuple[ImportedCandidate, ...]:
        representatives = {}
        for identity in identities:
            candidate = identity.representative(moment)
            representatives[candidate.key] = candidate
        return tuple(sorted(
            representatives.values(), key=lambda candidate: candidate.sort_key,
        ))

    def batch_of(self, obj: Mapping[str, Any]) -> Optional[str]:
        """Infer the import batch of an already-ingested object."""
        obj = _coerce_mapping(obj)
        digest = fingerprint(obj)
        batches = {
            candidate.batch for candidate in self._candidates.values()
            if candidate.fingerprint == digest
        }
        if len(batches) == 1:
            return next(iter(batches))
        return None

    def attach(
        self,
        obj: Mapping[str, Any],
        batch: Optional[str] = None,
        references: Optional[Sequence[str]] = None,
        include_archived: bool = False,
    ) -> Attachment:
        """Resolve every reference carried by one object.

        For a Relationship, both ``source_ref`` and ``target_ref`` are resolved
        against the same referrer version, which is how the two sides of the
        reference end up on compatible object versions.
        """
        if not isinstance(obj, Mapping):
            raise TypeError("attach() expects a STIX mapping")
        obj = _coerce_mapping(obj)

        referrer_batch = batch or self.batch_of(obj)
        referrer_version = _as_datetime(obj.get("modified") or obj.get("created"))
        refs = tuple(sorted(references)) if references else _reference_values(obj)
        if not refs:
            raise ValueError("object carries no references to resolve")

        resolutions = {
            reference: self.resolve(
                reference,
                batch=referrer_batch,
                version=referrer_version,
                include_archived=include_archived,
            )
            for reference in refs
        }
        status = _combined_status(tuple(resolutions.values()))
        return Attachment(
            object_id=str(obj.get("id", "")),
            status=status,
            references=resolutions,
            batch=referrer_batch,
            version=referrer_version,
        )

    def replay(
        self,
        events: Sequence[Mapping[str, Any]],
        referrer: Any = None,
        version: Any = None,
        batch: Optional[str] = None,
    ) -> Tuple[ReplayStep, ...]:
        """Apply anchor events and record the resulting attachment each time.

        Each event is a mapping with ``action`` (``confirm`` or ``revoke``) and
        ``reference``.  A confirm event also needs ``candidate`` (a candidate
        key, STIX id, or the word ``unique`` for a sole candidate) and ``by``.
        A revoke event may name a candidate key to withdraw a single decision.
        ``referrer``, ``version``, and ``batch`` provide the context used to
        resolve the reference after every event; an event may override them.
        """
        steps: List[ReplayStep] = []
        for index, event in enumerate(events, start=1):
            action = str(event.get("action", "")).lower()
            reference = event["reference"]

            if action == "confirm":
                candidate = event.get("candidate")
                if candidate == "unique":
                    candidate = None
                anchor = self.confirm_anchor(
                    reference=reference,
                    candidate_key=(
                        candidate if isinstance(candidate, str) and
                        candidate in self._candidates else None
                    ),
                    candidate=None if candidate is None else candidate,
                    confirmed_by=event.get("by") or event.get("confirmed_by"),
                    note=event.get("note", ""),
                    confirmed_at=_as_datetime(event.get("at")),
                )
                candidate_obj = self._candidates[anchor.candidate_key]
                resolution = self.resolve(
                    reference,
                    referrer=event.get("referrer", referrer),
                    version=event.get("version", version),
                    batch=event.get("batch", batch),
                )
                steps.append(ReplayStep(
                    index=index,
                    action=action,
                    reference=reference,
                    resolution=resolution,
                    candidate=candidate_obj,
                    detail=anchor.note,
                ))
            elif action in ("revoke", "revoke-anchor"):
                changed = self.revoke_anchor(
                    reference=reference,
                    candidate_key=event.get("candidate"),
                    revoked_by=event.get("by") or event.get("revoked_by") or "",
                    note=event.get("note", ""),
                    revoked_at=_as_datetime(event.get("at")),
                )
                resolution = self.resolve(
                    reference,
                    referrer=event.get("referrer", referrer),
                    version=event.get("version", version),
                    batch=event.get("batch", batch),
                )
                steps.append(ReplayStep(
                    index=index,
                    action=action,
                    reference=reference,
                    resolution=resolution,
                    candidate=(
                        self._candidates[changed[0].candidate_key]
                        if changed else None
                    ),
                    detail=event.get("note", ""),
                ))
            else:
                raise ValueError("unknown replay action: {!r}".format(action))

        return tuple(steps)

    def snapshot(self, name: Optional[str] = None) -> Dict[str, Any]:
        """Return a deterministic, JSON-friendly snapshot of the state."""
        return {
            "name": name,
            "batches": list(self.batches),
            "archived_batches": list(self.archived_batches),
            "candidates": [
                candidate.to_dict()
                for candidate in sorted(
                    self._candidates.values(),
                    key=lambda candidate: candidate.sort_key,
                )
            ],
            "anchors": [
                anchor.to_dict()
                for anchor in sorted(
                    self._anchors.anchors,
                    key=lambda anchor: (
                        anchor.reference, anchor.confirmed_at, anchor.candidate_key,
                    ),
                )
            ],
        }

    @classmethod
    def restore(cls, state: Mapping[str, Any]) -> "ImportService":
        """Rebuild a service from :meth:`snapshot` output."""
        service = cls()
        for candidate in state.get("candidates", []):
            service.ingest(candidate["object"], batch=candidate["batch"])

        for batch in state.get("archived_batches", []):
            if batch not in service._batches:
                service._batches.add(batch)
            service._archived.add(batch)

        for anchor in state.get("anchors", []):
            service._anchors.restore(IdentityAnchor(
                reference=anchor["reference"],
                candidate_key=anchor["candidate_key"],
                confirmed_by=anchor["confirmed_by"],
                confirmed_at=_as_datetime(anchor["confirmed_at"]),
                note=anchor.get("note", ""),
                revoked=bool(anchor.get("revoked", False)),
                revoked_by=anchor.get("revoked_by"),
                revoked_at=_as_datetime(anchor.get("revoked_at")),
            ))

        return service


def resolve_reference(
    service: ImportService,
    reference: str,
    referrer: Any = None,
    **kwargs: Any,
) -> Resolution:
    """Convenience wrapper around :meth:`ImportService.resolve`."""
    return service.resolve(reference, referrer=referrer, **kwargs)


def attach_references(
    service: ImportService,
    obj: Mapping[str, Any],
    **kwargs: Any,
) -> Attachment:
    """Convenience wrapper around :meth:`ImportService.attach`."""
    return service.attach(obj, **kwargs)


__all__ = [
    "AmbiguousCandidateError",
    "AnchorError",
    "AnchorRegistry",
    "Attachment",
    "IdentityAnchor",
    "IdentityResolutionError",
    "ImportService",
    "ImportedCandidate",
    "OccupancySlot",
    "ReplayStep",
    "Resolution",
    "ResolutionStatus",
    "attach_references",
    "fingerprint",
    "resolve_reference",
]
