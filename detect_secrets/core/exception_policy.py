"""
Independent exception decision API.

This module provides a library-only interface for deciding whether a
PotentialSecret found during a scan is covered by a previously granted
exception ("allowlist entry").

Design properties:

*   An ExceptionRecord binds a *secret identity* (hash of the secret value
    plus rule id) to a *project scope*, a *rule version* and an *expiry
    time*. The approval rationale is kept, but the plaintext secret never is.
*   Identity deliberately excludes filename and line number, so moving a file
    (or editing lines around the secret) does not revoke an exception.
    Replacing the secret value, widening the project scope, or bumping the
    rule's semantic version all produce a non-APPROVED decision, forcing a
    fresh judgement.
*   Expiry is evaluated against a caller-provided time snapshot, never the
    wall clock, so historical reports can be replayed deterministically.
*   Merging two stores never picks a side arbitrarily: records that disagree
    on the same binding key are surfaced as explainable conflicts and are
    excluded from the merged store.

No approval UI and no notifications live here; this is a pure decision layer.
"""
import enum
from dataclasses import dataclass
from datetime import datetime
from datetime import timezone
from typing import Any
from typing import Dict
from typing import Iterable
from typing import Iterator
from typing import List
from typing import Optional
from typing import Tuple

from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.exceptions import ConflictingExceptionError


FORMAT_VERSION = '1.0'

#: Binding key: (secret_hash, rule_id, scope, rule_version).
BindingKey = Tuple[str, str, str, str]


def _require_aware(value: datetime, name: str) -> datetime:
    """Normalizes a datetime to UTC, rejecting naive values.

    Decisions must be reproducible from a serialized record, so ambiguous
    (timezone-naive) timestamps are rejected rather than guessed at.
    """
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f'{name} must be a timezone-aware datetime.')
    return value.astimezone(timezone.utc)


def _format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _parse_time(value: str) -> datetime:
    return _require_aware(
        datetime.fromisoformat(value.replace('Z', '+00:00')),
        'serialized timestamp',
    )


@dataclass(frozen=True)
class SecretIdentity:
    """Stable identity of a secret, independent of where it was found.

    Two findings share an identity iff they have the same secret value (by
    hash) and were produced by the same rule. Location is not part of the
    identity, which is exactly what allows file moves to keep an exception.
    """

    secret_hash: str
    rule_id: str

    @classmethod
    def from_secret(cls, secret: PotentialSecret) -> 'SecretIdentity':
        return cls(secret_hash=secret.secret_hash, rule_id=secret.type)

    def to_dict(self) -> Dict[str, str]:
        return {
            'secret_hash': self.secret_hash,
            'rule_id': self.rule_id,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> 'SecretIdentity':
        return cls(
            secret_hash=str(data['secret_hash']),
            rule_id=str(data['rule_id']),
        )


@dataclass(frozen=True)
class ExceptionRecord:
    """A granted exception.

    Binds a secret identity to the project scope it was approved for, the
    semantic version of the rule it was approved under, and the time it
    expires. The rationale preserves *why* the exception was approved; only
    the hash of the secret is ever stored.
    """

    identity: SecretIdentity
    scope: str
    rule_version: str
    expires_at: datetime
    rationale: str
    decided_at: datetime
    decided_by: str = ''

    def __post_init__(self) -> None:
        object.__setattr__(self, 'expires_at', _require_aware(self.expires_at, 'expires_at'))
        object.__setattr__(self, 'decided_at', _require_aware(self.decided_at, 'decided_at'))

    @classmethod
    def grant(
        cls,
        secret: PotentialSecret,
        scope: str,
        rule_version: str,
        expires_at: datetime,
        rationale: str,
        decided_at: datetime,
        decided_by: str = '',
    ) -> 'ExceptionRecord':
        """Grants an exception for a scanned secret, keeping only its hash."""
        return cls(
            identity=SecretIdentity.from_secret(secret),
            scope=scope,
            rule_version=rule_version,
            expires_at=expires_at,
            rationale=rationale,
            decided_at=decided_at,
            decided_by=decided_by,
        )

    @property
    def binding_key(self) -> BindingKey:
        return (
            self.identity.secret_hash,
            self.identity.rule_id,
            self.scope,
            self.rule_version,
        )

    def is_expired(self, at: datetime) -> bool:
        """An exception is valid strictly before its expiry time."""
        return _require_aware(at, 'at') >= self.expires_at

    def to_dict(self) -> Dict[str, str]:
        return {
            'secret_hash': self.identity.secret_hash,
            'rule_id': self.identity.rule_id,
            'scope': self.scope,
            'rule_version': self.rule_version,
            'expires_at': _format_time(self.expires_at),
            'decided_at': _format_time(self.decided_at),
            'decided_by': self.decided_by,
            'rationale': self.rationale,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> 'ExceptionRecord':
        return cls(
            identity=SecretIdentity(
                secret_hash=str(data['secret_hash']),
                rule_id=str(data['rule_id']),
            ),
            scope=str(data['scope']),
            rule_version=str(data['rule_version']),
            expires_at=_parse_time(str(data['expires_at'])),
            rationale=str(data['rationale']),
            decided_at=_parse_time(str(data['decided_at'])),
            decided_by=str(data.get('decided_by', '')),
        )


class ExceptionStatus(enum.Enum):
    APPROVED = 'approved'
    NOT_FOUND = 'not_found'
    EXPIRED = 'expired'
    RULE_VERSION_MISMATCH = 'rule_version_mismatch'
    SCOPE_MISMATCH = 'scope_mismatch'


@dataclass(frozen=True)
class ExceptionDecision:
    """Outcome of evaluating one secret against an ExceptionStore."""

    status: ExceptionStatus
    reason: str
    evaluated_at: datetime
    record: Optional[ExceptionRecord] = None

    @property
    def is_exempt(self) -> bool:
        return self.status is ExceptionStatus.APPROVED


@dataclass(frozen=True)
class MergeConflict:
    """Two records that share a binding key but disagree on content.

    Merging never picks one silently: the conflicting records are withheld
    from the merged store (so the secret must be re-judged) and surfaced
    here with an explanation.
    """

    binding_key: BindingKey
    ours: ExceptionRecord
    theirs: ExceptionRecord

    @property
    def differing_fields(self) -> List[str]:
        ours, theirs = self.ours.to_dict(), self.theirs.to_dict()
        return sorted(
            field
            for field in ours
            if ours[field] != theirs[field]
        )

    def explain(self) -> str:
        differences = '; '.join(
            '{}: {!r} vs {!r}'.format(
                field,
                self.ours.to_dict()[field],
                self.theirs.to_dict()[field],
            )
            for field in self.differing_fields
        )
        return (
            f'conflicting exceptions for secret {self.binding_key[0]} '
            f'(rule {self.binding_key[1]}, scope {self.binding_key[2]!r}, '
            f'rule version {self.binding_key[3]}): {differences}. '
            'Neither side was applied; the secret requires a fresh decision.'
        )


@dataclass(frozen=True)
class MergeResult:
    store: 'ExceptionStore'
    conflicts: Tuple[MergeConflict, ...]

    @property
    def ok(self) -> bool:
        return not self.conflicts


class ExceptionStore:
    """A serializable set of exception records, keyed by binding key."""

    def __init__(self, records: Iterable[ExceptionRecord] = ()) -> None:
        self._records: Dict[BindingKey, ExceptionRecord] = {}
        for record in records:
            self.add(record)

    def add(self, record: ExceptionRecord) -> None:
        existing = self._records.get(record.binding_key)
        if existing is not None and existing != record:
            raise ConflictingExceptionError(
                f'an exception already exists for {record.binding_key}; '
                'merge stores explicitly to surface conflicts',
            )
        self._records[record.binding_key] = record

    def __iter__(self) -> Iterator[ExceptionRecord]:
        return iter(self.records)

    def __len__(self) -> int:
        return len(self._records)

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, ExceptionStore):
            return NotImplemented
        return self._records == other._records

    @property
    def records(self) -> Tuple[ExceptionRecord, ...]:
        return tuple(
            self._records[key]
            for key in sorted(self._records)
        )

    def decide(
        self,
        identity: SecretIdentity,
        scope: str,
        rule_version: str,
        at: datetime,
    ) -> ExceptionDecision:
        """Decides whether an identity is excepted, as of the caller's snapshot.

        The result is a pure function of the store and the arguments, so
        historical reports replay identically when given the same inputs.
        """
        at = _require_aware(at, 'at')

        record = self._records.get(
            (identity.secret_hash, identity.rule_id, scope, rule_version),
        )
        if record is not None:
            if record.is_expired(at):
                return ExceptionDecision(
                    status=ExceptionStatus.EXPIRED,
                    reason=(
                        f'exception expired at {_format_time(record.expires_at)} '
                        f'(evaluated at {_format_time(at)})'
                    ),
                    evaluated_at=at,
                    record=record,
                )
            return ExceptionDecision(
                status=ExceptionStatus.APPROVED,
                reason=f'covered by active exception: {record.rationale}',
                evaluated_at=at,
                record=record,
            )

        same_scope = [
            candidate
            for candidate in self._records.values()
            if candidate.identity == identity and candidate.scope == scope
        ]
        if same_scope:
            versions = sorted({candidate.rule_version for candidate in same_scope})
            return ExceptionDecision(
                status=ExceptionStatus.RULE_VERSION_MISMATCH,
                reason=(
                    f'exception covers rule version(s) {versions}, but the scan used '
                    f'{rule_version!r}; rule semantics changed, so a fresh decision is required'
                ),
                evaluated_at=at,
            )

        same_identity = [
            candidate
            for candidate in self._records.values()
            if candidate.identity == identity
        ]
        if same_identity:
            scopes = sorted({candidate.scope for candidate in same_identity})
            return ExceptionDecision(
                status=ExceptionStatus.SCOPE_MISMATCH,
                reason=(
                    f'exception only covers scope(s) {scopes}, not {scope!r}; '
                    'scope expansion requires a fresh decision'
                ),
                evaluated_at=at,
            )

        return ExceptionDecision(
            status=ExceptionStatus.NOT_FOUND,
            reason='no exception covers this secret identity',
            evaluated_at=at,
        )

    def merge(self, other: 'ExceptionStore') -> MergeResult:
        """Merges two stores (e.g. from two branches) without picking sides.

        Records that agree merge cleanly; records that share a binding key
        but disagree are returned as conflicts and excluded from the merged
        store, so the affected secrets must be re-judged.
        """
        merged = ExceptionStore()
        conflicts = []

        other_records = {record.binding_key: record for record in other.records}
        for key in sorted(set(self._records) | set(other_records)):
            ours = self._records.get(key)
            theirs = other_records.get(key)
            if ours is None and theirs is not None:
                merged.add(theirs)
            elif theirs is None and ours is not None:
                merged.add(ours)
            elif ours is not None and ours == theirs:
                merged.add(ours)
            elif ours is not None and theirs is not None:
                conflicts.append(
                    MergeConflict(binding_key=key, ours=ours, theirs=theirs),
                )

        return MergeResult(store=merged, conflicts=tuple(conflicts))

    def to_dict(self) -> Dict[str, Any]:
        return {
            'version': FORMAT_VERSION,
            'exceptions': [record.to_dict() for record in self.records],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ExceptionStore':
        if 'exceptions' not in data:
            raise ValueError('not a serialized ExceptionStore: missing "exceptions" key')
        return cls(
            records=[ExceptionRecord.from_dict(item) for item in data['exceptions']],
        )


@dataclass(frozen=True)
class ReportEntry:
    """One secret's decision, captured in a historical report."""

    filename: str
    line_number: int
    identity: SecretIdentity
    scope: str
    rule_version: str
    status: ExceptionStatus
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'filename': self.filename,
            'line_number': self.line_number,
            **self.identity.to_dict(),
            'scope': self.scope,
            'rule_version': self.rule_version,
            'status': self.status.value,
            'reason': self.reason,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ReportEntry':
        return cls(
            filename=str(data['filename']),
            line_number=int(data['line_number']),
            identity=SecretIdentity.from_dict(data),
            scope=str(data['scope']),
            rule_version=str(data['rule_version']),
            status=ExceptionStatus(data['status']),
            reason=str(data['reason']),
        )


@dataclass(frozen=True)
class ExceptionReport:
    """A deterministic, replayable record of exception decisions for a scan."""

    scope: str
    evaluated_at: datetime
    entries: Tuple[ReportEntry, ...]

    @property
    def actionable(self) -> List[ReportEntry]:
        """Entries that are *not* exempt and therefore need attention."""
        return [
            entry
            for entry in self.entries
            if entry.status is not ExceptionStatus.APPROVED
        ]

    def replay(self, store: ExceptionStore) -> List[str]:
        """Re-runs every entry's decision against the given store, using the
        original evaluated-at snapshot.

        Returns a human-readable list of mismatches; an empty list means the
        historical judgements reproduce exactly.
        """
        mismatches = []
        for entry in self.entries:
            decision = store.decide(
                entry.identity,
                entry.scope,
                entry.rule_version,
                self.evaluated_at,
            )
            if decision.status is not entry.status:
                mismatches.append(
                    f'{entry.filename}:{entry.line_number} '
                    f'({entry.identity.rule_id}, {entry.identity.secret_hash}): '
                    f'report says {entry.status.value}, replay gives {decision.status.value}',
                )
        return mismatches

    def to_dict(self) -> Dict[str, Any]:
        return {
            'version': FORMAT_VERSION,
            'scope': self.scope,
            'evaluated_at': _format_time(self.evaluated_at),
            'results': [entry.to_dict() for entry in self.entries],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ExceptionReport':
        if 'results' not in data:
            raise ValueError('not a serialized ExceptionReport: missing "results" key')
        return cls(
            scope=str(data['scope']),
            evaluated_at=_parse_time(str(data['evaluated_at'])),
            entries=tuple(ReportEntry.from_dict(item) for item in data['results']),
        )


def evaluate_collection(
    collection: SecretsCollection,
    store: ExceptionStore,
    scope: str,
    rule_versions: Dict[str, str],
    at: datetime,
) -> ExceptionReport:
    """Applies exception decisions to a scan result.

    :param collection: scan output to evaluate.
    :param store: exceptions to evaluate against.
    :param scope: project scope the scan was performed under.
    :param rule_versions: mapping of secret type (rule id) to the semantic
        version of the rule used for this scan.
    :param at: caller-provided time snapshot used for all expiry checks.
    :raises ValueError: if a found secret's type has no rule version provided.
    """
    at = _require_aware(at, 'at')

    entries = []
    for filename in sorted(collection.files):
        secrets = sorted(
            collection.data[filename],
            key=lambda secret: (secret.secret_hash, secret.type, secret.line_number),
        )
        for secret in secrets:
            if secret.type not in rule_versions:
                raise ValueError(
                    f'no rule version provided for {secret.type!r}; '
                    'rule versions are required so exceptions stay bound to rule semantics',
                )
            identity = SecretIdentity.from_secret(secret)
            decision = store.decide(identity, scope, rule_versions[secret.type], at)
            entries.append(
                ReportEntry(
                    filename=filename,
                    line_number=secret.line_number,
                    identity=identity,
                    scope=scope,
                    rule_version=rule_versions[secret.type],
                    status=decision.status,
                    reason=decision.reason,
                ),
            )

    return ExceptionReport(scope=scope, evaluated_at=at, entries=tuple(entries))

