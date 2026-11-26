# This file is part of CycloneDX Python Library
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.

"""
Provenance overlay for :class:`cyclonedx.model.component_evidence.ComponentEvidence`.

CycloneDX evidence says *what* was observed, but a BOM can be produced from several
on-site unpacking events.  When two unpacking events share a part number, the part
number alone cannot tell which local sample a conclusion belongs to.

The models in this module add an in-memory provenance layer that binds a conclusion
to:

* a local unpacking sample (``LocalSample``);
* the batch interval the evidence can support (``BatchInterval``); and
* the evidence seal and photo index (``EvidenceSeal`` / ``photo_index``).

The layer is deliberately kept outside the CycloneDX wire format, because the
CycloneDX schema does not define these fields and rejects unknown evidence
properties.  It is still attached to the public ``ComponentEvidence`` and
``Identity`` models, so review can be performed directly on imported BOMs.

Attribution rules
-----------------

1. A batch-interval intersection makes a sample a **candidate** only.
2. A candidate is **attributed** only when the photo index **and** the seal
   confirmation both match.
3. If more than one batch claims the same evidence, the result is **contested**
   and a warning identifies the competing batches and samples.
4. A legacy manifest has no batch information.  That state is preserved as
   ``BatchInterval.unknown()`` -- it is never treated as a wildcard.
"""

from collections.abc import Iterable, Iterator, Mapping
from enum import Enum
from typing import Any, Optional, Union

from .._internal.compare import ComparableTuple as _ComparableTuple
from ..exception.model import InvalidValueException

_Fingerprint = tuple[Optional[str], Optional[str]]
_BatchBound = Union[int, str]


def _is_before(left: Any, right: Any) -> bool:
    return bool(left < right)


def _is_after(left: Any, right: Any) -> bool:
    return bool(left > right)


class BatchInterval:
    """
    An inclusive interval of batch numbers that a piece of evidence can support.

    ``BatchInterval.unknown()`` is an explicit state.  It is used for evidence
    imported from manifests that predate provenance tracking, and it never matches
    another interval.  Treating unknown as a wildcard would silently re-create the
    cross-batch attribution bug this model is meant to prevent.

    Bounds may be omitted to express an open interval.  ``BatchInterval(2, 5)``
    covers batches 2, 3, 4 and 5.
    """

    def __init__(
        self,
        start: Optional[_BatchBound] = None,
        end: Optional[_BatchBound] = None,
        *,
        unknown: Optional[bool] = None,
    ) -> None:
        if unknown is None:
            unknown = start is None and end is None
        if unknown:
            if start is not None or end is not None:
                raise InvalidValueException('unknown batch interval must not define bounds')
        else:
            if isinstance(start, int) and start < 0:
                raise InvalidValueException(f'batch interval start {start!r} must not be negative')
            if isinstance(end, int) and end < 0:
                raise InvalidValueException(f'batch interval end {end!r} must not be negative')
            if start is not None and end is not None:
                try:
                    inverted = _is_after(start, end)
                except TypeError as error:
                    raise InvalidValueException('batch interval bounds must be comparable') from error
                if inverted:
                    raise InvalidValueException(
                        f'batch interval start {start!r} must not be greater than end {end!r}')
        self._start = None if unknown else start
        self._end = None if unknown else end
        self._unknown = bool(unknown)

    @classmethod
    def unknown(cls) -> 'BatchInterval':
        """Return the explicit *batch unknown* layer."""
        return cls(unknown=True)

    @property
    def start(self) -> Optional[_BatchBound]:
        """Inclusive lower bound, or ``None`` for an open lower bound."""
        return self._start

    @property
    def end(self) -> Optional[_BatchBound]:
        """Inclusive upper bound, or ``None`` for an open upper bound."""
        return self._end

    @property
    def first(self) -> Optional[_BatchBound]:
        """Alias for :attr:`start`."""
        return self._start

    @property
    def last(self) -> Optional[_BatchBound]:
        """Alias for :attr:`end`."""
        return self._end

    @property
    def is_unknown(self) -> bool:
        return self._unknown

    @property
    def is_known(self) -> bool:
        return not self._unknown

    def __contains__(self, batch: object) -> bool:
        if self._unknown or not isinstance(batch, (int, str)):
            return False
        try:
            if self._start is not None and _is_before(batch, self._start):
                return False
            if self._end is not None and _is_after(batch, self._end):
                return False
            return True
        except TypeError:
            return False

    def contains(self, batch: object) -> bool:
        """Return whether ``batch`` is inside this interval."""
        return batch in self

    def intersects(self, other: 'BatchInterval') -> bool:
        """
        Return whether two known intervals overlap.

        An unknown interval never intersects anything.  Intersection is only a
        candidacy signal; callers must still confirm photo index and seal.
        """
        if self._unknown or other.is_unknown:
            return False
        try:
            if self._end is not None and other.start is not None and _is_before(self._end, other.start):
                return False
            if other.end is not None and self._start is not None and _is_before(other.end, self._start):
                return False
            return True
        except TypeError:
            return False

    def overlaps(self, other: 'BatchInterval') -> bool:
        """Alias for :meth:`intersects`."""
        return self.intersects(other)

    def intersection(self, other: 'BatchInterval') -> Optional['BatchInterval']:
        """Return the overlapping interval, or ``None`` when it does not intersect."""
        if not self.intersects(other):
            return None
        start = self._start
        if other.start is not None and (start is None or _is_after(other.start, start)):
            start = other.start
        end = self._end
        if other.end is not None and (end is None or _is_before(other.end, end)):
            end = other.end
        return BatchInterval(start, end, unknown=False)

    def to_dict(self) -> dict[str, Any]:
        if self._unknown:
            return {'unknown': True}
        return {'start': self._start, 'end': self._end, 'unknown': False}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> 'BatchInterval':
        if data.get('unknown'):
            return cls.unknown()
        if 'unknown' in data:
            return cls(data.get('start'), data.get('end'), unknown=False)
        return cls(data.get('start'), data.get('end'))

    def __comparable_tuple(self) -> _ComparableTuple:
        if self._unknown:
            return _ComparableTuple((0, None, None))
        return _ComparableTuple((1, self._start, self._end))

    def __eq__(self, other: object) -> bool:
        if isinstance(other, BatchInterval):
            return self.__comparable_tuple() == other.__comparable_tuple()
        return False

    def __lt__(self, other: Any) -> bool:
        if isinstance(other, BatchInterval):
            return self.__comparable_tuple() < other.__comparable_tuple()
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.__comparable_tuple())

    def __repr__(self) -> str:
        if self._unknown:
            return '<BatchInterval unknown>'
        return f'<BatchInterval {self._start!r}..{self._end!r}>'


class EvidenceSeal:
    """An evidence seal recorded during an on-site unpacking."""

    def __init__(self, seal_id: str, *, verified: bool = True) -> None:
        if not seal_id:
            raise InvalidValueException('seal_id must not be empty')
        self.seal_id = seal_id
        self.verified = verified

    def matches(self, other: 'EvidenceSeal') -> bool:
        return self.seal_id == other.seal_id

    def confirms(self, other: 'EvidenceSeal') -> bool:
        """Both seals carry the same id and both reconciliation checks passed."""
        return self.matches(other) and self.verified and other.verified

    def to_dict(self) -> dict[str, Any]:
        return {'sealId': self.seal_id, 'verified': self.verified}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> 'EvidenceSeal':
        return cls(str(data['sealId']), verified=bool(data.get('verified', True)))

    def __comparable_tuple(self) -> _ComparableTuple:
        return _ComparableTuple((self.seal_id, self.verified))

    def __eq__(self, other: object) -> bool:
        if isinstance(other, EvidenceSeal):
            return self.__comparable_tuple() == other.__comparable_tuple()
        return False

    def __lt__(self, other: Any) -> bool:
        if isinstance(other, EvidenceSeal):
            return self.__comparable_tuple() < other.__comparable_tuple()
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.__comparable_tuple())

    def __repr__(self) -> str:
        return f'<EvidenceSeal seal_id={self.seal_id!r}, verified={self.verified}>'


class LocalSample:
    """A local on-site unpacking sample."""

    def __init__(
        self,
        *,
        sample_id: str,
        batch: Optional[BatchInterval] = None,
        photo_index: Optional[str] = None,
        seal: Optional[EvidenceSeal] = None,
        part_number: Optional[str] = None,
    ) -> None:
        if not sample_id:
            raise InvalidValueException('sample_id must not be empty')
        self.sample_id = sample_id
        self.batch = batch if batch is not None else BatchInterval.unknown()
        self.photo_index = photo_index
        self.seal = seal
        self.part_number = part_number

    @property
    def evidence_fingerprint(self) -> _Fingerprint:
        return (self.seal.seal_id if self.seal is not None else None, self.photo_index)

    def to_dict(self) -> dict[str, Any]:
        return {
            'sampleId': self.sample_id,
            'batch': self.batch.to_dict(),
            'photoIndex': self.photo_index,
            'seal': self.seal.to_dict() if self.seal is not None else None,
            'partNumber': self.part_number,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> 'LocalSample':
        seal = data.get('seal')
        return cls(
            sample_id=str(data['sampleId']),
            batch=BatchInterval.from_dict(data['batch']) if data.get('batch') else None,
            photo_index=data.get('photoIndex'),
            seal=EvidenceSeal.from_dict(seal) if seal else None,
            part_number=data.get('partNumber'),
        )

    def __eq__(self, other: object) -> bool:
        if isinstance(other, LocalSample):
            return self.sample_id == other.sample_id
        return False

    def __hash__(self) -> int:
        return hash(self.sample_id)

    def __repr__(self) -> str:
        return f'<LocalSample sample_id={self.sample_id!r}, batch={self.batch!r}>'


class ProvenanceSource(str, Enum):
    """Where a provenance record came from."""

    ONSITE = 'onsite'
    LEGACY = 'legacy'


class EvidenceProvenance:
    """
    Provenance attached to one evidence conclusion (an ``Identity``).

    ``sample_id`` is the local unpacking sample the conclusion points back to.
    ``batch`` is the interval the conclusion can support.  ``seal`` and
    ``photo_index`` are the two independent checks needed for attribution.
    """

    def __init__(
        self,
        *,
        conclusion: Optional[str] = None,
        sample_id: Optional[str] = None,
        batch: Optional[BatchInterval] = None,
        seal: Optional[EvidenceSeal] = None,
        photo_index: Optional[str] = None,
        part_number: Optional[str] = None,
        source: ProvenanceSource = ProvenanceSource.ONSITE,
    ) -> None:
        self.conclusion = conclusion
        self.sample_id = sample_id
        self.batch = batch if batch is not None else BatchInterval.unknown()
        self.seal = seal
        self.photo_index = photo_index
        self.part_number = part_number
        self.source = source

    @classmethod
    def from_legacy(cls, *, conclusion: Optional[str] = None) -> 'EvidenceProvenance':
        """Preserve the explicit *batch unknown* layer for a legacy manifest."""
        return cls(conclusion=conclusion, batch=BatchInterval.unknown(), source=ProvenanceSource.LEGACY)

    @classmethod
    def from_sample(
        cls,
        sample: LocalSample,
        *,
        conclusion: Optional[str] = None,
    ) -> 'EvidenceProvenance':
        return cls(
            conclusion=conclusion,
            sample_id=sample.sample_id,
            batch=sample.batch,
            seal=sample.seal,
            photo_index=sample.photo_index,
            part_number=sample.part_number,
        )

    @property
    def is_legacy(self) -> bool:
        return self.source is ProvenanceSource.LEGACY

    @property
    def batch_is_unknown(self) -> bool:
        return self.batch.is_unknown

    @property
    def evidence_fingerprint(self) -> _Fingerprint:
        return (self.seal.seal_id if self.seal is not None else None, self.photo_index)

    @property
    def has_photo_index(self) -> bool:
        return self.photo_index is not None

    @property
    def has_seal(self) -> bool:
        return self.seal is not None

    def trace_sample_ids(self) -> tuple[str, ...]:
        """Sample ids explicitly named by this provenance record."""
        return (self.sample_id,) if self.sample_id else ()

    def supports(self, batch: object) -> bool:
        """Return whether this record can support the given batch number."""
        return self.batch.contains(batch)

    def to_dict(self) -> dict[str, Any]:
        return {
            'conclusion': self.conclusion,
            'sampleId': self.sample_id,
            'batch': self.batch.to_dict(),
            'seal': self.seal.to_dict() if self.seal is not None else None,
            'photoIndex': self.photo_index,
            'partNumber': self.part_number,
            'source': self.source.value,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> 'EvidenceProvenance':
        seal = data.get('seal')
        source = ProvenanceSource(data.get('source', ProvenanceSource.ONSITE.value))
        batch = BatchInterval.from_dict(data['batch']) if data.get('batch') else None
        return cls(
            conclusion=data.get('conclusion'),
            sample_id=data.get('sampleId'),
            batch=batch,
            seal=EvidenceSeal.from_dict(seal) if seal else None,
            photo_index=data.get('photoIndex'),
            part_number=data.get('partNumber'),
            source=source,
        )

    def __comparable_tuple(self) -> _ComparableTuple:
        return _ComparableTuple((
            self.conclusion,
            self.sample_id,
            self.batch,
            self.seal,
            self.photo_index,
            self.part_number,
            self.source.value,
        ))

    def __eq__(self, other: object) -> bool:
        if isinstance(other, EvidenceProvenance):
            return self.__comparable_tuple() == other.__comparable_tuple()
        return False

    def __lt__(self, other: Any) -> bool:
        if isinstance(other, EvidenceProvenance):
            return self.__comparable_tuple() < other.__comparable_tuple()
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.__comparable_tuple())

    def __repr__(self) -> str:
        return '<EvidenceProvenance' \
            f' conclusion={self.conclusion!r}, sample_id={self.sample_id!r},' \
            f' batch={self.batch!r}, source={self.source.value!r}>'


class AttributionStatus(str, Enum):
    """Outcome of resolving one conclusion against local samples."""

    ATTRIBUTED = 'attributed'
    CANDIDATE = 'candidate'
    CONTESTED = 'contested'
    UNATTRIBUTED = 'unattributed'
    UNKNOWN = 'unknown'


class AttributionWarning:
    """A human-readable review warning with structured context."""

    BATCH_UNKNOWN = 'batch-unknown'
    CROSS_BATCH_EVIDENCE = 'cross-batch-evidence'
    BATCH_CONTENTION = 'batch-contention'
    SOURCE_OUTSIDE_INTERVAL = 'source-sample-outside-interval'

    def __init__(
        self,
        code: str,
        message: str,
        *,
        sample_ids: Iterable[str] = (),
        batches: Iterable[BatchInterval] = (),
    ) -> None:
        self.code = code
        self.message = message
        self.sample_ids = tuple(sample_ids)
        self.batches = tuple(batches)

    def __str__(self) -> str:
        return self.message

    def __eq__(self, other: object) -> bool:
        if isinstance(other, AttributionWarning):
            return (self.code, self.message) == (other.code, other.message)
        return False

    def __hash__(self) -> int:
        return hash((self.code, self.message))

    def __repr__(self) -> str:
        return f'<AttributionWarning code={self.code!r}, message={self.message!r}>'


class SampleAttribution:
    """Why a single local sample is or is not eligible for one conclusion."""

    def __init__(
        self,
        sample: LocalSample,
        *,
        batch_intersects: bool,
        photo_matches: bool,
        seal_confirmed: bool,
    ) -> None:
        self.sample = sample
        self.batch_intersects = batch_intersects
        self.photo_matches = photo_matches
        self.seal_confirmed = seal_confirmed

    @property
    def attributed(self) -> bool:
        return self.batch_intersects and self.photo_matches and self.seal_confirmed

    @property
    def reasons(self) -> tuple[str, ...]:
        reasons = []
        if not self.batch_intersects:
            reasons.append('batch interval does not intersect')
        if not self.photo_matches:
            reasons.append('photo index does not match')
        if not self.seal_confirmed:
            reasons.append('seal is not confirmed')
        return tuple(reasons)

    def __repr__(self) -> str:
        return '<SampleAttribution' \
            f' sample_id={self.sample.sample_id!r}, attributed={self.attributed},' \
            f' reasons={self.reasons!r}>'


class EvidenceConflict:
    """The same evidence fingerprint appears in samples from different batches."""

    def __init__(
        self,
        *,
        seal_ids: Iterable[str] = (),
        photo_indexes: Iterable[str] = (),
        samples: Iterable[LocalSample],
    ) -> None:
        self.seal_ids = frozenset(seal_ids)
        self.photo_indexes = frozenset(photo_indexes)
        if not self.seal_ids and not self.photo_indexes:
            raise InvalidValueException('evidence conflict requires a shared seal or photo index')
        self.samples = tuple(samples)

    def shares_with(self, provenance: EvidenceProvenance) -> bool:
        seal_id = provenance.seal.seal_id if provenance.seal is not None else None
        return (
            (seal_id is not None and seal_id in self.seal_ids)
            or (provenance.photo_index is not None and provenance.photo_index in self.photo_indexes)
        )

    @property
    def sample_ids(self) -> tuple[str, ...]:
        return tuple(s.sample_id for s in self.samples)

    @property
    def batches(self) -> tuple[BatchInterval, ...]:
        unique = {s.batch for s in self.samples}
        return tuple(sorted(unique))

    @property
    def message(self) -> str:
        samples = ', '.join(
            f'{s.sample_id} (batch {s.batch!r})' for s in self.samples)
        shared = []
        if self.seal_ids:
            shared.append('seal(s) ' + ', '.join(repr(s) for s in sorted(self.seal_ids)))
        if self.photo_indexes:
            shared.append('photo index(es) ' + ', '.join(repr(p) for p in sorted(self.photo_indexes)))
        return f'two batches contend for the same evidence ({" and ".join(shared)}): {samples}'

    def to_warning(self) -> AttributionWarning:
        return AttributionWarning(
            AttributionWarning.BATCH_CONTENTION,
            self.message,
            sample_ids=self.sample_ids,
            batches=self.batches,
        )

    def __repr__(self) -> str:
        return f'<EvidenceConflict seal_ids={self.seal_ids!r}, photo_indexes={self.photo_indexes!r},' \
            f' sample_ids={self.sample_ids!r}>'


class LocalSampleRegistry:
    """Index of the local unpacking samples known to an on-site review."""

    def __init__(self, samples: Iterable[LocalSample] = ()) -> None:
        self._samples = tuple(samples)
        by_id: dict[str, LocalSample] = {}
        for sample in self._samples:
            if sample.sample_id in by_id:
                raise InvalidValueException(f'duplicate local sample id {sample.sample_id!r}')
            by_id[sample.sample_id] = sample
        self._by_id = by_id

    @property
    def samples(self) -> tuple[LocalSample, ...]:
        return self._samples

    def get(self, sample_id: str) -> Optional[LocalSample]:
        return self._by_id.get(sample_id)

    def __contains__(self, sample_id: object) -> bool:
        return isinstance(sample_id, str) and sample_id in self._by_id

    def __iter__(self) -> Iterator[LocalSample]:
        return iter(self._samples)

    def __len__(self) -> int:
        return len(self._samples)

    def evidence_conflicts(self) -> tuple[EvidenceConflict, ...]:
        """Find seals or photo indexes shared by samples from different batches."""
        conflicts = []
        for component in _evidence_components(self._samples):
            if len({s.batch for s in component}) < 2:
                continue
            seal_ids = frozenset(s.seal.seal_id for s in component if s.seal is not None)
            photo_indexes = frozenset(s.photo_index for s in component if s.photo_index is not None)
            if not seal_ids and not photo_indexes:
                continue
            conflicts.append(EvidenceConflict(
                seal_ids=seal_ids,
                photo_indexes=photo_indexes,
                samples=component,
            ))
        return tuple(sorted(conflicts, key=lambda c: c.sample_ids))

    def conflicting_evidence_for(self, provenance: EvidenceProvenance) -> tuple[EvidenceConflict, ...]:
        return tuple(c for c in self.evidence_conflicts() if c.shares_with(provenance))

    def __repr__(self) -> str:
        return f'<LocalSampleRegistry samples={len(self._samples)}>'


class AttributionReport:
    """Resolution result for one conclusion point."""

    def __init__(
        self,
        *,
        conclusion: Optional[str],
        claim: EvidenceProvenance,
        status: AttributionStatus,
        samples: Iterable[SampleAttribution],
        warnings: Iterable[AttributionWarning],
    ) -> None:
        self.conclusion = conclusion
        self.claim = claim
        self.status = status
        self.samples = tuple(samples)
        self.warnings = tuple(warnings)

    @property
    def candidate_samples(self) -> tuple[LocalSample, ...]:
        return tuple(s.sample for s in self.samples if s.batch_intersects)

    @property
    def attributed_samples(self) -> tuple[LocalSample, ...]:
        return tuple(s.sample for s in self.samples if s.attributed)

    @property
    def candidate_sample_ids(self) -> tuple[str, ...]:
        return tuple(s.sample_id for s in self.candidate_samples)

    @property
    def attributed_sample_ids(self) -> tuple[str, ...]:
        return tuple(s.sample_id for s in self.attributed_samples)

    @property
    def evidence_match_samples(self) -> tuple[LocalSample, ...]:
        """Samples whose photo index and seal confirm, even outside the interval."""
        return tuple(s.sample for s in self.samples if s.photo_matches and s.seal_confirmed)

    @property
    def source_sample_ids(self) -> tuple[str, ...]:
        """Original sample ids this conclusion can be traced back to."""
        ids: list[str] = []
        for sample_id in self.claim.trace_sample_ids():
            if sample_id not in ids:
                ids.append(sample_id)
        for sample in (*self.attributed_samples, *self.evidence_match_samples):
            if sample.sample_id not in ids:
                ids.append(sample.sample_id)
        return tuple(ids)

    @property
    def has_warnings(self) -> bool:
        return bool(self.warnings)

    @property
    def warning_messages(self) -> tuple[str, ...]:
        return tuple(str(warning) for warning in self.warnings)

    @property
    def is_contested(self) -> bool:
        return self.status is AttributionStatus.CONTESTED

    def trace_sample_ids(self) -> tuple[str, ...]:
        return self.source_sample_ids

    def __repr__(self) -> str:
        return '<AttributionReport' \
            f' conclusion={self.conclusion!r}, status={self.status.value!r},' \
            f' source_sample_ids={self.source_sample_ids!r}>'


class EvidenceReview:
    """On-site review result for all conclusions of a component's evidence."""

    def __init__(
        self,
        reports: Iterable[AttributionReport],
        conflicts: Iterable[EvidenceConflict] = (),
    ) -> None:
        self.reports = tuple(reports)
        self.conflicts = tuple(conflicts)

    @property
    def warnings(self) -> tuple[AttributionWarning, ...]:
        warnings: list[AttributionWarning] = []
        for report in self.reports:
            for warning in report.warnings:
                if warning not in warnings:
                    warnings.append(warning)
        for conflict in self.conflicts:
            warning = conflict.to_warning()
            if warning not in warnings:
                warnings.append(warning)
        return tuple(warnings)

    @property
    def has_warnings(self) -> bool:
        return bool(self.warnings)

    @property
    def warning_messages(self) -> tuple[str, ...]:
        return tuple(str(warning) for warning in self.warnings)

    def trace_sample_ids(self) -> dict[str, tuple[str, ...]]:
        return {
            report.conclusion or f'conclusion-{index}': report.source_sample_ids
            for index, report in enumerate(self.reports)
        }

    def for_conclusion(self, conclusion: str) -> Optional[AttributionReport]:
        for report in self.reports:
            if report.conclusion == conclusion:
                return report
        return None

    def __iter__(self) -> Iterator[AttributionReport]:
        return iter(self.reports)

    def __len__(self) -> int:
        return len(self.reports)

    def __getitem__(self, index: int) -> AttributionReport:
        return self.reports[index]

    def __repr__(self) -> str:
        return f'<EvidenceReview reports={len(self.reports)}, warnings={len(self.warnings)}>'


def attribute_evidence(
    provenance: EvidenceProvenance,
    samples: Union[LocalSampleRegistry, LocalSample, Iterable[LocalSample]],
    *,
    conclusion: Optional[str] = None,
) -> AttributionReport:
    """
    Resolve one conclusion against local samples.

    Batch-interval intersection produces candidates.  A candidate becomes
    attributed only when photo index and seal confirmation both match.  Evidence
    shared by samples from different batches is reported as contention.
    """
    registry = _as_registry(samples)
    conclusion = conclusion if conclusion is not None else provenance.conclusion

    if provenance.batch.is_unknown:
        return _legacy_report(provenance, registry, conclusion)

    evaluations = [_evaluate_sample(provenance, sample) for sample in registry.samples]

    candidates = [e for e in evaluations if e.batch_intersects]
    attributed = [e for e in candidates if e.attributed]
    conflicts = registry.conflicting_evidence_for(provenance)

    warnings = _dedupe_warnings((
        *(conflict.to_warning() for conflict in conflicts),
        *_cross_batch_warnings(provenance, evaluations),
        *_explicit_source_warnings(provenance, registry),
    ))
    if attributed and not conflicts:
        contention = _contention_warning(attributed)
        if contention is not None:
            warnings = _dedupe_warnings((*warnings, contention))

    return AttributionReport(
        conclusion=conclusion,
        claim=provenance,
        status=_resolve_status(attributed, candidates, conflicts),
        samples=evaluations,
        warnings=warnings,
    )


def _legacy_report(
    provenance: EvidenceProvenance,
    registry: LocalSampleRegistry,
    conclusion: Optional[str],
) -> AttributionReport:
    evaluations: list[SampleAttribution] = []
    if provenance.sample_id is not None:
        sample = registry.get(provenance.sample_id)
        if sample is not None:
            evaluations.append(SampleAttribution(
                sample,
                batch_intersects=False,
                photo_matches=_photo_matches(provenance, sample),
                seal_confirmed=_seal_confirmed(provenance, sample),
            ))
    warning = AttributionWarning(
        AttributionWarning.BATCH_UNKNOWN,
        'batch is unknown for this conclusion; it is preserved as a legacy '
        'layer and cannot be attributed to a known batch',
        sample_ids=provenance.trace_sample_ids(),
    )
    return AttributionReport(
        conclusion=conclusion,
        claim=provenance,
        status=AttributionStatus.UNKNOWN,
        samples=evaluations,
        warnings=(warning,),
    )


def _evaluate_sample(provenance: EvidenceProvenance, sample: LocalSample) -> SampleAttribution:
    return SampleAttribution(
        sample,
        batch_intersects=_part_matches(provenance, sample) and provenance.batch.intersects(sample.batch),
        photo_matches=_photo_matches(provenance, sample),
        seal_confirmed=_seal_confirmed(provenance, sample),
    )


def _part_matches(provenance: EvidenceProvenance, sample: LocalSample) -> bool:
    return (
        provenance.part_number is None
        or sample.part_number is None
        or provenance.part_number == sample.part_number
    )


def _cross_batch_warnings(
    provenance: EvidenceProvenance,
    evaluations: Iterable[SampleAttribution],
) -> list[AttributionWarning]:
    warnings = []
    for evaluation in evaluations:
        if evaluation.batch_intersects or not (evaluation.photo_matches and evaluation.seal_confirmed):
            continue
        warnings.append(AttributionWarning(
            AttributionWarning.CROSS_BATCH_EVIDENCE,
            f'evidence also matches sample {evaluation.sample.sample_id!r} '
            f'(batch {evaluation.sample.batch!r}), outside the supported interval '
            f'{provenance.batch!r}',
            sample_ids=(evaluation.sample.sample_id,),
            batches=(provenance.batch, evaluation.sample.batch),
        ))
    return warnings


def _explicit_source_warnings(
    provenance: EvidenceProvenance,
    registry: LocalSampleRegistry,
) -> list[AttributionWarning]:
    if provenance.sample_id is None:
        return []
    explicit = registry.get(provenance.sample_id)
    if explicit is None or provenance.batch.intersects(explicit.batch):
        return []
    return [AttributionWarning(
        AttributionWarning.SOURCE_OUTSIDE_INTERVAL,
        f'source sample {explicit.sample_id!r} is in batch {explicit.batch!r}, '
        f'outside the supported interval {provenance.batch!r}',
        sample_ids=(explicit.sample_id,),
        batches=(provenance.batch, explicit.batch),
    )]


def _contention_warning(attributed: Iterable[SampleAttribution]) -> Optional[AttributionWarning]:
    distinct_batches = {e.sample.batch for e in attributed}
    if len(distinct_batches) < 2:
        return None
    samples = tuple(attributed)
    attributed_ids = ', '.join(e.sample.sample_id for e in samples)
    return AttributionWarning(
        AttributionWarning.BATCH_CONTENTION,
        f'{len(distinct_batches)} batches contend for the same evidence: {attributed_ids}',
        sample_ids=tuple(e.sample.sample_id for e in samples),
        batches=tuple(sorted(distinct_batches)),
    )


def _resolve_status(
    attributed: Iterable[SampleAttribution],
    candidates: Iterable[SampleAttribution],
    conflicts: Iterable[EvidenceConflict],
) -> AttributionStatus:
    attributed = tuple(attributed)
    if attributed:
        if len({e.sample.batch for e in attributed}) > 1 or tuple(conflicts):
            return AttributionStatus.CONTESTED
        return AttributionStatus.ATTRIBUTED
    if tuple(candidates):
        return AttributionStatus.CANDIDATE
    return AttributionStatus.UNATTRIBUTED


def _dedupe_warnings(warnings: Iterable[AttributionWarning]) -> list[AttributionWarning]:
    unique: list[AttributionWarning] = []
    for warning in warnings:
        if warning not in unique:
            unique.append(warning)
    return unique


def _as_registry(
    samples: Union[LocalSampleRegistry, LocalSample, Iterable[LocalSample]],
) -> LocalSampleRegistry:
    if isinstance(samples, LocalSampleRegistry):
        return samples
    if isinstance(samples, LocalSample):
        return LocalSampleRegistry((samples,))
    return LocalSampleRegistry(samples)


def _evidence_components(samples: Iterable[LocalSample]) -> tuple[tuple[LocalSample, ...], ...]:
    """Group samples connected by a shared seal id or shared photo index."""
    sample_list = tuple(samples)
    parent = {sample.sample_id: sample.sample_id for sample in sample_list}

    def find(node: str) -> str:
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    def union(left: str, right: str) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[right_root] = left_root

    first_by_evidence: dict[tuple[str, str], str] = {}
    for sample in sample_list:
        if sample.seal is not None:
            key = ('seal', sample.seal.seal_id)
            union(first_by_evidence.setdefault(key, sample.sample_id), sample.sample_id)
        if sample.photo_index is not None:
            key = ('photo', sample.photo_index)
            union(first_by_evidence.setdefault(key, sample.sample_id), sample.sample_id)

    groups: dict[str, list[LocalSample]] = {}
    for sample in sample_list:
        groups.setdefault(find(sample.sample_id), []).append(sample)
    return tuple(tuple(group) for group in groups.values())


def _photo_matches(provenance: EvidenceProvenance, sample: LocalSample) -> bool:
    return (
        provenance.photo_index is not None
        and sample.photo_index is not None
        and provenance.photo_index == sample.photo_index
    )


def _seal_confirmed(provenance: EvidenceProvenance, sample: LocalSample) -> bool:
    return (
        provenance.seal is not None
        and sample.seal is not None
        and provenance.seal.confirms(sample.seal)
    )
