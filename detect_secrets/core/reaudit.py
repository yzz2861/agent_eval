"""
Supplemental re-audit support for revoked audit exemptions.

When an on-duty reviewer revokes a historical audit exemption (a finding that was
previously marked as ``is_secret: false``), the underlying code does not change, so a
regular incremental scan has no diff to pick up and the affected files are never
brought back for review.

This module computes the supplemental scan scope by diffing two versions of the audit
records against the set of files that are still known to exist, runs the scans,
records failures and no-hit scans separately, keeps the original sign-off record
untouched for traceability, and flags any parallel scan whose window straddles the
revocation point for manual review.
"""
import copy
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from dataclasses import field
from datetime import datetime
from enum import Enum
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Mapping
from typing import Optional
from typing import Protocol
from typing import Set
from typing import Tuple


class ScanStatus(Enum):
    """Outcome of a single supplemental scan."""

    HIT = 'hit'
    NO_HIT = 'no_hit'
    FAILED = 'failed'


@dataclass(frozen=True)
class ExemptionKey:
    """Identifier of an audited finding within an audit record version."""

    filename: str
    secret_type: str
    secret_hash: str


@dataclass
class SupplementalScope:
    """Files that need supplemental scanning and why."""

    files: Set[str] = field(default_factory=set)
    revoked: Dict[str, Set[ExemptionKey]] = field(default_factory=dict)
    missing_files: Set[str] = field(default_factory=set)


@dataclass(frozen=True)
class ScanWindow:
    """The time interval covered by a scan, inclusive on both ends."""

    started_at: datetime
    finished_at: datetime

    def straddles(self, point_in_time: datetime) -> bool:
        """Whether ``point_in_time`` falls inside this scan window."""
        return self.started_at <= point_in_time <= self.finished_at


@dataclass(frozen=True)
class FileScanResult:
    """Result of scanning one file in the supplemental scope."""

    filename: str
    status: ScanStatus
    findings: Tuple[Mapping[str, Any], ...] = ()
    error: Optional[str] = None
    window: Optional[ScanWindow] = None


class Scanner(Protocol):
    """Callable protocol used to decouple the service from real plugin scanning."""

    def __call__(self, filename: str) -> FileScanResult:
        ...


@dataclass(frozen=True)
class ReauditReport:
    """Full outcome of a supplemental re-audit run."""

    scope: SupplementalScope
    hits: Dict[str, Tuple[Mapping[str, Any], ...]]
    no_hits: Tuple[str, ...]
    failures: Dict[str, str]
    needs_review: Tuple[str, ...]
    archived_signoff: Mapping[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the report into JSON-friendly plain data."""
        revoked = {
            filename: sorted(
                (
                    {
                        'type': key.secret_type,
                        'hashed_secret': key.secret_hash,
                    }
                    for key in keys
                ),
                key=lambda item: (item['type'], item['hashed_secret']),
            )
            for filename, keys in sorted(self.scope.revoked.items())
        }

        return {
            'scope': {
                'files': sorted(self.scope.files),
                'revoked_exemptions': revoked,
                'missing_files': sorted(self.scope.missing_files),
            },
            'scan_results': {
                'hits': {filename: list(findings) for filename, findings in self.hits.items()},
                'no_hits': list(self.no_hits),
                'failures': dict(self.failures),
            },
            'needs_review': list(self.needs_review),
            'archived_signoff': copy.deepcopy(dict(self.archived_signoff)),
        }


def _finding_key(filename: str, finding: Mapping[str, Any]) -> ExemptionKey:
    secret_hash = finding.get('hashed_secret') or finding.get('secret_hash')
    if not isinstance(secret_hash, str):
        raise KeyError(f'audit finding for {filename} is missing `hashed_secret`')

    secret_type = finding.get('type')
    if not isinstance(secret_type, str):
        raise KeyError(f'audit finding for {filename} is missing `type`')

    return ExemptionKey(
        filename=filename,
        secret_type=secret_type,
        secret_hash=secret_hash,
    )


def _iter_exemptions(
    audit_record: Mapping[str, Any],
) -> Iterable[Tuple[str, ExemptionKey]]:
    """Yield every finding explicitly marked as a false positive (``is_secret: false``)."""
    results = audit_record.get('results', {})
    if not isinstance(results, Mapping):
        return

    for filename, findings in results.items():
        if not isinstance(findings, Iterable):
            continue

        for finding in findings:
            if not isinstance(finding, Mapping) or finding.get('is_secret') is not False:
                continue

            yield str(filename), _finding_key(str(filename), finding)


def find_revoked_exemptions(
    old_record: Mapping[str, Any],
    new_record: Mapping[str, Any],
) -> Dict[str, Set[ExemptionKey]]:
    """
    Compare two versions of the audit records and return the exemptions that no longer
    hold in the newer version.

    An exemption is considered revoked when it was marked ``is_secret: false`` in the old
    record, but its finding is absent from the new record or no longer carries that
    explicit false-positive mark.
    """
    current: Set[ExemptionKey] = set()
    for _, key in _iter_exemptions(new_record):
        current.add(key)

    revoked: Dict[str, Set[ExemptionKey]] = {}
    for filename, key in _iter_exemptions(old_record):
        if key not in current:
            revoked.setdefault(filename, set()).add(key)

    return revoked


def compute_supplemental_scope(
    old_record: Mapping[str, Any],
    new_record: Mapping[str, Any],
    known_files: Iterable[str],
) -> SupplementalScope:
    """
    Determine which files need a supplemental scan.

    Only files that still exist and have genuinely lost at least one exemption are
    included. Revoked files that have since been deleted are recorded separately instead
    of being scheduled for scanning.
    """
    revoked = find_revoked_exemptions(old_record, new_record)
    existing_files = set(known_files)

    scope = SupplementalScope()
    for filename, keys in revoked.items():
        scope.revoked[filename] = set(keys)
        if filename in existing_files:
            scope.files.add(filename)
        else:
            scope.missing_files.add(filename)

    return scope


class SupplementaryScanService:
    """Runs supplemental scans for revoked audit exemptions."""

    def __init__(
        self,
        scanner: Scanner,
        revocation_effective_at: datetime,
        max_workers: Optional[int] = None,
    ) -> None:
        self._scanner = scanner
        self._revocation_effective_at = revocation_effective_at
        self._max_workers = max_workers

    def run(
        self,
        old_record: Mapping[str, Any],
        new_record: Mapping[str, Any],
        known_files: Iterable[str],
    ) -> ReauditReport:
        scope = compute_supplemental_scope(old_record, new_record, known_files)
        ordered_files = sorted(scope.files)

        if not ordered_files:
            results: List[FileScanResult] = []
        elif self._max_workers == 1 or len(ordered_files) == 1:
            results = [self._scan_one(filename) for filename in ordered_files]
        else:
            with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
                results = list(executor.map(self._scan_one, ordered_files))

        hits: Dict[str, Tuple[Mapping[str, Any], ...]] = {}
        no_hits: List[str] = []
        failures: Dict[str, str] = {}
        needs_review: List[str] = []

        for result in results:
            if result.status == ScanStatus.FAILED:
                failures[result.filename] = result.error or 'unknown error'
            elif result.status == ScanStatus.NO_HIT:
                no_hits.append(result.filename)
            else:
                hits[result.filename] = result.findings

            if self._crosses_revocation_point(result):
                needs_review.append(result.filename)

        return ReauditReport(
            scope=scope,
            hits=hits,
            no_hits=tuple(no_hits),
            failures=failures,
            needs_review=tuple(sorted(needs_review)),
            archived_signoff=self._archive_signoff(old_record),
        )

    def _scan_one(self, filename: str) -> FileScanResult:
        try:
            result = self._scanner(filename)
        except Exception as exc:
            return FileScanResult(
                filename=filename,
                status=ScanStatus.FAILED,
                error=f'{type(exc).__name__}: {exc}',
            )

        if result.filename != filename:
            return FileScanResult(
                filename=filename,
                status=ScanStatus.FAILED,
                error=(
                    'scanner returned a result for '
                    f'{result.filename!r} instead of {filename!r}'
                ),
            )

        return result

    def _crosses_revocation_point(self, result: FileScanResult) -> bool:
        return (
            result.window is not None
            and result.window.straddles(self._revocation_effective_at)
        )

    def _archive_signoff(self, old_record: Mapping[str, Any]) -> Mapping[str, Any]:
        """Deep-copy the previous sign-off so the original stays byte-for-byte intact."""
        return copy.deepcopy(dict(old_record))


def run_supplemental_scan(
    old_record: Mapping[str, Any],
    new_record: Mapping[str, Any],
    known_files: Iterable[str],
    scanner: Scanner,
    revocation_effective_at: datetime,
    max_workers: Optional[int] = None,
) -> ReauditReport:
    """Convenience wrapper around :class:`SupplementaryScanService`."""
    service = SupplementaryScanService(
        scanner=scanner,
        revocation_effective_at=revocation_effective_at,
        max_workers=max_workers,
    )
    return service.run(old_record, new_record, known_files)
