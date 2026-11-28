from datetime import datetime
from datetime import timedelta
from typing import Any
from typing import Dict
from typing import List
from typing import Mapping
from typing import Optional

import pytest

from detect_secrets.core.reaudit import compute_supplemental_scope
from detect_secrets.core.reaudit import ExemptionKey
from detect_secrets.core.reaudit import FileScanResult
from detect_secrets.core.reaudit import find_revoked_exemptions
from detect_secrets.core.reaudit import ReauditReport
from detect_secrets.core.reaudit import run_supplemental_scan
from detect_secrets.core.reaudit import ScanStatus
from detect_secrets.core.reaudit import ScanWindow
from detect_secrets.core.reaudit import SupplementaryScanService


REVOKED_AT = datetime(2026, 11, 28, 10, 0, 0)


def finding(
    secret_type: str,
    secret_hash: str,
    is_secret: Any = False,
) -> Dict[str, Any]:
    return {
        'type': secret_type,
        'hashed_secret': secret_hash,
        'line_number': 1,
        'is_secret': is_secret,
    }


def record(results: Mapping[str, List[Mapping[str, Any]]]) -> Dict[str, Any]:
    return {
        'version': '1.0.0+placeholder',
        'generated_at': '2026-11-28T00:00:00Z',
        'results': dict(results),
    }


class FakeScanner:
    """Synthetic scanner driven entirely by placeholder, in-memory responses."""

    def __init__(
        self,
        responses: Mapping[str, FileScanResult],
        raises: Optional[Mapping[str, Exception]] = None,
    ) -> None:
        self._responses = dict(responses)
        self._raises = dict(raises or {})
        self.calls: List[str] = []

    def __call__(self, filename: str) -> FileScanResult:
        self.calls.append(filename)
        if filename in self._raises:
            raise self._raises[filename]

        return self._responses[filename]


def window_before_revocation() -> ScanWindow:
    return ScanWindow(
        started_at=REVOKED_AT - timedelta(minutes=10),
        finished_at=REVOKED_AT - timedelta(minutes=5),
    )


def window_straddling_revocation() -> ScanWindow:
    return ScanWindow(
        started_at=REVOKED_AT - timedelta(minutes=5),
        finished_at=REVOKED_AT + timedelta(minutes=5),
    )


class TestFindRevokedExemptions:
    @staticmethod
    def test_detects_exemptions_that_no_longer_hold():
        old_record = record({
            'a.py': [finding('PlaceholderToken', 'hash-a')],
            'b.py': [finding('PlaceholderToken', 'hash-b')],
            'c.py': [finding('PlaceholderToken', 'hash-c')],
        })
        new_record = record({
            # Still exempt -> must not be flagged.
            'a.py': [finding('PlaceholderToken', 'hash-a')],
            # Still present, but the false-positive mark was lifted.
            'b.py': [finding('PlaceholderToken', 'hash-b', is_secret=None)],
            # Finding disappeared entirely from the new record.
            'c.py': [],
        })

        revoked = find_revoked_exemptions(old_record, new_record)

        assert set(revoked) == {'b.py', 'c.py'}
        assert revoked['b.py'] == {
            ExemptionKey('b.py', 'PlaceholderToken', 'hash-b'),
        }
        assert revoked['c.py'] == {
            ExemptionKey('c.py', 'PlaceholderToken', 'hash-c'),
        }

    @staticmethod
    def test_true_positive_findings_are_not_exemptions():
        old_record = record({
            'a.py': [finding('PlaceholderToken', 'hash-a', is_secret=True)],
        })
        new_record = record({'a.py': []})

        assert find_revoked_exemptions(old_record, new_record) == {}

    @staticmethod
    def test_missing_hash_raises_clear_error():
        old_record = record({
            'a.py': [{'type': 'PlaceholderToken', 'is_secret': False}],
        })
        new_record = record({'a.py': []})

        with pytest.raises(KeyError):
            find_revoked_exemptions(old_record, new_record)

    @staticmethod
    def test_missing_type_raises_clear_error():
        old_record = record({
            'a.py': [{'hashed_secret': 'hash-a', 'is_secret': False}],
        })
        new_record = record({'a.py': []})

        with pytest.raises(KeyError):
            find_revoked_exemptions(old_record, new_record)

    @staticmethod
    def test_malformed_results_are_ignored():
        old_record = {
            'version': '1.0.0+placeholder',
            'results': 'not-a-mapping',
        }
        new_record = record({'a.py': []})

        assert find_revoked_exemptions(old_record, new_record) == {}

    @staticmethod
    def test_non_iterable_findings_are_skipped():
        old_record = {
            'version': '1.0.0+placeholder',
            'results': {'a.py': 42},
        }
        new_record = record({'a.py': []})

        assert find_revoked_exemptions(old_record, new_record) == {}


class TestComputeSupplementalScope:
    @staticmethod
    def test_only_existing_files_with_lost_coverage_are_scheduled():
        old_record = record({
            'kept.py': [finding('PlaceholderToken', 'hash-kept')],
            'deleted.py': [finding('PlaceholderToken', 'hash-deleted')],
            'still_exempt.py': [finding('PlaceholderToken', 'hash-still')],
        })
        new_record = record({
            'kept.py': [finding('PlaceholderToken', 'hash-kept', is_secret=None)],
            'deleted.py': [],
            'still_exempt.py': [finding('PlaceholderToken', 'hash-still')],
        })

        scope = compute_supplemental_scope(
            old_record,
            new_record,
            known_files={'kept.py', 'still_exempt.py'},
        )

        assert scope.files == {'kept.py'}
        assert scope.missing_files == {'deleted.py'}
        assert set(scope.revoked) == {'kept.py', 'deleted.py'}

    @staticmethod
    def test_empty_scope_when_nothing_changed():
        old_record = record({
            'a.py': [finding('PlaceholderToken', 'hash-a')],
        })

        scope = compute_supplemental_scope(old_record, old_record, known_files={'a.py'})

        assert scope.files == set()
        assert scope.missing_files == set()
        assert scope.revoked == {}


class TestSupplementaryScanService:
    @staticmethod
    def _records():
        old_record = record({
            # Revoked, still exists -> hit.
            'hit.py': [finding('PlaceholderToken', 'hash-hit')],
            # Revoked, still exists -> no finding on re-scan.
            'clean.py': [finding('PlaceholderToken', 'hash-clean')],
            # Revoked, still exists -> scan blows up.
            'broken.py': [finding('PlaceholderToken', 'hash-broken')],
            # Revoked first, then the file was deleted -> never re-scanned.
            'deleted.py': [finding('PlaceholderToken', 'hash-deleted')],
            # Never lost coverage -> out of scope.
            'exempt.py': [finding('PlaceholderToken', 'hash-exempt')],
        })
        new_record = record({
            'hit.py': [finding('PlaceholderToken', 'hash-hit', is_secret=None)],
            'clean.py': [finding('PlaceholderToken', 'hash-clean', is_secret=None)],
            'broken.py': [finding('PlaceholderToken', 'hash-broken', is_secret=None)],
            'deleted.py': [],
            'exempt.py': [finding('PlaceholderToken', 'hash-exempt')],
        })
        return old_record, new_record

    @staticmethod
    def _responses() -> Dict[str, FileScanResult]:
        return {
            'hit.py': FileScanResult(
                filename='hit.py',
                status=ScanStatus.HIT,
                findings=({'type': 'PlaceholderToken', 'hashed_secret': 'hash-hit'},),
                window=window_before_revocation(),
            ),
            'clean.py': FileScanResult(
                filename='clean.py',
                status=ScanStatus.NO_HIT,
                window=window_before_revocation(),
            ),
            'broken.py': FileScanResult(
                filename='broken.py',
                status=ScanStatus.FAILED,
                error='synthetic read failure',
                window=window_straddling_revocation(),
            ),
        }

    @classmethod
    def _scanner(cls) -> FakeScanner:
        return FakeScanner(responses=cls._responses())

    def test_full_run_records_each_outcome_and_skips_deleted_file(self):
        old_record, new_record = self._records()
        scanner = self._scanner()
        service = SupplementaryScanService(
            scanner=scanner,
            revocation_effective_at=REVOKED_AT,
            max_workers=1,
        )

        report = service.run(
            old_record,
            new_record,
            known_files={'hit.py', 'clean.py', 'broken.py', 'exempt.py'},
        )

        assert sorted(report.scope.files) == ['broken.py', 'clean.py', 'hit.py']
        assert report.scope.missing_files == {'deleted.py'}
        assert sorted(scanner.calls) == ['broken.py', 'clean.py', 'hit.py']

        assert set(report.hits) == {'hit.py'}
        assert report.no_hits == ('clean.py',)
        assert report.failures == {'broken.py': 'synthetic read failure'}
        # Only the scan whose window straddled the revocation point needs review.
        assert report.needs_review == ('broken.py',)

    def test_scanner_exception_is_captured_as_failure(self):
        old_record, new_record = self._records()
        scanner = FakeScanner(
            responses=self._responses(),
            raises={'broken.py': RuntimeError('boom')},
        )
        report = run_supplemental_scan(
            old_record,
            new_record,
            known_files={'hit.py', 'clean.py', 'broken.py', 'exempt.py'},
            scanner=scanner,
            revocation_effective_at=REVOKED_AT,
            max_workers=1,
        )

        assert report.failures['broken.py'] == 'RuntimeError: boom'
        assert 'broken.py' not in report.hits
        assert 'broken.py' not in report.no_hits

    def test_mismatched_scanner_response_is_a_failure(self):
        old_record, new_record = self._records()
        scanner = FakeScanner(
            responses={
                filename: FileScanResult(
                    filename='someone-else.py',
                    status=ScanStatus.HIT,
                )
                for filename in ('hit.py', 'clean.py', 'broken.py')
            },
        )
        report = SupplementaryScanService(scanner, REVOKED_AT, max_workers=1).run(
            old_record,
            new_record,
            known_files={'hit.py', 'clean.py', 'broken.py'},
        )

        assert set(report.failures) == {'broken.py', 'clean.py', 'hit.py'}

    def test_archived_signoff_is_deep_copied_and_untouched(self):
        old_record, new_record = self._records()
        scanner = self._scanner()
        report = SupplementaryScanService(scanner, REVOKED_AT, max_workers=1).run(
            old_record,
            new_record,
            known_files={'hit.py', 'clean.py', 'broken.py'},
        )

        assert report.archived_signoff == old_record
        assert report.archived_signoff is not old_record
        assert report.archived_signoff['results'] is not old_record['results']

        report.archived_signoff['results']['tampered.py'] = []
        assert 'tampered.py' not in old_record['results']

    def test_parallel_run_produces_same_results_and_flags_straddling_scan(self):
        old_record, new_record = self._records()
        scanner = self._scanner()
        report = SupplementaryScanService(
            scanner=scanner,
            revocation_effective_at=REVOKED_AT,
            max_workers=4,
        ).run(
            old_record,
            new_record,
            known_files={'hit.py', 'clean.py', 'broken.py'},
        )

        assert isinstance(report, ReauditReport)
        assert set(report.hits) == {'hit.py'}
        assert sorted(report.no_hits) == ['clean.py']
        assert set(report.failures) == {'broken.py'}
        assert report.needs_review == ('broken.py',)
        assert sorted(scanner.calls) == ['broken.py', 'clean.py', 'hit.py']

    def test_to_dict_is_plain_serializable_data(self):
        old_record, new_record = self._records()
        report = SupplementaryScanService(
            scanner=self._scanner(),
            revocation_effective_at=REVOKED_AT,
            max_workers=1,
        ).run(
            old_record,
            new_record,
            known_files={'hit.py', 'clean.py', 'broken.py'},
        )

        data = report.to_dict()

        assert data['scope']['files'] == ['broken.py', 'clean.py', 'hit.py']
        assert data['scope']['missing_files'] == ['deleted.py']
        assert data['scan_results']['no_hits'] == ['clean.py']
        assert data['scan_results']['failures'] == {'broken.py': 'synthetic read failure'}
        assert data['needs_review'] == ['broken.py']
        assert data['archived_signoff'] == old_record


class TestScanWindow:
    @staticmethod
    def test_straddles_only_when_point_is_inside_window():
        window = window_straddling_revocation()

        assert window.straddles(REVOKED_AT) is True
        assert window.straddles(REVOKED_AT - timedelta(minutes=10)) is False
        assert window.straddles(REVOKED_AT + timedelta(minutes=10)) is False


class TestEmptyAndSingleFileScans:
    @staticmethod
    def test_no_revocations_returns_empty_report_without_calling_scanner():
        old_record = record({
            'a.py': [finding('PlaceholderToken', 'hash-a')],
        })
        scanner = FakeScanner(responses={})

        report = SupplementaryScanService(scanner, REVOKED_AT).run(
            old_record,
            old_record,
            known_files={'a.py'},
        )

        assert scanner.calls == []
        assert report.hits == {}
        assert report.no_hits == ()
        assert report.failures == {}
        assert report.needs_review == ()
        assert report.archived_signoff == old_record

    @staticmethod
    def test_single_file_runs_even_with_parallel_workers():
        old_record = record({
            'only.py': [finding('PlaceholderToken', 'hash-only')],
        })
        new_record = record({
            'only.py': [finding('PlaceholderToken', 'hash-only', is_secret=None)],
        })
        scanner = FakeScanner(
            responses={
                'only.py': FileScanResult(
                    filename='only.py',
                    status=ScanStatus.NO_HIT,
                    window=window_before_revocation(),
                ),
            },
        )

        report = SupplementaryScanService(scanner, REVOKED_AT, max_workers=8).run(
            old_record,
            new_record,
            known_files={'only.py'},
        )

        assert scanner.calls == ['only.py']
        assert report.no_hits == ('only.py',)
        assert report.scope.files == {'only.py'}
