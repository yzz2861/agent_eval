import json
import re
import subprocess
from pathlib import Path

from detect_secrets.core import baseline
from detect_secrets.core.coverage import CoverageLedger
from detect_secrets.core.coverage import CoverageStatus
from detect_secrets.core.coverage import ExclusionReason
from detect_secrets.plugins.base import RegexBasedDetector
from detect_secrets.settings import get_settings
from detect_secrets.settings import transient_settings
from detect_secrets.util.filetype import FileType
from testing.plugins import register_plugin


EXCLUDE_FILE_FILTER = 'detect_secrets.filters.regex.should_exclude_file'


def fake_config(plugin_limit=4.5, exclude_patterns=None):
    """A completely fake configuration, sufficient to scan with."""
    config = {
        'plugins_used': [
            {
                'name': 'Base64HighEntropyString',
                'limit': plugin_limit,
            },
        ],
    }
    if exclude_patterns is not None:
        config['filters_used'] = [
            {
                'path': EXCLUDE_FILE_FILTER,
                'pattern': exclude_patterns,
            },
        ]

    return config


def scan_directory(coverage, **kwargs):
    return baseline.create('.', should_scan_all_files=True, coverage=coverage, **kwargs)


class TestEmptyReports:
    """Two reports can both have zero findings, but only one supports release."""

    def test_fully_scanned_empty_report_supports_release(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path('config.txt').write_text('just some ordinary words\n')
        Path('notes.md').write_text('more ordinary words\n')

        with transient_settings(fake_config()):
            coverage = CoverageLedger()
            secrets = scan_directory(coverage)
            report = baseline.format_for_output(secrets, coverage=coverage)

        assert report['results'] == {}
        assert coverage.is_sufficient_for_release()
        assert coverage.missing_evidence() == {
            'excluded': [],
            'unknown': [],
            'unchecked': [],
        }

        # The report itself carries the coverage account.
        assert set(report['coverage']['sources']) == {'config.txt', 'notes.md'}
        for source in report['coverage']['sources'].values():
            assert source['status'] == 'scanned'
            assert source['plugins_applied'] == ['Base64 High Entropy String']

    def test_excluded_empty_report_does_not_support_release(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path('config.txt').write_text('just some ordinary words\n')

        config = fake_config(exclude_patterns=['config'])
        with transient_settings(config):
            coverage = CoverageLedger()
            secrets = scan_directory(coverage)
            report = baseline.format_for_output(secrets, coverage=coverage)

        # The findings are just as empty, but nothing was actually checked.
        assert report['results'] == {}
        assert not coverage.is_sufficient_for_release()
        assert coverage.missing_evidence()['excluded'] == ['config.txt']

        entry = coverage.entries['config.txt']
        assert entry.status is CoverageStatus.EXCLUDED
        assert entry.reason is ExclusionReason.FILTERED_BY_RULE
        assert entry.filter_path == EXCLUDE_FILE_FILTER

    def test_rules_for_other_file_types_do_not_count_as_checked(
        self,
        tmp_path,
        monkeypatch,
    ):
        class PythonOnlyFakeDetector(RegexBasedDetector):
            secret_type = 'Python Only Fake'
            applicable_file_types = {FileType.PYTHON}
            denylist = (re.compile(r'fake-secret'),)

        monkeypatch.chdir(tmp_path)
        Path('notes.txt').write_text('nothing to find here\n')

        with register_plugin(PythonOnlyFakeDetector()):
            get_settings().configure_plugins([{'name': 'PythonOnlyFakeDetector'}])

            coverage = CoverageLedger()
            secrets = scan_directory(coverage)

        assert not secrets
        assert not coverage.is_sufficient_for_release()
        assert coverage.missing_evidence()['unchecked'] == ['notes.txt']

        entry = coverage.entries['notes.txt']
        assert entry.status is CoverageStatus.SCANNED
        assert entry.plugins_applied == []
        assert entry.plugins_not_applicable == ['Python Only Fake']


class TestExclusionReasons:
    def test_untracked_inputs_are_filtered_by_workspace(self, tmp_path, monkeypatch):
        subprocess.call(['git', '-C', str(tmp_path), 'init'])
        Path(tmp_path, 'tracked.txt').write_text('ordinary words\n')
        subprocess.check_output(['git', '-C', str(tmp_path), 'add', 'tracked.txt'])
        Path(tmp_path, 'untracked.txt').write_text('ordinary words\n')

        monkeypatch.chdir(tmp_path)
        with transient_settings(fake_config()):
            coverage = CoverageLedger()
            secrets = baseline.create('.', coverage=coverage)

        assert not secrets
        assert not coverage.is_sufficient_for_release()

        assert coverage.entries['tracked.txt'].status is CoverageStatus.SCANNED
        untracked = coverage.entries['untracked.txt']
        assert untracked.status is CoverageStatus.EXCLUDED
        assert untracked.reason is ExclusionReason.NOT_IN_WORKSPACE

    def test_non_text_file_is_recorded(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path('binary.txt').write_bytes(b'\xff\xfe\x00\x01 not really text')

        with transient_settings(fake_config()):
            coverage = CoverageLedger()
            secrets = scan_directory(coverage)

        assert not secrets
        entry = coverage.entries['binary.txt']
        assert entry.status is CoverageStatus.EXCLUDED
        assert entry.reason is ExclusionReason.NON_TEXT_FILE

    def test_non_existent_file_is_recorded(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        with transient_settings(fake_config()):
            coverage = CoverageLedger()
            secrets = baseline.create('ghost.txt', coverage=coverage)

        assert not secrets
        entry = coverage.entries['ghost.txt']
        assert entry.status is CoverageStatus.EXCLUDED
        assert entry.reason is ExclusionReason.UNREADABLE


class TestHistoricalBaselines:
    def test_baseline_without_coverage_is_read_as_unknown(self):
        historical_baseline = {
            'version': '1.0.0',
            'plugins_used': [{'name': 'Base64HighEntropyString', 'limit': 4.5}],
            'filters_used': [],
            'results': {
                'old_file.py': [],
            },
        }

        coverage = baseline.load_coverage(historical_baseline)

        assert coverage.entries['old_file.py'].status is CoverageStatus.UNKNOWN
        assert not coverage.is_sufficient_for_release()
        assert coverage.missing_evidence()['unknown'] == ['old_file.py']

    def test_coverage_round_trips_through_baseline(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path('config.txt').write_text('just some ordinary words\n')

        with transient_settings(fake_config()):
            coverage = CoverageLedger()
            secrets = scan_directory(coverage)
            report = baseline.format_for_output(secrets, coverage=coverage)

            loaded = baseline.load_coverage(json.loads(json.dumps(report)))
            assert loaded == coverage
            assert loaded.is_sufficient_for_release()


class TestIncrementalRecomputation:
    """When filter conditions change, only the affected part is recomputed."""

    def test_only_affected_entries_become_stale(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path('kept.txt').write_text('nothing interesting here\n')
        Path('excluded.txt').write_text('nothing interesting here\n')

        with transient_settings(fake_config(exclude_patterns=['excluded'])):
            coverage = CoverageLedger()
            scan_directory(coverage)

            assert coverage.entries['kept.txt'].status is CoverageStatus.SCANNED
            assert coverage.entries['excluded.txt'].status is CoverageStatus.EXCLUDED

        # Changing the plugin configuration only affects scanned entries.
        with transient_settings(fake_config(plugin_limit=6.0, exclude_patterns=['excluded'])):
            assert coverage.stale_sources() == {'kept.txt'}
            assert set(coverage.carried_over().entries) == {'excluded.txt'}

        # Changing the exclusion rule only affects the entries it excluded.
        with transient_settings(fake_config(exclude_patterns=['something-else'])):
            assert coverage.stale_sources() == {'excluded.txt'}
            assert set(coverage.carried_over().entries) == {'kept.txt'}

        # With unchanged settings, nothing needs to be recomputed.
        with transient_settings(fake_config(exclude_patterns=['excluded'])):
            assert not coverage.stale_sources()

    def test_unknown_entries_are_never_stale(self):
        coverage = CoverageLedger()
        coverage.record_unknown('mystery.txt')

        with transient_settings(fake_config()):
            assert not coverage.stale_sources()
            assert set(coverage.carried_over().entries) == {'mystery.txt'}
            assert (
                coverage.carried_over().entries['mystery.txt'].status
                is CoverageStatus.UNKNOWN
            )
