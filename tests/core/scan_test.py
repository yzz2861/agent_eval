import os
import re
import time
import textwrap
from pathlib import Path

import pytest

from detect_secrets.core import scan
from detect_secrets.core.plugin_errors import PluginErrorSink
from detect_secrets.plugins.base import RegexBasedDetector
from detect_secrets.settings import transient_settings
from detect_secrets.util import git
from detect_secrets.util.path import get_relative_path_if_in_cwd
from testing.mocks import mock_named_temporary_file
from testing.plugins import register_plugin


class TestGetFilesToScan:
    @staticmethod
    def test_should_scan_specific_non_tracked_file(non_tracked_file):
        assert list(scan.get_files_to_scan(non_tracked_file.name, should_scan_all_files=False))

    @staticmethod
    def test_should_scan_tracked_files_in_directory(non_tracked_file):
        assert (
            get_relative_path_if_in_cwd(non_tracked_file.name) not in set(
                scan.get_files_to_scan(
                    os.path.dirname(non_tracked_file.name),
                    should_scan_all_files=False,
                ),
            )
        )

    @staticmethod
    def test_should_scan_all_files_in_directory_if_flag_is_provided(non_tracked_file):
        assert (
            get_relative_path_if_in_cwd(non_tracked_file.name) in set(
                scan.get_files_to_scan(
                    os.path.dirname(non_tracked_file.name),
                    should_scan_all_files=True,
                ),
            )
        )

    @staticmethod
    def test_handles_each_path_separately(non_tracked_file):
        results = list(
            scan.get_files_to_scan(
                non_tracked_file.name,
                'test_data/short_files',
            ),
        )

        # This implies that the test_data/short_files directory is scanned, because otherwise,
        # it would only be one file. However, at the same time, this test case isn't fragile to
        # additions to this directory.
        assert len(results) > 2

    @staticmethod
    def test_handles_multiple_directories():
        directories = [Path('test_data/short_files'), Path('test_data/files')]
        results = list(scan.get_files_to_scan(*directories))

        for prefix in directories:
            assert len(list(filter(lambda x: x.startswith(str(prefix)), results))) > 1

    @staticmethod
    @pytest.fixture(autouse=True, scope='class')
    def non_tracked_file():
        with mock_named_temporary_file(
            prefix=os.path.join(git.get_root_directory(), 'test_data/'),
        ) as f:
            f.write(b'content does not matter')
            f.seek(0)

            yield f


class TestScanFile:
    @staticmethod
    def test_handles_broken_yaml_gracefully():
        with mock_named_temporary_file(suffix='.yaml') as f:
            f.write(
                textwrap.dedent("""
                metadata:
                    name: {{ .values.name }}
                """)[1:].encode(),
            )
            f.seek(0)

            assert not list(scan.scan_file(f.name))

    @staticmethod
    def test_handles_binary_files_gracefully():
        # NOTE: This suffix needs to be something that isn't in the known file types, as determined
        # by `detect_secrets.util.filetype.determine_file_type`.
        with mock_named_temporary_file(suffix='.woff2') as f:
            f.write(b'\x86')
            f.seek(0)

            assert not list(scan.scan_file(f.name))


class WorkingTestDetector(RegexBasedDetector):
    secret_type = 'WorkingTestDetector'
    denylist = (re.compile(r'working-secret-[a-z0-9]+'),)


class BrokenTestDetector(RegexBasedDetector):
    secret_type = 'BrokenTestDetector'
    denylist = (re.compile(r'broken-trigger'),)

    def analyze_string(self, string):
        raise RuntimeError('token AKIA-LEAKED-SECRET-0000 should not be logged')


class SlowTestDetector(RegexBasedDetector):
    secret_type = 'SlowTestDetector'
    denylist = (re.compile(r'slow-trigger'),)

    def analyze_string(self, string):
        time.sleep(2)
        yield from super().analyze_string(string)


class TestPluginIsolation:
    @pytest.fixture
    def secret_file(self):
        with mock_named_temporary_file(suffix='.txt') as f:
            f.write(
                os.linesep.join([
                    'working-secret-aaaa1111 and broken-trigger',
                    'working-secret-bbbb2222 alone',
                ]).encode(),
            )
            f.seek(0)
            yield f.name

    @staticmethod
    def test_broken_plugin_does_not_abort_scan(secret_file):
        with register_plugin(BrokenTestDetector()), register_plugin(
            WorkingTestDetector(),
        ), transient_settings({
            'plugins_used': [
                {'name': 'BrokenTestDetector'},
                {'name': 'WorkingTestDetector'},
            ],
            'filters_used': [],
        }):
            sink = PluginErrorSink()
            secrets = list(scan.scan_file(secret_file, error_sink=sink))

        # Candidates discovered by the healthy plugin must not be swallowed.
        assert len(secrets) == 2
        assert all(secret.type == 'WorkingTestDetector' for secret in secrets)

        # The failure is recorded with file and plugin name.
        assert len(sink.errors) >= 1
        error = sink.errors[0]
        assert error.plugin == 'BrokenTestDetector'
        assert error.filename == secret_file
        assert error.error_type == 'error'
        assert 'AKIA-LEAKED-SECRET-0000' not in str(sink.errors)

    @staticmethod
    def test_scan_continues_without_a_supplied_sink(secret_file, mock_log):
        with register_plugin(BrokenTestDetector()), register_plugin(
            WorkingTestDetector(),
        ), transient_settings({
            'plugins_used': [
                {'name': 'BrokenTestDetector'},
                {'name': 'WorkingTestDetector'},
            ],
            'filters_used': [],
        }):
            secrets = list(scan.scan_file(secret_file))

        assert len(secrets) == 2
        assert 'AKIA-LEAKED-SECRET-0000' not in mock_log.messages.get('error', '')

    @staticmethod
    def test_timeout_is_isolated_and_distinct(monkeypatch, secret_file):
        monkeypatch.setenv('DETECT_SECRETS_PLUGIN_TIMEOUT', '0.2')
        with register_plugin(SlowTestDetector()), register_plugin(
            WorkingTestDetector(),
        ), transient_settings({
            'plugins_used': [
                {'name': 'SlowTestDetector'},
                {'name': 'WorkingTestDetector'},
            ],
            'filters_used': [],
        }):
            sink = PluginErrorSink()
            start = time.monotonic()
            secrets = list(scan.scan_file(secret_file, error_sink=sink))
            elapsed = time.monotonic() - start

        assert elapsed < 1.5
        assert len(secrets) == 2
        assert any(error.error_type == 'timeout' for error in sink.errors)
        assert all(error.plugin == 'SlowTestDetector' for error in sink.errors)


class TestAdhocScanLineIsolation:
    @staticmethod
    def test_broken_plugin_does_not_kill_adhoc_scan():
        with register_plugin(BrokenTestDetector()), register_plugin(
            WorkingTestDetector(),
        ), transient_settings({
            'plugins_used': [
                {'name': 'BrokenTestDetector'},
                {'name': 'WorkingTestDetector'},
            ],
            'filters_used': [],
        }):
            secrets = list(
                scan.scan_line('broken-trigger and working-secret-adhoc1'),
            )

        assert [secret.type for secret in secrets] == ['WorkingTestDetector']


@pytest.fixture(autouse=True)
def configure_plugins():
    with transient_settings({
        'plugins_used': [
            {
                'name': 'BasicAuthDetector',
            },
        ],
    }):
        yield
