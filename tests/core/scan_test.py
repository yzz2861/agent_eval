import os
import textwrap
from pathlib import Path
from unittest import mock

import pytest

from detect_secrets.core import scan
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.plugins.base import BasePlugin
from detect_secrets.plugins.base import MultiLinePlugin
from detect_secrets.settings import transient_settings
from detect_secrets.util import git
from detect_secrets.util.path import get_relative_path_if_in_cwd
from testing.mocks import mock_named_temporary_file


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
    def test_undecodable_file_is_not_treated_as_clean(mock_log_warning):
        # Files that fail to decode must surface a diagnostic, rather than
        # being silently treated as clean files.
        with mock_named_temporary_file(suffix='.woff2') as f:
            f.write(b'\x86\x87')
            f.seek(0)

            assert not list(scan.scan_file(f.name))

        assert 'Unable to decode' in mock_log_warning.warning_messages

    @staticmethod
    def test_handles_binary_files_gracefully():
        # NOTE: This suffix needs to be something that isn't in the known file types, as determined
        # by `detect_secrets.util.filetype.determine_file_type`.
        with mock_named_temporary_file(suffix='.woff2') as f:
            f.write(b'\x86')
            f.seek(0)

            assert not list(scan.scan_file(f.name))


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


class TestScanFileMultiline:
    PEM_BLOCK = (
        '-----BEGIN RSA PRIVATE KEY-----\n'
        'MIIBOgIBAAJBAK34QJDZFi+0hbDdtJ7xJzNjB5QRg4vZNgW4L1Z7d1+K1wIDAQAB\n'
        '-----END RSA PRIVATE KEY-----'
    )

    @staticmethod
    @pytest.fixture(autouse=True)
    def configure_multiline_plugins():
        with transient_settings({
            'plugins_used': [
                {
                    'name': 'BasicAuthDetector',
                },
                {
                    'name': 'PrivateKeyDetector',
                },
            ],
        }):
            yield

    @staticmethod
    def scan_content(content):
        with mock_named_temporary_file(suffix='.txt') as f:
            f.write(content.encode())
            f.seek(0)

            return list(scan.scan_file(f.name))

    def test_multiline_pem_reported_as_single_secret(self):
        secrets = self.scan_content('prefix line\n' + self.PEM_BLOCK + '\ntrailing\n')

        assert len(secrets) == 1
        secret = secrets[0]
        assert secret.type == 'Private Key'
        assert secret.line_number == 2
        assert secret.end_line_number == 4
        assert secret.secret_value == self.PEM_BLOCK
        assert secret.secret_hash == PotentialSecret.hash_secret(self.PEM_BLOCK)

    def test_multiline_pem_fingerprint_is_stable(self):
        # The same block must hash identically, regardless of where it
        # appears in the file, and across repeated scans.
        hashes = set()
        for prefix_lines in (0, 3):
            content = ('padding\n' * prefix_lines) + self.PEM_BLOCK + '\n'
            for _ in range(2):
                secrets = self.scan_content(content)
                assert len(secrets) == 1
                hashes.add(secrets[0].secret_hash)

        assert hashes == {PotentialSecret.hash_secret(self.PEM_BLOCK)}

    def test_unterminated_pem_header_still_flagged(self):
        # Without a closing marker, fall back to the historical single-line
        # detection, so existing baselines remain valid.
        secrets = self.scan_content(
            '-----BEGIN PRIVATE KEY-----\n'
            'unterminated body\n',
        )

        assert len(secrets) == 1
        secret = secrets[0]
        assert secret.line_number == 1
        assert secret.end_line_number is None
        assert secret.secret_hash == PotentialSecret.hash_secret('BEGIN PRIVATE KEY')

    def test_multiline_pem_beyond_window_size(self):
        # The scanning window is bounded, but secrets well past the window
        # size must still be found, with accurate line numbers.
        prefix_lines = scan.SCAN_WINDOW_LINES * 3
        secrets = self.scan_content(('padding\n' * prefix_lines) + self.PEM_BLOCK + '\n')

        assert len(secrets) == 1
        secret = secrets[0]
        assert secret.line_number == prefix_lines + 1
        assert secret.end_line_number == prefix_lines + 3
        assert secret.secret_hash == PotentialSecret.hash_secret(self.PEM_BLOCK)

    def test_multiline_pem_straddling_window_boundary(self):
        # A block that straddles a window boundary must be reported exactly
        # once -- not as both a partial header and a full block.
        prefix_lines = scan.SCAN_WINDOW_LINES - 4
        secrets = self.scan_content(('padding\n' * prefix_lines) + self.PEM_BLOCK + '\n')

        assert len(secrets) == 1
        secret = secrets[0]
        assert secret.line_number == prefix_lines + 1
        assert secret.end_line_number == prefix_lines + 3
        assert secret.secret_value == self.PEM_BLOCK

    def test_long_lines(self):
        long_padding = 'x' * 200000
        secrets = self.scan_content(
            long_padding + '\n'
            'url = "https://username:password@example.com"\n'
            + long_padding + '\n',
        )

        assert len(secrets) == 1
        secret = secrets[0]
        assert secret.type == 'Basic Auth Credentials'
        assert secret.line_number == 2
        assert secret.secret_hash == PotentialSecret.hash_secret('password')

    def test_single_line_secret_matches_adhoc_scan(self):
        # Single-line plugins must produce the same fingerprint whether the
        # secret is found through a file scan or an adhoc string scan.
        line = 'url = "https://username:password@example.com"'
        file_secrets = self.scan_content(line + '\n')
        adhoc_secrets = list(scan.scan_line(line))

        assert len(file_secrets) == 1
        assert file_secrets[0].line_number == 1
        assert file_secrets[0].end_line_number is None
        assert {secret.secret_hash for secret in adhoc_secrets} == {
            file_secrets[0].secret_hash,
        }

    def test_plugin_exceptions_are_isolated(self, mock_log_warning):
        class BrokenLinePlugin(BasePlugin):
            secret_type = 'Broken Line Plugin'

            def analyze_string(self, string):
                yield 'unreachable'

            def analyze_line(self, **kwargs):
                raise ValueError('line plugin boom')

        class BrokenMultiLinePlugin(MultiLinePlugin):
            secret_type = 'Broken Multiline Plugin'

            def analyze_string(self, string):
                yield 'unreachable'

            def analyze_multiline(self, **kwargs):
                raise ValueError('multiline plugin boom')

        with mock.patch.object(
            scan,
            'get_plugins',
            return_value=[
                BrokenLinePlugin(),
                BrokenMultiLinePlugin(),
            ] + scan.get_plugins(),
        ):
            secrets = self.scan_content(
                'url = "https://username:password@example.com"\n'
                + self.PEM_BLOCK + '\n',
            )

        # The broken plugins are isolated: the healthy plugins still report.
        assert {secret.type for secret in secrets} == {
            'Basic Auth Credentials',
            'Private Key',
        }
        assert 'BrokenLinePlugin' in mock_log_warning.warning_messages
        assert 'BrokenMultiLinePlugin' in mock_log_warning.warning_messages
