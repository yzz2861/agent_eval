import json
import os
import subprocess
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from detect_secrets.__version__ import VERSION
from detect_secrets.core import baseline
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.settings import get_settings
from detect_secrets.util.path import get_relative_path_if_in_cwd
from testing.mocks import mock_named_temporary_file


@pytest.fixture(autouse=True)
def configure_plugins():
    get_settings().configure_plugins([
        {
            'name': 'Base64HighEntropyString',
            'limit': 4.5,
        },
        {
            'name': 'HexHighEntropyString',
            'limit': 3,
        },
    ])


class TestCreate:
    @staticmethod
    @pytest.mark.parametrize(
        'path',
        (
            './test_data/files',

            # Test relative paths
            'test_data/../test_data/files/tmp/..',
        ),
    )
    def test_basic_usage(path):
        secrets = baseline.create(path)

        assert len(secrets.data.keys()) == 2
        assert len(secrets[str(Path('test_data/files/file_with_secrets.py'))]) == 1
        assert len(secrets[str(Path('test_data/files/tmp/file_with_secrets.py'))]) == 2

    @staticmethod
    def test_error_when_getting_git_tracked_files():
        with mock.patch('detect_secrets.util.git.subprocess.check_output') as m:
            m.side_effect = subprocess.CalledProcessError(1, 'does not matter')
            secrets = baseline.create('test_data/files/tmp')

            assert not secrets.data

    @staticmethod
    def test_non_existent_file():
        secrets = baseline.create('test_data/files/tmp/non-existent')
        assert not secrets.data

    @staticmethod
    def test_no_files_in_git_repo():
        with tempfile.TemporaryDirectory() as d:
            # Create a new directory, so scanning is sandboxed.
            with mock_named_temporary_file(dir=d, suffix='.py') as f:
                f.write(b'"2b00042f7481c7b056c4b410d28f33cf"')
                f.seek(0)

                secrets = baseline.create(d)

        assert f.name not in secrets.data

    @staticmethod
    def test_scan_all_files():
        with mock_named_temporary_file(dir='test_data/files/tmp', suffix='.py') as f:
            f.write(b'"2b00042f7481c7b056c4b410d28f33cf"')
            f.seek(0)

            secrets = baseline.create('test_data/files/tmp')
            assert f.name not in secrets.data

            secrets = baseline.create('test_data/files/tmp', should_scan_all_files=True)
            assert get_relative_path_if_in_cwd(f.name) in secrets.data


def test_load_and_output():
    with open('.secrets.baseline') as f:
        filedata = f.read()

    if os.sep == '\\':
        # Replace Linux path seperators for Windows ones
        filedata = filedata.replace('/', '\\\\')

    filedata_json = json.loads(filedata)
    secrets = baseline.load(filedata_json, filename='.secrets.baseline')
    output = baseline.format_for_output(secrets)

    for item in [filedata_json, output]:
        item.pop('generated_at')

    # We perform string matching because we want to ensure stable sorts.
    assert json.dumps(output) == json.dumps(filedata_json)

    # We need to make sure that default values carry through, for future backwards compatibility.
    for plugin in output['plugins_used']:
        if plugin['name'] == 'Base64HighEntropyString':
            assert plugin['limit'] == 4.5
            break


def test_plugin_not_found_in_baseline():
    # Test fix for the issue in #718
    data = {
        'version': '1.4.0',
        'plugins_used': [{
            'name': 'FakeCustomPlugin',
            'path': 'file://./path/to/plugin/that/does/not/exist/plugin.py',
        }],
        'results': {},
    }
    secrets = baseline.load(data)
    with pytest.raises(FileNotFoundError) as exc_info:
        baseline.format_for_output(secrets)

    # Check that filename of file that was not found is in the error message
    # (#718)
    exc_info.match(r'\./path/to/plugin/that/does/not/exist/plugin\.py')


def test_upgrade_does_nothing_if_newer_version():
    current_baseline = {'version': '3.0.0'}
    assert baseline.upgrade(current_baseline) == current_baseline


def test_upgrade_succeeds():
    current_baseline = {'version': '0.14.2', 'plugins_used': []}
    new_baseline = baseline.upgrade(current_baseline)

    assert new_baseline     # assert *something* exists
    assert current_baseline != new_baseline


class TestUpdate:
    SECRET_A = '60b725f10c9c85c70d97880dfe8191b3'
    SECRET_B = '3b5d5c3712955042212316173ccf37be'

    @staticmethod
    def _create_collection(*secrets):
        collection = SecretsCollection()
        for secret in secrets:
            collection[secret.filename].add(secret)

        return collection

    @staticmethod
    def _create_baseline(*secrets):
        return {
            'version': VERSION,
            'results': TestUpdate._create_collection(*secrets).json(),
        }

    @staticmethod
    def _get_secret(collection, filename, secret_value):
        secret_hash = PotentialSecret.hash_secret(secret_value)
        return next(
            secret
            for secret in collection[filename]
            if secret.secret_hash == secret_hash
        )

    def test_line_move_keeps_exemption_bound_to_content(self):
        # The audited false positive moved offsets, and a *different* secret now
        # sits at the previously exempted line. The exemption must follow the
        # content hash, not the line number.
        old_baseline = self._create_baseline(
            PotentialSecret(
                'Hex High Entropy String',
                'file.py',
                self.SECRET_A,
                line_number=5,
                is_secret=False,
            ),
        )
        new_scan = self._create_collection(
            PotentialSecret(
                'Hex High Entropy String',
                'file.py',
                self.SECRET_A,
                line_number=9,
            ),
            PotentialSecret(
                'Hex High Entropy String',
                'file.py',
                self.SECRET_B,
                line_number=5,
            ),
        )

        updated = baseline.update(new_scan, old_baseline)

        moved_secret = self._get_secret(updated, 'file.py', self.SECRET_A)
        assert moved_secret.is_secret is False
        assert moved_secret.line_number == 9

        new_secret = self._get_secret(updated, 'file.py', self.SECRET_B)
        assert new_secret.is_secret is None

    def test_deleted_file_entries_are_dropped(self):
        old_baseline = self._create_baseline(
            PotentialSecret(
                'Hex High Entropy String',
                'kept.py',
                self.SECRET_A,
                line_number=1,
                is_secret=False,
            ),
            PotentialSecret(
                'Hex High Entropy String',
                'deleted.py',
                self.SECRET_B,
                line_number=1,
                is_secret=False,
            ),
        )
        new_scan = self._create_collection(
            PotentialSecret(
                'Hex High Entropy String',
                'kept.py',
                self.SECRET_A,
                line_number=1,
            ),
        )

        updated = baseline.update(new_scan, old_baseline)

        assert updated.files == {'kept.py'}

    def test_new_secrets_are_not_inherited_as_known(self):
        old_baseline = self._create_baseline(
            PotentialSecret(
                'Hex High Entropy String',
                'file.py',
                self.SECRET_A,
                line_number=1,
                is_secret=False,
                is_verified=True,
            ),
        )
        new_scan = self._create_collection(
            PotentialSecret(
                'Hex High Entropy String',
                'file.py',
                self.SECRET_A,
                line_number=1,
            ),
            PotentialSecret(
                'Hex High Entropy String',
                'file.py',
                self.SECRET_B,
                line_number=2,
            ),
        )

        updated = baseline.update(new_scan, old_baseline)

        known_secret = self._get_secret(updated, 'file.py', self.SECRET_A)
        assert known_secret.is_secret is False
        assert known_secret.is_verified is True

        new_secret = self._get_secret(updated, 'file.py', self.SECRET_B)
        assert new_secret.is_secret is None
        assert new_secret.is_verified is False

    @pytest.mark.parametrize(
        'old_label, new_label',
        (
            (False, True),
            (True, False),
        ),
    )
    def test_conflicting_labels_resolve_to_strictest(self, old_label, new_label):
        old_baseline = self._create_baseline(
            PotentialSecret(
                'Hex High Entropy String',
                'file.py',
                self.SECRET_A,
                line_number=1,
                is_secret=old_label,
            ),
        )
        new_scan = self._create_collection(
            PotentialSecret(
                'Hex High Entropy String',
                'file.py',
                self.SECRET_A,
                line_number=1,
                is_secret=new_label,
            ),
        )

        updated = baseline.update(new_scan, old_baseline)

        assert self._get_secret(updated, 'file.py', self.SECRET_A).is_secret is True

    def test_unaudited_old_entries_stay_unaudited(self):
        old_baseline = self._create_baseline(
            PotentialSecret(
                'Hex High Entropy String',
                'file.py',
                self.SECRET_A,
                line_number=1,
            ),
        )
        new_scan = self._create_collection(
            PotentialSecret(
                'Hex High Entropy String',
                'file.py',
                self.SECRET_A,
                line_number=3,
            ),
        )

        updated = baseline.update(new_scan, old_baseline)

        secret = self._get_secret(updated, 'file.py', self.SECRET_A)
        assert secret.is_secret is None
        assert secret.line_number == 3
