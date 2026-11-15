import os
import re
import shutil
import tempfile
import time

from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.plugins.base import RegexBasedDetector
from detect_secrets.settings import transient_settings
from testing.plugins import register_plugin


class AggregateBrokenDetector(RegexBasedDetector):
    secret_type = 'AggregateBrokenDetector'
    denylist = (re.compile(r"broken-trigger"),)

    def analyze_string(self, string):
        raise RuntimeError('AKIA-AGGREGATE-LEAK should not appear')


class AggregateSlowDetector(RegexBasedDetector):
    secret_type = 'AggregateSlowDetector'
    denylist = (re.compile(r"slow-trigger"),)

    def analyze_string(self, string):
        time.sleep(2)
        yield from super().analyze_string(string)


def _write_file(content):
    handle, name = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(handle, 'w') as f:
        f.write(content)
    return name


class TestPluginErrorAggregation:
    @staticmethod
    def test_errors_recorded_while_secrets_survive():
        filename = _write_file('broken-trigger on this line')
        try:
            with register_plugin(AggregateBrokenDetector()), transient_settings({
                'plugins_used': [{'name': 'AggregateBrokenDetector'}],
                'filters_used': [],
            }):
                secrets = SecretsCollection()
                secrets.scan_file(filename)

            assert secrets.has_plugin_errors
            error = secrets.plugin_errors.errors[0]
            assert error.plugin == 'AggregateBrokenDetector'
            assert error.filename.endswith(os.path.basename(filename))
            assert error.error_type == 'error'
            assert 'AKIA-AGGREGATE-LEAK' not in str(secrets.plugin_errors.errors)
        finally:
            os.unlink(filename)

    @staticmethod
    def test_clean_collection_has_no_errors():
        secrets = SecretsCollection()
        secrets.scan_file('test_data/config.env')
        assert not secrets.has_plugin_errors
        assert len(secrets.plugin_errors.errors) == 0

    @staticmethod
    def test_scan_files_propagates_worker_errors(monkeypatch):
        # Spawned workers cannot see in-memory registered plugins, so load a
        # real importable plugin file (the production custom-plugin path).
        import multiprocessing as mp
        monkeypatch.setattr(mp, 'get_start_method', lambda allow_none=False: 'fork')

        plugin_dir = tempfile.mkdtemp()
        plugin_path = os.path.join(plugin_dir, 'worker_plugin.py')
        with open(plugin_path, 'w') as f:
            f.write(
                chr(10).join([
                    'import re',
                    'from detect_secrets.plugins.base import RegexBasedDetector',
                    'class WorkerBrokenDetector(RegexBasedDetector):',
                    '    secret_type = "WorkerBrokenDetector"',
                    '    denylist = (re.compile(r"broken-trigger"),)',
                    '    def analyze_string(self, string):',
                    '        raise RuntimeError("AKIA-WORKER-LEAK")',
                ]),
            )

        broken_file = _write_file('broken-trigger here')
        clean_file = _write_file('plain content only')
        try:
            with transient_settings({
                'plugins_used': [{
                    'name': 'WorkerBrokenDetector',
                    'path': f'file://{plugin_path}',
                }],
                'filters_used': [],
            }):
                secrets = SecretsCollection()
                secrets.scan_files(broken_file, clean_file, num_processors=2)

            assert secrets.has_plugin_errors
            plugins = {error.plugin for error in secrets.plugin_errors.errors}
            assert plugins == {'WorkerBrokenDetector'}
            affected = {
                os.path.basename(error.filename)
                for error in secrets.plugin_errors.errors
            }
            assert os.path.basename(broken_file) in affected
            assert all(
                'AKIA-WORKER-LEAK' not in str(error)
                for error in secrets.plugin_errors.errors
            )
        finally:
            os.unlink(broken_file)
            os.unlink(clean_file)
            shutil.rmtree(plugin_dir, ignore_errors=True)

    @staticmethod
    def test_timeout_errors_are_distinct(monkeypatch):
        monkeypatch.setenv('DETECT_SECRETS_PLUGIN_TIMEOUT', '0.2')
        filename = _write_file('slow-trigger here')
        try:
            with register_plugin(AggregateSlowDetector()), transient_settings({
                'plugins_used': [{'name': 'AggregateSlowDetector'}],
                'filters_used': [],
            }):
                secrets = SecretsCollection()
                start = time.monotonic()
                secrets.scan_file(filename)
                elapsed = time.monotonic() - start

            assert elapsed < 1.5
            assert secrets.has_plugin_errors
            assert all(
                error.error_type == 'timeout'
                for error in secrets.plugin_errors.errors
            )
        finally:
            os.unlink(filename)
