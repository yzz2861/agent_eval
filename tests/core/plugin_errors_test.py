import time

from detect_secrets.core import plugin_errors as pe
from detect_secrets.core.plugin_errors import PluginErrorSink
from detect_secrets.core.plugin_errors import PluginMemoryLimitError
from detect_secrets.core.plugin_errors import PluginTimeoutError
from detect_secrets.core.plugin_errors import plugin_error_context
from detect_secrets.core.plugin_errors import run_plugin


SECRET = "AKIA-SECRET-MUST-NOT-LEAK-1234567890"


class TestRunPlugin:
    @staticmethod
    def test_returns_result_on_success():
        with plugin_error_context() as sink:
            result = run_plugin('Good', lambda: 42, filename='f.txt')
        assert result == 42
        assert not sink.errors

    @staticmethod
    def test_isolates_exception_and_records_file_and_plugin():
        def broken():
            raise RuntimeError(f'boom: {SECRET}')

        with plugin_error_context() as sink:
            result = run_plugin('Broken', broken, filename='config/env', line_number=9)

        assert result is None
        assert len(sink.errors) == 1
        error = sink.errors[0]
        assert error.plugin == 'Broken'
        assert error.filename == 'config/env'
        assert error.line_number == 9
        assert error.error_type == 'error'

    @staticmethod
    def test_exception_text_is_never_recorded(mock_log):
        def broken():
            raise RuntimeError(f'boom: {SECRET}')

        with plugin_error_context() as sink:
            run_plugin('Broken', broken, filename='f')

        serialized = str(sink.errors)
        logged = mock_log.messages.get("error", "")
        assert SECRET not in serialized
        assert SECRET not in logged

    @staticmethod
    def test_sibling_calls_keep_running_after_failure():
        calls = []

        def broken():
            raise ValueError('boom')

        def working():
            calls.append('ran')
            return 'ok'

        with plugin_error_context() as sink:
            assert run_plugin('Broken', broken, filename='f') is None
            assert run_plugin('Working', working, filename='f') == 'ok'

        assert calls == ["ran"]
        assert len(sink.errors) == 1


class TestTimeout:
    @staticmethod
    def test_timeout_is_distinct_error(monkeypatch):
        monkeypatch.setenv('DETECT_SECRETS_PLUGIN_TIMEOUT', '0.2')

        def slow():
            time.sleep(2)

        with plugin_error_context() as sink:
            start = time.monotonic()
            result = run_plugin('Slow', slow, filename='f')
            elapsed = time.monotonic() - start

        assert result is None
        assert elapsed < 1.5
        assert len(sink.errors) == 1
        assert sink.errors[0].error_type == 'timeout'
        assert sink.errors[0].plugin == 'Slow'

    @staticmethod
    def test_completed_call_is_not_a_timeout(monkeypatch):
        monkeypatch.setenv('DETECT_SECRETS_PLUGIN_TIMEOUT', '5')
        with plugin_error_context() as sink:
            assert run_plugin('Fast', lambda: 1, filename='f') == 1
        assert not sink.errors

    @staticmethod
    def test_invalid_timeout_env_is_ignored(monkeypatch):
        monkeypatch.setenv('DETECT_SECRETS_PLUGIN_TIMEOUT', 'not-a-number')
        with plugin_error_context() as sink:
            assert run_plugin('Fast', lambda: 1, filename='f') == 1
        assert not sink.errors


class TestMemoryLimit:
    @staticmethod
    def test_memory_breach_is_distinct_error(monkeypatch):
        monkeypatch.setenv('DETECT_SECRETS_PLUGIN_MEMORY_LIMIT', '1024')
        monkeypatch.setattr(pe, '_memory_usage_probe', lambda: 2048)

        with plugin_error_context() as sink:
            result = run_plugin('Hungry', lambda: 'x', filename='f')

        assert result is None
        assert len(sink.errors) == 1
        assert sink.errors[0].error_type == 'memory'

    @staticmethod
    def test_under_budget_runs_normally(monkeypatch):
        monkeypatch.setenv('DETECT_SECRETS_PLUGIN_MEMORY_LIMIT', '4096')
        monkeypatch.setattr(pe, '_memory_usage_probe', lambda: 1024)
        with plugin_error_context() as sink:
            assert run_plugin('Fine', lambda: 'x', filename='f') == 'x'
        assert not sink.errors

    @staticmethod
    def test_memory_error_exception_is_classified(monkeypatch):
        monkeypatch.delenv('DETECT_SECRETS_PLUGIN_MEMORY_LIMIT', raising=False)

        def blow_up():
            raise MemoryError("cannot allocate")

        with plugin_error_context() as sink:
            assert run_plugin('Boom', blow_up, filename='f') is None
        assert sink.errors[0].error_type == "memory"


class TestSink:
    @staticmethod
    def test_error_type_classification():
        sink = PluginErrorSink()
        sink.record('f', 'P', PluginTimeoutError('x'))
        sink.record('f', 'P', PluginMemoryLimitError('x'))
        sink.record('f', 'P', ValueError('x'))
        assert [e.error_type for e in sink.errors] == [
            'timeout', 'memory', 'error',
        ]

    @staticmethod
    def test_empty_sink_is_falsy_but_usable():
        sink = PluginErrorSink()
        assert not sink
        sink.record("f", "P", ValueError("x"))
        assert sink
        assert len(sink) == 1

    @staticmethod
    def test_context_resets_sink():
        outer = PluginErrorSink()
        with plugin_error_context(outer) as sink:
            assert sink is outer
            assert pe.get_plugin_error_sink() is outer
        assert pe.get_plugin_error_sink() is None
        assert len(outer) == 0
