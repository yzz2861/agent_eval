# SPDX-License-Identifier: MIT OR Apache-2.0
# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the MIT License.  See the LICENSE file in the root of this
# repository for complete details.

import contextvars
import copy
import gc
import pickle
import sys
import threading
import time

from io import BytesIO, StringIO
from unittest.mock import patch

import pytest

from structlog import (
    BufferedLogger,
    BufferedLoggerClosed,
    BufferedLoggerFactory,
    BufferedSinkError,
    BufferFull,
    BytesLogger,
    BytesLoggerFactory,
    PrintLogger,
    PrintLoggerFactory,
    WriteLogger,
    WriteLoggerFactory,
    wrap_logger,
)
from structlog._output import (
    WRITE_LOCKS,
    FullQueuePolicy,
    stderr,
    stdout,
)
from structlog.contextvars import (
    bind_contextvars,
    clear_contextvars,
    merge_contextvars,
)
from structlog.processors import CallsiteParameter, CallsiteParameterAdder

from .helpers import stdlib_log_methods


@pytest.mark.parametrize(
    ("logger_cls", "mode"),
    [(PrintLogger, "w"), (WriteLogger, "w"), (BytesLogger, "wb")],
)
def test_write_locks_released_on_gc(logger_cls, mode, tmp_path):
    """
    WRITE_LOCKS entry is removed automatically when the file object is GC'd.

    Closing the file is not enough -- the entry persists until the file object
    itself is collected.
    """
    gc.collect()
    size_before = len(WRITE_LOCKS)
    f = (tmp_path / "test.log").open(mode)
    logger = logger_cls(f)

    assert len(WRITE_LOCKS) == size_before + 1

    # close() alone does not remove the entry
    f.close()

    assert len(WRITE_LOCKS) == size_before + 1

    del logger, f
    gc.collect()

    assert len(WRITE_LOCKS) == size_before


class TestLoggers:
    """
    Tests common to the Print and WriteLoggers.
    """

    @pytest.fixture(name="logger_cls", params=(WriteLogger, PrintLogger))
    @staticmethod
    def _logger_cls(request):
        return request.param

    def test_prints_to_stdout_by_default(self, logger_cls, capsys):
        """
        Instantiating without arguments gives conveniently a logger to standard
        out.
        """
        logger_cls().msg("hello")

        out, err = capsys.readouterr()
        assert "hello\n" == out
        assert "" == err

    def test_prints_to_correct_file(self, logger_cls, tmp_path, capsys):
        """
        Supplied files are respected.
        """
        p = tmp_path / "test.log"

        with p.open("w") as f:
            logger_cls(f).msg("hello")
            out, err = capsys.readouterr()

            assert "" == out == err

        assert "hello\n" == p.read_text()

    def test_lock(self, logger_cls, sio):
        """
        Creating a logger adds a lock to WRITE_LOCKS.
        """
        assert sio not in WRITE_LOCKS

        logger_cls(sio)

        assert sio in WRITE_LOCKS

    @pytest.mark.parametrize("method", stdlib_log_methods)
    def test_stdlib_methods_support(self, logger_cls, method, sio):
        """
        Print/WriteLogger implements methods of stdlib loggers.
        """
        getattr(logger_cls(sio), method)("hello")

        assert "hello" in sio.getvalue()

    @pytest.mark.parametrize("file", [None, stdout, stderr])
    @pytest.mark.parametrize("proto", range(pickle.HIGHEST_PROTOCOL + 1))
    def test_pickle(self, logger_cls, file, proto):
        """
        Can be pickled and unpickled for stdout and stderr.

        Can't compare output because capsys et all would confuse the logic.
        """
        pl = logger_cls(file=file)

        rv = pickle.loads(pickle.dumps(pl, proto))

        rv.msg("hello")  # doesn't raise an error

        assert pl._file is rv._file
        assert pl._lock is rv._lock

    @pytest.mark.parametrize("proto", range(pickle.HIGHEST_PROTOCOL + 1))
    def test_pickle_not_stdout_stderr(self, logger_cls, tmp_path, proto):
        """
        Loggers with different files than stdout/stderr raise a
        PickingError.
        """
        f = tmp_path / "file.log"
        f.write_text("")

        with f.open() as file:
            pl = logger_cls(file=file)

            with pytest.raises(
                pickle.PicklingError, match=r"Only (.+)Loggers to"
            ):
                pickle.dumps(pl, proto)

    def test_deepcopy(self, logger_cls, capsys):
        """
        Deepcopied logger works.
        """
        copied_logger = copy.deepcopy(logger_cls())
        copied_logger.msg("hello")

        out, err = capsys.readouterr()
        assert "hello\n" == out
        assert "" == err

    def test_deepcopy_no_stdout(self, logger_cls, tmp_path):
        """
        Only loggers that log to stdout or stderr can be deepcopy-ed.
        """
        p = tmp_path / "log.txt"
        with p.open(mode="w") as f:
            logger = logger_cls(f)
            logger.msg("hello")

            with pytest.raises(copy.error):
                copy.deepcopy(logger)

        assert "hello\n" == p.read_text()

    def test_repr(self, logger_cls):
        """
        __repr__ makes sense.
        """
        assert repr(logger_cls()).startswith(f"<{logger_cls.__name__}(file=")

    def test_stdout_monkeypatch(self, capsys):
        """
        If stdout gets monkeypatched, the new instance receives the output.
        """
        p = PrintLogger()
        new_stdout = StringIO()

        with patch.object(sys, "stdout", new_stdout):
            p.msg("hello")

        out, err = capsys.readouterr()

        assert "hello\n" == new_stdout.getvalue()
        assert "" == out
        assert "" == err


class TestPrintLoggerFactory:
    def test_does_not_cache(self):
        """
        Due to doctest weirdness, we must not reuse PrintLoggers.
        """
        f = PrintLoggerFactory()

        assert f() is not f()

    def test_passes_file(self):
        """
        If a file is passed to the factory, it get passed on to the logger.
        """
        pl = PrintLoggerFactory(stderr)()

        assert stderr is pl._file

    def test_ignores_args(self):
        """
        PrintLogger doesn't take positional arguments.  If any are passed to
        the factory, they are not passed to the logger.
        """
        PrintLoggerFactory()(1, 2, 3)


class TestWriteLoggerFactory:
    def test_does_not_cache(self):
        """
        Due to doctest weirdness, we must not reuse WriteLoggers.
        """
        f = WriteLoggerFactory()

        assert f() is not f()

    def test_passes_file(self):
        """
        If a file is passed to the factory, it get passed on to the logger.
        """
        pl = WriteLoggerFactory(stderr)()

        assert stderr is pl._file

    def test_ignores_args(self):
        """
        WriteLogger doesn't take positional arguments.  If any are passed to
        the factory, they are not passed to the logger.
        """
        WriteLoggerFactory()(1, 2, 3)


class TestBytesLogger:
    def test_prints_to_stdout_by_default(self, capsys):
        """
        Instantiating without arguments gives conveniently a logger to standard
        out.
        """
        BytesLogger().msg(b"hell\xc3\xb6")

        out, err = capsys.readouterr()
        assert "hellö\n" == out
        assert "" == err

    def test_prints_to_correct_file(self, tmp_path, capsys):
        """
        Supplied files are respected.
        """
        p = tmp_path / "test.log"

        with p.open("wb") as f:
            BytesLogger(f).msg(b"hello")
            out, err = capsys.readouterr()

            assert "" == out == err

        assert "hello\n" == p.read_text()

    def test_repr(self):
        """
        __repr__ shows the name if set, otherwise it shows the file.
        """
        assert repr(BytesLogger(name="test")).startswith(
            "<BytesLogger(name='test', file="
        )
        assert repr(BytesLogger()).startswith("<BytesLogger(file=")

    def test_lock(self, sio):
        """
        Creating a logger adds a lock to WRITE_LOCKS.
        """
        assert sio not in WRITE_LOCKS

        BytesLogger(sio)

        assert sio in WRITE_LOCKS

    @pytest.mark.parametrize("method", stdlib_log_methods)
    def test_stdlib_methods_support(self, method):
        """
        BytesLogger implements methods of stdlib loggers.
        """
        sio = BytesIO()

        getattr(BytesLogger(sio), method)(b"hello")

        assert b"hello" in sio.getvalue()

    @pytest.mark.parametrize("file", [None, stdout.buffer, stderr.buffer])
    @pytest.mark.parametrize("proto", range(pickle.HIGHEST_PROTOCOL + 1))
    def test_pickle(self, file, proto):
        """
        Can be pickled and unpickled for stdout and stderr.

        Can't compare output because capsys et all would confuse the logic.
        """
        pl = BytesLogger(file=file)

        rv = pickle.loads(pickle.dumps(pl, proto))

        rv.msg(b"hello")  # doesn't raise an error

        assert pl._file is rv._file
        assert pl._lock is rv._lock
        assert rv.name is None

    @pytest.mark.parametrize("proto", range(pickle.HIGHEST_PROTOCOL + 1))
    def test_pickle_preserves_name(self, proto):
        """
        Pickled and unpickled BytesLoggers preserve their names.
        """
        rv = pickle.loads(pickle.dumps(BytesLogger(name="test_logger"), proto))

        assert "test_logger" == rv.name

    def test_unpickle_from_old_state_sets_name_to_none(self):
        """
        BytesLoggers from old pickles receive the default name.
        """
        logger = object.__new__(BytesLogger)

        logger.__setstate__("stdout")

        assert logger.name is None

    @pytest.mark.parametrize("proto", range(pickle.HIGHEST_PROTOCOL + 1))
    def test_pickle_not_stdout_stderr(self, tmp_path, proto):
        """
        BytesLoggers with different files than stdout/stderr raise a
        PickingError.
        """
        f = tmp_path / "file.log"
        f.write_text("")

        with f.open("rb") as file:
            pl = BytesLogger(file=file)

            with pytest.raises(
                pickle.PicklingError, match="Only BytesLoggers to"
            ):
                pickle.dumps(pl, proto)

    def test_deepcopy(self, capsys):
        """
        Deepcopied BytesLogger works.
        """
        copied_logger = copy.deepcopy(BytesLogger())
        copied_logger.msg(b"hello")

        out, err = capsys.readouterr()
        assert "hello\n" == out
        assert "" == err

    def test_deepcopy_preserves_name(self):
        """
        Deepcopied BytesLoggers preserve their names.
        """
        copied_logger = copy.deepcopy(BytesLogger(name="test_logger"))

        assert "test_logger" == copied_logger.name

    def test_name_attribute(self):
        """
        BytesLogger accepts a name keyword argument.
        """
        bl = BytesLogger(name="test_logger")

        assert "test_logger" == bl.name

    def test_name_defaults_to_none(self):
        """
        BytesLogger name defaults to None when not provided.
        """
        bl = BytesLogger()

        assert bl.name is None

    def test_deepcopy_no_stdout(self, tmp_path):
        """
        Only BytesLoggers that log to stdout or stderr can be deepcopy-ed.
        """
        p = tmp_path / "log.txt"
        with p.open(mode="wb") as f:
            logger = BytesLogger(f)
            logger.msg(b"hello")

            with pytest.raises(copy.error):
                copy.deepcopy(logger)

        assert "hello\n" == p.read_text()


class TestBytesLoggerFactory:
    def test_does_not_cache(self):
        """
        Due to doctest weirdness, we must not reuse BytesLoggers.
        """
        f = BytesLoggerFactory()

        assert f() is not f()

    def test_passes_file(self):
        """
        If a file is passed to the factory, it get passed on to the logger.
        """
        pl = BytesLoggerFactory(stderr)()

        assert stderr is pl._file

    def test_passes_name_from_args(self):
        """
        The first positional argument is used as the logger name.
        """
        bl = BytesLoggerFactory()("my_logger")

        assert "my_logger" == bl.name

    def test_name_defaults_to_none(self):
        """
        If no positional arguments are passed to the factory, the logger
        name defaults to None.
        """
        bl = BytesLoggerFactory()()

        assert bl.name is None

    def test_extra_args_ignored(self):
        """
        Positional arguments beyond the first are silently ignored.
        """
        bl = BytesLoggerFactory()("my_logger", 2, 3)

        assert "my_logger" == bl.name


class BlockingSink:
    def __init__(self):
        self.started = threading.Event()
        self.release = threading.Event()
        self.lock = threading.Lock()
        self.received = []
        self.threads = set()

    def __call__(self, event):
        with self.lock:
            self.threads.add(threading.get_ident())
            self.received.append(event)
            index = len(self.received)

        if index == 1:
            self.started.set()
            self.release.wait(5)


class FailingSink:
    def __init__(self, failures=1):
        self.failures = failures
        self.received = []

    def __call__(self, event):
        self.received.append(event)
        if len(self.received) <= self.failures:
            raise RuntimeError(event)


class TestBufferedLogger:
    def test_capacity_counts_active_and_queued_events(self):
        sink = BlockingSink()
        logger = BufferedLogger(
            sink, capacity=2, full_policy=FullQueuePolicy.RAISE
        )

        try:
            assert 1 == logger.msg("first")
            sink.started.wait(5)
            assert 2 == logger.msg("second")

            with pytest.raises(BufferFull):
                logger.msg("third")
        finally:
            sink.release.set()
            logger.close()

        assert ["first", "second"] == sink.received

    def test_wait_policy_unblocks_in_sequence_order(self):
        sink = BlockingSink()
        logger = BufferedLogger(
            sink, capacity=2, full_policy=FullQueuePolicy.WAIT
        )
        delivered = threading.Event()

        def produce():
            logger.msg("third")
            delivered.set()

        try:
            logger.msg("first")
            sink.started.wait(5)
            logger.msg("second")
            producer = threading.Thread(target=produce)
            producer.start()
            assert not delivered.wait(0.05)
            sink.release.set()
            producer.join(5)
            assert not producer.is_alive()
            logger.flush()
        finally:
            sink.release.set()
            logger.close()

        assert ["first", "second", "third"] == sink.received

    def test_context_manager_closes_and_drains(self):
        sink = []

        with BufferedLogger(sink.append, capacity=1) as logger:
            sequence = logger.msg("hello")
            assert 1 == sequence

        assert ["hello"] == sink

    def test_factory_shares_lifecycle_between_bound_loggers(self):
        sink = []
        factory = BufferedLoggerFactory(sink.append, capacity=1)

        assert factory() is factory()
        factory().msg("first")
        assert 1 == factory.flush()
        factory.close()

        with pytest.raises(BufferedLoggerClosed):
            factory().msg("second")
        assert ["first"] == sink

    def test_drop_policy_does_not_block_and_preserves_sequence_gap(self):
        sink = BlockingSink()
        logger = BufferedLogger(
            sink, capacity=2, full_policy=FullQueuePolicy.DROP
        )

        try:
            assert 1 == logger.msg("first")
            sink.started.wait(5)
            assert 2 == logger.msg("second")
            assert logger.msg("dropped") is None
            sink.release.set()
            assert 2 == logger.flush()
        finally:
            sink.release.set()
            logger.close()

        assert ["first", "second"] == sink.received

    def test_flush_waits_only_for_events_received_when_called(self):
        sink = BlockingSink()
        logger = BufferedLogger(sink, capacity=4)
        flushed = threading.Event()

        def flush_first_two():
            logger.flush()
            flushed.set()

        try:
            logger.msg("first")
            sink.started.wait(5)
            logger.msg("second")
            flusher = threading.Thread(target=flush_first_two)
            flusher.start()
            assert not flushed.wait(0.05)
            logger.msg("third")
            sink.release.set()
            flusher.join(5)
            assert not flusher.is_alive()
            assert flushed.is_set()
            logger.flush()
        finally:
            sink.release.set()
            logger.close()

        assert ["first", "second", "third"] == sink.received

    def test_concurrent_flushers_all_return_after_current_events(self):
        sink = BlockingSink()
        logger = BufferedLogger(sink, capacity=8)
        barrier = threading.Barrier(8)
        errors = []

        def flush():
            barrier.wait(5)
            try:
                logger.flush()
            except BaseException as exc:
                errors.append(exc)

        try:
            logger.msg("first")
            sink.started.wait(5)
            for index in range(6):
                logger.msg(f"queued-{index}")

            flushers = [threading.Thread(target=flush) for _ in range(8)]
            for thread in flushers:
                thread.start()

            sink.release.set()
            for thread in flushers:
                thread.join(5)
                assert not thread.is_alive()
        finally:
            sink.release.set()
            logger.close()

        assert [] == errors
        assert "first" == sink.received[0]

    def test_close_rejects_new_events_and_drains_remaining(self):
        sink = BlockingSink()
        logger = BufferedLogger(sink, capacity=4)

        try:
            logger.msg("first")
            sink.started.wait(5)
            logger.msg("second")
            closer = threading.Thread(target=logger.close)
            closer.start()
            closer.join(0.05)
            assert closer.is_alive()
            with pytest.raises(BufferedLoggerClosed):
                logger.msg("third")
            sink.release.set()
            closer.join(5)
            assert not closer.is_alive()
            logger.close()
        finally:
            sink.release.set()

        assert ["first", "second"] == sink.received

    def test_close_wakes_waiting_full_producer(self):
        sink = BlockingSink()
        logger = BufferedLogger(sink, capacity=2)
        outcome = []

        def produce():
            try:
                logger.msg("third")
            except BaseException as exc:
                outcome.append(exc)

        try:
            logger.msg("first")
            sink.started.wait(5)
            logger.msg("second")
            producer = threading.Thread(target=produce)
            producer.start()
            while logger._waiting_producers == 0:
                time.sleep(0.001)
            closer = threading.Thread(target=logger.close)
            closer.start()
            producer.join(5)
            assert not producer.is_alive()
            assert BufferedLoggerClosed is type(outcome[0])
            sink.release.set()
            closer.join(5)
            assert not closer.is_alive()
        finally:
            sink.release.set()

        assert ["first", "second"] == sink.received

    def test_sink_failure_reports_failed_and_blocked_sequences(self):
        sink = FailingSink(failures=10)
        logger = BufferedLogger(
            sink, capacity=4, full_policy=FullQueuePolicy.RAISE
        )

        logger.msg("first")
        logger.msg("second")
        logger.msg("third")
        while not logger._failed:
            time.sleep(0.001)

        with pytest.raises(BufferedSinkError) as exc_info:
            logger.flush()

        assert 1 == exc_info.value.failed_sequence
        assert (1, 2, 3) == exc_info.value.unfinished_sequences
        assert isinstance(exc_info.value.exceptions[1], RuntimeError)

        with pytest.raises(BufferedSinkError):
            logger.msg("fourth")

        with pytest.raises(BufferedSinkError):
            logger.close()

        sink.failures = 0
        logger.close()
        assert "first" in sink.received
        assert "second" in sink.received
        assert "third" in sink.received

    def test_context_is_captured_from_producer(self):
        variable = contextvars.ContextVar("request_id")
        captured = []

        def sink(event):
            captured.append((event, variable.get(None), threading.get_ident()))

        logger = BufferedLogger(sink, capacity=1)

        def produce():
            variable.set("request-1")
            logger.msg("hello")

        producer = threading.Thread(target=produce)
        producer.start()
        producer.join(5)
        logger.close()

        assert [("hello", "request-1", logger._thread.ident)] == captured

    def test_callsite_information_is_captured_from_producer(self):
        captured = []

        def sink(**event):
            captured.append(event)

        buffered = BufferedLogger(sink, capacity=1)
        logger = wrap_logger(
            buffered,
            processors=[
                CallsiteParameterAdder(
                    [CallsiteParameter.LINENO, CallsiteParameter.THREAD]
                )
            ],
        )
        expected_lineno = sys._getframe().f_lineno + 1
        logger.info("hello")
        buffered.close()

        assert expected_lineno == captured[0]["lineno"]
        assert threading.get_ident() == captured[0]["thread"]

    def test_contextvar_merge_runs_before_background_delivery(self):
        captured = []

        def sink(**event):
            captured.append(event)

        bind_contextvars(request_id="bound")
        buffered = BufferedLogger(sink, capacity=1)
        logger = wrap_logger(
            buffered,
            processors=[merge_contextvars],
        )

        logger.info("hello")
        buffered.close()

        assert "bound" == captured[0]["request_id"]
        clear_contextvars()
