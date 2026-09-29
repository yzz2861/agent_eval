# SPDX-License-Identifier: MIT OR Apache-2.0
# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the MIT License.  See the LICENSE file in the root of this
# repository for complete details.

import contextvars
import threading
import time

import pytest

from structlog import AsyncSink, FullPolicy
from structlog.exceptions import BufferFullError, SinkDeliveryError


TIMEOUT = 5.0


class RecordingSink:
    """
    A sink that records delivered messages and can block on / fail specific
    messages.
    """

    def __init__(self, *, delay=0.0, fail_on=()):
        self.calls = []
        self.delay = delay
        self.fail_on = set(fail_on)
        self.gates = {}
        self.blocked_on = threading.Event()
        self._lock = threading.Lock()

    def msg(self, message):
        gate = self.gates.get(message)
        if gate is not None:
            self.blocked_on.set()
            gate.wait(TIMEOUT)

        if self.delay:
            time.sleep(self.delay)

        if message in self.fail_on:
            raise ValueError(f"boom: {message}")

        with self._lock:
            self.calls.append(message)

    log = debug = info = warn = warning = msg
    fatal = failure = err = error = critical = exception = msg

    def recorded(self):
        with self._lock:
            return list(self.calls)


def join(thread, timeout=TIMEOUT):
    thread.join(timeout)
    assert not thread.is_alive()


class TestLifecycle:
    def test_emit_before_start_raises(self):
        sink = AsyncSink(RecordingSink())

        with pytest.raises(RuntimeError, match="not started"):
            sink.msg("hi")

    def test_flush_before_start_raises(self):
        sink = AsyncSink(RecordingSink())

        with pytest.raises(RuntimeError, match="not started"):
            sink.flush()

    def test_double_start_raises(self):
        sink = AsyncSink(RecordingSink())
        sink.start()

        with pytest.raises(RuntimeError, match="already started"):
            sink.start()

        sink.close()

    def test_emit_after_close_raises(self):
        rec = RecordingSink()
        sink = AsyncSink(rec)
        sink.start()
        sink.msg("hi")
        sink.close()

        with pytest.raises(RuntimeError, match="closed"):
            sink.msg("nope")

        assert ["hi"] == rec.recorded()

    def test_close_is_idempotent(self):
        sink = AsyncSink(RecordingSink())
        sink.start()
        sink.close()
        sink.close()

    def test_close_before_start(self):
        sink = AsyncSink(RecordingSink())
        sink.close()

        with pytest.raises(RuntimeError, match="closed"):
            sink.start()

    def test_max_size_must_be_positive(self):
        with pytest.raises(ValueError, match="max_size"):
            AsyncSink(RecordingSink(), max_size=0)

    def test_context_manager(self):
        rec = RecordingSink()

        with AsyncSink(rec) as sink:
            sink.msg("hi")

        assert ["hi"] == rec.recorded()

        with pytest.raises(RuntimeError, match="closed"):
            sink.msg("nope")

    def test_repr(self):
        sink = AsyncSink(RecordingSink(), max_size=3, on_full="drop")

        r = repr(sink)
        assert r.startswith("<AsyncSink(")
        assert "max_size=3" in r
        assert "on_full='drop'" in r


class TestDelivery:
    def test_delivers_in_receive_order(self):
        rec = RecordingSink()

        with AsyncSink(rec) as sink:
            for i in range(100):
                sink.msg(f"e{i}")

        assert [f"e{i}" for i in range(100)] == rec.recorded()

    def test_forwards_method_name_args_kwargs(self):
        class Spy:
            def __init__(self):
                self.calls = []

            def anything(self, *args, **kwargs):
                self.calls.append((args, kwargs))

        spy = Spy()

        with AsyncSink(spy) as sink:
            sink.anything(1, 2, x=3)

        assert [((1, 2), {"x": 3})] == spy.calls

    def test_flush_waits_for_slow_sink(self):
        rec = RecordingSink(delay=0.02)
        sink = AsyncSink(rec)
        sink.start()

        for i in range(10):
            sink.msg(f"e{i}")

        assert sink.pending > 0

        sink.flush()

        assert 10 == len(rec.recorded())
        assert 0 == sink.pending

        sink.close()

    def test_flush_ignores_events_received_after_call(self):
        """
        A flush returns once everything received before the call is
        delivered, even if the worker is stuck on an event that arrived
        later.
        """
        rec = RecordingSink()
        rec.gates["first"] = threading.Event()
        rec.gates["late"] = threading.Event()
        sink = AsyncSink(rec)
        sink.start()

        sink.msg("first")
        sink.msg("second")
        assert rec.blocked_on.wait(TIMEOUT)

        flushed = threading.Event()

        def do_flush():
            sink.flush()
            flushed.set()

        t = threading.Thread(target=do_flush)
        t.start()

        # Give the flush thread ample time to snapshot its watermark
        # before "late" is received.
        time.sleep(0.2)
        sink.msg("late")
        assert not flushed.is_set()

        # Deliver first & second; the worker then gets stuck on "late".
        rec.gates["first"].set()

        join(t)
        assert flushed.is_set()
        assert ["first", "second"] == rec.recorded()

        rec.gates["late"].set()
        sink.close()
        assert ["first", "second", "late"] == rec.recorded()

    def test_contextvars_are_captured_on_producer(self):
        """
        The sink sees the producer's context, not the worker thread's.
        """
        var = contextvars.ContextVar("var", default="unset")
        seen = {}

        class ContextSink:
            def msg(self, message):
                seen["value"] = var.get()
                seen["thread"] = threading.current_thread().name

        var.set("request-123")

        sink = AsyncSink(ContextSink())
        sink.start()
        sink.msg("hello")
        sink.flush()
        var.set("changed-afterwards")
        sink.close()

        assert "request-123" == seen["value"]
        assert "structlog-AsyncSink" == seen["thread"]


class TestFullPolicies:
    @pytest.fixture
    def blocked_sink(self):
        """
        A started AsyncSink (max_size=2) whose worker is stuck on "first"
        behind a cleared gate.
        """
        rec = RecordingSink()
        rec.gates["first"] = threading.Event()
        sink = AsyncSink(rec, max_size=2)
        sink.start()
        sink.msg("first")
        assert rec.blocked_on.wait(TIMEOUT)

        yield sink, rec

        rec.gates["first"].set()
        sink.close()

    def test_wait_blocks_until_space(self, blocked_sink):
        sink, rec = blocked_sink
        sink.msg("e1")
        sink.msg("e2")

        emitted = threading.Event()

        def emit():
            sink.msg("e3")  # buffer is full: must block
            emitted.set()

        t = threading.Thread(target=emit)
        t.start()

        assert not emitted.wait(0.2)

        rec.gates["first"].set()
        join(t)
        sink.close()

        assert ["first", "e1", "e2", "e3"] == rec.recorded()
        assert 0 == sink.dropped

    def test_drop_discards_and_counts(self):
        rec = RecordingSink()
        rec.gates["first"] = threading.Event()
        sink = AsyncSink(rec, max_size=1, on_full=FullPolicy.DROP)
        sink.start()
        sink.msg("first")
        assert rec.blocked_on.wait(TIMEOUT)

        sink.msg("kept")
        sink.msg("dropped1")
        sink.msg("dropped2")

        assert 2 == sink.dropped

        rec.gates["first"].set()
        sink.close()

        assert ["first", "kept"] == rec.recorded()

    def test_raise_reports_full_buffer(self):
        rec = RecordingSink()
        rec.gates["first"] = threading.Event()
        sink = AsyncSink(rec, max_size=1, on_full="raise")
        sink.start()
        sink.msg("first")
        assert rec.blocked_on.wait(TIMEOUT)

        sink.msg("kept")

        with pytest.raises(BufferFullError, match="full"):
            sink.msg("nope")

        rec.gates["first"].set()
        sink.close()

        assert ["first", "kept"] == rec.recorded()


class TestFailures:
    def test_flush_reports_unfinished_sequences_once(self):
        rec = RecordingSink(fail_on={"bad1", "bad2"})
        sink = AsyncSink(rec)
        sink.start()

        sink.msg("ok1")  # seq 1
        sink.msg("bad1")  # seq 2
        sink.msg("ok2")  # seq 3
        sink.msg("bad2")  # seq 4
        sink.msg("ok3")  # seq 5

        with pytest.raises(SinkDeliveryError) as ei:
            sink.flush()

        assert (2, 4) == ei.value.sequences
        assert "[2, 4]" in str(ei.value)
        assert isinstance(ei.value.failures[2], ValueError)
        assert isinstance(ei.value.failures[4], ValueError)

        # Delivery continues past failures ...
        assert ["ok1", "ok2", "ok3"] == rec.recorded()

        # ... and each failure is reported exactly once.
        sink.flush()
        sink.close()

    def test_close_reports_failures(self):
        rec = RecordingSink(fail_on={"bad"})
        sink = AsyncSink(rec)
        sink.start()
        sink.msg("bad")

        with pytest.raises(SinkDeliveryError) as ei:
            sink.close()

        assert (1,) == ei.value.sequences

        # Already reported: closing again is quiet.
        sink.close()


class TestConcurrency:
    def test_concurrent_producers_and_flushers(self):
        rec = RecordingSink(delay=0.001)
        sink = AsyncSink(rec, max_size=20)
        sink.start()

        def produce(n):
            for i in range(50):
                sink.msg(f"p{n}-{i}")

        def flush_repeatedly():
            for _ in range(10):
                sink.flush()

        threads = [
            *[threading.Thread(target=produce, args=(n,)) for n in range(4)],
            *[threading.Thread(target=flush_repeatedly) for _ in range(3)],
        ]
        for t in threads:
            t.start()
        for t in threads:
            join(t, timeout=30)

        sink.close()

        calls = rec.recorded()
        assert 200 == len(calls)
        # Per-producer order is preserved.
        for n in range(4):
            mine = [c for c in calls if c.startswith(f"p{n}-")]
            assert [f"p{n}-{i}" for i in range(50)] == mine

    def test_close_race_with_producers(self):
        """
        Producers racing with close() either get their event delivered or
        get a RuntimeError; nothing is lost or hangs.
        """
        rec = RecordingSink(delay=0.001)
        sink = AsyncSink(rec, max_size=10)
        sink.start()

        accepted = [0] * 4

        def produce(n):
            i = 0
            while True:
                try:
                    sink.msg(f"p{n}-{i}")
                except RuntimeError:
                    return
                accepted[n] += 1
                i += 1

        threads = [
            threading.Thread(target=produce, args=(n,)) for n in range(4)
        ]
        for t in threads:
            t.start()

        time.sleep(0.1)
        sink.close()

        for t in threads:
            join(t)

        assert len(rec.recorded()) == sum(accepted)

    def test_close_drains_and_joins_worker(self):
        rec = RecordingSink(delay=0.01)
        sink = AsyncSink(rec)
        sink.start()

        for i in range(5):
            sink.msg(f"e{i}")

        sink.close()

        assert [f"e{i}" for i in range(5)] == rec.recorded()
        assert not any(
            t.name == "structlog-AsyncSink" for t in threading.enumerate()
        )

    def test_close_wakes_waiting_producer(self):
        """
        A producer blocked on a full buffer is woken by close() with an
        error instead of hanging.
        """
        rec = RecordingSink()
        rec.gates["first"] = threading.Event()
        sink = AsyncSink(rec, max_size=1)
        sink.start()
        sink.msg("first")
        assert rec.blocked_on.wait(TIMEOUT)
        sink.msg("buffered")

        errors = []

        def emit():
            try:
                sink.msg("too-much")  # blocks: buffer full
            except RuntimeError as e:
                errors.append(e)

        t = threading.Thread(target=emit)
        t.start()
        time.sleep(0.2)

        rec.gates["first"].set()
        sink.close()
        join(t)

        assert 1 == len(errors)
        # Everything accepted before close was still delivered.
        assert ["first", "buffered"] == rec.recorded()
