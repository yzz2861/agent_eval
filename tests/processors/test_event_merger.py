# SPDX-License-Identifier: MIT OR Apache-2.0
# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the MIT License.  See the LICENSE file in the root of this
# repository for complete details.

from __future__ import annotations

import threading

import pytest

import structlog

from structlog.exceptions import DropEvent
from structlog.processors import EventMerger
from structlog.testing import CapturingLoggerFactory


class FakeClock:
    """
    A manually advanced clock for deterministic window control.
    """

    def __init__(self, start=1_000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def passes(merger, event_dict, method_name="info"):
    """
    Return True if *event_dict* passes through *merger*, False if dropped.
    """
    try:
        result = merger(None, method_name, event_dict)
    except DropEvent:
        return False

    assert result is event_dict

    return True


@pytest.fixture(name="clock")
def _clock():
    return FakeClock()


@pytest.fixture(name="summaries")
def _summaries():
    return []


@pytest.fixture(name="make_merger")
def _make_merger(clock, summaries):
    def factory(**kw):
        kw.setdefault("window", 10.0)
        kw.setdefault("clock", clock)
        kw.setdefault(
            "emit",
            lambda method_name, event_dict: summaries.append(
                (method_name, event_dict)
            ),
        )

        return EventMerger(**kw)

    return factory


@pytest.fixture(name="merger")
def _merger(make_merger):
    return make_merger()


def suppressed(summaries):
    return [event_dict["suppressed"] for _, event_dict in summaries]


class TestEventMerger:
    def test_first_event_passes_through_immediately(self, merger, summaries):
        """
        The first occurrence of an identity is returned unchanged and no
        summary exists yet.
        """
        event_dict = {"event": "boom"}

        assert passes(merger, event_dict)
        assert [] == summaries

    def test_duplicate_within_window_is_dropped(self, merger, summaries):
        """
        Repetitions within the window raise DropEvent without emitting
        anything.
        """
        assert passes(merger, {"event": "boom"})
        assert not passes(merger, {"event": "boom"})
        assert not passes(merger, {"event": "boom"})

        assert [] == summaries

    def test_summary_at_window_end_and_conservation(
        self, merger, clock, summaries
    ):
        """
        When the window ends, the next event passes again and a summary with
        the suppressed count is emitted. First events plus suppressed counts
        equal the total number of events.
        """
        total = passed = 0
        for _ in range(3):
            for _ in range(5):
                total += 1
                passed += passes(merger, {"event": "boom"})
            clock.advance(11)

        merger.flush()

        assert 3 == passed
        assert [4, 4, 4] == suppressed(summaries)
        assert total == passed + sum(suppressed(summaries))

        method_name, summary = summaries[0]
        assert "info" == method_name
        assert "event_merger.summary" == summary["event"]
        assert {"event": "boom"} == summary["identity"]
        assert 10.0 == summary["window"]

    def test_summary_uses_method_of_first_event(self, merger, summaries):
        """
        The summary is emitted using the log method of the group's first
        event.
        """
        merger(None, "warning", {"event": "boom"})
        with pytest.raises(DropEvent):
            merger(None, "error", {"event": "boom"})

        merger.flush()

        assert "warning" == summaries[0][0]

    def test_flush_emits_pending_counts_once(self, merger, summaries):
        """
        flush() reports pending counts; a second flush has nothing to report.
        """
        passes(merger, {"event": "boom"})
        passes(merger, {"event": "boom"})

        merger.flush()

        assert [1] == suppressed(summaries)

        merger.flush()

        assert [1] == suppressed(summaries)

    def test_flush_starts_a_new_window(self, merger, summaries):
        """
        After flush(), the next occurrence is a first event again.
        """
        passes(merger, {"event": "boom"})
        passes(merger, {"event": "boom"})

        merger.flush()

        assert passes(merger, {"event": "boom"})
        assert [1] == suppressed(summaries)

    def test_group_without_duplicates_emits_no_summary(
        self, merger, summaries
    ):
        """
        Groups that saw no repetitions don't produce noise on flush().
        """
        passes(merger, {"event": "boom"})

        merger.flush()

        assert [] == summaries

    def test_different_events_do_not_merge(self, merger):
        """
        Different values of the identity keys form separate groups.
        """
        assert passes(merger, {"event": "a"})
        assert passes(merger, {"event": "b"})

    def test_request_scoped_fields_merge_by_default(self, merger):
        """
        Without request_id in keys, events from different requests merge.
        """
        assert passes(merger, {"event": "boom", "request_id": "1"})
        assert not passes(merger, {"event": "boom", "request_id": "2"})

    def test_request_scoped_fields_separate_if_configured(
        self, make_merger, summaries
    ):
        """
        Adding request_id to keys keeps different requests apart and reports
        the field in the summary identity.
        """
        merger = make_merger(keys=("event", "request_id"))

        assert passes(merger, {"event": "boom", "request_id": "1"})
        assert passes(merger, {"event": "boom", "request_id": "2"})
        assert not passes(merger, {"event": "boom", "request_id": "1"})

        merger.flush()

        assert [1] == suppressed(summaries)
        assert {"event": "boom", "request_id": "1"} == summaries[0][1][
            "identity"
        ]

    def test_exception_type_is_part_of_identity(self, merger):
        """
        Same event but different exception types don't merge.
        """
        assert passes(merger, {"event": "boom", "exc_info": ValueError("x")})
        assert passes(merger, {"event": "boom", "exc_info": KeyError("x")})

    def test_same_exception_type_merges_regardless_of_message(
        self, merger, summaries
    ):
        """
        Identity is based on the exception type, not its repr, so different
        messages of the same type still merge.
        """
        assert passes(merger, {"event": "boom", "exc_info": ValueError("x")})
        assert not passes(
            merger, {"event": "boom", "exc_info": ValueError("y")}
        )

        merger.flush()

        assert [1] == suppressed(summaries)
        assert "ValueError" == summaries[0][1]["identity"]["exc_type"]

    def test_exc_info_true_uses_current_exception(self, merger):
        """
        exc_info=True resolves to the currently handled exception's type.
        """
        try:
            raise ValueError("x")
        except ValueError:
            assert passes(merger, {"event": "boom", "exc_info": True})
            assert not passes(merger, {"event": "boom", "exc_info": True})

    def test_exc_info_can_be_excluded_from_identity(self, make_merger):
        """
        include_exc_info=False merges events with different exceptions.
        """
        merger = make_merger(include_exc_info=False)

        assert passes(merger, {"event": "boom", "exc_info": ValueError("x")})
        assert not passes(merger, {"event": "boom", "exc_info": KeyError("x")})

    def test_unhashable_field_values_merge_by_repr(self, make_merger):
        """
        Unhashable identity field values are compared by their repr.
        """
        merger = make_merger(keys=("event", "ctx"))

        assert passes(merger, {"event": "boom", "ctx": {"a": 1}})
        assert not passes(merger, {"event": "boom", "ctx": {"a": 1}})
        assert passes(merger, {"event": "boom", "ctx": {"a": 2}})

    def test_max_groups_eviction_reports_pending_count(
        self, make_merger, clock, summaries
    ):
        """
        When max_groups is exceeded, the group closest to its window end is
        evicted and its pending count is reported immediately.
        """
        merger = make_merger(window=100.0, max_groups=2)

        passes(merger, {"event": "a"})
        passes(merger, {"event": "a"})
        clock.advance(1)
        passes(merger, {"event": "b"})
        clock.advance(1)

        assert [] == summaries

        passes(merger, {"event": "c"})

        assert [1] == suppressed(summaries)
        assert {"event": "a"} == summaries[0][1]["identity"]

    def test_eviction_without_pending_count_is_silent(
        self, make_merger, summaries
    ):
        """
        Evicting a group that saw no repetitions emits nothing.
        """
        merger = make_merger(max_groups=1)

        passes(merger, {"event": "a"})
        passes(merger, {"event": "b"})

        assert [] == summaries

    def test_close_flushes_and_is_idempotent(self, merger, summaries):
        """
        close() reports pending counts exactly once, even if called twice.
        """
        passes(merger, {"event": "boom"})
        passes(merger, {"event": "boom"})

        merger.close()

        assert [1] == suppressed(summaries)

        merger.close()
        merger.flush()

        assert [1] == suppressed(summaries)

    def test_events_pass_through_after_close(self, merger, summaries):
        """
        A closed merger neither counts nor drops anything.
        """
        merger.close()

        assert passes(merger, {"event": "boom"})
        assert passes(merger, {"event": "boom"})
        assert [] == summaries

    def test_context_manager_closes(self, make_merger, summaries):
        """
        The merger can be used as a context manager that closes on exit.
        """
        with make_merger() as merger:
            passes(merger, {"event": "boom"})
            passes(merger, {"event": "boom"})

        assert [1] == suppressed(summaries)

    def test_summary_reentry_is_not_counted(self, merger, summaries):
        """
        An event dict marked as a summary passes through uncounted and the
        marker is removed, so summaries re-entering the chain neither merge
        nor leak the marker downstream.
        """
        event_dict = {
            "event": "event_merger.summary",
            "suppressed": 5,
            "_structlog_event_merger_summary": True,
        }

        result = merger(None, "info", event_dict)

        assert {"event": "event_merger.summary", "suppressed": 5} == result

        merger.flush()

        assert [] == summaries

    def test_clock_jump_backwards_does_not_double_count(
        self, merger, clock, summaries
    ):
        """
        A backwards clock jump prolongs the current window instead of
        expiring groups early or counting events twice.
        """
        passes(merger, {"event": "boom"})
        passes(merger, {"event": "boom"})

        clock.advance(20)
        clock.advance(-30)

        assert not passes(merger, {"event": "boom"})
        assert [] == summaries

        clock.advance(25)

        assert passes(merger, {"event": "boom"})
        assert [2] == suppressed(summaries)

    def test_threads_conserve_counts(self, make_merger, summaries):
        """
        Under concurrency, exactly one first event passes and every other
        event is accounted for in the summaries.
        """
        merger = make_merger(window=10_000.0)
        thread_count, events_per_thread = 8, 500
        barrier = threading.Barrier(thread_count)
        passed = []
        passed_lock = threading.Lock()

        def worker():
            barrier.wait()
            local = 0
            for _ in range(events_per_thread):
                local += passes(merger, {"event": "boom"})
            with passed_lock:
                passed.append(local)

        threads = [
            threading.Thread(target=worker) for _ in range(thread_count)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        merger.flush()

        assert 1 == sum(passed)
        assert thread_count * events_per_thread == sum(passed) + sum(
            suppressed(summaries)
        )

    def test_summary_reenters_configured_chain(self, clock):
        """
        With the default emit, summaries re-enter the configured processor
        chain via structlog.get_logger() and are not merged again.
        """
        merger = EventMerger(window=10.0, clock=clock)
        factory = CapturingLoggerFactory()
        structlog.configure(
            processors=[merger],
            logger_factory=factory,
            cache_logger_on_first_use=False,
        )
        log = structlog.get_logger()

        log.info("boom")
        log.info("boom")
        log.info("boom")
        clock.advance(11)
        log.info("boom")

        calls = factory.logger.calls

        assert 3 == len(calls)
        assert "boom" == calls[0].kwargs["event"]
        assert "boom" == calls[2].kwargs["event"]

        summary_call = calls[1]
        assert "info" == summary_call.method_name
        assert "event_merger.summary" == summary_call.kwargs["event"]
        assert 2 == summary_call.kwargs["suppressed"]
        assert {"event": "boom"} == summary_call.kwargs["identity"]
        assert "_structlog_event_merger_summary" not in summary_call.kwargs

    def test_window_must_be_positive(self):
        """
        A non-positive window is rejected.
        """
        with pytest.raises(ValueError, match="window"):
            EventMerger(window=0)

    def test_max_groups_must_be_at_least_one(self):
        """
        max_groups below 1 is rejected.
        """
        with pytest.raises(ValueError, match="max_groups"):
            EventMerger(max_groups=0)
