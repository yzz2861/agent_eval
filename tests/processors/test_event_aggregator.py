# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import threading

import pytest

import structlog

from structlog.exceptions import DropEvent
from structlog.processors import EventAggregator
from structlog.testing import LogCapture


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def exc(exception_type: type[BaseException]) -> tuple[object, object, None]:
    return exception_type, exception_type(), None


def process(
    aggregator: EventAggregator, event_dict: dict[str, object]
) -> dict[str, object]:
    return aggregator(None, "error", event_dict)


def suppress(
    aggregator: EventAggregator, event_dict: dict[str, object]
) -> bool:
    try:
        process(aggregator, event_dict)
    except DropEvent:
        return True
    return False


def test_first_event_is_immediate_and_flush_summary_is_conserved():
    clock = FakeClock()
    aggregator = EventAggregator(window=5, clock=clock)

    first = process(aggregator, {"event": "boom"})

    assert first == {"event": "boom"}
    assert suppress(aggregator, {"event": "boom"})
    assert suppress(aggregator, {"event": "boom"})

    clock.now = 4
    assert suppress(aggregator, {"event": "boom"})

    [summary] = aggregator.flush()

    assert summary["count"] == 4
    assert summary["suppressed_count"] == 3
    assert summary["count"] == 1 + summary["suppressed_count"]
    assert summary["aggregation_reason"] == "flush"


def test_window_end_emits_summary_when_next_event_arrives():
    clock = FakeClock()
    emitted: list[dict[str, object]] = []

    def sink(logger: object, method_name: str, event_dict: dict[str, object]):
        emitted.append(aggregator(logger, method_name, event_dict))

    aggregator = EventAggregator(window=5, clock=clock, emit=sink)

    first = process(aggregator, {"event": "boom"})
    assert suppress(aggregator, {"event": "boom"})

    clock.now = 5
    next_event = process(aggregator, {"event": "other"})

    assert first == {"event": "boom"}
    assert next_event == {"event": "other"}
    assert len(emitted) == 1
    assert emitted[0]["event"] == "boom"
    assert emitted[0]["count"] == 2
    assert emitted[0]["suppressed_count"] == 1
    assert "_structlog_aggregated" not in emitted[0]


def test_window_end_without_emit_waits_for_explicit_flush():
    clock = FakeClock()
    aggregator = EventAggregator(window=5, clock=clock)

    process(aggregator, {"event": "boom"})
    assert suppress(aggregator, {"event": "boom"})

    clock.now = 5
    assert process(aggregator, {"event": "other"}) == {"event": "other"}

    summaries = aggregator.flush()
    assert len(summaries) == 1
    assert summaries[0]["event"] == "boom"
    assert summaries[0]["aggregation_reason"] == "window"


def test_backward_clock_jump_does_not_end_window():
    clock = FakeClock()
    aggregator = EventAggregator(window=5, clock=clock)

    process(aggregator, {"event": "boom"})
    clock.now = 3
    assert suppress(aggregator, {"event": "boom"})
    clock.now = 0
    assert suppress(aggregator, {"event": "boom"})
    clock.now = 4
    assert suppress(aggregator, {"event": "boom"})

    assert aggregator.flush()[0]["suppressed_count"] == 3


def test_identity_uses_exception_type_and_selected_fields_not_repr():
    aggregator = EventAggregator(group_by=("event", "detail"))

    process(
        aggregator,
        {"event": "boom", "detail": ["db"], "request_id": "a"},
    )
    assert suppress(
        aggregator,
        {"event": "boom", "detail": ["db"], "request_id": "b"},
    )
    assert not suppress(
        aggregator,
        {"event": "boom", "detail": ["api"], "request_id": "a"},
    )

    process(aggregator, {"event": "failed", "exc_info": exc(ValueError)})
    assert suppress(
        aggregator, {"event": "failed", "exc_info": exc(ValueError)}
    )
    assert not suppress(
        aggregator, {"event": "failed", "exc_info": exc(TypeError)}
    )


def test_current_exception_is_captured_on_first_event():
    aggregator = EventAggregator()

    try:
        raise ValueError("first")
    except ValueError:
        process(aggregator, {"event": "failed", "exc_info": True})

    assert suppress(
        aggregator, {"event": "failed", "exc_info": exc(ValueError)}
    )

    [summary] = aggregator.flush()
    assert summary["exc_info"][0] is ValueError


def test_request_key_controls_cross_request_merging():
    without_request = EventAggregator()
    process(without_request, {"event": "boom", "request_id": "a"})
    assert suppress(
        without_request, {"event": "boom", "request_id": "b"}
    )

    with_request = EventAggregator(request_key="request_id")
    process(with_request, {"event": "boom", "request_id": "a"})
    assert not suppress(
        with_request, {"event": "boom", "request_id": "b"}
    )
    assert suppress(
        with_request, {"event": "boom", "request_id": "b"}
    )


def test_request_key_need_not_be_added_twice():
    aggregator = EventAggregator(
        group_by=("event", "request_id"), request_key="request_id"
    )

    process(aggregator, {"event": "boom", "request_id": "a"})
    assert not suppress(
        aggregator, {"event": "boom", "request_id": "b"}
    )


def test_log_method_can_be_part_of_identity():
    aggregator = EventAggregator(include_log_method=True)

    aggregator(None, "error", {"event": "boom"})
    with pytest.raises(DropEvent):
        aggregator(None, "error", {"event": "boom"})
    aggregator(None, "warning", {"event": "boom"})


def test_eviction_reports_unreported_count():
    aggregator = EventAggregator(max_groups=1)

    process(aggregator, {"event": "old"})
    assert suppress(aggregator, {"event": "old"})
    process(aggregator, {"event": "new"})

    [summary] = aggregator.flush()

    assert summary["event"] == "old"
    assert summary["count"] == 2
    assert summary["suppressed_count"] == 1
    assert summary["aggregation_reason"] == "evicted"


def test_singleton_eviction_is_silent():
    aggregator = EventAggregator(max_groups=1)

    process(aggregator, {"event": "old"})
    process(aggregator, {"event": "new"})

    assert aggregator.flush() == []


def test_close_reports_then_passes_events_through():
    aggregator = EventAggregator()

    process(aggregator, {"event": "boom"})
    assert suppress(aggregator, {"event": "boom"})

    [summary] = aggregator.close()
    assert summary["count"] == 2

    assert process(aggregator, {"event": "after-close"}) == {
        "event": "after-close"
    }
    assert aggregator.close() == []


def test_explicit_flush_starts_a_new_window():
    aggregator = EventAggregator()

    process(aggregator, {"event": "boom"})
    assert aggregator.flush() == []
    assert not suppress(aggregator, {"event": "boom"})


def test_summary_reentering_chain_is_not_counted_again():
    clock = FakeClock()
    emitted: list[dict[str, object]] = []

    def sink(logger: object, method_name: str, event_dict: dict[str, object]):
        emitted.append(aggregator(logger, method_name, event_dict))

    aggregator = EventAggregator(window=5, clock=clock, emit=sink)
    process(aggregator, {"event": "boom"})
    assert suppress(aggregator, {"event": "boom"})
    aggregator.flush(None)

    assert len(emitted) == 1
    assert emitted[0]["count"] == 2


def test_automatic_summary_runs_through_bound_logger_chain():
    capture = LogCapture()
    aggregator = EventAggregator(window=5, clock=FakeClock())
    log = structlog.wrap_logger(
        None,
        processors=[aggregator, capture],
        wrapper_class=structlog.BoundLogger,
    )
    def emit_summary(logger: object, method_name: str, event_dict: dict):
        event = event_dict.pop("event")
        log._proxy_to_logger(method_name, event, **event_dict)

    aggregator.emit = emit_summary

    log.error("boom")
    log.error("boom")
    aggregator.flush(None, "error")

    assert len(capture.entries) == 2
    assert capture.entries[0]["event"] == "boom"
    assert capture.entries[1]["count"] == 2
    assert capture.entries[1]["suppressed_count"] == 1
    assert "_structlog_aggregated" not in capture.entries[1]


def test_flush_during_emit_does_not_duplicate_summary():
    reentered: list[object] = []

    def sink(logger: object, method_name: str, event_dict: dict[str, object]):
        reentered.append(aggregator.flush(logger, method_name))

    aggregator = EventAggregator(emit=sink)
    process(aggregator, {"event": "boom"})
    assert suppress(aggregator, {"event": "boom"})

    summaries = aggregator.flush(None)

    assert len(summaries) == 1
    assert reentered == [[]]


def test_concurrent_counters_are_conserved():
    thread_count = 8
    repeats = 200
    aggregator = EventAggregator(max_groups=1)
    barrier = threading.Barrier(thread_count)
    suppressed = 0
    immediate = 0
    lock = threading.Lock()

    def worker() -> None:
        nonlocal suppressed, immediate
        barrier.wait()
        for _ in range(repeats):
            try:
                process(aggregator, {"event": "boom"})
            except DropEvent:
                with lock:
                    suppressed += 1
            else:
                with lock:
                    immediate += 1

    threads = [threading.Thread(target=worker) for _ in range(thread_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    summaries = aggregator.close()

    assert immediate == 1
    assert suppressed == thread_count * repeats - 1
    assert sum(summary["suppressed_count"] for summary in summaries) == (
        suppressed
    )
    assert sum(summary["count"] for summary in summaries) + immediate - len(
        summaries
    ) == thread_count * repeats
