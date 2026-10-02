from __future__ import annotations

import time

import dramatiq
from dramatiq.brokers.stub import StubBroker
from dramatiq.worker import ReadyQueue, _WorkQueueItem


MS = 1_000_000  # one millisecond, expressed in the queue's nanosecond clock.


class FakeClock:
    """A controllable monotonic nanosecond clock."""

    def __init__(self) -> None:
        self.now = 0

    def __call__(self) -> int:
        return self.now

    def advance(self, milliseconds: int) -> None:
        self.now += milliseconds * MS


def make_queue(clk: FakeClock, *, max_priority: int = 10, age_enabled: bool = True, interval_ms: int = 1) -> ReadyQueue:
    return ReadyQueue(
        max_priority=max_priority,
        age_enabled=age_enabled,
        age_interval_ns=interval_ms * MS,
        clock=clk,
    )


def item(priority: int, label: object) -> _WorkQueueItem:
    return _WorkQueueItem(priority=priority, message=label, _queued_time=0)  # type: ignore[arg-type]


def drain(queue: ReadyQueue) -> list[object]:
    return [entry.message for entry in queue.drain()]


def pop(queue: ReadyQueue) -> object:
    return queue.get_nowait().message


def test_disabled_compensation_keeps_static_priority_order() -> None:
    clk = FakeClock()
    queue = make_queue(clk, age_enabled=False)

    queue.put(item(5, "low"))
    queue.put(item(0, "high"))
    queue.put(item(2, "mid"))

    # Even after the low-priority message has waited a very long time it is
    # never promoted when compensation is disabled: the original behaviour is
    # preserved.
    clk.advance(10_000)

    assert pop(queue) == "high"
    assert pop(queue) == "mid"
    assert pop(queue) == "low"


def test_fifo_order_is_kept_for_equal_static_priority() -> None:
    clk = FakeClock()
    queue = make_queue(clk, age_enabled=False)

    for label in range(5):
        queue.put(item(3, label))

    assert drain(queue) == [0, 1, 2, 3, 4]


def test_waiting_raises_effective_priority_under_a_fixed_clock() -> None:
    clk = FakeClock()
    queue = make_queue(clk, max_priority=10)

    # A low-priority message becomes ready at t=0.
    queue.put(item(10, "low"))

    # Before enough time passes, a freshly-enqueued high-priority message
    # still runs first.
    queue.put(item(0, "fresh-high"))
    assert pop(queue) == "fresh-high"

    # The low message has waited exactly 9ms -> effective priority 1.
    clk.advance(9)
    queue.put(item(0, "new-high"))
    # Priority 0 (new-high) still beats effective priority 1 (low).
    assert pop(queue) == "new-high"

    # After one more millisecond the low message has waited 10ms in total,
    # reaching effective priority 0.  It is now as urgent as a fresh
    # priority-0 message and, being older, runs first.
    clk.advance(1)
    queue.put(item(0, "another-new-high"))
    assert pop(queue) == "low"
    assert pop(queue) == "another-new-high"


def test_equal_effective_priority_keeps_enqueue_order_across_buckets() -> None:
    clk = FakeClock()
    queue = make_queue(clk, max_priority=10)

    # Both enqueued at t=0.  After 2ms the priority-2 message has effective
    # priority 0, the same as the genuinely high-priority message.
    queue.put(item(0, "high-a"))
    queue.put(item(2, "aged-b"))
    queue.put(item(0, "high-c"))

    clk.advance(2)

    # All three now have effective priority 0, so strict enqueue (FIFO)
    # order applies even though they live in different buckets.
    assert pop(queue) == "high-a"
    assert pop(queue) == "aged-b"
    assert pop(queue) == "high-c"


def test_continuous_high_priority_stream_cannot_starve_enqueued_message() -> None:
    clk = FakeClock()
    queue = make_queue(clk, max_priority=2)

    # The victim low-priority message is enqueued first, at t=0.
    queue.put(item(2, "low"))

    # Simulate a worker that keeps taking work while brand-new
    # high-priority messages keep arriving.
    taken: list[object] = []
    for arrival in range(6):
        clk.advance(1)
        queue.put(item(0, f"high-{arrival}"))
        taken.append(pop(queue))

    # The low message reaches effective priority 0 after 2ms, i.e. on the
    # second arrival, where it is older than the fresh high-priority message
    # and therefore runs first.
    assert "low" in taken
    assert taken.index("low") == 1


def test_effective_priority_never_drops_below_zero() -> None:
    clk = FakeClock()
    queue = make_queue(clk, max_priority=2)

    queue.put(item(2, "old-low"))
    # Age it far beyond the time needed to reach priority 0.
    clk.advance(100)

    # A fresh priority-0 message ties with the now-ceilinged low message at
    # effective priority 0; enqueue order lets the older message win, but a
    # genuinely still-higher priority cannot exist below 0.
    queue.put(item(0, "fresh-zero"))
    queue.put(item(1, "fresh-one"))

    assert pop(queue) == "old-low"
    assert pop(queue) == "fresh-zero"
    assert pop(queue) == "fresh-one"


def test_wait_clock_starts_when_message_becomes_ready() -> None:
    clk = FakeClock()
    queue = make_queue(clk, max_priority=2)

    # Time spent *before* entering the ready queue (e.g. sitting in a delay
    # queue waiting for its ETA) must not count: the clock starts at put()
    # time, not earlier.
    clk.advance(50)
    queue.put(item(2, "just-ready"))

    # Only 1ms of *ready* waiting has accrued, so effective priority is 1,
    # not the 0 it would be if the pre-ready 50ms had been counted.
    clk.advance(1)
    queue.put(item(0, "fresh-high"))
    assert pop(queue) == "fresh-high"
    assert pop(queue) == "just-ready"


def test_requeued_message_restarts_its_wait_clock() -> None:
    clk = FakeClock()
    queue = make_queue(clk, max_priority=2)

    queue.put(item(2, "returned"))
    clk.advance(2)
    # The message had aged all the way to effective priority 0...
    aged = queue.get_nowait()

    # ...but when it is re-enqueued (retry / requeue) it is a fresh entry,
    # so its waiting time starts over from zero.
    queue.put(aged)
    queue.put(item(0, "fresh-high"))
    assert pop(queue) == "fresh-high"

    clk.advance(1)
    queue.put(item(0, "later-high"))
    # After only 1ms back in the queue its effective priority is 1, so the
    # fresh priority-0 message still wins.
    assert pop(queue) == "later-high"
    assert pop(queue) == "returned"


def test_queue_does_not_reorder_bucket_contents() -> None:
    """Taking a promoted message must not disturb the stored FIFO buckets.

    The queue is selected from bucket heads only; removing one item leaves
    the relative enqueue order of every other item untouched.
    """

    clk = FakeClock()
    queue = make_queue(clk, max_priority=2)

    queue.put(item(2, "low-0"))
    queue.put(item(2, "low-1"))
    clk.advance(2)
    queue.put(item(0, "high"))

    # low-0 is promoted to effective priority 0 and, being oldest, wins.
    assert pop(queue) == "low-0"

    # The remaining priority-2 bucket is untouched and still FIFO.
    bucket = queue._buckets[2]
    assert [entry.item.message for entry in bucket] == ["low-1"]


def test_worker_promotes_waiting_messages_with_compensation_enabled() -> None:
    """End-to-end (stub broker) check that waiting lifts low-priority work.

    A single worker thread pauses while messages accumulate in the local
    ready queue; after a short wait the low-priority message should have
    been lifted above freshly-arrived, otherwise-identical high-priority
    work (it ties at effective priority 0 and wins by FIFO).
    """

    broker = StubBroker()
    broker.emit_after("process_boot")
    try:
        results: list[str] = []

        @dramatiq.actor(broker=broker, priority=0)
        def high() -> None:
            results.append("high")

        @dramatiq.actor(broker=broker, priority=2)
        def low() -> None:
            results.append("low")

        # One level of boost per 50ms.
        worker = dramatiq.Worker(
            broker,
            worker_threads=1,
            priority_age_enabled=True,
            priority_age_interval_ms=50,
        )
        worker.queue_prefetch = 20
        worker.start()
        try:
            for worker_thread in worker.workers:
                worker_thread.pause()
                worker_thread.paused_event.wait()

            low.send()
            # Give the consumer time to pull the message onto the ready
            # queue before the clock starts mattering.
            deadline = time.monotonic() + 2
            while worker.work_queue.qsize() < 1 and time.monotonic() < deadline:
                time.sleep(0.005)
            assert worker.work_queue.qsize() == 1

            # Wait long enough for the priority-2 message to reach
            # effective priority 0 (2 * 50ms).
            time.sleep(0.15)
            high.send()
            deadline = time.monotonic() + 2
            while worker.work_queue.qsize() < 2 and time.monotonic() < deadline:
                time.sleep(0.005)

            worker.resume()
            broker.join("default", fail_fast=False)
            worker.join()
        finally:
            worker.stop()

        assert results == ["low", "high"]
    finally:
        broker.flush_all()
        broker.close()


def test_worker_keeps_static_priority_with_compensation_disabled() -> None:
    """End-to-end (stub broker) check of the default, unchanged behaviour."""

    broker = StubBroker()
    broker.emit_after("process_boot")
    try:
        results: list[str] = []

        @dramatiq.actor(broker=broker, priority=0)
        def high() -> None:
            results.append("high")

        @dramatiq.actor(broker=broker, priority=2)
        def low() -> None:
            results.append("low")

        worker = dramatiq.Worker(broker, worker_threads=1, priority_age_enabled=False)
        worker.queue_prefetch = 20
        worker.start()
        try:
            for worker_thread in worker.workers:
                worker_thread.pause()
                worker_thread.paused_event.wait()

            low.send()
            high.send()
            deadline = time.monotonic() + 2
            while worker.work_queue.qsize() < 2 and time.monotonic() < deadline:
                time.sleep(0.005)

            worker.resume()
            broker.join("default", fail_fast=False)
            worker.join()
        finally:
            worker.stop()

        assert results == ["high", "low"]
    finally:
        broker.flush_all()
        broker.close()
