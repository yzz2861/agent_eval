from __future__ import annotations

import time

import pytest

import dramatiq
from dramatiq.errors import BatchResultError
from dramatiq.middleware import Batching, MiddlewareError

from .common import worker


def get_batch_manager(broker):
    for middleware in broker.middleware:
        if isinstance(middleware, Batching):
            return middleware.manager
    return None


def wait_for_condition(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def test_batch_actors_process_messages_in_batches(stub_broker, stub_worker):
    # Given a batch actor that records the batches it receives
    batches = []

    @dramatiq.actor(max_batch_size=3, batch_max_wait_ms=60000)
    def record(batch):
        batches.append(batch)
        return [None] * len(batch)

    # When I send it exactly as many messages as fit in one batch
    for i in range(3):
        record.send(i)

    stub_broker.join(record.queue_name)
    stub_worker.join()

    # Then the function should have been called once with all 3 inputs
    assert len(batches) == 1
    assert batches[0] == [((0,), {}), ((1,), {}), ((2,), {})]


def test_batch_actors_flush_after_max_wait(stub_broker, stub_worker):
    # Given a batch actor whose batch size is never reached
    batches = []

    @dramatiq.actor(max_batch_size=10, batch_max_wait_ms=200)
    def record(batch):
        batches.append(batch)
        return [None] * len(batch)

    # When I send fewer messages than the batch size
    record.send(1)
    record.send(2)

    stub_broker.join(record.queue_name)
    stub_worker.join()

    # Then the partial batch should have been flushed after the wait time
    assert len(batches) == 1
    assert batches[0] == [((1,), {}), ((2,), {})]


def test_batch_buffers_are_capped_at_max_batch_size(stub_broker, stub_worker):
    # Given a batch actor with a small batch size
    batches = []

    @dramatiq.actor(max_batch_size=3, batch_max_wait_ms=300)
    def record(batch):
        batches.append([args[0] for args, _ in batch])
        return [None] * len(batch)

    # When I send more messages than fit in a single batch
    for i in range(7):
        record.send(i)

    stub_broker.join(record.queue_name)
    stub_worker.join()

    # Then no batch should have exceeded the batch size and every
    # message should have been processed exactly once
    assert sorted(len(batch) for batch in batches) == [1, 3, 3]
    assert sorted(item for batch in batches for item in batch) == list(range(7))


def test_batch_actors_do_not_mix_batch_keys(stub_broker, stub_worker):
    # Given a batch actor whose messages carry different batch keys
    batches = []

    @dramatiq.actor(max_batch_size=2, batch_max_wait_ms=60000)
    def record(batch):
        batches.append(sorted(args[0] for args, _ in batch))
        return [None] * len(batch)

    # When I send interleaved messages with two different batch keys
    record.send_with_options(args=(1,), batch_key="a")
    record.send_with_options(args=(2,), batch_key="b")
    record.send_with_options(args=(3,), batch_key="a")
    record.send_with_options(args=(4,), batch_key="b")

    stub_broker.join(record.queue_name)
    stub_worker.join()

    # Then messages with different keys should not have been mixed
    assert sorted(batches) == [[1, 3], [2, 4]]


def test_batch_actors_do_not_mix_with_other_actors(stub_broker, stub_worker):
    # Given two batch actors on the same queue
    batches_a = []
    batches_b = []

    @dramatiq.actor(max_batch_size=2, batch_max_wait_ms=60000)
    def actor_a(batch):
        batches_a.append(sorted(args[0] for args, _ in batch))
        return [None] * len(batch)

    @dramatiq.actor(max_batch_size=2, batch_max_wait_ms=60000)
    def actor_b(batch):
        batches_b.append(sorted(args[0] for args, _ in batch))
        return [None] * len(batch)

    # When I send interleaved messages to both actors
    actor_a.send(1)
    actor_b.send(2)
    actor_a.send(3)
    actor_b.send(4)

    stub_broker.join(actor_a.queue_name)
    stub_worker.join()

    # Then each actor should only have received its own messages
    assert batches_a == [[1, 3]]
    assert batches_b == [[2, 4]]


def test_failed_batch_items_are_retried_on_their_own(stub_broker, stub_worker):
    # Given a batch actor that fails a single item exactly once
    attempts = []
    fail_once = {2}

    @dramatiq.actor(max_batch_size=3, batch_max_wait_ms=300, max_retries=3, min_backoff=100, max_backoff=200)
    def process(batch):
        inputs = [args[0] for args, _ in batch]
        attempts.append(inputs)
        results = []
        for value in inputs:
            if value in fail_once:
                fail_once.discard(value)
                results.append(ValueError("boom"))
            else:
                results.append(None)
        return results

    # When I send a full batch of messages
    process.send(1)
    process.send(2)
    process.send(3)

    stub_broker.join(process.queue_name)
    stub_worker.join()

    # Then only the failed item should have been retried and the
    # successful items should not have been reprocessed
    assert attempts[0] == [1, 2, 3]
    assert attempts[1] == [2]
    assert len(attempts) == 2
    assert not stub_broker.dead_letters


def test_batch_function_crash_fails_the_whole_batch(stub_broker, stub_worker):
    # Given a batch actor whose function raises an exception
    @dramatiq.actor(max_batch_size=2, batch_max_wait_ms=60000, max_retries=0)
    def process(batch):
        raise RuntimeError("batch exploded")

    # When I send a full batch of messages
    process.send(1)
    process.send(2)

    stub_broker.join(process.queue_name, fail_fast=False)
    stub_worker.join()

    # Then every message in the batch should have failed with that exception
    assert len(stub_broker.dead_letters) == 2
    assert all(isinstance(message._exception, RuntimeError) for message in stub_broker.dead_letters)


def test_batch_wrong_result_count_fails_the_whole_batch(stub_broker, stub_worker):
    # Given a batch actor that returns fewer results than inputs
    @dramatiq.actor(max_batch_size=2, batch_max_wait_ms=60000, max_retries=0)
    def process(batch):
        return [None]

    # When I send a full batch of messages
    process.send(1)
    process.send(2)

    stub_broker.join(process.queue_name, fail_fast=False)
    stub_worker.join()

    # Then every message in the batch should have failed with a BatchResultError
    assert len(stub_broker.dead_letters) == 2
    assert all(isinstance(message._exception, BatchResultError) for message in stub_broker.dead_letters)


def test_unflushed_batches_are_requeued_on_worker_shutdown(stub_broker):
    # Given a batch actor whose batch size is never reached
    processed = []

    @dramatiq.actor(max_batch_size=10, batch_max_wait_ms=60000)
    def process(batch):
        processed.extend(args[0] for args, _ in batch)
        return [None] * len(batch)

    # When I send a few messages and stop the worker while they are
    # still sitting in the batch buffer
    with worker(stub_broker, worker_timeout=100):
        for i in range(3):
            process.send(i)

        manager = get_batch_manager(stub_broker)
        assert wait_for_condition(
            lambda: manager is not None and sum(len(buffer.messages) for buffer in manager.buffers.values()) == 3
        )

    # And I start a new worker and complete the batch
    with worker(stub_broker, worker_timeout=100) as new_worker:
        for i in range(3, 10):
            process.send(i)

        stub_broker.join(process.queue_name)
        new_worker.join()

    # Then none of the buffered messages should have been lost
    assert sorted(processed) == list(range(10))


def test_regular_actors_are_unaffected_by_batching(stub_broker, stub_worker):
    # Given a regular actor and a batch actor on the same queue
    results = []
    batches = []

    @dramatiq.actor
    def regular(value):
        results.append(value)

    @dramatiq.actor(max_batch_size=2, batch_max_wait_ms=60000)
    def batched(batch):
        batches.append(batch)
        return [None] * len(batch)

    # When I send messages to both
    regular.send(1)
    batched.send(2)
    batched.send(3)
    regular.send(4)

    stub_broker.join(regular.queue_name)
    stub_worker.join()

    # Then the regular actor should have been called once per message
    assert sorted(results) == [1, 4]
    assert len(batches) == 1


def test_batch_actors_reject_invalid_options(stub_broker):
    # Given an invalid max_batch_size
    # When I declare a batch actor
    # Then an error should be raised
    with pytest.raises(MiddlewareError):

        @dramatiq.actor(max_batch_size=0)
        def bad_batch_size(batch):
            return []

    with pytest.raises(MiddlewareError):

        @dramatiq.actor(max_batch_size=2, batch_max_wait_ms=-1)
        def bad_max_wait(batch):
            return []
