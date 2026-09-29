from __future__ import annotations

import threading

import pytest

import dramatiq
from dramatiq import Worker, group, pipeline
from dramatiq.cancel import CancellationBackend, CancellationToken, LocalCancellationBackend
from dramatiq.errors import MessageCancelled
from dramatiq.middleware import Cancel, GroupCallbacks
from dramatiq.results import Results
from dramatiq.results.backends import StubBackend
from dramatiq.results.errors import ResultFailure

EVENT_TIMEOUT = 10


def make_worker(broker):
    return Worker(broker, worker_timeout=100, worker_threads=4)


def test_cancel_backend_is_idempotent():
    # Given a local cancellation backend
    backend = LocalCancellationBackend()

    # When I cancel the same message multiple times
    backend.cancel("some-id")
    backend.cancel("some-id")
    backend.cancel("some-id")

    # Then the message is cancelled exactly once
    assert backend.is_cancelled("some-id")
    assert len(backend._cancelled) == 1

    # And clearing the message removes all cancellation state
    backend.clear("some-id")
    assert not backend.is_cancelled("some-id")


def test_cancel_backend_is_abstract():
    backend = CancellationBackend()
    with pytest.raises(NotImplementedError):
        backend.cancel("x")
    with pytest.raises(NotImplementedError):
        backend.is_cancelled("x")
    with pytest.raises(NotImplementedError):
        backend.clear("x")


def test_token_raises_when_cancelled():
    backend = LocalCancellationBackend()
    token = CancellationToken(backend, "id")
    assert not token.is_cancelled()
    backend.cancel("id")
    assert token.is_cancelled()
    with pytest.raises(MessageCancelled):
        token.raise_if_cancelled()


def test_cancelled_message_that_has_not_started_is_skipped(stub_broker):
    # Given a broker with the Cancel middleware
    cancel = Cancel()
    stub_broker.add_middleware(cancel)

    calls = []

    @dramatiq.actor
    def track():
        calls.append(1)

    # When I enqueue a message and cancel it before any worker starts
    message = track.send()
    cancel.cancel(message.message_id)

    worker = make_worker(stub_broker)
    worker.start()
    try:
        stub_broker.join(track.queue_name)
        worker.join()
    finally:
        worker.stop()

    # Then the actor never runs and the message is acked, not dead-lettered
    assert calls == []
    assert stub_broker.dead_letters == []


def test_running_actor_exits_at_checkpoint_when_cancelled(stub_broker, stub_worker):
    # Given a broker with the Cancel middleware
    cancel = Cancel()
    stub_broker.add_middleware(cancel)

    started = threading.Event()
    proceed = threading.Event()
    calls = []

    @dramatiq.actor(max_retries=10)
    def long_task():
        token = Cancel.get_current_token()
        calls.append(token)
        started.set()
        assert proceed.wait(EVENT_TIMEOUT)
        token.raise_if_cancelled()
        calls.append("completed")

    # When the actor starts and I cancel it while it is running
    message = long_task.send()
    assert started.wait(EVENT_TIMEOUT)
    cancel.cancel(message.message_id)
    proceed.set()
    stub_broker.join(long_task.queue_name)
    stub_worker.join()

    # Then the actor exited at its checkpoint and was not retried
    assert len(calls) == 1
    assert isinstance(calls[0].message_id, str)
    assert calls[0].message_id == message.message_id
    assert stub_broker.dead_letters == []


def test_cancelled_message_is_not_retried(stub_broker, stub_worker):
    # Given a broker with the Cancel middleware
    cancel = Cancel()
    stub_broker.add_middleware(cancel)

    attempts = []

    @dramatiq.actor(max_retries=10, min_backoff=1, max_backoff=10)
    def flaky():
        attempts.append(1)
        raise MessageCancelled("cancelled")

    # When a message ends with MessageCancelled
    flaky.send()
    stub_broker.join(flaky.queue_name)
    stub_worker.join()

    # Then it is not retried and not dead-lettered
    assert len(attempts) == 1
    assert stub_broker.dead_letters == []


def test_completed_result_is_not_overwritten_by_late_cancel(stub_broker, stub_worker):
    # Given a broker with the Cancel and Results middleware
    cancel = Cancel()
    backend = StubBackend()
    stub_broker.add_middleware(cancel)
    stub_broker.add_middleware(Results(backend=backend))

    @dramatiq.actor(store_results=True)
    def compute():
        return 42

    # When a message completes and I cancel it afterwards
    message = compute.send()
    stub_broker.join(compute.queue_name)
    stub_worker.join()
    cancel.cancel(message.message_id)

    # Then the stored result is the completed value
    assert message.get_result(backend=backend) == 42


def test_cancelled_message_stores_cancelled_result(stub_broker, stub_worker):
    # Given a broker with the Cancel and Results middleware
    cancel = Cancel()
    backend = StubBackend()
    stub_broker.add_middleware(cancel)
    stub_broker.add_middleware(Results(backend=backend))

    started = threading.Event()
    proceed = threading.Event()

    @dramatiq.actor(store_results=True)
    def long_task():
        started.set()
        assert proceed.wait(EVENT_TIMEOUT)
        Cancel.get_current_token().raise_if_cancelled()

    # When a running message is cancelled
    message = long_task.send()
    assert started.wait(EVENT_TIMEOUT)
    cancel.cancel(message.message_id)
    proceed.set()
    stub_broker.join(long_task.queue_name)
    stub_worker.join()

    # Then its result reflects the cancellation so waiters are unblocked
    with pytest.raises(ResultFailure):
        message.get_result(backend=backend)


def test_message_cancelled_before_start_stores_cancelled_result(stub_broker):
    # Given a broker with the Cancel and Results middleware
    cancel = Cancel()
    backend = StubBackend()
    stub_broker.add_middleware(cancel)
    stub_broker.add_middleware(Results(backend=backend))

    @dramatiq.actor(store_results=True)
    def compute():
        return 42

    # When a message is cancelled before it starts
    message = compute.send()
    cancel.cancel(message.message_id)

    worker = make_worker(stub_broker)
    worker.start()
    try:
        stub_broker.join(compute.queue_name)
        worker.join()
    finally:
        worker.stop()

    # Then its result reflects the cancellation rather than None
    with pytest.raises(ResultFailure):
        message.get_result(backend=backend)


def test_cancel_terminates_pipeline(stub_broker, stub_worker):
    # Given a broker with the Cancel middleware
    cancel = Cancel()
    stub_broker.add_middleware(cancel)

    ran = []

    @dramatiq.actor
    def step1():
        ran.append("step1")
        return 1

    @dramatiq.actor
    def step2(x):
        ran.append("step2")

    # When I cancel the first message of a pipeline before it runs
    pipe = pipeline([step1.message(), step2.message()])
    cancel.cancel(pipe.messages[0].message_id)
    pipe.run()
    stub_broker.join(step1.queue_name)
    stub_worker.join()

    # Then neither step runs
    assert ran == []


def test_cancel_mid_pipeline_does_not_run_successor(stub_broker, stub_worker):
    # Given a broker with the Cancel middleware
    cancel = Cancel()
    stub_broker.add_middleware(cancel)

    started = threading.Event()
    proceed = threading.Event()
    ran = []

    @dramatiq.actor
    def step1():
        ran.append("step1")
        started.set()
        assert proceed.wait(EVENT_TIMEOUT)
        Cancel.get_current_token().raise_if_cancelled()
        return 1

    @dramatiq.actor
    def step2(x):
        ran.append("step2")

    # When the first step of a pipeline is cancelled while running
    pipe = pipeline([step1.message(), step2.message()])
    pipe.run()
    assert started.wait(EVENT_TIMEOUT)
    cancel.cancel(pipe.messages[0].message_id)
    proceed.set()
    stub_broker.join(step1.queue_name)
    stub_worker.join()

    # Then the successor never runs
    assert ran == ["step1"]


def test_cancelled_group_member_counts_towards_completion(stub_broker, stub_worker, stub_rate_limiter_backend):
    # Given a broker with the Cancel and GroupCallbacks middleware
    cancel = Cancel()
    stub_broker.add_middleware(cancel)
    stub_broker.add_middleware(GroupCallbacks(stub_rate_limiter_backend))

    done = threading.Event()
    ran = []

    @dramatiq.actor
    def task1():
        ran.append("task1")

    @dramatiq.actor
    def task2():
        ran.append("task2")

    @dramatiq.actor
    def on_complete():
        done.set()

    # When one member of a group is cancelled before it starts
    tasks = group([task1.message(), task2.message()])
    tasks.add_completion_callback(on_complete.message())
    cancel.cancel(tasks.children[0].message_id)
    tasks.run()
    stub_broker.join(task1.queue_name)
    stub_worker.join()

    # Then the cancelled member still counts towards group completion
    assert ran == ["task2"]
    assert done.wait(EVENT_TIMEOUT)


def test_token_is_none_outside_of_actor_code(stub_broker, stub_worker):
    # Given a broker with the Cancel middleware
    cancel = Cancel()
    stub_broker.add_middleware(cancel)

    tokens = []

    @dramatiq.actor
    def capture():
        tokens.append(Cancel.get_current_token())

    # When an actor runs
    message = capture.send()
    stub_broker.join(capture.queue_name)
    stub_worker.join()

    # Then the token is available inside the actor but not outside
    assert tokens[0] is not None
    assert tokens[0].message_id == message.message_id
    assert not tokens[0].is_cancelled()
    assert Cancel.get_current_token() is None


def test_cancel_and_complete_race_settles_on_single_terminal_state(stub_broker, stub_worker):
    # Given a broker with the Cancel and Results middleware
    cancel = Cancel()
    backend = StubBackend()
    stub_broker.add_middleware(cancel)
    stub_broker.add_middleware(Results(backend=backend))

    checkpoint = threading.Event()
    release = threading.Event()

    @dramatiq.actor(store_results=True)
    def compute():
        checkpoint.set()
        assert release.wait(EVENT_TIMEOUT)
        Cancel.get_current_token().raise_if_cancelled()
        return 42

    # When the cancellation lands before the actor"s checkpoint
    message = compute.send()
    assert checkpoint.wait(EVENT_TIMEOUT)
    cancel.cancel(message.message_id)
    release.set()
    stub_broker.join(compute.queue_name)
    stub_worker.join()

    # Then the message is cancelled and no success result is stored
    with pytest.raises(ResultFailure):
        message.get_result(backend=backend)

    # And when the cancellation lands after an identical message completed,
    # the completed result wins
    checkpoint.clear()
    release.set()
    message = compute.send()
    stub_broker.join(compute.queue_name)
    stub_worker.join()
    cancel.cancel(message.message_id)
    assert message.get_result(backend=backend) == 42
