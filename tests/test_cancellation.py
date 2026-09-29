from __future__ import annotations

import threading

import pytest

import dramatiq
from dramatiq import MessageCanceled, Worker
from dramatiq.cancellation import LocalCancellationBackend
from dramatiq.middleware import Cancellation, GroupCallbacks
from dramatiq.results import ResultMissing, Results

EVENT_TIMEOUT = 10


def test_cancel_requires_cancellation_middleware(stub_broker):
    # Given a broker without the Cancellation middleware
    @dramatiq.actor
    def task():
        pass

    # When I try to cancel a message
    # Then a RuntimeError is raised
    with pytest.raises(RuntimeError):
        stub_broker.cancel(task.message())


def test_local_backend_cancel_is_idempotent():
    # Given a local cancellation backend
    backend = LocalCancellationBackend()

    # When I cancel the same message multiple times
    # Then every call succeeds and the message stays canceled
    assert backend.cancel("some-id") is True
    assert backend.cancel("some-id") is True
    assert backend.is_canceled("some-id") is True


def test_local_backend_terminal_state_is_first_to_arrive():
    # Given a local cancellation backend
    backend = LocalCancellationBackend()

    # When a message completes before it is canceled
    assert backend.complete("completed-first") is True

    # Then the late cancellation is rejected
    assert backend.cancel("completed-first") is False
    assert backend.is_canceled("completed-first") is False

    # When a message is canceled before it completes
    assert backend.cancel("canceled-first") is True

    # Then the late completion is rejected
    assert backend.complete("canceled-first") is False
    assert backend.is_canceled("canceled-first") is True


def test_local_backend_cancel_and_complete_race_to_a_single_terminal_state():
    # Given a local cancellation backend
    backend = LocalCancellationBackend()

    # When a cancellation request and a completion acknowledgement
    # arrive at the same time, over many trials
    for attempt in range(100):
        message_id = "raced-%d" % attempt
        outcomes = {}
        start = threading.Barrier(3)

        def cancel():
            start.wait()
            outcomes["cancel"] = backend.cancel(message_id)

        def complete():
            start.wait()
            outcomes["complete"] = backend.complete(message_id)

        threads = [threading.Thread(target=cancel), threading.Thread(target=complete)]
        for thread in threads:
            thread.start()
        start.wait()
        for thread in threads:
            thread.join()

        # Then exactly one of them wins and the recorded state agrees
        assert outcomes["cancel"] != outcomes["complete"]
        assert backend.is_canceled(message_id) == outcomes["cancel"]


def test_local_backend_clear_forgets_state():
    # Given a local cancellation backend with a canceled message
    backend = LocalCancellationBackend()
    backend.cancel("some-id")

    # When I clear the message
    backend.clear("some-id")

    # Then its state is forgotten
    assert backend.is_canceled("some-id") is False


def test_canceled_messages_that_have_not_started_are_skipped(stub_broker):
    # Given a broker with the Cancellation middleware and no running worker
    stub_broker.add_middleware(Cancellation())
    runs = []

    @dramatiq.actor
    def task():
        runs.append(1)

    # When I enqueue a message and cancel it before any worker starts
    message = task.send()
    assert stub_broker.cancel(message) is True

    # And a worker later processes the queue
    worker = Worker(stub_broker, worker_timeout=100)
    worker.start()
    try:
        stub_broker.join(task.queue_name)
    finally:
        worker.stop()

    # Then the actor never runs and the message is acknowledged
    assert runs == []
    assert stub_broker.dead_letters == []


def test_running_actors_exit_at_cancellation_checkpoints(stub_broker, stub_worker):
    # Given a broker with the Cancellation middleware
    stub_broker.add_middleware(Cancellation())
    started = threading.Event()
    release = threading.Event()
    runs = []
    caught = []

    @dramatiq.actor(max_retries=3)
    def task():
        runs.append(1)
        started.set()
        assert release.wait(EVENT_TIMEOUT)
        token = Cancellation.get_current_token()
        try:
            token.check()
        except MessageCanceled as e:
            caught.append(e)
            raise

    # When the actor is running and its message gets canceled
    message = task.send()
    assert started.wait(EVENT_TIMEOUT)
    assert stub_broker.cancel(message) is True
    release.set()
    stub_broker.join(task.queue_name)

    # Then the actor exits at the checkpoint with MessageCanceled
    assert len(caught) == 1

    # And the message is acknowledged without being retried
    assert runs == [1]
    assert stub_broker.dead_letters == []


def test_current_token_is_only_available_inside_actor_code(stub_broker, stub_worker):
    # Given a broker with the Cancellation middleware
    stub_broker.add_middleware(Cancellation())
    tokens = []

    @dramatiq.actor
    def task():
        tokens.append(Cancellation.get_current_token())

    # When the actor runs
    task.send()
    stub_broker.join(task.queue_name)

    # Then a token is available inside the actor but not outside
    assert len(tokens) == 1
    assert tokens[0] is not None
    assert tokens[0].is_canceled is False
    assert Cancellation.get_current_token() is None


def test_completed_results_are_not_overwritten_by_late_cancellation(stub_broker, stub_worker, stub_result_backend):
    # Given a broker with Results and Cancellation middleware
    stub_broker.add_middleware(Results(backend=stub_result_backend))
    stub_broker.add_middleware(Cancellation())

    @dramatiq.actor(store_results=True)
    def task():
        return 42

    # When a message completes and is canceled afterwards
    message = task.send()
    assert message.get_result(backend=stub_result_backend, block=True) == 42
    assert stub_broker.cancel(message) is False

    # Then the cancellation is rejected and the result is preserved
    cancellation = stub_broker.get_cancellation_middleware()
    assert cancellation.is_canceled(message) is False
    assert message.get_result(backend=stub_result_backend) == 42


def test_cancellation_discards_late_completions(stub_broker, stub_worker, stub_result_backend):
    # Given a broker with Results and Cancellation middleware
    stub_broker.add_middleware(Results(backend=stub_result_backend))
    cancellation = Cancellation()
    stub_broker.add_middleware(cancellation)
    started = threading.Event()
    release = threading.Event()

    @dramatiq.actor(store_results=True)
    def task():
        started.set()
        assert release.wait(EVENT_TIMEOUT)
        return 42

    # When a message is canceled while it is running and the actor
    # completes anyway without checking its token
    message = task.send()
    assert started.wait(EVENT_TIMEOUT)
    assert stub_broker.cancel(message) is True
    release.set()
    stub_broker.join(task.queue_name)

    # Then the cancellation wins: no result is stored and the
    # terminal state is "canceled"
    assert cancellation.is_canceled(message) is True
    with pytest.raises(ResultMissing):
        message.get_result(backend=stub_result_backend)
    assert stub_broker.dead_letters == []


def test_canceled_messages_do_not_store_results_when_skipped(stub_broker, stub_result_backend):
    # Given a broker with Results and Cancellation middleware
    stub_broker.add_middleware(Results(backend=stub_result_backend))
    stub_broker.add_middleware(Cancellation())

    @dramatiq.actor(store_results=True)
    def task():
        pass

    # When a message is canceled before it starts
    message = task.send()
    stub_broker.cancel(message)

    worker = Worker(stub_broker, worker_timeout=100)
    worker.start()
    try:
        stub_broker.join(task.queue_name)
    finally:
        worker.stop()

    # Then no result is stored for it
    with pytest.raises(ResultMissing):
        message.get_result(backend=stub_result_backend)


def test_cancellation_stops_pipelines(stub_broker, stub_worker):
    # Given a broker with the Cancellation middleware and a pipeline
    stub_broker.add_middleware(Cancellation())
    started = threading.Event()
    release = threading.Event()
    successor_runs = []

    @dramatiq.actor
    def first():
        started.set()
        assert release.wait(EVENT_TIMEOUT)
        Cancellation.get_current_token().check()

    @dramatiq.actor
    def second():
        successor_runs.append(1)

    pipe = dramatiq.pipeline([first.message(), second.message()])

    # When the first message is canceled while it is running
    pipe.run()
    assert started.wait(EVENT_TIMEOUT)
    assert stub_broker.cancel(pipe.messages[0]) is True
    release.set()
    stub_broker.join(first.queue_name)

    # Then the pipeline's successor never runs
    assert successor_runs == []
    assert stub_broker.dead_letters == []


def test_canceled_group_members_count_towards_completion(
    stub_broker, stub_worker, stub_rate_limiter_backend
):
    # Given a broker with GroupCallbacks and Cancellation middleware
    stub_broker.add_middleware(GroupCallbacks(stub_rate_limiter_backend))
    stub_broker.add_middleware(Cancellation())
    started = threading.Event()
    release = threading.Event()
    callback_runs = []

    @dramatiq.actor
    def quick():
        pass

    @dramatiq.actor
    def slow():
        started.set()
        assert release.wait(EVENT_TIMEOUT)
        Cancellation.get_current_token().check()

    @dramatiq.actor
    def on_complete():
        callback_runs.append(1)

    # And a group with a completion callback
    canceled_message = slow.message()
    grp = dramatiq.group([quick.message(), canceled_message])
    grp.add_completion_callback(on_complete.message())

    # When one of the group's members is canceled while it is running
    grp.run()
    assert started.wait(EVENT_TIMEOUT)
    assert stub_broker.cancel(canceled_message) is True
    release.set()
    stub_broker.join(quick.queue_name)

    # Then the canceled member counts towards the group's completion
    # and the completion callback runs
    assert callback_runs == [1]
    assert stub_broker.dead_letters == []
