from __future__ import annotations

import pytest

import dramatiq
from dramatiq import compensating_pipeline
from dramatiq.compensation.backends import StubBackend
from dramatiq.middleware import Compensations, Retries


@pytest.fixture()
def state_backend():
    return StubBackend()


@pytest.fixture()
def compensation_middleware(stub_broker, state_backend):
    middleware = Compensations(state_backend=state_backend)
    stub_broker.add_middleware(middleware, before=Retries)
    return middleware


def test_compensating_pipeline_runs_to_completion(stub_broker, stub_worker, compensation_middleware):
    # Given an actor that records its calls and a compensation actor
    calls = []
    compensated = []

    @dramatiq.actor
    def step(name, *_):
        calls.append(name)
        return name.upper()

    @dramatiq.actor
    def undo(name, result):
        compensated.append((name, result))

    # When I run a compensating pipeline whose steps all succeed
    pipe = compensating_pipeline([
        (step.message("a"), undo.message("ua")),
        (step.message("b"), undo.message("ub")),
        (step.message("c"), undo.message("uc")),
    ])
    pipe.run()
    stub_broker.join(step.queue_name)
    stub_broker.join(undo.queue_name)

    # Then all steps should have run in order, passing results along
    assert calls == ["a", "b", "c"]

    # And no compensation should have run
    assert compensated == []

    # And the run should be marked completed, with each step's result recorded
    state = pipe.get_state()
    assert state["status"] == "completed"
    assert state["completed"] == 3
    assert state["results"] == {0: "A", 1: "B", 2: "C"}
    assert pipe.completed
    assert not pipe.compensated


def test_permanent_failure_compensates_completed_steps_in_reverse_order(
    stub_broker, stub_worker, compensation_middleware
):
    # Given a pipeline whose last step always fails
    compensated = []

    @dramatiq.actor
    def step(name, *_):
        return name.upper()

    @dramatiq.actor(max_retries=0)
    def boom(*_):
        raise RuntimeError("kaput")

    @dramatiq.actor
    def undo(name, result):
        compensated.append((name, result))

    # When I run the pipeline
    pipe = compensating_pipeline([
        (step.message("a"), undo.message("ua")),
        (step.message("b"), undo.message("ub")),
        (boom.message(), None),
    ])
    pipe.run()
    stub_broker.join(step.queue_name, fail_fast=False)
    stub_broker.join(undo.queue_name, fail_fast=False)

    # Then the completed steps should have been compensated in reverse
    # order, each compensation receiving its step's result
    assert compensated == [("ub", "B"), ("ua", "A")]

    # And the run should record where and why it failed
    state = pipe.get_state()
    assert state["status"] == "compensated"
    assert state["failed_step"] == 2
    assert "kaput" in state["error"]
    assert pipe.compensated
    assert not pipe.completed


def test_compensation_does_not_start_until_retries_are_exhausted(stub_broker, stub_worker, compensation_middleware):
    # Given an actor that fails twice and then succeeds
    attempts = []
    compensated = []

    @dramatiq.actor(max_retries=2, min_backoff=10, max_backoff=50)
    def flaky():
        attempts.append(1)
        if len(attempts) < 3:
            raise RuntimeError("try again")
        return "ok"

    @dramatiq.actor
    def undo(result):
        compensated.append(result)

    # When I run a compensating pipeline with that actor
    pipe = compensating_pipeline([
        (flaky.message(), undo.message()),
    ])
    pipe.run()
    stub_broker.join(flaky.queue_name)
    stub_broker.join(undo.queue_name)

    # Then the actor should have been retried until it succeeded
    assert len(attempts) == 3

    # And no compensation should have run
    assert compensated == []
    assert pipe.get_state()["status"] == "completed"


def test_failing_first_step_marks_run_failed_without_compensating(stub_broker, stub_worker, compensation_middleware):
    # Given a pipeline whose first step fails permanently
    compensated = []

    @dramatiq.actor(max_retries=0)
    def boom():
        raise RuntimeError("kaput")

    @dramatiq.actor
    def undo(result):
        compensated.append(result)

    # When I run the pipeline
    pipe = compensating_pipeline([
        (boom.message(), undo.message()),
    ])
    pipe.run()
    stub_broker.join(boom.queue_name, fail_fast=False)
    stub_broker.join(undo.queue_name, fail_fast=False)

    # Then there is nothing to compensate
    assert compensated == []

    # And the run should be marked failed rather than compensated
    state = pipe.get_state()
    assert state["status"] == "failed"
    assert state["failed_step"] == 0


def test_duplicate_deliveries_do_not_advance_steps_twice(stub_broker, stub_worker, compensation_middleware):
    # Given a compensating pipeline that has run to completion
    calls = []

    @dramatiq.actor
    def step(name, *_):
        calls.append(name)
        return name

    pipe = compensating_pipeline([
        step.message("a"),
        step.message("b"),
    ])
    pipe.run()
    stub_broker.join(step.queue_name)
    assert calls == ["a", "b"]

    # When the first message is redelivered (e.g. its ack was lost)
    stub_broker.enqueue(pipe.messages[0])
    stub_broker.join(step.queue_name)

    # Then the first actor runs again (delivery is at-least-once) but
    # the pipeline does not advance a second time
    assert calls == ["a", "b", "a"]
    state = pipe.get_state()
    assert state["status"] == "completed"
    assert state["completed"] == 2


def test_failed_compensation_preserves_position_and_can_be_resumed(
    stub_broker, stub_worker, compensation_middleware
):
    # Given a pipeline that fails and whose second compensation also fails
    compensated = []
    undo_b_broken = [True]

    @dramatiq.actor
    def step(name, *_):
        return name.upper()

    @dramatiq.actor(max_retries=0)
    def boom(*_):
        raise RuntimeError("kaput")

    @dramatiq.actor(max_retries=0)
    def undo_b(result):
        if undo_b_broken[0]:
            raise RuntimeError("undo kaput")
        compensated.append(("ub", result))

    @dramatiq.actor
    def undo_a(result):
        compensated.append(("ua", result))

    # When I run the pipeline
    pipe = compensating_pipeline([
        (step.message("a"), undo_a.message()),
        (step.message("b"), undo_b.message()),
        (boom.message(), None),
    ])
    pipe.run()
    stub_broker.join(step.queue_name, fail_fast=False)
    stub_broker.join(undo_a.queue_name, fail_fast=False)
    stub_broker.join(undo_b.queue_name, fail_fast=False)

    # Then the run should be stuck at the failed compensation,
    # without claiming to be fully rolled back
    state = pipe.get_state()
    assert state["status"] == "compensation_failed"
    assert state["comp_position"] == 1
    assert "undo kaput" in state["error"]

    # And the earlier compensation should not have run past the failed one
    assert compensated == []

    # When I fix the compensation and resume the run
    undo_b_broken[0] = False
    assert pipe.resume()
    stub_broker.join(undo_a.queue_name, fail_fast=False)
    stub_broker.join(undo_b.queue_name, fail_fast=False)

    # Then the remaining compensations should run in reverse order
    assert compensated == [("ub", "B"), ("ua", "A")]
    assert pipe.get_state()["status"] == "compensated"

    # When a compensation message is redelivered after the run finished
    stub_broker.enqueue(
        undo_a.message().copy(
            args=("A",),
            options={
                "comp_run_id": pipe.run_id,
                "comp_step": 0,
                "comp_mode": "compensation",
            },
        )
    )
    stub_broker.join(undo_a.queue_name, fail_fast=False)

    # Then the duplicate should not move the run backwards
    assert pipe.get_state()["status"] == "compensated"


def test_state_backend_transitions_are_atomic(state_backend):
    # Given a run with three compensatable steps
    compensation = {"queue_name": "default", "actor_name": "undo", "args": (), "kwargs": {}, "options": {}}
    assert state_backend.create_run("run", steps=[{"compensation": compensation}] * 3, ttl=10000)

    # Duplicate run creation should be rejected
    assert not state_backend.create_run("run", steps=[], ttl=10000)

    # Forward steps should only advance from the expected position
    assert not state_backend.advance_forward("run", step=1, result="b", ttl=10000)
    assert state_backend.advance_forward("run", step=0, result="a", ttl=10000)
    assert not state_backend.advance_forward("run", step=0, result="a", ttl=10000)
    assert state_backend.advance_forward("run", step=1, result="b", ttl=10000)

    # Compensation can't start from a step that hasn't failed at the head
    assert not state_backend.begin_compensation("run", failed_step=1, error="x", ttl=10000)
    assert state_backend.begin_compensation("run", failed_step=2, error="x", ttl=10000)
    assert not state_backend.begin_compensation("run", failed_step=2, error="x", ttl=10000)

    # Compensations can't skip past the current position
    assert not state_backend.advance_compensation("run", step=0, ttl=10000)
    assert state_backend.advance_compensation("run", step=1, ttl=10000)
    assert not state_backend.advance_compensation("run", step=1, ttl=10000)
    assert state_backend.advance_compensation("run", step=0, ttl=10000)

    state = state_backend.get_run("run")
    assert state["status"] == "compensated"
    assert state["results"] == {0: "a", 1: "b"}


def test_state_backend_preserves_failed_compensation_for_resume(state_backend):
    # Given a compensating run positioned at step 0
    compensation = {"queue_name": "default", "actor_name": "undo", "args": (), "kwargs": {}, "options": {}}
    state_backend.create_run("run", steps=[{"compensation": compensation}] * 2, ttl=10000)
    state_backend.advance_forward("run", step=0, result="a", ttl=10000)
    state_backend.begin_compensation("run", failed_step=1, error="x", ttl=10000)

    # When the compensation of step 1 fails while step 0 is current
    # Then the failure should be rejected
    assert not state_backend.fail_compensation("run", step=1, error="y", ttl=10000)

    # When the compensation of the current step fails
    assert state_backend.fail_compensation("run", step=0, error="y", ttl=10000)

    # Then the run should keep its position instead of completing
    state = state_backend.get_run("run")
    assert state["status"] == "compensation_failed"
    assert state["comp_position"] == 0
    assert state["error"] == "y"

    # And it should be resumable exactly once
    assert state_backend.resume_compensation("run", ttl=10000)
    assert not state_backend.resume_compensation("run", ttl=10000)
    assert state_backend.get_run("run")["status"] == "compensating"
