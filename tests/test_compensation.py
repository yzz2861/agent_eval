from __future__ import annotations

import dramatiq
from dramatiq.compensation import LocalCompensationBackend, compensating_pipeline
from dramatiq.compensation.backend import COMPENSATED, COMPENSATION_FAILED, COMPLETED


def test_compensating_pipeline_completes_forward_work(stub_broker, stub_worker):
    backend = LocalCompensationBackend()

    @dramatiq.actor
    def add_one(value):
        return value + 1

    @dramatiq.actor
    def compensate(value):
        raise AssertionError(f"unexpected compensation for {value!r}")

    pipe = compensating_pipeline(
        [
            add_one.message(1),
            (add_one.message(), compensate),
        ],
        backend=backend,
    )

    pipe.run()
    stub_broker.join(add_one.queue_name, fail_fast=False)
    stub_worker.join()

    state = pipe.get_state()
    assert state["status"] == COMPLETED
    assert state["results"] == [2, 3]
    assert state["compensated_steps"] == []


def test_compensating_pipeline_retries_before_starting_compensation(stub_broker, stub_worker):
    backend = LocalCompensationBackend()
    attempts = []

    @dramatiq.actor(max_retries=2, min_backoff=1, max_backoff=1)
    def eventually_succeeds(value):
        attempts.append(value)
        if len(attempts) == 1:
            raise RuntimeError("temporary failure")
        return value + 1

    @dramatiq.actor
    def compensate(value):
        raise AssertionError(f"unexpected compensation for {value!r}")

    pipe = compensating_pipeline(
        [(eventually_succeeds.message(1), compensate)],
        backend=backend,
    )

    pipe.run()
    stub_broker.join(eventually_succeeds.queue_name, fail_fast=False)
    stub_worker.join()

    assert len(attempts) == 2
    assert pipe.get_state()["status"] == COMPLETED


def test_compensating_pipeline_compensates_successful_steps_in_reverse(stub_broker, stub_worker):
    backend = LocalCompensationBackend()
    compensated = []

    @dramatiq.actor
    def reserve_order():
        return "order-1"

    @dramatiq.actor
    def charge_order(order_id):
        return f"payment-{order_id}"

    @dramatiq.actor(max_retries=0, min_backoff=1, max_backoff=1)
    def ship_order(payment_id):
        raise RuntimeError("shipping unavailable")

    @dramatiq.actor
    def refund_payment(payment_id):
        compensated.append(("payment", payment_id))

    @dramatiq.actor
    def cancel_order(order_id):
        compensated.append(("order", order_id))

    pipe = compensating_pipeline(
        [
            (reserve_order.message(), cancel_order),
            (charge_order.message(), refund_payment),
            ship_order.message(),
        ],
        backend=backend,
    )

    pipe.run()
    stub_broker.join(reserve_order.queue_name, fail_fast=False)
    stub_worker.join()

    state = pipe.get_state()
    assert state["status"] == COMPENSATED
    assert state["failed_step"] == 2
    assert state["results"][:2] == ["order-1", "payment-order-1"]
    assert state["compensated_steps"] == [1, 0]
    assert compensated == [
        ("payment", "payment-order-1"),
        ("order", "order-1"),
    ]


def test_compensation_steps_can_retry(stub_broker, stub_worker):
    backend = LocalCompensationBackend()
    refund_attempts = []
    compensated = []

    @dramatiq.actor
    def reserve_order():
        return "order-3"

    @dramatiq.actor(max_retries=0, min_backoff=1, max_backoff=1)
    def charge_order(order_id):
        raise RuntimeError("charge failed")

    @dramatiq.actor(max_retries=1, min_backoff=1, max_backoff=1)
    def cancel_order(order_id):
        refund_attempts.append(order_id)
        if len(refund_attempts) == 1:
            raise RuntimeError("temporary compensation failure")
        compensated.append(order_id)

    pipe = compensating_pipeline(
        [
            (reserve_order.message(), cancel_order),
            charge_order.message(),
        ],
        backend=backend,
    )

    pipe.run()
    stub_broker.join(reserve_order.queue_name, fail_fast=False)
    stub_worker.join()

    state = pipe.get_state()
    assert len(refund_attempts) == 2
    assert state["status"] == COMPENSATED
    assert state["compensated_steps"] == [0]
    assert compensated == ["order-3"]


def test_compensating_pipeline_can_resume_from_failed_compensation(stub_broker, stub_worker):
    backend = LocalCompensationBackend()
    payment_compensation_attempts = []
    compensated = []

    @dramatiq.actor
    def reserve_order():
        return "order-2"

    @dramatiq.actor
    def charge_order(order_id):
        return f"payment-{order_id}"

    @dramatiq.actor(max_retries=0, min_backoff=1, max_backoff=1)
    def ship_order(payment_id):
        raise RuntimeError("shipping unavailable")

    @dramatiq.actor(max_retries=0, min_backoff=1, max_backoff=1)
    def refund_payment(payment_id):
        payment_compensation_attempts.append(payment_id)
        if len(payment_compensation_attempts) == 1:
            raise RuntimeError("payment gateway unavailable")
        compensated.append(("payment", payment_id))

    @dramatiq.actor
    def cancel_order(order_id):
        compensated.append(("order", order_id))

    pipe = compensating_pipeline(
        [
            (reserve_order.message(), cancel_order),
            (charge_order.message(), refund_payment),
            ship_order.message(),
        ],
        backend=backend,
    )

    pipe.run()
    stub_broker.join(reserve_order.queue_name, fail_fast=False)
    stub_worker.join()

    failed_state = pipe.get_state()
    assert failed_state["status"] == COMPENSATION_FAILED
    assert failed_state["compensation_step"] == 1
    assert failed_state["error"]["type"] == "RuntimeError"
    assert failed_state["error"]["message"] == "payment gateway unavailable"
    assert compensated == []
    duplicate_resume = backend.resume(pipe.pipeline_id)
    assert duplicate_resume.message.message_id == failed_state["active_message_id"]
    assert pipe.get_state()["active_message_id"] == failed_state["active_message_id"]

    pipe.resume()
    stub_broker.join(reserve_order.queue_name, fail_fast=False)
    stub_worker.join()

    recovered_state = pipe.get_state()
    assert recovered_state["status"] == COMPENSATED
    assert recovered_state["compensation_step"] is None
    assert recovered_state["compensated_steps"] == [1, 0]
    assert compensated == [
        ("payment", "payment-order-2"),
        ("order", "order-2"),
    ]


def test_local_backend_rejects_stale_step_and_compensation_advances():
    backend = LocalCompensationBackend()

    @dramatiq.actor
    def noop(value=None):
        return value

    created = backend.create_pipeline(
        "pipeline-1",
        [
            {"message": noop.message(1).asdict(), "compensation": noop.message().asdict()},
            {"message": noop.message().asdict(), "compensation": noop.message().asdict()},
            {"message": noop.message().asdict(), "compensation": None},
        ],
    )
    first_message_id = created.message.message_id

    first_success = backend.succeed_step("pipeline-1", 0, first_message_id, "result-0")
    second_message_id = first_success.message.message_id
    second_success = backend.succeed_step("pipeline-1", 1, second_message_id, "result-1")
    third_message_id = second_success.message.message_id

    stale_first = backend.succeed_step("pipeline-1", 0, first_message_id, "stale-0")
    stale_second = backend.succeed_step("pipeline-1", 1, second_message_id, "stale-1")

    assert stale_first.state["active_message_id"] == third_message_id
    assert stale_second.state["active_message_id"] == third_message_id
    assert stale_first.state["results"] == ["result-0", "result-1", None]
    assert stale_second.message is None

    backend.fail_step("pipeline-1", 2, third_message_id, RuntimeError("final failure"))
    first_compensation_message_id = backend.get_state("pipeline-1")["active_message_id"]
    first_compensation = backend.succeed_compensation(
        "pipeline-1",
        1,
        first_compensation_message_id,
    )
    second_compensation_message_id = first_compensation.message.message_id

    stale_compensation = backend.succeed_compensation("pipeline-1", 1, first_compensation_message_id)
    assert stale_compensation.message is None
    assert stale_compensation.state["active_message_id"] == second_compensation_message_id
    assert stale_compensation.state["compensation_step"] == 0
