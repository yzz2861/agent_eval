from __future__ import annotations

import multiprocessing
import os

from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Pipe
from signal import SIG_DFL, SIGINT, SIGTERM, getsignal
from signal import signal as set_signal
from time import monotonic, sleep
from unittest.mock import Mock

import pytest

from sanic.worker.constants import ProcessState
from sanic.worker.manager import WorkerManager
from sanic.worker.upgrade import (
    UpgradeItem,
    UpgradeOperation,
    UpgradeStatus,
)


class FakeProcess:
    def __init__(self, name, pid, *, fail=False):
        self.name = name
        self.pid = pid
        self.fail = fail
        self.generation = 0
        self.alive = True
        self.state = {"server": True, "state": "ACKED"}
        self.started = False
        self.committed = False
        self.rolled_back = False

    def begin_startup_first(self, **config):
        self.started = True
        self.generation += 1
        if self.fail:
            self.alive = False
            raise RuntimeError("candidate exited with code 1")

    def is_alive(self):
        return self.alive

    def current_state(self):
        return dict(self.state)

    def commit_startup_first(self):
        self.committed = True

    def rollback_startup_first(self):
        self.rolled_back = True
        self.alive = True
        self.generation -= 1


def make_operation(processes, max_unavailable=1, readiness_check=None):
    return UpgradeOperation(
        operation_id="stable-upgrade",
        items=[UpgradeItem(process=process) for process in processes],
        max_unavailable=max_unavailable,
        timeout=0.1,
        readiness_check=readiness_check or (lambda process, state: True),
    )


def test_upgrade_stops_after_failure_and_rolls_back():
    first = FakeProcess("first", 1)
    second = FakeProcess("second", 2, fail=True)
    third = FakeProcess("third", 3)
    operation = make_operation([first, second, third])

    operation.run()

    assert operation.status is UpgradeStatus.FAILED
    assert operation.error == "candidate exited with code 1"
    assert first.committed is True
    assert second.rolled_back is True
    assert third.started is False
    status = operation.snapshot({"first": 1, "second": 0, "third": 0})
    assert status["completed"] == ["first"]
    assert status["failed"] == {"second": "candidate exited with code 1"}
    assert status["pending"] == ["third"]
    assert status["generations"] == {
        "first": 1,
        "second": 0,
        "third": 0,
    }


def test_upgrade_respects_concurrency_limit():
    processes = [FakeProcess("one", 1), FakeProcess("two", 2)]
    operation = make_operation(processes, max_unavailable=2)

    operation.run()

    assert operation.status is UpgradeStatus.COMPLETED
    assert all(process.committed for process in processes)


def test_default_readiness_requires_serving_for_servers():
    assert (
        UpgradeOperation._default_ready(
            {"state": ProcessState.ACKED.name, "server": True}
        )
        is False
    )
    assert (
        UpgradeOperation._default_ready(
            {
                "state": ProcessState.ACKED.name,
                "server": True,
                "serving": True,
            }
        )
        is True
    )
    assert (
        UpgradeOperation._default_ready(
            {"state": ProcessState.ACKED.name, "server": False}
        )
        is True
    )


def test_manager_returns_same_operation_for_duplicate_requests():
    process = Mock()
    process.name = "Sanic-Server-0-0"
    process.restartable = True
    process.generation = 0
    context = Mock()
    context.Process.return_value = process
    publisher, subscriber = Pipe()
    manager = WorkerManager(
        1,
        capacity_worker,
        {},
        context,
        (publisher, subscriber),
        {},
    )

    first = manager.upgrade(operation_id="stable-id", timeout=0.01)
    second = manager.upgrade(operation_id="stable-id", timeout=0.01)

    assert first is second
    status = manager.upgrade_status("stable-id")
    assert status["id"] == "stable-id"
    assert status["targets"] == ["Sanic-Server-0-0"]


def capacity_worker(
    *,
    workers,
    readiness,
    candidate_started,
    config=None,
):
    set_signal(SIGINT, SIG_DFL)
    set_signal(SIGTERM, SIG_DFL)
    generation = int((config or {}).get("UPGRADE_GENERATION", 0))
    slot = int(os.environ["SANIC_WORKER_NAME"].split("-")[2])
    ready = readiness[slot]
    worker = workers[slot]
    last_sequence = worker["response_sequence"].value

    if slot == 1 and generation == 1:
        candidate_started.value = 2
        deadline = monotonic() + 3
        while monotonic() < deadline:
            if candidate_started.value == 3:
                break
            sleep(0.01)
        os._exit(1)

    ready.value = 1
    while True:
        number = worker["request_sequence"].value
        if number <= last_sequence:
            sleep(0.02)
            continue
        last_sequence = number
        sleep(worker["request_delay"].value / 1000)
        worker["response_sequence"].value = number
        worker["response_pid"].value = os.getpid()
        worker["response_generation"].value = generation


def send_request(workers, slot, delay=0.0):
    worker = workers[slot]
    sequence = worker["sequence"]
    worker["sequence"] += 1
    worker["request_sequence"].value = sequence
    worker["request_delay"].value = int(delay * 1000)
    deadline = monotonic() + 3
    response_sequence = 0
    while monotonic() < deadline:
        response_sequence = worker["response_sequence"].value
        if response_sequence == sequence:
            break
        sleep(0.01)
    pid = worker["response_pid"].value
    response_generation = worker["response_generation"].value
    assert response_sequence == sequence
    return {
        "slot": slot,
        "pid": pid,
        "generation": response_generation,
    }


@pytest.mark.skipif(
    not hasattr(multiprocessing, "get_context"),
    reason="Requires multiprocessing contexts",
)
def test_second_new_worker_failure_preserves_capacity():
    ctx = multiprocessing.get_context("fork")
    publisher, subscriber = Pipe(True)
    readiness = [ctx.Value("i", 0) for _ in range(3)]
    candidate_started = ctx.Value("i", 0)
    candidate_started.value = 1
    workers = []
    for _ in range(3):
        workers.append(
            {
                "request_sequence": ctx.Value("i", 0),
                "request_delay": ctx.Value("i", 0),
                "response_sequence": ctx.Value("i", 0),
                "response_pid": ctx.Value("i", 0),
                "response_generation": ctx.Value("i", 0),
                "sequence": 0,
                "last_sequence": 0,
            }
        )

    previous_signals = (
        getsignal(SIGINT),
        getsignal(SIGTERM),
    )
    manager = WorkerManager(
        3,
        capacity_worker,
        {
            "workers": [
                {
                    key: worker[key]
                    for key in (
                        "request_sequence",
                        "request_delay",
                        "response_sequence",
                        "response_pid",
                        "response_generation",
                    )
                }
                for worker in workers
            ],
            "readiness": readiness,
            "candidate_started": candidate_started,
        },
        ctx,
        (publisher, subscriber),
        {},
    )

    try:
        ordered_processes = sorted(
            manager.transient_processes,
            key=lambda process: process.name,
        )
        manager.start()
        deadline = monotonic() + 3
        while monotonic() < deadline:
            if all(value.value for value in readiness):
                break
            sleep(0.01)
        assert all(value.value for value in readiness)

        for process in ordered_processes:
            process.set_state(ProcessState.ACKED, force=True)
            process.worker_state[process.state_name]["serving"] = True

        initial_pids = [process.pid for process in ordered_processes]
        operation = manager.upgrade(
            operation_id="capacity-repro",
            max_unavailable=1,
            timeout=0.05,
            config={"upgrade_generation": 1},
            readiness_check=lambda process, state: (
                process.is_alive()
                and (
                    int(process.name.split("-")[2]) != 1
                    or state.get("generation") != 1
                )
            ),
        )

        fast_results = []
        fast_errors = []

        def send_fast_pairs():
            while (
                operation.status is UpgradeStatus.RUNNING
                and candidate_started.value == 1
            ):
                try:
                    with ThreadPoolExecutor(max_workers=2) as executor:
                        futures = [
                            executor.submit(send_request, workers, 0, 0.02)
                        ]
                        fast_results.extend(
                            future.result() for future in futures
                        )
                except Exception as exc:
                    fast_errors.append(exc)
                sleep(0.02)

        load_thread = ThreadPoolExecutor(max_workers=1)
        load_future = load_thread.submit(send_fast_pairs)

        deadline = monotonic() + 3
        while monotonic() < deadline and candidate_started.value == 1:
            sleep(0.01)
        assert candidate_started.value == 2
        load_future.result(timeout=3)
        assert fast_results
        assert not fast_errors

        with ThreadPoolExecutor(max_workers=2) as executor:
            slow_slot0 = executor.submit(send_request, workers, 0, 0.3)
            candidate_started.value = 3
            slow_slot1 = executor.submit(send_request, workers, 1, 0.3)
            slow_results = [
                slow_slot0.result(timeout=3),
                slow_slot1.result(timeout=3),
            ]

        deadline = monotonic() + 3
        while monotonic() < deadline:
            if operation.status is UpgradeStatus.FAILED:
                break
            sleep(0.01)
        load_future.result(timeout=3)
        load_thread.shutdown()

        assert operation.status is UpgradeStatus.FAILED
        assert fast_results
        assert not fast_errors
        assert {result["slot"] for result in slow_results} == {0, 1}
        assert {result["generation"] for result in slow_results} == {0, 1}

        status = manager.upgrade_status("capacity-repro")
        assert status["completed"] == ["Sanic-Server-0-0"]
        assert status["pending"] == ["Sanic-Server-2-0"]
        assert set(status["failed"]) == {"Sanic-Server-1-0"}
        assert status["generations"] == {
            "Sanic-Server-0-0": 1,
            "Sanic-Server-1-0": 0,
            "Sanic-Server-2-0": 0,
        }

        processes_by_name = {
            process.name: process for process in ordered_processes
        }
        failed_item = next(
            item for item in operation.items if item.name == "Sanic-Server-1-0"
        )
        candidate_pid = failed_item.candidate_pid
        post_failure = [send_request(workers, slot) for slot in (0, 1, 2)]
        assert {result["slot"] for result in post_failure} == {0, 1, 2}
        assert processes_by_name["Sanic-Server-0-0"].pid != initial_pids[0]
        assert processes_by_name["Sanic-Server-1-0"].pid == initial_pids[1]
        assert processes_by_name["Sanic-Server-2-0"].pid == initial_pids[2]

        with pytest.raises(ProcessLookupError):
            os.kill(candidate_pid, 0)
        with pytest.raises(ProcessLookupError):
            os.kill(initial_pids[0], 0)
    finally:
        manager.shutdown()
        manager.join()
        manager.cleanup()
        set_signal(SIGINT, previous_signals[0])
        set_signal(SIGTERM, previous_signals[1])

    remaining_children = {
        child.pid for child in multiprocessing.active_children()
    }
    assert not remaining_children.intersection(
        set(initial_pids) | {candidate_pid}
    )
