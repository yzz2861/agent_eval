"""Rolling worker upgrade demo.

Runs the real sanic.worker.manager.WorkerManager with three server
workers backed by a tiny queue-based echo service (queues are used
instead of TCP so the demo also runs in network-restricted
sandboxes), then performs a rolling upgrade in which the **second**
new-generation worker crashes on startup.

While the upgrade rolls out, a hammer thread continuously sends
requests and every one of them must be answered, proving the
available capacity never drops below the configured worker count.
Afterwards the demo verifies that:

- the operation has a stable id and reported a failure reason,
- the first item completed, the second failed, the third cancelled,
- the still-healthy old generation keeps serving (3 workers),
- the crashed child was cleaned up, and
- no orphaned or zombie processes remain.

Run with: python examples/rolling_upgrade.py
"""

import os
import queue
import sys
import threading
import time

from multiprocessing import Pipe, get_context

from sanic.worker.manager import WorkerManager


NUM_WORKERS = 3
MAX_CONCURRENT = 1
REQUEST_INTERVAL = 0.005
UPGRADE_TIMEOUT = 60.0
FAIL_ENV = "DEMO_FAIL_WORKER"


def echo_serve(request_queue, response_queue, state_queue, **_):
    """Tiny echo service running inside a managed worker process."""
    name = os.environ.get("SANIC_WORKER_NAME", "?")
    if os.environ.get(FAIL_ENV) == name:
        # Simulate a hard crash during startup of the new generation
        os._exit(1)
    pid = os.getpid()
    state_queue.put((name, {"state": "ACKED", "pid": pid}))
    try:
        while True:
            try:
                item = request_queue.get(timeout=0.2)
            except queue.Empty:
                continue
            if item is None:
                break
            response_queue.put((item, name, pid))
    except KeyboardInterrupt:
        pass


def is_alive(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def main():
    ctx = get_context("spawn")
    request_queue = ctx.Queue()
    response_queue = ctx.Queue()
    state_queue = ctx.Queue()
    monitor_sub, monitor_pub = Pipe(True)
    worker_state = {}

    manager = WorkerManager(
        NUM_WORKERS,
        echo_serve,
        {
            "request_queue": request_queue,
            "response_queue": response_queue,
            "state_queue": state_queue,
        },
        ctx,
        (monitor_pub, monitor_sub),
        worker_state,
    )

    # Children report their state (ACK etc.) through the state queue;
    # in a real deployment this is the shared worker_state dict.
    stop_collect = threading.Event()

    def collect_states():
        while not stop_collect.is_set():
            try:
                name, state = state_queue.get(timeout=0.2)
            except queue.Empty:
                continue
            worker_state[name] = {**worker_state.get(name, {}), **state}

    collector = threading.Thread(target=collect_states, daemon=True)
    collector.start()

    errors = []

    def run_manager():
        try:
            manager.run()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    runner = threading.Thread(target=run_manager, daemon=True)
    runner.start()

    # Wait for the initial generation to come online
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        acked = [
            value
            for value in worker_state.values()
            if isinstance(value, dict)
            and value.get("server")
            and value.get("state") == "ACKED"
        ]
        if len(acked) == NUM_WORKERS:
            break
        time.sleep(0.1)
    else:
        raise RuntimeError("Initial workers failed to start")
    print(f"Initial generation serving: {NUM_WORKERS} workers")

    # Continuously hammer the service for the whole upgrade
    sent = {}
    received = {}
    stop_hammer = threading.Event()

    def hammer():
        seq = 0
        while not stop_hammer.is_set():
            sent[seq] = time.monotonic()
            request_queue.put(seq)
            seq += 1
            time.sleep(REQUEST_INTERVAL)

    def collect_responses():
        while not stop_hammer.is_set():
            try:
                item, name, pid = response_queue.get(timeout=0.2)
            except queue.Empty:
                continue
            received[item] = (name, pid)

    hammer_thread = threading.Thread(target=hammer, daemon=True)
    response_thread = threading.Thread(target=collect_responses, daemon=True)
    hammer_thread.start()
    response_thread.start()

    # The second new-generation worker will crash on startup
    crashed_name = "Sanic-Server-1-G1-0"
    os.environ[FAIL_ENV] = crashed_name

    op_id = manager.upgrade(max_concurrent=MAX_CONCURRENT)
    duplicate = manager.upgrade(max_concurrent=MAX_CONCURRENT)
    assert duplicate == op_id, "duplicate request stacked a second round"
    print(f"Upgrade started: {op_id} (duplicate request returned same id)")

    def serving_count():
        return sum(
            1
            for value in worker_state.values()
            if isinstance(value, dict)
            and value.get("server")
            and value.get("state") == "ACKED"
            and is_alive(value.get("pid") or -1)
        )

    min_serving = NUM_WORKERS
    deadline = time.monotonic() + UPGRADE_TIMEOUT
    while time.monotonic() < deadline:
        min_serving = min(min_serving, serving_count())
        if manager.upgrade_status()["phase"] != "RUNNING":
            break
        time.sleep(0.1)
    else:
        raise RuntimeError("Upgrade did not finish in time")
    min_serving = min(min_serving, serving_count())
    assert min_serving >= NUM_WORKERS, (
        f"capacity dropped to {min_serving} workers during the upgrade"
    )
    print(f"Capacity never dropped below {min_serving} workers")

    # Let in-flight responses arrive, then stop hammering
    time.sleep(0.5)
    stop_hammer.set()
    hammer_thread.join()
    response_thread.join()

    status = manager.upgrade_status()
    print("Final upgrade status:")
    for key in ("operation_id", "phase", "generation", "failure_reason"):
        print(f"  {key}: {status[key]}")
    for item in status["items"]:
        print(
            f"  - {item['old_process']} -> {item['new_process']}: "
            f"{item['state']}"
        )

    assert status["operation_id"] == op_id
    assert status["phase"] == "FAILED"
    assert crashed_name in status["failure_reason"]
    assert status["completed"] == ["Sanic-Server-0-0"]
    assert [item["state"] for item in status["items"]] == [
        "SWAPPED",
        "FAILED",
        "CANCELLED",
    ]
    assert status["generation"] == 0

    # Capacity: every request sent during the upgrade was answered
    missing = set(sent) - set(received)
    assert not missing, f"{len(missing)} requests went unanswered"
    responders = {pid for _, pid in received.values()}
    print(
        f"Capacity check: {len(received)}/{len(sent)} requests answered "
        f"by {len(responders)} distinct worker processes"
    )

    # The healthy old generation plus the swapped-in worker still serve
    serving = {
        value["pid"]
        for value in worker_state.values()
        if isinstance(value, dict)
        and value.get("server")
        and value.get("state") == "ACKED"
        and is_alive(value.get("pid") or -1)
    }
    assert len(serving) == NUM_WORKERS, (
        f"expected {NUM_WORKERS} serving workers, found {serving}"
    )
    print(f"Still serving with {len(serving)} workers: {sorted(serving)}")

    # Shut everything down and confirm no orphans remain
    all_pids = (
        set(responders)
        | {item["old_pid"] for item in status["items"] if item["old_pid"]}
        | {item["new_pid"] for item in status["items"] if item["new_pid"]}
    )
    manager.shutdown()
    monitor_pub.send(None)
    runner.join(timeout=30)
    assert not runner.is_alive(), "manager did not shut down"
    assert not errors, f"manager raised: {errors}"

    orphans = [pid for pid in all_pids if is_alive(pid)]
    assert not orphans, f"orphaned processes remain: {orphans}"
    print(f"Orphan check: all {len(all_pids)} child processes reaped")

    stop_collect.set()
    collector.join()
    print("DEMO PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
