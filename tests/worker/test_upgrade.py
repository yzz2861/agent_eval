from itertools import count
from signal import SIGINT
from time import sleep
from unittest.mock import MagicMock, Mock, patch

import pytest

from sanic.worker.manager import MonitorCycle, WorkerManager
from sanic.worker.upgrade import UpgradeItemState, UpgradePhase


def fake_serve(): ...


def ack(worker_state, process_name, pid):
    worker_state[process_name] = {
        **worker_state[process_name],
        "state": "ACKED",
        "pid": pid,
    }


@pytest.fixture
def patched_os():
    with (
        patch("sanic.worker.process.os") as process_os,
        patch("sanic.worker.upgrade.os") as upgrade_os,
    ):
        yield process_os, upgrade_os


@pytest.fixture
def cluster(patched_os):
    pids = count(100)
    processes = []

    def factory(name, target, kwargs, daemon):
        process = MagicMock()
        process.pid = next(pids)
        process.is_alive.return_value = True
        processes.append(process)
        return process

    context = Mock()
    context.Process.side_effect = factory
    worker_state = {}
    manager = WorkerManager(
        3, fake_serve, {}, context, (Mock(), Mock()), worker_state
    )
    return manager, processes, worker_state


def test_rolling_upgrade_replaces_workers_one_at_a_time(cluster):
    manager, processes, worker_state = cluster
    op_id = manager.upgrade()

    assert op_id == "upgrade-1"
    assert manager.upgrader.phase is UpgradePhase.RUNNING
    assert len(manager.upgrader.items) == 3

    manager.upgrader.tick()
    items = manager.upgrader.items
    assert items[0].state is UpgradeItemState.STARTING
    assert items[1].state is UpgradeItemState.PENDING
    assert items[2].state is UpgradeItemState.PENDING
    assert len(processes) == 4

    # No ACK yet: nothing else is launched
    manager.upgrader.tick()
    assert items[0].state is UpgradeItemState.STARTING
    assert len(processes) == 4

    ack(worker_state, "Sanic-Server-0-G1-0", processes[3].pid)
    manager.upgrader.tick()
    assert items[0].state is UpgradeItemState.SWAPPED
    assert items[1].state is UpgradeItemState.STARTING
    assert "Server-0" not in manager.transient
    assert len(processes) == 5

    # The retired old process is reaped and its state cleaned up
    processes[0].is_alive.return_value = False
    manager.upgrader.tick()
    processes[0].join.assert_called_once()
    assert "Sanic-Server-0-0" not in worker_state

    ack(worker_state, "Sanic-Server-1-G1-0", processes[4].pid)
    manager.upgrader.tick()
    assert items[1].state is UpgradeItemState.SWAPPED
    assert items[2].state is UpgradeItemState.STARTING

    ack(worker_state, "Sanic-Server-2-G1-0", processes[5].pid)
    manager.upgrader.tick()
    assert manager.upgrader.phase is UpgradePhase.COMPLETED
    assert manager.upgrader.generation == 1
    assert set(manager.transient) == {
        "Server-0-G1",
        "Server-1-G1",
        "Server-2-G1",
    }

    status = manager.upgrade_status()
    assert status["phase"] == "COMPLETED"
    assert status["completed"] == [
        "Sanic-Server-0-0",
        "Sanic-Server-1-0",
        "Sanic-Server-2-0",
    ]


def test_duplicate_upgrade_request_does_not_stack(cluster):
    manager, processes, _ = cluster
    op_id = manager.upgrade()
    manager.upgrader.tick()

    again = manager.upgrade()
    manager.upgrader.tick()

    assert again == op_id
    assert len(manager.upgrader.items) == 3
    # 3 original processes + 1 in-flight replacement, no second round
    assert len(processes) == 4


def test_max_concurrent_limits_in_flight_replacements(cluster):
    manager, processes, _ = cluster
    manager.upgrade(max_concurrent=2)
    manager.upgrader.tick()
    manager.upgrader.tick()

    assert len(processes) == 5
    states = [item.state for item in manager.upgrader.items]
    assert states == [
        UpgradeItemState.STARTING,
        UpgradeItemState.STARTING,
        UpgradeItemState.PENDING,
    ]


def test_crashed_new_process_stops_rollout(cluster, patched_os):
    process_os, _ = patched_os
    manager, processes, worker_state = cluster
    manager.upgrade()
    manager.upgrader.tick()
    ack(worker_state, "Sanic-Server-0-G1-0", processes[3].pid)
    manager.upgrader.tick()

    items = manager.upgrader.items
    assert items[0].state is UpgradeItemState.SWAPPED
    assert items[1].state is UpgradeItemState.STARTING

    # The second new-generation process crashes during startup
    crashed = processes[4]
    crashed.is_alive.return_value = False
    crashed.exitcode = 1
    manager.upgrader.tick()

    assert manager.upgrader.phase is UpgradePhase.FAILED
    assert "Sanic-Server-1-G1-0" in manager.upgrader.failure_reason
    assert items[1].state is UpgradeItemState.FAILED
    assert items[2].state is UpgradeItemState.CANCELLED

    # The healthy old generation is kept and never terminated
    assert "Server-1" in manager.transient
    assert "Server-2" in manager.transient
    assert process_os.kill.call_count == 2
    process_os.kill.assert_any_call(100, SIGINT)  # swapped old Server-0
    process_os.kill.assert_any_call(crashed.pid, SIGINT)  # cleanup

    # The crashed child is reaped and fully cleaned up
    manager.upgrader.tick()
    crashed.join.assert_called_once()
    assert "Server-1-G1" not in manager.transient
    assert "Sanic-Server-1-G1-0" not in worker_state
    assert manager.upgrader.generation == 0

    status = manager.upgrade_status()
    assert status["phase"] == "FAILED"
    assert status["completed"] == ["Sanic-Server-0-0"]
    assert status["items"][1]["failure_reason"]


def test_unacknowledged_new_process_stops_rollout(cluster):
    manager, processes, _ = cluster
    manager.upgrade(ack_timeout=0.01)
    manager.upgrader.tick()
    assert manager.upgrader.items[0].state is UpgradeItemState.STARTING

    sleep(0.02)
    manager.upgrader.tick()

    assert manager.upgrader.phase is UpgradePhase.FAILED
    assert "did not ACK" in manager.upgrader.failure_reason


def test_failed_readiness_check_stops_rollout(cluster):
    manager, processes, worker_state = cluster
    manager.upgrade(
        readiness_check=lambda process, state: False, ack_timeout=0.01
    )
    manager.upgrader.tick()
    ack(worker_state, "Sanic-Server-0-G1-0", processes[3].pid)
    manager.upgrader.tick()

    # ACKed but not ready: the old process is not retired yet
    assert manager.upgrader.items[0].state is UpgradeItemState.STARTING
    assert "Server-0" in manager.transient

    sleep(0.02)
    manager.upgrader.tick()
    assert manager.upgrader.phase is UpgradePhase.FAILED
    assert "Readiness check" in manager.upgrader.failure_reason


def test_raising_readiness_check_stops_rollout(cluster):
    manager, processes, worker_state = cluster

    def readiness_check(process, state):
        raise RuntimeError("readiness exploded")

    manager.upgrade(readiness_check=readiness_check)
    manager.upgrader.tick()
    ack(worker_state, "Sanic-Server-0-G1-0", processes[3].pid)
    manager.upgrader.tick()

    assert manager.upgrader.phase is UpgradePhase.FAILED
    assert "readiness exploded" in manager.upgrader.failure_reason


def test_stale_same_name_state_does_not_trick_upgrader(cluster):
    manager, processes, worker_state = cluster
    # A stale ACKED state from another process generation under the
    # same name must not be mistaken for the new process being ready
    worker_state["Sanic-Server-0-G1-0"] = {
        "server": True,
        "state": "ACKED",
        "pid": 999999,
    }
    manager.upgrade()
    manager.upgrader.tick()

    item = manager.upgrader.items[0]
    assert item.state is UpgradeItemState.STARTING
    assert item.new_pid == processes[3].pid
    assert "Server-0" in manager.transient

    # An ACKED state with the wrong pid is also ignored
    ack(worker_state, "Sanic-Server-0-G1-0", 999999)
    manager.upgrader.tick()
    assert item.state is UpgradeItemState.STARTING

    ack(worker_state, "Sanic-Server-0-G1-0", processes[3].pid)
    manager.upgrader.tick()
    assert item.state is UpgradeItemState.SWAPPED


def test_status_is_published_to_worker_state(cluster):
    manager, _, worker_state = cluster
    op_id = manager.upgrade()

    status = worker_state["Sanic-Upgrade"]
    assert status["operation_id"] == op_id
    assert status["phase"] == "RUNNING"
    assert status["generation"] == 0
    assert status["target_generation"] == 1
    assert status["failure_reason"] is None
    assert len(status["items"]) == 3
    assert manager.upgrade_status()["operation_id"] == op_id


def test_monitor_message_triggers_upgrade(cluster):
    manager, _, _ = cluster
    cycle = manager._handle_message("__UPGRADE__:2")

    assert cycle is MonitorCycle.CONTINUE
    assert manager.upgrader.phase is UpgradePhase.RUNNING
    assert manager.upgrader.max_concurrent == 2


def test_upgrade_without_server_processes_raises(cluster):
    manager, processes, _ = cluster
    for process in processes:
        process.is_alive.return_value = False

    with pytest.raises(RuntimeError, match="No server processes"):
        manager.upgrade()


def test_upgrade_with_invalid_max_concurrent_raises(cluster):
    manager, _, _ = cluster
    with pytest.raises(ValueError, match="max_concurrent"):
        manager.upgrade(max_concurrent=0)
