from unittest.mock import Mock

from sanic.worker.process import ProcessState, WorkerProcess


def test_startup_first_generation_uses_isolated_state_key():
    current_process = Mock()
    current_process.pid = 200
    replacement_process = Mock()
    replacement_process.pid = 201
    factory = Mock(side_effect=[current_process, replacement_process])
    worker_state = {}
    worker = WorkerProcess(
        factory,
        "Sanic-Server-0-0",
        "Srv 0",
        lambda **_: None,
        {},
        worker_state,
        restartable=True,
    )

    worker.set_state(ProcessState.ACKED, force=True)
    worker_state["Sanic-Server-0-0"]["serving"] = True
    replacement_state_name = worker.begin_startup_first()
    replacement_process.is_alive.return_value = False
    replacement_process.exitcode = 1
    worker.rollback_startup_first()

    assert replacement_state_name == ("Sanic-Server-0-0#generation-1")
    assert replacement_state_name not in worker_state
    assert worker.state_name == "Sanic-Server-0-0"
    assert worker.generation == 0
    assert worker_state["Sanic-Server-0-0"]["state"] == "ACKED"
    assert worker_state["Sanic-Server-0-0"]["serving"] is True
