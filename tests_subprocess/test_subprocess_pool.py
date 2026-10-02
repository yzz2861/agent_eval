"""Integration tests for per-actor subprocess execution.

These tests live outside of tests/ because tests/conftest.py imports
optional dependencies (pylibmc) that are not installed in this
environment.  The module is intentionally self-contained: child
processes re-import it to find the actors, so everything they need is
declared at module level, exactly like a real deployment where actors
are registered on the global broker at import time.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest

import dramatiq
from dramatiq.brokers.stub import StubBroker
from dramatiq.middleware import Middleware
from dramatiq.results import Results
from dramatiq.results.backends import StubBackend
from dramatiq.subprocess_pool import (
    RemoteActorError,
    Subprocess,
    SubprocessCrashed,
    SubprocessPool,
    SubprocessProtocolError,
    SubprocessTimeout,
)
from dramatiq.worker import Worker

broker = StubBroker()
dramatiq.set_broker(broker)
broker.add_middleware(Subprocess())

result_backend = StubBackend()
broker.add_middleware(Results(backend=result_backend))

#: Exceptions seen by the parent process while processing messages.
recorded_exceptions = []


class ExceptionRecorder(Middleware):
    def after_process_message(self, broker, message, *, result=None, exception=None):
        if exception is not None:
            recorded_exceptions.append((message.actor_name, exception))


broker.add_middleware(ExceptionRecorder())

#: Hard time limit for the blocking actor, in seconds.
BLOCKING_TIMEOUT_SECS = 1.0


@dramatiq.actor(subprocess=True, store_results=True)
def normal_task(value):
    """A healthy actor that runs in a subprocess."""
    return {"pid": os.getpid(), "value": value * 2}


@dramatiq.actor(store_results=True)
def local_task(value):
    """A healthy actor that stays in the worker process."""
    return {"pid": os.getpid(), "value": value * 2}


@dramatiq.actor(subprocess=True, max_retries=0)
def failing_task():
    """An actor that raises inside the subprocess."""
    raise ValueError("boom from child")


@dramatiq.actor(subprocess=True, max_retries=0)
def crashing_task():
    """An actor whose subprocess dies without answering."""
    os._exit(42)


@dramatiq.actor(subprocess=True, subprocess_timeout=BLOCKING_TIMEOUT_SECS, max_retries=0)
def blocking_task(pid_file):
    """An actor that hangs forever and must be killed by the hard timeout."""
    with open(pid_file, "w") as f:
        f.write(str(os.getpid()))
    time.sleep(3600)


@dramatiq.actor(subprocess=True, subprocess_timeout=3600, max_retries=0)
def patient_blocking_task(pid_file):
    """An actor with a generous timeout, used to test worker shutdown."""
    with open(pid_file, "w") as f:
        f.write(str(os.getpid()))
    time.sleep(3600)


def wait_for_file(path, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(path):
            return True
        time.sleep(0.05)
    return False


def recorded(actor_name):
    matches = [e for n, e in recorded_exceptions if n == actor_name]
    assert matches, "expected an exception for %r" % actor_name
    return matches[0]


@pytest.fixture()
def worker():
    stub_worker = Worker(broker, worker_threads=4)
    stub_worker.start()
    try:
        yield stub_worker
    finally:
        stub_worker.stop()
        broker.flush_all()
        recorded_exceptions.clear()


def test_normal_task_runs_in_subprocess_others_stay_in_worker(worker):
    # Given a subprocess actor and a regular actor
    # When I send both a message
    subprocess_msg = normal_task.send(21)
    local_msg = local_task.send(11)
    broker.join(normal_task.queue_name)

    # Then the subprocess actor ran in a different process and its
    # result made it back to the parent
    result = subprocess_msg.get_result(backend=result_backend, block=True, timeout=10000)
    assert result["value"] == 42
    assert result["pid"] != os.getpid()

    # And the regular actor ran in the worker process as before
    local_result = local_msg.get_result(backend=result_backend, block=True, timeout=10000)
    assert local_result == {"pid": os.getpid(), "value": 22}


def test_failing_task_reports_remote_exception(worker):
    # Given an actor that raises inside the subprocess
    dead_before = len(broker.dead_letters)

    # When I send it a message
    failing_task.send()
    broker.join(failing_task.queue_name, fail_fast=False)

    # Then the parent sees a RemoteActorError carrying the child's
    # exception details, and the message is dead-lettered
    exc = recorded("failing_task")
    assert isinstance(exc, RemoteActorError)
    assert exc.error_type == "ValueError"
    assert "boom from child" in exc.error_message
    assert "ValueError" in exc.remote_traceback
    assert len(broker.dead_letters) == dead_before + 1


def test_crashing_task_reports_crash(worker):
    # Given an actor whose subprocess dies without answering
    # When I send it a message
    crashing_task.send()
    broker.join(crashing_task.queue_name, fail_fast=False)

    # Then the parent reports the crash instead of hanging
    exc = recorded("crashing_task")
    assert isinstance(exc, SubprocessCrashed)


def test_blocking_task_is_killed_at_hard_timeout(worker, tmp_path):
    # Given an actor that hangs forever with a 1s hard time limit
    pid_file = tmp_path / "blocked.pid"
    started = time.monotonic()

    # When I send it a message
    blocking_task.send(str(pid_file))
    broker.join(blocking_task.queue_name, fail_fast=False)
    elapsed = time.monotonic() - started

    # Then the message fails fast with SubprocessTimeout instead of
    # waiting for the 1h sleep to finish
    assert elapsed < 60
    exc = recorded("blocking_task")
    assert isinstance(exc, SubprocessTimeout)

    # And the child process was confirmed dead before the slot was
    # released
    assert wait_for_file(pid_file)
    child_pid = int(pid_file.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(child_pid, 0)

    # And the freed slot processes the next message normally: the
    # late result of the killed child cannot leak into it
    followup = normal_task.send(2)
    broker.join(normal_task.queue_name, fail_fast=False)
    assert followup.get_result(backend=result_backend, block=True, timeout=10000)["value"] == 4


def test_max_processes_limits_concurrency(tmp_path):
    # Given a worker that allows only one subprocess at a time
    stub_worker = Worker(broker, worker_threads=2, subprocess_max_processes=1)
    stub_worker.start()
    try:
        # When I send two messages to the blocking actor
        started = time.monotonic()
        blocking_task.send(str(tmp_path / "a.pid"))
        blocking_task.send(str(tmp_path / "b.pid"))
        broker.join(blocking_task.queue_name, fail_fast=False)
        elapsed = time.monotonic() - started

        # Then they were serialized: each one hits the 1s hard
        # timeout, so both together take at least 2 seconds
        assert elapsed >= BLOCKING_TIMEOUT_SECS * 2
    finally:
        stub_worker.stop()
        broker.flush_all()
        recorded_exceptions.clear()


def test_worker_shutdown_reclaims_children(tmp_path):
    # Given a worker running a subprocess actor with a huge timeout
    stub_worker = Worker(broker, worker_threads=1)
    stub_worker.start()
    pid_file = tmp_path / "shutdown.pid"
    patient_blocking_task.send(str(pid_file))
    assert wait_for_file(pid_file)
    child_pid = int(pid_file.read_text())

    # When the worker is shut down while the child is still running
    stub_worker.stop(timeout=3000)

    # Then the child process is reclaimed
    with pytest.raises(ProcessLookupError):
        os.kill(child_pid, 0)
    broker.flush_all()
    recorded_exceptions.clear()


def test_foreign_response_is_never_attributed_to_a_message(monkeypatch):
    # Given a child process that answers with someone else's message id
    # (this is what a late result from a previous message looks like)
    pool = SubprocessPool(broker, default_timeout=10)
    script = (
        "import sys;"
        "sys.stdin.readline();"
        "sys.stdout.write('{\"message_id\":\"some-other-message\",\"status\":\"ok\",\"result\":1}'+chr(10));"
        "sys.stdout.flush()"
    )

    def fake_spawn(module_name, module_file):
        return subprocess.Popen([sys.executable, "-c", script], stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    monkeypatch.setattr(pool, "_spawn", fake_spawn)

    # When the pool runs a message, then the foreign response is
    # rejected instead of being accepted as the message's result
    with pytest.raises(SubprocessProtocolError):
        pool.run(actor_name="normal_task", message_id="the-real-message", args=(1,), kwargs={})
