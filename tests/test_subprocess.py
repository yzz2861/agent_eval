from __future__ import annotations

import os
import time
from contextlib import contextmanager
from types import SimpleNamespace
from unittest import mock

import dramatiq
import pytest
from dramatiq.middleware.time_limit import TimeLimitExceeded
from dramatiq.subprocess import SubprocessCrashed, SubprocessRequest, _SubprocessWorker
from dramatiq.worker import Worker

from .subprocess_actors import (
    SubprocessTestError,
    blocking_subprocess,
    capture,
    crashing_subprocess,
    failing_subprocess,
    normal_subprocess,
    reset_capture,
    subprocess_broker,
    tracked_subprocess,
)


@contextmanager
def subprocess_worker(**kwargs):
    worker = Worker(subprocess_broker, worker_timeout=10, worker_threads=1, subprocess_processes=1, **kwargs)
    worker.start()
    try:
        yield worker
    finally:
        worker.stop()


def test_subprocess_normal_and_in_process_actors_can_coexist() -> None:
    in_process_pids = []

    @dramatiq.actor(broker=subprocess_broker, queue_name="subprocess")
    def in_process_actor() -> None:
        in_process_pids.append(os.getpid())

    subprocess_broker.flush_all()
    reset_capture()

    with subprocess_worker() as stub_worker:
        normal_subprocess.send(7)
        in_process_actor.send()
        subprocess_broker.join(normal_subprocess.queue_name)
        child_pid = capture.results[0]["pid"]

    result = capture.results[0]
    assert result["value"] == 7
    assert result["pid"] != os.getpid()
    assert in_process_pids == [os.getpid()]
    assert not stub_worker.subprocess_pool.workers
    with pytest.raises(ProcessLookupError):
        os.kill(child_pid, 0)


def test_subprocess_actor_returns_exception_information() -> None:
    subprocess_broker.flush_all()
    reset_capture()

    with subprocess_worker():
        failing_subprocess.send()
        subprocess_broker.join(failing_subprocess.queue_name, fail_fast=False)

    exception = capture.exceptions[0]
    assert isinstance(exception, SubprocessTestError)
    assert str(exception) == "boom"
    assert exception.subprocess_traceback
    assert subprocess_broker.dead_letters_by_queue[failing_subprocess.queue_name]


def test_blocked_subprocess_is_killed_before_slot_is_released() -> None:
    subprocess_broker.flush_all()
    reset_capture()

    with subprocess_worker() as stub_worker:
        normal_subprocess.send(1)
        subprocess_broker.join(normal_subprocess.queue_name)
        first_pid = capture.results[0]["pid"]

        blocking_subprocess.send()
        subprocess_broker.join(blocking_subprocess.queue_name, fail_fast=False, timeout=5000)
        stub_worker.join()

        exception = capture.exceptions[-1]
        assert isinstance(exception, TimeLimitExceeded)

        normal_subprocess.send(2)
        subprocess_broker.join(normal_subprocess.queue_name, timeout=5000, fail_fast=False)
        stub_worker.join()
        replacement_pid = capture.results[-1]["pid"]

    assert first_pid != replacement_pid
    assert replacement_pid != os.getpid()
    with pytest.raises(ProcessLookupError):
        os.kill(first_pid, 0)


def test_crashed_subprocess_is_reaped_before_slot_is_released() -> None:
    subprocess_broker.flush_all()
    reset_capture()

    with subprocess_worker() as stub_worker:
        normal_subprocess.send(1)
        subprocess_broker.join(normal_subprocess.queue_name)
        first_pid = capture.results[0]["pid"]

        crashing_subprocess.send()
        subprocess_broker.join(crashing_subprocess.queue_name, fail_fast=False, timeout=5000)
        stub_worker.join()

        assert isinstance(capture.exceptions[-1], SubprocessCrashed)

        normal_subprocess.send(2)
        subprocess_broker.join(normal_subprocess.queue_name, timeout=5000, fail_fast=False)
        stub_worker.join()
        replacement_pid = capture.results[-1]["pid"]

    assert first_pid != replacement_pid
    with pytest.raises(ProcessLookupError):
        os.kill(first_pid, 0)


def test_late_response_cannot_be_attributed_to_another_message(monkeypatch: pytest.MonkeyPatch) -> None:
    worker = object.__new__(_SubprocessWorker)
    worker.process = mock.Mock(pid=123)
    worker.pool = SimpleNamespace(logger=mock.Mock())

    class Connection:
        def send_bytes(self, data: bytes) -> None: ...
        def recv_bytes(self) -> bytes:
            return b""
        def poll(self, timeout: float | None) -> bool:
            return True

    worker.parent_connection = Connection()
    monkeypatch.setattr(
        worker.parent_connection,
        "recv_bytes",
        lambda: b'{"message_id":"old-message","status":"ok","result":1,"exception":null,"traceback":null}',
    )

    request = SubprocessRequest(
        message_id="new-message",
        actor_module="tests.subprocess_actors",
        actor_name="normal_subprocess",
        actor_qualname="normal_subprocess",
        args=(1,),
        kwargs={},
    )
    with pytest.raises(SubprocessCrashed, match="old-message"):
        worker.execute(request, timeout=1)


def test_subprocess_concurrency_is_limited() -> None:
    subprocess_broker.flush_all()
    reset_capture()

    started = time.monotonic()
    with subprocess_worker():
        tracked_subprocess.send(1, 0.3)
        tracked_subprocess.send(2, 0.3)
        subprocess_broker.join(tracked_subprocess.queue_name)
        elapsed = time.monotonic() - started

    assert len(capture.results) == 2
    assert len(set(capture.results)) == 1
    assert elapsed >= 0.55
