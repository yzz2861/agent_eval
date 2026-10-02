from __future__ import annotations

import os
import time

import dramatiq
from dramatiq.brokers.stub import StubBroker
from dramatiq.middleware import Middleware


class SubprocessTestError(Exception):
    pass


class CaptureMiddleware(Middleware):
    def __init__(self) -> None:
        self.results = []
        self.exceptions = []

    def after_process_message(self, broker, message, *, result=None, exception=None):
        self.results.append(result)
        self.exceptions.append(exception)


subprocess_broker = StubBroker(middleware=[m() for m in dramatiq.middleware.default_middleware] + [CaptureMiddleware()])
capture = subprocess_broker.middleware[-1]


def reset_capture() -> None:
    capture.results.clear()
    capture.exceptions.clear()


@dramatiq.actor(
    broker=subprocess_broker,
    queue_name="subprocess",
    subprocess=True,
    max_retries=0,
)
def normal_subprocess(value: int) -> dict[str, int]:
    return {"value": value, "pid": os.getpid()}


@dramatiq.actor(
    broker=subprocess_broker,
    queue_name="subprocess",
    subprocess=True,
    max_retries=0,
)
def failing_subprocess() -> None:
    raise SubprocessTestError("boom")


@dramatiq.actor(
    broker=subprocess_broker,
    queue_name="subprocess",
    subprocess=True,
    max_retries=0,
    time_limit=200,
)
def blocking_subprocess() -> None:
    while True:
        time.sleep(1)


@dramatiq.actor(
    broker=subprocess_broker,
    queue_name="subprocess",
    subprocess=True,
    max_retries=0,
)
def crashing_subprocess() -> None:
    os._exit(7)


@dramatiq.actor(
    broker=subprocess_broker,
    queue_name="subprocess",
    subprocess=True,
    max_retries=0,
)
def tracked_subprocess(run_id: int, duration: float) -> int:
    pid = os.getpid()
    started = time.monotonic()
    time.sleep(duration)
    return pid
