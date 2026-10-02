from __future__ import annotations

import dataclasses
import importlib
import json
import multiprocessing
import queue
import threading
import time
import traceback
from typing import TYPE_CHECKING, Any, NoReturn, Optional

if TYPE_CHECKING:
    from .actor import Actor
    from .broker import Broker
from .errors import ActorNotFound, DramatiqError
from .logging import get_logger
from .middleware.time_limit import TimeLimitExceeded

DEFAULT_SUBPROCESS_TIME_LIMIT = 600_000


class SubprocessError(DramatiqError):
    """Base class for errors raised by the subprocess executor."""


class SubprocessCrashed(SubprocessError):
    """Raised when an actor subprocess exits or its protocol fails."""


class SubprocessTimeout(TimeLimitExceeded):
    """Raised in the parent when an actor subprocess exceeds its limit."""


@dataclasses.dataclass(frozen=True, slots=True)
class SubprocessRequest:
    message_id: str
    actor_module: str
    actor_name: str
    actor_qualname: str
    args: tuple[Any, ...]
    kwargs: dict[str, Any]


@dataclasses.dataclass(frozen=True, slots=True)
class SubprocessResponse:
    message_id: str
    status: str = "ok"
    result: Any = None
    exception: Optional[dict[str, Any]] = None
    traceback: Optional[str] = None


class _SubprocessWorker:
    def __init__(self, pool: "SubprocessPool", worker_id: int) -> None:
        self.pool = pool
        self.worker_id = worker_id
        self.parent_connection, child_connection = multiprocessing.Pipe(duplex=True)
        self.process = pool.context.Process(
            target=_subprocess_main,
            args=(child_connection,),
            daemon=True,
        )
        self.process.start()
        child_connection.close()
        self.terminated = threading.Event()
        self.terminate_lock = threading.Lock()

    def execute(self, request: SubprocessRequest, timeout: Optional[float]) -> Any:
        try:
            self.parent_connection.send_bytes(_encode_request(request))
        except (BrokenPipeError, OSError) as e:
            raise SubprocessCrashed(f"Subprocess {self.process.pid} crashed before executing actor.") from e

        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
            if not self.parent_connection.poll(remaining):
                raise SubprocessTimeout(f"Actor {request.actor_name!r} exceeded its subprocess time limit.")

            try:
                response = _decode_response(self.parent_connection.recv_bytes())
            except (EOFError, OSError, ValueError, json.JSONDecodeError) as e:
                if self.process.exitcode is not None:
                    raise SubprocessCrashed(
                        f"Subprocess {self.process.pid} exited with code {self.process.exitcode}."
                    ) from e
                raise SubprocessCrashed(f"Subprocess {self.process.pid} returned an invalid response.") from e

            if response.message_id != request.message_id:
                raise SubprocessCrashed(
                    f"Subprocess {self.process.pid} returned a response for message {response.message_id!r} "
                    f"while processing {request.message_id!r}."
                )

            if response.exception is not None:
                if response.traceback:
                    self.pool.logger.error(
                        "Actor %r raised in subprocess %s:\n%s",
                        request.actor_name,
                        self.process.pid,
                        response.traceback,
                    )
                _raise_exception(response.exception, response.traceback)

            return response.result

    def terminate(self) -> None:
        with self.terminate_lock:
            if self.terminated.is_set():
                return

            self.terminated.set()
            if self.process.exitcode is None:
                self.process.terminate()
                self.process.join(timeout=1)
                if self.process.exitcode is None:
                    self.process.kill()
                    self.process.join()
            try:
                self.parent_connection.close()
            except OSError:
                pass

            self.pool.forget(self)


class SubprocessPool:
    def __init__(self, *, max_workers: int = 1) -> None:
        if max_workers < 1:
            raise ValueError("max_workers must be greater than 0")

        self.logger = get_logger(__name__, type(self))
        self.max_workers = max_workers
        self.context = multiprocessing.get_context("spawn")
        self.slots = threading.BoundedSemaphore(max_workers)
        self.idle_workers: queue.Queue[_SubprocessWorker] = queue.Queue()
        self.workers: set[_SubprocessWorker] = set()
        self.workers_lock = threading.Lock()
        self.next_worker_id = 0
        self.stopping = threading.Event()
        self.closed = False

    def execute(self, actor: "Actor", message: Any, *, time_limit: Optional[float]) -> Any:
        worker: Optional[_SubprocessWorker] = None
        reusable = False
        try:
            while not self.stopping.is_set():
                if self.slots.acquire(timeout=0.1):
                    break
            else:
                raise SubprocessCrashed("Subprocess pool is shutting down.")

            if self.stopping.is_set():
                raise SubprocessCrashed("Subprocess pool is shutting down.")

            try:
                worker = self.idle_workers.get_nowait()
            except queue.Empty:
                worker = self._start_worker()

            request = SubprocessRequest(
                message_id=message.message_id,
                actor_module=_callable_module(actor.fn),
                actor_name=actor.actor_name,
                actor_qualname=_callable_qualname(actor.fn),
                args=tuple(message.args),
                kwargs=dict(message.kwargs),
            )
            try:
                result = worker.execute(request, None if time_limit == float("inf") else time_limit / 1000)
                reusable = True
                return result
            except SubprocessTimeout:
                self.logger.warning(
                    "Hard time limit exceeded for message %r; terminating subprocess %s.",
                    message.message_id,
                    worker.process.pid,
                )
                raise
            except SubprocessCrashed:
                self.logger.warning(
                    "Subprocess for message %r failed; terminating subprocess %s.",
                    message.message_id,
                    worker.process.pid,
                    exc_info=True,
                )
                raise
        finally:
            if worker is not None:
                if reusable:
                    self.idle_workers.put(worker)
                else:
                    worker.terminate()
            self.slots.release()

    def shutdown(self) -> None:
        if self.closed:
            return

        self.closed = True
        self.stopping.set()

        with self.workers_lock:
            self.stopping.set()
            workers = list(self.workers)

        for worker in workers:
            worker.terminate()

        while True:
            try:
                worker = self.idle_workers.get_nowait()
            except queue.Empty:
                return
            worker.terminate()

    def _start_worker(self) -> _SubprocessWorker:
        with self.workers_lock:
            if self.stopping.is_set():
                raise SubprocessCrashed("Subprocess pool is shutting down.")

            worker_id = self.next_worker_id
            self.next_worker_id += 1
            worker = _SubprocessWorker(self, worker_id)
            self.workers.add(worker)
        return worker

    def forget(self, worker: _SubprocessWorker) -> None:
        with self.workers_lock:
            self.workers.discard(worker)


def _subprocess_main(connection: multiprocessing.connection.Connection) -> None:
    try:
        while True:
            request = _decode_request(connection.recv_bytes())

            try:
                actor = _resolve_registered_actor(request.actor_module, request.actor_name, request.actor_qualname)
                result = actor(*request.args, **request.kwargs)
                json.dumps(result, allow_nan=False)
                response = SubprocessResponse(message_id=request.message_id, result=result)
            except BaseException as exception:
                response = SubprocessResponse(
                    message_id=request.message_id,
                    status="error",
                    exception=_exception_info(exception),
                    traceback=traceback.format_exc(),
                )

            connection.send_bytes(_encode_response(response))
    except (EOFError, BrokenPipeError):
        return
    finally:
        connection.close()


def _resolve_registered_actor(module_name: str, actor_name: str, actor_qualname: str) -> "Actor":
    from . import broker as broker_module
    from .broker import Broker

    module = importlib.import_module(module_name)

    brokers = [value for value in vars(module).values() if isinstance(value, Broker)]
    if broker_module.global_broker is not None:
        brokers.append(broker_module.global_broker)

    for broker in dict.fromkeys(brokers):
        actor = broker.actors.get(actor_name)
        if (
            actor is not None
            and _callable_module(actor.fn) == module_name
            and _callable_qualname(actor.fn) == actor_qualname
        ):
            return actor

    raise ActorNotFound(actor_name)


def _encode_request(request: SubprocessRequest) -> bytes:
    return json.dumps(dataclasses.asdict(request), separators=(",", ":"), allow_nan=False).encode("utf-8")


def _decode_request(data: bytes) -> SubprocessRequest:
    payload = json.loads(data.decode("utf-8"), parse_constant=_reject_json_constant)
    if not isinstance(payload, dict):
        raise SubprocessCrashed("Subprocess request must be a JSON object.")

    required = {"message_id", "actor_module", "actor_name", "actor_qualname", "args", "kwargs"}
    if set(payload) != required:
        raise SubprocessCrashed("Subprocess request contains invalid fields.")
    if (
        not all(
            isinstance(payload[name], str)
            for name in ("message_id", "actor_module", "actor_name", "actor_qualname")
        )
        or not isinstance(payload["args"], list)
        or not isinstance(payload["kwargs"], dict)
        or not all(isinstance(key, str) for key in payload["kwargs"])
    ):
        raise SubprocessCrashed("Subprocess request contains invalid parameters.")

    return SubprocessRequest(
        message_id=payload["message_id"],
        actor_module=payload["actor_module"],
        actor_name=payload["actor_name"],
        actor_qualname=payload["actor_qualname"],
        args=tuple(payload["args"]),
        kwargs=payload["kwargs"],
    )


def _encode_response(response: SubprocessResponse) -> bytes:
    return json.dumps(dataclasses.asdict(response), separators=(",", ":"), allow_nan=False).encode("utf-8")


def _decode_response(data: bytes) -> SubprocessResponse:
    payload = json.loads(data.decode("utf-8"), parse_constant=_reject_json_constant)
    if not isinstance(payload, dict):
        raise SubprocessCrashed("Subprocess response must be a JSON object.")

    allowed = {"message_id", "status", "result", "exception", "traceback"}
    if not allowed.issuperset(payload):
        raise SubprocessCrashed("Subprocess response contains invalid fields.")
    if payload.get("status") not in {"ok", "error"}:
        raise SubprocessCrashed("Subprocess response contains an invalid status.")
    if payload.get("exception") is not None and not isinstance(payload["exception"], dict):
        raise SubprocessCrashed("Subprocess response contains an invalid exception.")

    return SubprocessResponse(**payload)


def _reject_json_constant(value: str) -> NoReturn:
    raise ValueError(f"Unsupported JSON constant {value!r}")


def _exception_info(exception: BaseException) -> dict[str, Any]:
    args: list[Any] = []
    try:
        json.dumps(exception.args, allow_nan=False)
        args = list(exception.args)
    except (TypeError, ValueError):
        args = [str(exception)]

    return {
        "module": type(exception).__module__,
        "name": type(exception).__name__,
        "message": str(exception),
        "args": args,
    }


def _raise_exception(info: dict[str, Any], traceback_text: Optional[str]) -> None:
    module_name = info.get("module", "builtins")
    exception_name = info.get("name", "Exception")
    message = info.get("message", "")

    try:
        module = importlib.import_module(module_name)
        exception_type = getattr(module, exception_name)
        if not isinstance(exception_type, type) or not issubclass(exception_type, BaseException):
            raise TypeError
        args = info.get("args")
        if isinstance(args, list):
            exception = exception_type(*args)
        else:
            exception = exception_type(message)
    except Exception:
        exception = SubprocessCrashed(f"{module_name}.{exception_name}: {message}")

    setattr(exception, "subprocess_traceback", traceback_text)
    raise exception


def _callable_module(fn: Any) -> str:
    return getattr(fn, "__module__", None) or type(fn).__module__


def _callable_qualname(fn: Any) -> str:
    return getattr(fn, "__qualname__", None) or type(fn).__qualname__
