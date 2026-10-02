"""Per-actor subprocess execution.

Actors declared with `subprocess=True` are executed in a dedicated
child process instead of a worker thread.  This isolates the worker
from actors that call into native libraries that may hang or crash:
the parent process keeps owning message acknowledgement and retries,
while the child only runs the registered actor callable.

The parent and child speak a restricted protocol: a single
newline-delimited JSON document per direction over the child's
stdin/stdout.  Pickle is never used, so only JSON-encodable values
can cross the process boundary.

Each message is executed by a fresh child process (spawned via
:mod:`subprocess`, which works with macOS' spawn start method) and
every request/response pair is tagged with the message id, so a late
result can never be attributed to a different message.  When a hard
timeout fires or a child crashes, the child is reaped *before* its
concurrency slot is released.
"""

from __future__ import annotations

import importlib
import os
import selectors
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from .encoder import JSONEncoder
from .logging import get_logger
from .middleware.middleware import Middleware

if TYPE_CHECKING:
    from .broker import Broker

#: The encoder used for the parent/child wire protocol.  This is
#: deliberately JSON (never pickle) so that the protocol stays
#: restricted to plain data.
_encoder = JSONEncoder()

#: How long to wait for a killed child to actually exit.
_REAP_TIMEOUT_SECS = 30


class SubprocessError(Exception):
    """Base class for subprocess execution errors."""


class SubprocessTimeout(SubprocessError):
    """Raised when a child process exceeds its hard time limit."""


class SubprocessCrashed(SubprocessError):
    """Raised when a child process dies without sending a response."""


class SubprocessProtocolError(SubprocessError):
    """Raised when a child sends malformed or mismatched data."""


class Subprocess(Middleware):
    """Middleware that lets individual actors opt into subprocess
    execution by declaring `subprocess=True`:

        broker.add_middleware(Subprocess(max_processes=2, timeout=60))

        @dramatiq.actor(subprocess=True, subprocess_timeout=10)
        def risky_native_call():
            ...

    Actors without the option keep running in the regular worker
    threads.  The parent process keeps owning message acknowledgement
    and retries; the child process only runs the actor callable.

    Parameters:
      max_processes(int): The maximum number of child processes that
        may run concurrently.  Acts as the default for
        `Worker(subprocess_max_processes=...)`.
      timeout(float): The default hard time limit in seconds for one
        message.  Acts as the default for
        `Worker(subprocess_timeout=...)` and may be overridden per
        actor with the `subprocess_timeout` option.
    """

    def __init__(self, *, max_processes: int = 4, timeout: float = 300.0) -> None:
        self.max_processes = max_processes
        self.timeout = timeout

    @property
    def actor_options(self) -> set[str]:
        return {"subprocess", "subprocess_timeout"}


class RemoteActorError(SubprocessError):
    """Raised in the parent when the actor raised inside the child.

    Attributes:
      actor_name(str): The actor that failed.
      error_type(str): The class name of the remote exception.
      error_message(str): The str() of the remote exception.
      remote_traceback(str): The formatted remote traceback.
    """

    def __init__(self, actor_name: str, error_type: str, error_message: str, remote_traceback: str) -> None:
        self.actor_name = actor_name
        self.error_type = error_type
        self.error_message = error_message
        self.remote_traceback = remote_traceback
        super().__init__(
            "Actor %r raised %s in a subprocess: %s\n--- remote traceback ---\n%s"
            % (actor_name, error_type, error_message, remote_traceback)
        )


def _module_path_entry(module_name: str, module_file: str) -> str:
    """Compute the sys.path entry that makes `module_name` importable
    given the file it was loaded from.
    """
    parts = module_name.split(".")
    return str(Path(module_file).resolve().parents[len(parts) - 1])


def _actor_module(actor) -> tuple[str, Optional[str]]:
    """Return the (module name, module file) an actor's fn belongs to."""
    module_name = actor.fn.__module__ or "__main__"
    module = sys.modules.get(module_name)
    module_file = getattr(module, "__file__", None)
    if module_name == "__main__" and module_file is None:
        raise SubprocessError(
            "Actor %r is defined in an interactive __main__ module and cannot be "
            "re-imported inside a subprocess.  Move the actor to an importable module." % actor.actor_name
        )
    return module_name, module_file


class SubprocessPool:
    """Runs actors in one-shot child processes with a hard timeout.

    Parameters:
      broker(Broker): The broker the actors are registered on.
      max_processes(int): The maximum number of child processes that
        may run concurrently.  Calls beyond that block until a slot
        frees up.
      default_timeout(float): The default hard time limit in seconds
        for a single message.  Actors may override this with the
        `subprocess_timeout` option.
    """

    def __init__(self, broker: "Broker", *, max_processes: int = 4, default_timeout: float = 300.0) -> None:
        self.logger = get_logger(__name__, type(self))
        self.broker = broker
        self.max_processes = max_processes
        self.default_timeout = default_timeout
        self._slots = threading.BoundedSemaphore(max_processes)
        self._children: dict[int, "subprocess.Popen[bytes]"] = {}
        self._lock = threading.Lock()
        self._closed = False

    def run(
        self,
        *,
        actor_name: str,
        message_id: str,
        args: tuple,
        kwargs: dict,
        timeout: Optional[float] = None,
    ) -> Any:
        """Execute an actor in a child process and return its result.

        Raises RemoteActorError if the actor raised, SubprocessTimeout
        if the hard time limit was exceeded and SubprocessCrashed if
        the child died without responding.
        """
        actor = self.broker.get_actor(actor_name)
        module_name, module_file = _actor_module(actor)
        # Encode before spawning anything so unencodable arguments
        # fail fast, like a regular actor call would.
        request = _encoder.encode(
            {
                "message_id": message_id,
                "actor": actor_name,
                "args": list(args),
                "kwargs": kwargs,
            }
        )
        if timeout is None:
            timeout = self.default_timeout

        self._slots.acquire()
        proc = None
        try:
            with self._lock:
                if self._closed:
                    raise SubprocessError("The subprocess pool is closed.")
            proc = self._spawn(module_name, module_file)
            with self._lock:
                self._children[proc.pid] = proc

            if TYPE_CHECKING:
                assert proc.stdin
            proc.stdin.write(request + b"\n")
            proc.stdin.flush()
            proc.stdin.close()

            response = self._read_response(proc, timeout)
            # The response must be tagged with the id of the message
            # we sent.  Anything else is a late or foreign result and
            # must not be attributed to this message.
            if response.get("message_id") != message_id:
                raise SubprocessProtocolError(
                    "Discarding response for message %r while processing message %r."
                    % (response.get("message_id"), message_id)
                )

            status = response.get("status")
            if status == "ok":
                return response.get("result")
            elif status == "error":
                raise RemoteActorError(
                    actor_name,
                    response.get("error_type", "Exception"),
                    response.get("error_message", ""),
                    response.get("traceback", ""),
                )
            else:
                raise SubprocessProtocolError("Child sent a response with unknown status %r." % (status,))
        finally:
            if proc is not None:
                # Confirm the child is gone before releasing its slot
                # so a hung or crashing child can never hold a slot
                # hostage and its output can never leak into the next
                # message.
                self._reap(proc)
                with self._lock:
                    self._children.pop(proc.pid, None)
            self._slots.release()

    def close(self) -> None:
        """Terminate and reap all remaining child processes."""
        with self._lock:
            self._closed = True
            children = list(self._children.values())
        for proc in children:
            try:
                self._reap(proc)
            except Exception:  # pragma: no cover
                self.logger.warning("Failed to reap child process %d.", proc.pid, exc_info=True)
        with self._lock:
            for proc in children:
                self._children.pop(proc.pid, None)

    def _spawn(self, module_name: str, module_file: Optional[str]) -> "subprocess.Popen[bytes]":
        argv = [
            sys.executable,
            "-c",
            "import sys;from dramatiq.subprocess_pool import _child_main;sys.exit(_child_main(sys.argv[1:]))",
            module_name,
        ]
        if module_file:
            argv.append(_module_path_entry(module_name, module_file))
        else:
            argv.append("-")
        self.logger.debug("Spawning child process: %r", argv)
        return subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            # The child's stderr is inherited so its logging and crash
            # output shows up in the worker's logs.
            stderr=None,
        )

    def _read_response(self, proc: "subprocess.Popen[bytes]", timeout: Optional[float]) -> dict:
        if TYPE_CHECKING:
            assert proc.stdout
        deadline = None if timeout is None else time.monotonic() + timeout
        chunks = []
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while True:
                wait = None if deadline is None else max(deadline - time.monotonic(), 0)
                if wait == 0:
                    raise SubprocessTimeout(
                        "Child process %d exceeded its hard time limit and was killed." % proc.pid
                    )
                if not selector.select(timeout=wait):
                    raise SubprocessTimeout(
                        "Child process %d exceeded its hard time limit and was killed." % proc.pid
                    )
                chunk = os.read(proc.stdout.fileno(), 65536)
                if not chunk:
                    break
                chunks.append(chunk)
                if b"\n" in chunk:
                    break

        data = b"".join(chunks)
        if not data.strip():
            raise SubprocessCrashed(
                "Child process %d exited with code %s without sending a response." % (proc.pid, proc.poll())
            )
        line = data.split(b"\n", 1)[0]
        response = _encoder.decode(line)
        if not isinstance(response, dict):
            raise SubprocessProtocolError("Child process %d sent a non-object response." % proc.pid)
        return response

    def _reap(self, proc: "subprocess.Popen[bytes]") -> None:
        if proc.poll() is None:
            self.logger.debug("Killing child process %d.", proc.pid)
            proc.kill()
        try:
            proc.wait(timeout=_REAP_TIMEOUT_SECS)
        except subprocess.TimeoutExpired:  # pragma: no cover
            self.logger.warning("Child process %d did not exit after being killed.", proc.pid)


def _child_main(argv: list[str]) -> int:
    """Entry point of the child process.

    Imports the module the actor lives in (which registers the actor
    on the global broker), reads one JSON request from stdin, runs the
    registered actor and writes one JSON response to stdout.
    """
    module_name = argv[0]
    path_entry = argv[1] if len(argv) > 1 else "-"
    if path_entry != "-":
        sys.path.insert(0, path_entry)

    importlib.import_module(module_name)

    from .broker import get_broker

    broker = get_broker()

    raw = sys.stdin.buffer.readline()
    try:
        request = _encoder.decode(raw)
        message_id = request.get("message_id")
    except Exception:
        # Without a valid request there is no message id to tag a
        # response with, so bail out and let the parent report a
        # crashed child.
        traceback.print_exc()
        return 2

    try:
        actor_name = request["actor"]
        # Only actors that are actually registered on the broker may
        # be executed; anything else raises ActorNotFound here.
        actor = broker.get_actor(actor_name)
        result = actor(*request.get("args", ()), **request.get("kwargs", {}))
        response = {"message_id": message_id, "status": "ok", "result": result}
    except BaseException as e:
        response = {
            "message_id": message_id,
            "status": "error",
            "error_type": type(e).__name__,
            "error_message": str(e),
            "traceback": traceback.format_exc(),
        }

    try:
        payload = _encoder.encode(response)
    except (TypeError, ValueError):
        payload = _encoder.encode(
            {
                "message_id": message_id,
                "status": "error",
                "error_type": "UnencodableResult",
                "error_message": "The actor's result could not be encoded as JSON.",
                "traceback": traceback.format_exc(),
            }
        )

    sys.stdout.buffer.write(payload + b"\n")
    sys.stdout.buffer.flush()
    return 0

