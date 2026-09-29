# SPDX-License-Identifier: MIT OR Apache-2.0
# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the MIT License.  See the LICENSE file in the root of this
# repository for complete details.

"""
Logger classes responsible for output.
"""

from __future__ import annotations

import contextvars
import copy
import sys
import threading
import weakref

from collections import deque
from collections.abc import Callable
from enum import Enum
from pickle import PicklingError
from sys import stderr, stdout
from typing import IO, Any, BinaryIO, TextIO

from .exceptions import BufferFullError, SinkDeliveryError


if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


WRITE_LOCKS: weakref.WeakKeyDictionary[IO[Any], threading.Lock] = (
    weakref.WeakKeyDictionary()
)


def _get_lock_for_file(file: IO[Any]) -> threading.Lock:
    lock = WRITE_LOCKS.get(file)
    if lock is None:
        lock = threading.Lock()
        WRITE_LOCKS[file] = lock

    return lock


class PrintLogger:
    """
    Print events into a file.

    Args:
        file: File to print to. (default: `sys.stdout`)

    >>> from structlog import PrintLogger
    >>> PrintLogger().info("hello")
    hello

    Useful if you follow `current logging best practices
    <logging-best-practices>`.

    Also very useful for testing and examples since `logging` is finicky in
    doctests.

    .. versionchanged:: 22.1.0
       The implementation has been switched to use `print` for better
       monkeypatchability.
    """

    def __init__(self, file: TextIO | None = None):
        self._file = file or stdout

        self._lock = _get_lock_for_file(self._file)

    def __getstate__(self) -> str:
        """
        Our __getattr__ magic makes this necessary.
        """
        if self._file is stdout:
            return "stdout"

        if self._file is stderr:
            return "stderr"

        raise PicklingError(
            "Only PrintLoggers to sys.stdout and sys.stderr can be pickled."
        )

    def __setstate__(self, state: Any) -> None:
        """
        Our __getattr__ magic makes this necessary.
        """
        if state == "stdout":
            self._file = stdout
        else:
            self._file = stderr

        self._lock = _get_lock_for_file(self._file)

    def __deepcopy__(self, memodict: dict[str, object]) -> PrintLogger:
        """
        Create a new PrintLogger with the same attributes. Similar to pickling.
        """
        if self._file not in (stdout, stderr):
            raise copy.error(
                "Only PrintLoggers to sys.stdout and sys.stderr "
                "can be deepcopied."
            )

        newself = self.__class__(self._file)

        newself._lock = _get_lock_for_file(newself._file)

        return newself

    def __repr__(self) -> str:
        return f"<PrintLogger(file={self._file!r})>"

    def msg(self, message: str) -> None:
        """
        Print *message*.
        """
        f = self._file if self._file is not stdout else None
        with self._lock:
            print(message, file=f, flush=True)

    log = debug = info = warn = warning = msg
    fatal = failure = err = error = critical = exception = msg


class PrintLoggerFactory:
    r"""
    Produce `PrintLogger`\ s.

    To be used with `structlog.configure`\ 's ``logger_factory``.

    Args:
        file: File to print to. (default: `sys.stdout`)

    Positional arguments are silently ignored.

    .. versionadded:: 0.4.0
    """

    def __init__(self, file: TextIO | None = None):
        self._file = file

    def __call__(self, *args: Any) -> PrintLogger:
        return PrintLogger(self._file)


class WriteLogger:
    """
    Write events into a file.

    Args:
        file: File to print to. (default: `sys.stdout`)

    >>> from structlog import WriteLogger
    >>> WriteLogger().info("hello")
    hello

    Useful if you follow
    `current logging best practices <logging-best-practices>`.

    Also very useful for testing and examples since `logging` is finicky in
    doctests.

    A little faster and a little less versatile than `structlog.PrintLogger`.

    .. versionadded:: 22.1.0
    """

    def __init__(self, file: TextIO | None = None):
        self._file = file or sys.stdout
        self._write = self._file.write
        self._flush = self._file.flush

        self._lock = _get_lock_for_file(self._file)

    def __getstate__(self) -> str:
        """
        Our __getattr__ magic makes this necessary.
        """
        if self._file is stdout:
            return "stdout"

        if self._file is stderr:
            return "stderr"

        raise PicklingError(
            "Only WriteLoggers to sys.stdout and sys.stderr can be pickled."
        )

    def __setstate__(self, state: Any) -> None:
        """
        Our __getattr__ magic makes this necessary.
        """
        if state == "stdout":
            self._file = stdout
        else:
            self._file = stderr

        self._write = self._file.write
        self._flush = self._file.flush
        self._lock = _get_lock_for_file(self._file)

    def __deepcopy__(self, memodict: dict[str, object]) -> WriteLogger:
        """
        Create a new WriteLogger with the same attributes. Similar to pickling.
        """
        if self._file not in (sys.stdout, sys.stderr):
            raise copy.error(
                "Only WriteLoggers to sys.stdout and sys.stderr "
                "can be deepcopied."
            )

        newself = self.__class__(self._file)

        newself._write = newself._file.write
        newself._flush = newself._file.flush
        newself._lock = _get_lock_for_file(newself._file)

        return newself

    def __repr__(self) -> str:
        return f"<WriteLogger(file={self._file!r})>"

    def msg(self, message: str) -> None:
        """
        Write and flush *message*.
        """
        with self._lock:
            self._write(message + "\n")
            self._flush()

    log = debug = info = warn = warning = msg
    fatal = failure = err = error = critical = exception = msg


class WriteLoggerFactory:
    r"""
    Produce `WriteLogger`\ s.

    To be used with `structlog.configure`\ 's ``logger_factory``.

    Args:
        file: File to print to. (default: `sys.stdout`)

    Positional arguments are silently ignored.

    .. versionadded:: 22.1.0
    """

    def __init__(self, file: TextIO | None = None):
        self._file = file

    def __call__(self, *args: Any) -> WriteLogger:
        return WriteLogger(self._file)


class BytesLogger:
    r"""
    Writes bytes into a file.

    Useful if you follow `current logging best practices
    <logging-best-practices>` together with a formatter that returns bytes
    (e.g. `orjson <https://github.com/ijl/orjson>`_).

    Args:
        file: File to print to. (default: `sys.stdout`\ ``.buffer``)

        name:
            Optional name for the logger. If provided, it will be picked up
            as the logger's name when used with
            `structlog.stdlib.add_logger_name()` without using standard
            library integration. ``BytesLogger`` itself does nothing with it.

    .. versionadded:: 20.2.0

    .. versionadded:: 26.1.0 The ``name`` attribute.
    """

    __slots__ = ("_file", "_flush", "_lock", "_write", "name")

    name: str | None

    def __init__(
        self, file: BinaryIO | None = None, *, name: str | None = None
    ):
        self._file = file or sys.stdout.buffer
        self._write = self._file.write
        self._flush = self._file.flush

        self.name = name

        self._lock = _get_lock_for_file(self._file)

    def __getstate__(self) -> tuple[str, str | None]:
        """
        Our __getattr__ magic makes this necessary.
        """
        if self._file is sys.stdout.buffer:
            return "stdout", self.name

        if self._file is sys.stderr.buffer:
            return "stderr", self.name

        raise PicklingError(
            "Only BytesLoggers to sys.stdout and sys.stderr can be pickled."
        )

    def __setstate__(self, state: Any) -> None:
        """
        Our __getattr__ magic makes this necessary.
        """
        if isinstance(state, str):
            name = None
        else:
            state, name = state

        if state == "stdout":
            self._file = sys.stdout.buffer
        else:
            self._file = sys.stderr.buffer

        self._write = self._file.write
        self._flush = self._file.flush
        self.name = name
        self._lock = _get_lock_for_file(self._file)

    def __deepcopy__(self, memodict: dict[str, object]) -> BytesLogger:
        """
        Create a new BytesLogger with the same attributes. Similar to pickling.
        """
        if self._file not in (sys.stdout.buffer, sys.stderr.buffer):
            raise copy.error(
                "Only BytesLoggers to sys.stdout and sys.stderr "
                "can be deepcopied."
            )

        newself = self.__class__(self._file, name=self.name)

        newself._write = newself._file.write
        newself._flush = newself._file.flush
        newself._lock = _get_lock_for_file(newself._file)

        return newself

    def __repr__(self) -> str:
        if self.name is None:
            return f"<BytesLogger(file={self._file!r})>"

        return f"<BytesLogger(name={self.name!r}, file={self._file!r})>"

    def msg(self, message: bytes) -> None:
        """
        Write *message*.
        """
        with self._lock:
            self._write(message + b"\n")
            self._flush()

    log = debug = info = warn = warning = msg
    fatal = failure = err = error = critical = exception = msg


class BytesLoggerFactory:
    r"""
    Produce `BytesLogger`\ s.

    To be used with `structlog.configure`\ 's ``logger_factory``.

    Args:
        file: File to print to. (default: `sys.stdout`\ ``.buffer``)

    Positional arguments are silently ignored.

    .. versionadded:: 20.2.0
    """

    __slots__ = ("_file",)

    def __init__(self, file: BinaryIO | None = None):
        self._file = file

    def __call__(self, *args: Any) -> BytesLogger:
        return BytesLogger(self._file, name=args[0] if args else None)


class FullPolicy(Enum):
    """
    What an `AsyncSink` does with a new event while its bounded buffer is
    full.

    .. versionadded:: 26.2.0
    """

    WAIT = "wait"
    """Block the caller until the buffer has room again (backpressure)."""

    DROP = "drop"
    """Silently discard the new event; counted in `AsyncSink.dropped`."""

    RAISE = "raise"
    """Raise `structlog.exceptions.BufferFullError` in the caller."""


class AsyncSink:
    r"""
    Forward log events to a wrapped *sink* from a single background thread
    through a bounded buffer, so a slow or briefly blocked sink doesn't
    stall business threads.

    The wrapped sink can be any logger-like object (e.g. `PrintLogger`);
    log methods are looked up dynamically and forwarded to it.

    Args:
        sink: Wrapped logger-like object that events are forwarded to.

        max_size: Maximum number of buffered, not-yet-delivered events.

        on_full: `FullPolicy` member (or its value: ``"wait"``,
            ``"drop"``, ``"raise"``) that is applied to a new event while
            the buffer is full.

    The lifecycle is explicit: `start` spawns the background thread,
    `flush` waits for delivery, and `close` stops accepting new events,
    delivers everything still buffered, and joins the thread. `AsyncSink`
    is also a context manager that starts on entry and closes on exit.

    Ordering & flushing:
        Each accepted event gets a monotonically increasing receive
        sequence number on the calling thread and events are delivered to
        the sink in that order. `flush` waits until every event received
        *before* the call has been delivered (or has failed) -- events
        received while a flush is in progress don't prolong it.

    Context capture:
        The event is rendered by the processor chain and the current
        `contextvars` context is captured, both on the calling thread. The
        background thread re-enters the captured context when calling the
        sink, so request context and call-site information are always the
        producer's, never the worker's.

    Error handling:
        If the sink raises an exception, the failure is recorded together
        with the event's sequence number and delivery continues with the
        next event. `flush` and `close` raise
        `structlog.exceptions.SinkDeliveryError` listing the unfinished
        sequence numbers; each failure is reported exactly once.

    .. versionadded:: 26.2.0
    """

    def __init__(
        self,
        sink: Any,
        *,
        max_size: int = 1000,
        on_full: FullPolicy | str = FullPolicy.WAIT,
    ) -> None:
        if max_size < 1:
            msg = f"max_size must be >= 1, got {max_size}."
            raise ValueError(msg)

        self._sink = sink
        self._max_size = max_size
        self._on_full = (
            on_full if isinstance(on_full, FullPolicy) else FullPolicy(on_full)
        )

        self._cond = threading.Condition()
        self._buffer: deque[
            tuple[
                int, str, tuple[Any, ...], dict[str, Any], contextvars.Context
            ]
        ] = deque()
        self._seq = 0
        self._done = 0
        self._dropped = 0
        self._failed: dict[int, BaseException] = {}
        self._reported: set[int] = set()
        self._started = False
        self._closing = False
        self._closed = False
        self._thread: threading.Thread | None = None

    def __repr__(self) -> str:
        return (
            f"<AsyncSink(sink={self._sink!r}, max_size={self._max_size}, "
            f"on_full={self._on_full.value!r})>"
        )

    def __getattr__(self, name: str) -> Callable[..., None]:
        """
        Return a producer method that enqueues a call to the sink's method
        called *name*.
        """
        if name.startswith("__"):
            raise AttributeError(name)

        def emit(*args: Any, **kwargs: Any) -> None:
            self._enqueue(name, args, kwargs)

        emit.__name__ = name
        return emit

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    @property
    def dropped(self) -> int:
        """
        Number of events discarded because the buffer was full.

        Only nonzero with `FullPolicy.DROP`.
        """
        with self._cond:
            return self._dropped

    @property
    def pending(self) -> int:
        """
        Number of accepted events that haven't been delivered yet.
        """
        with self._cond:
            return self._seq - self._done

    def start(self) -> None:
        """
        Spawn the background delivery thread.

        No events are accepted before this is called.
        """
        with self._cond:
            if self._closing:
                msg = "AsyncSink is closed and cannot be (re)started."
                raise RuntimeError(msg)

            if self._started:
                msg = "AsyncSink is already started."
                raise RuntimeError(msg)

            self._started = True
            self._thread = threading.Thread(
                target=self._run,
                name="structlog-AsyncSink",
                daemon=True,
            )
            self._thread.start()

    def flush(self) -> None:
        """
        Block until every event received before this call has been
        delivered to the sink (or failed).

        Events received after this call begins don't delay it.

        Raises:
            structlog.exceptions.SinkDeliveryError: The sink failed to
                deliver an event received before this call that hasn't been
                reported yet.
        """
        with self._cond:
            if not self._started:
                msg = "AsyncSink is not started yet; call start() first."
                raise RuntimeError(msg)

            watermark = self._seq
            self._cond.wait_for(lambda: self._done >= watermark)
            failures = self._take_unreported(watermark)

        if failures:
            raise SinkDeliveryError(failures)

    def close(self) -> None:
        """
        Stop accepting new events, deliver everything still buffered, and
        join the background thread.

        Idempotent. Raises `structlog.exceptions.SinkDeliveryError` if the
        sink failed events that haven't been reported yet.
        """
        with self._cond:
            self._closing = True
            self._cond.notify_all()
            thread = self._thread

        if thread is not None:
            thread.join()

        with self._cond:
            self._closed = True
            failures = self._take_unreported(self._seq)

        if failures:
            raise SinkDeliveryError(failures)

    def _check_open(self) -> None:
        """
        Raise if events can't be accepted. Must be called with the lock.
        """
        if self._closing:
            msg = "AsyncSink is closed and does not accept new events."
            raise RuntimeError(msg)

        if not self._started:
            msg = "AsyncSink is not started yet; call start() first."
            raise RuntimeError(msg)

    def _enqueue(
        self, name: str, args: tuple[Any, ...], kwargs: dict[str, Any]
    ) -> None:
        # Capture the producer's context before anything can switch
        # threads.
        ctx = contextvars.copy_context()

        with self._cond:
            self._check_open()

            if len(self._buffer) >= self._max_size:
                if self._on_full is FullPolicy.DROP:
                    self._dropped += 1
                    return

                if self._on_full is FullPolicy.RAISE:
                    msg = (
                        "AsyncSink buffer is full "
                        f"(max_size={self._max_size})."
                    )
                    raise BufferFullError(msg)

                self._cond.wait_for(
                    lambda: len(self._buffer) < self._max_size or self._closing
                )
                self._check_open()

            self._seq += 1
            self._buffer.append((self._seq, name, args, kwargs, ctx))
            self._cond.notify_all()

    def _take_unreported(self, watermark: int) -> dict[int, BaseException]:
        """
        Return failures up to *watermark* not reported yet, and mark them
        reported. Must be called with the lock.
        """
        failures = {
            seq: exc
            for seq, exc in self._failed.items()
            if seq <= watermark and seq not in self._reported
        }
        self._reported.update(failures)

        return failures

    def _run(self) -> None:
        while True:
            with self._cond:
                while not self._buffer and not self._closing:
                    self._cond.wait()

                if not self._buffer:
                    # Closing and fully drained.
                    return

                seq, name, args, kwargs, ctx = self._buffer.popleft()
                self._cond.notify_all()

            error: BaseException | None = None
            try:
                ctx.run(getattr(self._sink, name), *args, **kwargs)
            except Exception as exc:  # noqa: BLE001 # record and deliver on
                error = exc

            with self._cond:
                if error is not None:
                    self._failed[seq] = error

                self._done = seq
                self._cond.notify_all()
