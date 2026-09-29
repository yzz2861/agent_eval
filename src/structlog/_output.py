# SPDX-License-Identifier: MIT OR Apache-2.0
# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the MIT License.  See the LICENSE file in the root of this
# repository for complete details.

"""
Logger classes responsible for output.
"""

from __future__ import annotations

import copy
import sys
import threading
import weakref

from collections import deque
from contextvars import Context, copy_context
from enum import Enum
from pickle import PicklingError
from queue import Full as QueueFull
from sys import stderr, stdout
from typing import IO, Any, BinaryIO, NamedTuple, TextIO

from typing_extensions import Self

from .contextvars import _ASYNC_CALLING_STACK, _ASYNC_CALLING_THREAD


WRITE_LOCKS: weakref.WeakKeyDictionary[IO[Any], threading.Lock] = (
    weakref.WeakKeyDictionary()
)


class FullQueuePolicy(str, Enum):
    """
    Behavior when a buffered logger receives an event at full capacity.
    """

    WAIT = "wait"
    DROP = "drop"
    RAISE = "raise"


class BufferFull(QueueFull):
    """
    Raised when a buffered logger is full and configured to raise.
    """

    def __init__(self, capacity: int):
        self.capacity = capacity
        super().__init__(f"log buffer is full (capacity={capacity})")


class BufferedLoggerClosed(RuntimeError):  # noqa: N818
    """
    Raised when a closed buffered logger receives another event.
    """


class BufferedSinkError(RuntimeError):
    """
    Raised when one or more buffered events could not be delivered.

    The event reported as :attr:`failed_sequence` blocks all later events,
    so :attr:`unfinished_sequences` contains it and every event still queued
    behind it.
    """

    def __init__(
        self,
        failed_sequence: int,
        unfinished_sequences: tuple[int, ...],
        exceptions: dict[int, BaseException],
    ):
        self.failed_sequence = failed_sequence
        self.unfinished_sequences = unfinished_sequences
        self.exceptions = exceptions
        super().__init__(
            "sink failed for log sequence "
            f"{failed_sequence}; unfinished sequences: "
            f"{unfinished_sequences}"
        )


class _BufferedEvent(NamedTuple):
    sequence: int
    args: tuple[Any, ...]
    kwargs: dict[str, Any]
    method_name: str
    context: Context


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


class BufferedLogger:
    """
    Deliver rendered log events to *sink* from a bounded queue.

    Args:
        sink: Object that writes events. A callable is invoked directly;
            otherwise the method matching the log level is used.
        capacity: Maximum number of events accepted but not yet delivered.
        full_policy: What to do when the buffer is full: ``wait``, ``drop``,
            or ``raise``.

    The processor chain runs in the calling thread before an event enters the
    queue. The current `contextvars` context is copied at that point and
    activated around the sink call in the worker thread, so both request
    context and call-site information remain attributable to the producer.

    Events are delivered in the order of their monotonic receive sequence.
    :meth:`flush` only waits for events that had been received when it was
    called; events arriving afterwards do not extend its wait.

    Call :meth:`close` when the sink should be shut down. It rejects new
    events, drains queued events, and reports all unfinished sequences if the
    sink still fails.
    """

    def __init__(
        self,
        sink: Any,
        capacity: int = 1000,
        *,
        full_policy: FullQueuePolicy | str = FullQueuePolicy.WAIT,
    ):
        if capacity < 1:
            msg = "capacity must be at least 1"
            raise ValueError(msg)

        self._sink = sink
        self.capacity = capacity
        self.full_policy = self._coerce_full_policy(full_policy)

        self._condition = threading.Condition()
        self._lifecycle_lock = threading.Lock()
        self._events: deque[_BufferedEvent] = deque()
        self._next_sequence = 1
        self._completed_sequence = 0
        self._active_event: _BufferedEvent | None = None
        self._closed = False
        self._failed = False
        self._failures: dict[int, BaseException] = {}
        self._waiting_producers = 0
        self._thread = threading.Thread(
            target=self._run, name="structlog-buffered-output", daemon=True
        )
        self._thread.start()

    def __repr__(self) -> str:
        return (
            f"<BufferedLogger(sink={self._sink!r}, "
            f"capacity={self.capacity}, full_policy={self.full_policy!r})>"
        )

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    @staticmethod
    def _coerce_full_policy(policy: FullQueuePolicy | str) -> FullQueuePolicy:
        if isinstance(policy, FullQueuePolicy):
            return policy

        try:
            return FullQueuePolicy(policy)
        except ValueError:
            msg = (
                "full_policy must be one of "
                f"{[policy.value for policy in FullQueuePolicy]}"
            )
            raise ValueError(msg) from None

    def _sink_error(
        self, sequences: tuple[int, ...] | None = None
    ) -> BufferedSinkError:
        if sequences is None:
            sequences = tuple(event.sequence for event in self._events)

        failed_sequence = next(
            seq for seq in sequences if seq in self._failures
        )
        return BufferedSinkError(
            failed_sequence,
            sequences,
            {
                seq: self._failures[seq]
                for seq in sequences
                if seq in self._failures
            },
        )

    def msg(self, *args: Any, **kwargs: Any) -> int | None:
        return self._emit("msg", args, kwargs)

    def _emit(
        self,
        method_name: str,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> int | None:
        frame = sys._getframe()
        thread_info = (
            threading.get_ident(),
            threading.current_thread().name,
        )
        context = copy_context()
        self._capture_producer_context(context, frame, thread_info)

        with self._condition:
            while True:
                if self._closed:
                    raise BufferedLoggerClosed("buffered logger is closed")
                if self._failed:
                    raise self._sink_error()

                is_full = (
                    len(self._events) + (self._active_event is not None)
                    >= self.capacity
                )
                if not is_full:
                    break

                if self.full_policy is FullQueuePolicy.DROP:
                    return None
                if self.full_policy is FullQueuePolicy.RAISE:
                    raise BufferFull(self.capacity)

                self._waiting_producers += 1
                try:
                    self._condition.wait()
                finally:
                    self._waiting_producers -= 1

            sequence = self._next_sequence
            self._next_sequence += 1
            event = _BufferedEvent(
                sequence, args, kwargs, method_name, context
            )
            self._events.append(event)
            self._condition.notify_all()

        return sequence

    def flush(self) -> int:
        """
        Wait for delivery of every event received by this call.
        """
        with self._condition:
            target = self._next_sequence - 1

            while self._completed_sequence < target:
                if self._failed:
                    raise self._sink_error()
                if self._closed and not self._events:
                    msg = "buffered logger is closed"
                    raise BufferedLoggerClosed(msg)

                self._condition.wait()

        return target

    def close(self) -> None:
        """
        Reject new events and deliver all events already in the buffer.
        """
        with self._lifecycle_lock:
            with self._condition:
                if not self._closed:
                    self._closed = True
                    self._condition.notify_all()

            self._thread.join()

            while True:
                with self._condition:
                    if not self._events:
                        self._failed = False
                        self._failures.clear()
                        self._condition.notify_all()
                        return

                    event = self._events.popleft()
                    self._active_event = event

                try:
                    self._deliver(event)
                except BaseException as exc:
                    with self._condition:
                        self._active_event = None
                        self._failed = True
                        self._failures[event.sequence] = exc
                        self._events.appendleft(event)
                        error = self._sink_error()
                        self._condition.notify_all()
                    raise error from exc

                with self._condition:
                    self._active_event = None
                    self._completed_sequence = event.sequence
                    self._failures.pop(event.sequence, None)
                    self._condition.notify_all()

    @staticmethod
    def _capture_producer_context(
        context: Context,
        frame: Any,
        thread_info: tuple[int, str],
    ) -> None:
        def capture() -> None:
            if _ASYNC_CALLING_STACK.get(None) is None:
                _ASYNC_CALLING_STACK.set(frame)
            if _ASYNC_CALLING_THREAD.get(None) is None:
                _ASYNC_CALLING_THREAD.set(thread_info)

        context.run(capture)

    def _run(self) -> None:
        while True:
            with self._condition:
                while not self._events and not self._closed:
                    self._condition.wait()

                if not self._events:
                    return

                event = self._events.popleft()
                self._active_event = event

            try:
                self._deliver(event)
            except BaseException as exc:  # noqa: BLE001
                with self._condition:
                    self._active_event = None
                    self._failed = True
                    self._failures[event.sequence] = exc
                    self._events.appendleft(event)
                    self._condition.notify_all()
                return

            with self._condition:
                self._active_event = None
                self._completed_sequence = event.sequence
                self._failures.pop(event.sequence, None)
                self._condition.notify_all()

    def _deliver(self, event: _BufferedEvent) -> None:
        def deliver() -> None:
            if callable(self._sink):
                self._sink(*event.args, **event.kwargs)
            else:
                getattr(self._sink, event.method_name)(
                    *event.args, **event.kwargs
                )

        event.context.run(deliver)

    log = debug = info = warn = warning = msg
    fatal = failure = err = error = critical = exception = msg


class BufferedLoggerFactory:
    r"""
    Produce `BufferedLogger`\ s sharing one buffered sink.
    """

    def __init__(
        self,
        sink: Any,
        capacity: int = 1000,
        *,
        full_policy: FullQueuePolicy | str = FullQueuePolicy.WAIT,
    ):
        self._logger = BufferedLogger(sink, capacity, full_policy=full_policy)

    def __call__(self, *args: Any) -> BufferedLogger:
        return self._logger

    def flush(self) -> int:
        return self._logger.flush()

    def close(self) -> None:
        self._logger.close()
