# SPDX-License-Identifier: MIT OR Apache-2.0
# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the MIT License.  See the LICENSE file in the root of this
# repository for complete details.

"""
Exceptions factored out to avoid import loops.
"""

from __future__ import annotations


class DropEvent(BaseException):
    """
    If raised by an processor, the event gets silently dropped.

    Derives from BaseException because it's technically not an error.
    """


class NoConsoleRendererConfiguredError(Exception):
    """
    A user asked for the current `structlog.dev.ConsoleRenderer` but none is
    configured.

    .. versionadded:: 25.5.0
    """


class MultipleConsoleRenderersConfiguredError(Exception):
    """
    A user asked for the current `structlog.dev.ConsoleRenderer` and more than one is configured.

    .. versionadded:: 25.5.0
    """


class BufferFullError(Exception):
    """
    A `structlog.AsyncSink` using the ``raise`` full-policy was asked to accept
    a log event while its bounded buffer was full.

    The event is *not* enqueued; the caller decides how to handle it.

    .. versionadded:: 26.2.0
    """


class SinkDeliveryError(Exception):
    """
    One or more log events could not be delivered to an
    `structlog.AsyncSink`'s wrapped sink.

    Raised by `structlog.AsyncSink.flush` and `structlog.AsyncSink.close`.
    Each failure is reported exactly once: a sequence number that was part of
    a raised error is not reported again by later calls.

    Attributes:
        failures: Map of receive sequence number to the exception the sink
            raised for that event.
        sequences: Sorted tuple of the receive sequence numbers that could
            not be delivered.

    .. versionadded:: 26.2.0
    """

    def __init__(self, failures: dict[int, BaseException]) -> None:
        self.failures: dict[int, BaseException] = dict(failures)
        self.sequences: tuple[int, ...] = tuple(sorted(self.failures))
        super().__init__(
            f"{len(self.sequences)} log event(s) could not be delivered "
            f"to the sink; unfinished sequence numbers: "
            f"{list(self.sequences)}"
        )
